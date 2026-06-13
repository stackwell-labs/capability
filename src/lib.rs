//! `capability` — one primitive for the platform's revocable-grant pattern.
//!
//! Drive grants, postbox relay-handles, Granite's issued grants, and social-graph
//! contacts are four hand-rolled versions of one idea: *a scoped, revocable
//! permission the resource owner issued, the actor presents, the resource checks
//! **live**.* This crate owns only that one rule — the [`verify`] check — plus the
//! [`Capability`] type it operates on. It does NOT own storage or issuance:
//! services keep their own DB, consent flow, and scope shape.
//!
//! The invariant `verify` makes true *by construction*: a capability check must
//! (a) be rejected if revoked, (b) only be honored in the [`Environment`] it was
//! minted in, (c) only honor the rightful holder, (d) stay within scope — checked
//! in exactly that order, so a revoked cap is dead before anything else is
//! examined, and a cross-environment cap leaks nothing about holder or scope.
//!
//! See `DESIGN.md` for the full rationale and the (deliberately deferred) chain /
//! attenuation extension.

#![forbid(unsafe_code)]

use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// An opaque capability id — a service's handle / grant_id. The crate never
/// interprets it; it is carried so a fetched cap knows its own identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CapId(pub String);

impl fmt::Display for CapId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which world a capability belongs to. Minted from the granter's verified chirp
/// identity (`ChirpVerifiedToken.environment`) — the bit is cryptographically
/// rooted upstream in chirp's keyset separation, so the only way it can be wrong
/// here is service code constructing it by hand. Don't: derive it from a verified
/// token at mint and at presentation.
///
/// `Test` carries the chirp test tenant (the `{tenant}` of
/// `/test/{tenant}/jwks.json`), so a grant minted under one tenant's test keyset
/// does not verify for another's.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Environment {
    Prod,
    Test { tenant: String },
}

impl fmt::Display for Environment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Environment::Prod => f.write_str("prod"),
            Environment::Test { tenant } => write!(f, "test:{tenant}"),
        }
    }
}

/// The one "no laundering into prod" mismatch. Returned when a stored artifact's
/// environment does not equal the caller's. Carries the `Display` of both so the
/// caller can log/audit which way the laundering was attempted (a `Test{tenant}`
/// artifact reaching for `Prod`, or vice versa, or a cross-tenant test mismatch)
/// without re-deriving it. Equality is exact and per-tenant (`Test{a} != Test{b}`),
/// since [`Environment`] derives `Eq`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvMismatch {
    /// The environment the artifact (grant / approval / token) was minted in.
    pub stored: Environment,
    /// The environment the caller is acting in (derived from its verified
    /// credential / keyset — never requester-set).
    pub caller: Environment,
}

impl fmt::Display for EnvMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "environment mismatch: artifact minted in {} but caller is acting in {} \
             (a {} artifact must never act in {})",
            self.stored, self.caller, self.stored, self.caller
        )
    }
}

impl std::error::Error for EnvMismatch {}

impl Environment {
    /// THE no-laundering guard. Every effect plane (capability grants, Granite
    /// approvals, any future env-tagged artifact) derives the SAME check from this
    /// one method instead of re-hand-rolling it: *the stored artifact's environment
    /// must equal the caller's, else refuse.*
    ///
    /// `self` is the artifact's environment (the world it was minted in); `caller`
    /// is the environment the actor is running in — both DERIVED from a verified
    /// credential / keyset upstream, never requester-set, so the bit is unforgeable
    /// here. Call this immediately before an irreversible act so there is no gap
    /// between the check and the action. A `Test{tenant}` artifact can never act in
    /// `Prod` (or another tenant), and a `Prod` artifact can never be acted on by a
    /// `Test` caller — enforced by construction here, not by a comment at each
    /// call site.
    ///
    /// Fail-closed is the caller's responsibility at the *boundary*: an absent /
    /// untagged environment must be read as the strictest (`Prod`) before reaching
    /// this guard — this crate's `Environment` has no serde default precisely so a
    /// missing tag fails loudly rather than silently laundering into prod.
    pub fn ensure_matches(&self, caller: &Environment) -> Result<(), EnvMismatch> {
        ensure_same_environment(self, caller)
    }
}

/// Free-function form of the [`Environment::ensure_matches`] guard, for call sites
/// that read more naturally as `ensure_same_environment(stored, caller)` (e.g. a
/// service comparing a loaded approval's environment against the caller's inside a
/// loaded-then-write section). Identical semantics: exact, per-tenant equality, or
/// a typed [`EnvMismatch`].
pub fn ensure_same_environment(
    stored: &Environment,
    caller: &Environment,
) -> Result<(), EnvMismatch> {
    if stored == caller {
        Ok(())
    } else {
        Err(EnvMismatch {
            stored: stored.clone(),
            caller: caller.clone(),
        })
    }
}

/// Liveness of a capability. `verify` reads this first, so flipping a stored cap to
/// `Revoked` is an instant, global "off" switch — the whole point of the pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Status {
    Active,
    Revoked,
}

/// What a capability lets its holder *do*. The lattice over these is the heart of
/// the unified authority plane (see `capability-lattice.md`):
///
/// - `Read`, `Append`, `Grant` are **reversible** — freely held, freely
///   [attenuated](Capability::attenuate) downward, never need a Warden.
/// - `Purge`, `Control` are **irreversible** — *unreachable by attenuation* and
///   with **no public constructor**. The sole origin of a `Rights` value carrying
///   one is [`warden::settle`], minted against a granite approval. "An agent cannot
///   destroy data" is therefore a **type fact**: nothing an agent holds or can call
///   manufactures a `Purge`/`Control` right.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Right {
    /// Read existing data. Reversible.
    Read,
    /// Append new data (op-DAG growth; never destroys). Reversible.
    Append,
    /// Delegate (attenuate-and-issue) a weaker capability. Reversible.
    Grant,
    /// Irreversibly destroy data (crypto-shred / purge). Warden-only.
    Purge,
    /// Irreversibly control a namespace (create/delete db, etc.). Warden-only.
    Control,
}

impl Right {
    /// The Warden discontinuity: `Purge`/`Control` are the irreversible rights.
    /// A `Rights` set may carry one *only* if it was produced by [`warden::settle`].
    pub const fn is_irreversible(self) -> bool {
        matches!(self, Right::Purge | Right::Control)
    }
}

/// A set of [`Right`]s — what a capability authorizes.
///
/// The invariant the type enforces **by construction**: a `Rights` value that
/// contains an irreversible right ([`Right::Purge`] / [`Right::Control`]) can be
/// built *only* by [`warden::settle`]. Every public constructor on this type
/// ([`Rights::reversible`], [`Rights::READ`], …, [`Rights::subset_of`]'s inputs)
/// rejects irreversible rights, and [`Capability::attenuate`] can only *drop*
/// rights. So no sequence of public/local calls yields a purge-authorizing set —
/// that is the negative agent-safety vector, true by type, not by check.
///
/// Internally the set is just a `u8` bitset; the irreversible bits are settable
/// only through the private [`Rights::from_bits_with_warden_seal`] used by
/// [`warden::settle`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Rights {
    bits: u8,
}

impl Rights {
    const READ_BIT: u8 = 1 << 0;
    const APPEND_BIT: u8 = 1 << 1;
    const GRANT_BIT: u8 = 1 << 2;
    const PURGE_BIT: u8 = 1 << 3;
    const CONTROL_BIT: u8 = 1 << 4;

    const fn bit_of(r: Right) -> u8 {
        match r {
            Right::Read => Self::READ_BIT,
            Right::Append => Self::APPEND_BIT,
            Right::Grant => Self::GRANT_BIT,
            Right::Purge => Self::PURGE_BIT,
            Right::Control => Self::CONTROL_BIT,
        }
    }

    const IRREVERSIBLE_MASK: u8 = Self::PURGE_BIT | Self::CONTROL_BIT;

    /// The empty rights set.
    pub const NONE: Rights = Rights { bits: 0 };
    /// `{Read}`.
    pub const READ: Rights = Rights {
        bits: Self::READ_BIT,
    };
    /// `{Read, Append}` — the agent default (what `amber`'s agent scope holds).
    pub const READ_APPEND: Rights = Rights {
        bits: Self::READ_BIT | Self::APPEND_BIT,
    };

    /// Build a reversible rights set. **Panics** is impossible — instead, any
    /// irreversible right in `rights` makes this return `None`, so there is no
    /// public path from an iterator of rights to a purge-authorizing set. This is
    /// the only public constructor that takes arbitrary rights, and it is sealed
    /// against the irreversible ones.
    pub fn reversible<I: IntoIterator<Item = Right>>(rights: I) -> Option<Rights> {
        let mut bits = 0u8;
        for r in rights {
            if r.is_irreversible() {
                return None;
            }
            bits |= Self::bit_of(r);
        }
        Some(Rights { bits })
    }

    /// The *only* way an irreversible right enters a `Rights` value. Private to the
    /// crate; reachable solely through [`warden::settle`]. (The arbitrary-bits form
    /// is never exposed — adopters cannot name it.)
    fn from_bits_with_warden_seal(bits: u8) -> Rights {
        Rights { bits }
    }

    /// Does this set contain `r`?
    pub const fn contains(self, r: Right) -> bool {
        self.bits & Self::bit_of(r) != 0
    }

    /// Is this set a subset of `other`? The lattice order on rights.
    pub const fn subset_of(self, other: Rights) -> bool {
        self.bits & other.bits == self.bits
    }

    /// Does this set carry an irreversible ([`Right::is_irreversible`]) right?
    pub const fn has_irreversible(self) -> bool {
        self.bits & Self::IRREVERSIBLE_MASK != 0
    }

    /// Iterate the rights in the set (for audit / display).
    pub fn iter(self) -> impl Iterator<Item = Right> {
        [
            Right::Read,
            Right::Append,
            Right::Grant,
            Right::Purge,
            Right::Control,
        ]
        .into_iter()
        .filter(move |&r| self.contains(r))
    }
}

/// An issued capability: the resource owner (`owner`) granted `holder` a `scope`d
/// permission, identified by `id`. The crate models only the *result* of issuance,
/// never how it was granted. Services persist this in their own store; it is
/// `Serialize`/`Deserialize` whenever the scope `S` is.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(bound(
        serialize = "S: Serialize",
        deserialize = "S: Deserialize<'de>"
    ))
)]
pub struct Capability<S> {
    /// Opaque id — the service's handle / grant_id.
    pub id: CapId,
    /// Who issued it: the resource owner / recipient.
    pub owner: String,
    /// Who may present it: the acting app/agent id (or sub).
    pub holder: String,
    /// The world it was minted in (from the granter's verified token). Required —
    /// deliberately no serde default, so a legacy record without it fails loudly
    /// at deserialize instead of silently becoming a prod credential. Services
    /// adopting this version migrate stored rows explicitly (everything persisted
    /// before environments existed was prod-minted: backfill `Prod` once, in the
    /// migration, not as a standing default).
    pub environment: Environment,
    /// Service-defined scope (see [`Scope`]).
    pub scope: S,
    /// What the holder may *do* (see [`Rights`]). A capability carrying an
    /// irreversible right ([`Right::Purge`]/[`Right::Control`]) can only have been
    /// produced by [`warden::settle`].
    pub rights: Rights,
    /// Live revocation state.
    pub status: Status,
    /// Unix seconds at issuance.
    pub created_at: i64,
}

impl<S: Clone> Capability<S> {
    /// FREE · LOCAL · TOTAL · DOWNWARD-ONLY. The lattice meet: derive a *weaker*
    /// capability from one you hold. There is deliberately **no** `widen` /
    /// `add_right` anywhere in this crate.
    ///
    /// The new `scope` must be [within](Scope::within) the current scope, and the
    /// new `rights` must be a [subset](Rights::subset_of) of the current rights —
    /// otherwise [`AttenuateError`]. No I/O, no Warden, no network. Holding a
    /// capability lets you derive *only* weaker ones.
    ///
    /// Because `attenuate` can only *drop* rights and `Rights`'s public
    /// constructors reject the irreversible ones, no `attenuate` sequence starting
    /// from a reversible capability can ever reach a `Purge`/`Control` right — the
    /// negative agent-safety vector, true by construction.
    pub fn attenuate(&self, scope: S, rights: Rights) -> Result<Capability<S>, AttenuateError>
    where
        S: Scope,
    {
        if !scope.within(&self.scope) {
            return Err(AttenuateError::ScopeWidened);
        }
        if !rights.subset_of(self.rights) {
            return Err(AttenuateError::RightsWidened);
        }
        Ok(Capability {
            id: self.id.clone(),
            owner: self.owner.clone(),
            holder: self.holder.clone(),
            environment: self.environment.clone(),
            scope,
            rights,
            status: self.status,
            created_at: self.created_at,
        })
    }
}

/// Why an [`attenuate`](Capability::attenuate) call was rejected. Both variants mean
/// the request tried to go *up* the lattice (the only thing `attenuate` forbids).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttenuateError {
    /// The requested scope is not within the parent's scope (would widen).
    ScopeWidened,
    /// The requested rights are not a subset of the parent's (would add a right).
    RightsWidened,
}

impl fmt::Display for AttenuateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            AttenuateError::ScopeWidened => "attenuate may only narrow scope, never widen it",
            AttenuateError::RightsWidened => "attenuate may only drop rights, never add them",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for AttenuateError {}

/// A service-defined scope answers two questions: does what I hold cover what's
/// being requested ([`covers`](Scope::covers)), and is a candidate scope *within*
/// (narrower than or equal to) this one ([`within`](Scope::within), the lattice
/// partial order [`attenuate`](Capability::attenuate) needs).
///
/// `Request` is the service's "requested action" type.
pub trait Scope {
    type Request;

    /// Does this scope cover the requested action? The `verify`/`authorizes` check.
    fn covers(&self, requested: &Self::Request) -> bool;

    /// Is `self` *within* `parent` — i.e. does the parent scope dominate this one in
    /// the lattice (narrower-or-equal)? Used by [`Capability::attenuate`] to forbid
    /// widening.
    ///
    /// **Fail-closed default:** the default returns `false`. A scope type that does
    /// not define its own partial order therefore cannot be attenuated *into* (every
    /// attenuation is rejected as a widen) — never the reverse. Services that want
    /// downward delegation override this with their real narrowing relation (drive's
    /// subtree containment, amber's db/namespace prefix, etc.).
    fn within(&self, _parent: &Self) -> bool {
        false
    }
}

/// Why a [`verify`] check failed. The variant tells the caller which rule was
/// violated; the order they're checked is fixed (see [`verify`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapError {
    /// The capability has been revoked. Checked FIRST.
    Revoked,
    /// The presenter's environment is not the one the capability was minted in.
    /// Checked before holder/scope so a cross-environment cap leaks nothing.
    EnvironmentMismatch,
    /// The presenter is not the capability's `holder`.
    WrongHolder,
    /// The requested action falls outside the capability's scope.
    OutOfScope,
    /// The capability does not carry the [`Right`] the action requires. Checked
    /// LAST — after revocation, environment, holder, and scope — so a revoked or
    /// cross-environment cap never leaks via a rights mismatch.
    MissingRight,
}

impl fmt::Display for CapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            CapError::Revoked => "capability has been revoked",
            CapError::EnvironmentMismatch => {
                "capability presented from a different environment than it was minted in"
            }
            CapError::WrongHolder => "capability presented by the wrong holder",
            CapError::OutOfScope => "requested action is outside the capability's scope",
            CapError::MissingRight => "capability does not carry the right the action requires",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for CapError {}

/// THE check. Every "may X do Y" in every service goes through this. Order matters:
/// revocation first (so a revoked cap is dead before anything else is examined),
/// then environment (so a cross-environment cap leaks nothing about holder or
/// scope), then holder, then scope.
///
/// `presenter_env` must come from the presenter's *verified* token
/// (`ChirpVerifiedToken.environment`), never from anything the presenter sent.
pub fn verify<S: Scope>(
    cap: &Capability<S>,
    presented_by: &str,
    presenter_env: &Environment,
    requested: &S::Request,
) -> Result<(), CapError> {
    match cap.status {
        Status::Revoked => return Err(CapError::Revoked),
        Status::Active => {}
    }
    if cap.environment != *presenter_env {
        return Err(CapError::EnvironmentMismatch);
    }
    if cap.holder != presented_by {
        return Err(CapError::WrongHolder);
    }
    if !cap.scope.covers(requested) {
        return Err(CapError::OutOfScope);
    }
    Ok(())
}

/// THE check, rights-aware. Identical to [`verify`] but adds a final rights step:
/// after revocation → environment → holder → scope, the capability must also carry
/// the [`Right`] the action requires. The rights step is **last** by design, so a
/// revoked or cross-environment cap dies before rights are ever examined — a rights
/// mismatch never leaks on a dead or cross-env cap.
///
/// `presenter_env` must come from the presenter's *verified* token, never from
/// anything the presenter sent.
pub fn authorizes<S: Scope>(
    cap: &Capability<S>,
    presented_by: &str,
    presenter_env: &Environment,
    requested: &S::Request,
    required: Right,
) -> Result<(), CapError> {
    verify(cap, presented_by, presenter_env, requested)?;
    if !cap.rights.contains(required) {
        return Err(CapError::MissingRight);
    }
    Ok(())
}

/// The sealed Warden boundary: the *only* origin of a capability carrying an
/// irreversible right ([`Right::Purge`] / [`Right::Control`]).
///
/// # The dependency-direction seal
///
/// `capability` is the leaf primitive — it must **not** depend on `granite-client`
/// (that arrow points the other way: `granite-client` re-exports
/// [`Environment`]). So `warden::settle` cannot take a `granite-client`
/// `ApprovalGrant`/`GrantVerification`. Instead this module defines an **opaque
/// approval witness** ([`ApprovalWitness`]) whose only constructor
/// ([`ApprovalWitness::from_granite`]) is the seam the granite side calls, passing
/// only *primitive projections* `capability` already owns (the approval's
/// environment, the scope+action it was bound to, and which irreversible right it
/// approved). The witness's fields are private, so:
///
/// - Adopters (drive/amber/an agent) **cannot** construct an [`ApprovalWitness`]
///   out of thin air — they must obtain one from the granite side, which only
///   produces it from a real, settled approval.
/// - `capability` never names a granite type, so the dependency arrow
///   `capability ← granite-client` stays unreversed.
///
/// [`settle`] consumes the witness and yields a short-lived capability bound to the
/// approval's scope + action — the two-phase submit→approve→settle binding amber
/// and drive already enforce, expressed as a type.
pub mod warden {
    use super::*;

    /// Which irreversible right an approval authorized. A closed enum so the witness
    /// can only ever carry `Purge` or `Control`, never a reversible right.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Irreversible {
        Purge,
        Control,
    }

    impl Irreversible {
        /// The [`Right`] this maps to.
        pub const fn right(self) -> Right {
            match self {
                Irreversible::Purge => Right::Purge,
                Irreversible::Control => Right::Control,
            }
        }
    }

    /// An **opaque, unforgeable** proof that a granite approval settled. Its fields
    /// are private; the only constructor is [`ApprovalWitness::from_granite`], which
    /// the granite side (granite-client / the granite backend) calls after it has
    /// destructured its own `ApprovalGrant` into these primitives. Adopters cannot
    /// build one locally — that is what makes an irreversible right unreachable
    /// except through a real settled approval.
    ///
    /// It deliberately carries **no** granite type — only an [`Environment`], the
    /// approved scope, who may hold the minted cap, the approval id, and which
    /// [`Irreversible`] right was approved. This keeps `capability` a leaf.
    #[derive(Debug, Clone)]
    pub struct ApprovalWitness<S> {
        environment: Environment,
        scope: S,
        owner: String,
        holder: String,
        approval_id: String,
        right: Irreversible,
    }

    impl<S> ApprovalWitness<S> {
        /// THE seam. Called by the granite side after a real approval settles,
        /// passing primitive projections of its `ApprovalGrant`. Because this is the
        /// sole constructor and it lives behind the granite side's settle logic, an
        /// adopter cannot manufacture an irreversible right — it must route through
        /// a genuine approval. `capability` names no granite type here.
        pub fn from_granite(
            environment: Environment,
            scope: S,
            owner: String,
            holder: String,
            approval_id: String,
            right: Irreversible,
        ) -> ApprovalWitness<S> {
            ApprovalWitness {
                environment,
                scope,
                owner,
                holder,
                approval_id,
                right,
            }
        }

        /// The approval id this witness was minted from (for audit / the cap's id).
        pub fn approval_id(&self) -> &str {
            &self.approval_id
        }

        /// Which irreversible right the approval authorized.
        pub fn right(&self) -> Irreversible {
            self.right
        }
    }

    /// Mint a capability carrying an irreversible right. The **only** function in the
    /// crate that produces a `Rights` value containing [`Right::Purge`] /
    /// [`Right::Control`].
    ///
    /// The minted capability is bound to the approval's scope, owner, holder, and
    /// environment, and carries exactly the one approved irreversible right (no
    /// reversible rights are smuggled in — exercise reversible rights via a separate
    /// reversibly-constructed capability). It is `Active`; revocation/expiry remain
    /// the service's responsibility.
    ///
    /// This is `amber`'s `settle_purge`/`settle_shred` and `drive`'s
    /// `erase_owner_settle`, expressed as the one typed mint.
    pub fn settle<S>(witness: ApprovalWitness<S>, created_at: i64) -> Capability<S> {
        let bits = Rights::bit_of(witness.right.right());
        Capability {
            id: CapId(witness.approval_id),
            owner: witness.owner,
            holder: witness.holder,
            environment: witness.environment,
            scope: witness.scope,
            rights: Rights::from_bits_with_warden_seal(bits),
            status: Status::Active,
            created_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scope that covers a fixed allowed value — enough to exercise the
    /// in-scope / out-of-scope branches of `verify`.
    struct OneOf(&'static str);
    impl Scope for OneOf {
        type Request = &'static str;
        fn covers(&self, requested: &&'static str) -> bool {
            self.0 == *requested
        }
        fn within(&self, parent: &Self) -> bool {
            self.0 == parent.0
        }
    }

    fn test_env(tenant: &str) -> Environment {
        Environment::Test {
            tenant: tenant.into(),
        }
    }

    fn cap(holder: &str, status: Status, scope: OneOf) -> Capability<OneOf> {
        cap_in(holder, status, scope, Environment::Prod)
    }

    fn cap_in(
        holder: &str,
        status: Status,
        scope: OneOf,
        environment: Environment,
    ) -> Capability<OneOf> {
        Capability {
            id: CapId("cap_1".into()),
            owner: "owner_alice".into(),
            holder: holder.into(),
            environment,
            scope,
            rights: Rights::READ,
            status,
            created_at: 1_780_000_000,
        }
    }

    #[test]
    fn happy_path_ok() {
        let c = cap("holder_app", Status::Active, OneOf("read"));
        assert_eq!(verify(&c, "holder_app", &Environment::Prod, &"read"), Ok(()));
    }

    #[test]
    fn happy_path_ok_in_test_env() {
        let c = cap_in("holder_app", Status::Active, OneOf("read"), test_env("t1"));
        assert_eq!(verify(&c, "holder_app", &test_env("t1"), &"read"), Ok(()));
    }

    #[test]
    fn revoked_is_revoked() {
        let c = cap("holder_app", Status::Revoked, OneOf("read"));
        assert_eq!(
            verify(&c, "holder_app", &Environment::Prod, &"read"),
            Err(CapError::Revoked)
        );
    }

    /// The laundering path this field exists to close: a test-minted cap presented
    /// by a prod identity (and vice versa) dies on environment.
    #[test]
    fn test_cap_dead_in_prod_and_vice_versa() {
        let test_cap = cap_in("holder_app", Status::Active, OneOf("read"), test_env("t1"));
        assert_eq!(
            verify(&test_cap, "holder_app", &Environment::Prod, &"read"),
            Err(CapError::EnvironmentMismatch)
        );
        let prod_cap = cap("holder_app", Status::Active, OneOf("read"));
        assert_eq!(
            verify(&prod_cap, "holder_app", &test_env("t1"), &"read"),
            Err(CapError::EnvironmentMismatch)
        );
    }

    /// Test environments are per-tenant: tenant A's cap doesn't verify for tenant B.
    #[test]
    fn test_tenants_are_isolated_from_each_other() {
        let c = cap_in("holder_app", Status::Active, OneOf("read"), test_env("t1"));
        assert_eq!(
            verify(&c, "holder_app", &test_env("t2"), &"read"),
            Err(CapError::EnvironmentMismatch)
        );
    }

    #[test]
    fn wrong_holder_is_wrong_holder() {
        let c = cap("holder_app", Status::Active, OneOf("read"));
        assert_eq!(
            verify(&c, "someone_else", &Environment::Prod, &"read"),
            Err(CapError::WrongHolder)
        );
    }

    #[test]
    fn out_of_scope_is_out_of_scope() {
        let c = cap("holder_app", Status::Active, OneOf("read"));
        assert_eq!(
            verify(&c, "holder_app", &Environment::Prod, &"write"),
            Err(CapError::OutOfScope)
        );
    }

    /// The load-bearing ordering property: a revoked cap that ALSO mismatches on
    /// environment, holder, and scope still reports `Revoked` — revocation is
    /// checked before anything else, so a dead cap never leaks anything.
    #[test]
    fn revocation_checked_before_everything_else() {
        let c = cap_in("holder_app", Status::Revoked, OneOf("read"), test_env("t1"));
        // Wrong environment AND wrong holder AND out of scope, yet revocation wins.
        assert_eq!(
            verify(&c, "someone_else", &Environment::Prod, &"write"),
            Err(CapError::Revoked)
        );
    }

    /// Environment is checked before holder and scope: a cross-environment cap
    /// leaks nothing about either.
    #[test]
    fn environment_checked_before_holder_and_scope() {
        let c = cap_in("holder_app", Status::Active, OneOf("read"), test_env("t1"));
        assert_eq!(
            verify(&c, "someone_else", &Environment::Prod, &"write"),
            Err(CapError::EnvironmentMismatch)
        );
    }

    /// And holder is checked before scope: a wrong holder with an out-of-scope
    /// request reports `WrongHolder`, not `OutOfScope`.
    #[test]
    fn holder_checked_before_scope() {
        let c = cap("holder_app", Status::Active, OneOf("read"));
        assert_eq!(
            verify(&c, "someone_else", &Environment::Prod, &"write"),
            Err(CapError::WrongHolder)
        );
    }

    #[test]
    fn ensure_matches_same_env_is_ok() {
        assert_eq!(Environment::Prod.ensure_matches(&Environment::Prod), Ok(()));
        assert_eq!(
            test_env("t1").ensure_matches(&test_env("t1")),
            Ok(())
        );
    }

    #[test]
    fn ensure_matches_prod_vs_test_is_err_both_ways() {
        let err = Environment::Prod.ensure_matches(&test_env("t1")).unwrap_err();
        assert_eq!(err.stored, Environment::Prod);
        assert_eq!(err.caller, test_env("t1"));

        let err = test_env("t1").ensure_matches(&Environment::Prod).unwrap_err();
        assert_eq!(err.stored, test_env("t1"));
        assert_eq!(err.caller, Environment::Prod);
    }

    #[test]
    fn ensure_matches_test_a_vs_test_b_is_err() {
        let err = test_env("a").ensure_matches(&test_env("b")).unwrap_err();
        assert_eq!(err.stored, test_env("a"));
        assert_eq!(err.caller, test_env("b"));
    }

    /// The free-function form is identical to the method.
    #[test]
    fn free_ensure_same_environment_matches_method() {
        assert_eq!(
            ensure_same_environment(&Environment::Prod, &Environment::Prod),
            Ok(())
        );
        assert_eq!(
            ensure_same_environment(&test_env("a"), &test_env("b")),
            test_env("a").ensure_matches(&test_env("b"))
        );
    }

    /// The error Display names both environments so it can be audited.
    #[test]
    fn env_mismatch_display_carries_both() {
        let err = test_env("t1").ensure_matches(&Environment::Prod).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("test:t1"), "{s}");
        assert!(s.contains("prod"), "{s}");
    }

    /// A serde-able scope so the whole Capability is serde-able.
    #[cfg(feature = "serde")]
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    struct UnitScope;
    #[cfg(feature = "serde")]
    impl Scope for UnitScope {
        type Request = ();
        fn covers(&self, _requested: &()) -> bool {
            true
        }
        fn within(&self, _parent: &Self) -> bool {
            true
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn capability_roundtrips_when_scope_is_serde() {
        for environment in [Environment::Prod, test_env("t1")] {
            let c = Capability {
                id: CapId("cap_42".into()),
                owner: "owner".into(),
                holder: "holder".into(),
                environment,
                scope: UnitScope,
                rights: Rights::READ_APPEND,
                status: Status::Active,
                created_at: 7,
            };
            let json = serde_json::to_string(&c).unwrap();
            let back: Capability<UnitScope> = serde_json::from_str(&json).unwrap();
            assert_eq!(c, back);
        }
    }

    /// A legacy record with no `environment` field must fail loudly at
    /// deserialize — never silently default to prod. Backfilling legacy rows is
    /// an explicit one-time migration in each service, not a standing default.
    #[cfg(feature = "serde")]
    #[test]
    fn legacy_record_without_environment_fails_to_deserialize() {
        let legacy = r#"{
            "id": "cap_42",
            "owner": "owner",
            "holder": "holder",
            "scope": null,
            "status": "Active",
            "created_at": 7
        }"#;
        let err = serde_json::from_str::<Capability<UnitScope>>(legacy).unwrap_err();
        assert!(err.to_string().contains("environment"), "{err}");
    }

    // ----------------------------------------------------------------------
    // Lattice conformance vectors (capability-lattice.md "Conformance").
    // ----------------------------------------------------------------------

    /// A scope with a real narrowing order: a set of allowed strings; `within` is
    /// subset containment, `covers` is membership.
    #[derive(Clone, PartialEq, Eq, Debug)]
    struct SetScope(Vec<&'static str>);
    impl Scope for SetScope {
        type Request = &'static str;
        fn covers(&self, requested: &&'static str) -> bool {
            self.0.contains(requested)
        }
        fn within(&self, parent: &Self) -> bool {
            // self ⊆ parent
            self.0.iter().all(|x| parent.0.contains(x))
        }
    }

    fn lattice_cap(scope: SetScope, rights: Rights) -> Capability<SetScope> {
        Capability {
            id: CapId("cap_lat".into()),
            owner: "owner".into(),
            holder: "agent".into(),
            environment: Environment::Prod,
            scope,
            rights,
            status: Status::Active,
            created_at: 1,
        }
    }

    /// Rights public constructors reject the irreversible rights — there is no
    /// public path from an iterator of rights to a Purge/Control set.
    #[test]
    fn rights_reversible_rejects_irreversible() {
        assert!(Rights::reversible([Right::Read, Right::Append, Right::Grant]).is_some());
        assert!(Rights::reversible([Right::Read, Right::Purge]).is_none());
        assert!(Rights::reversible([Right::Control]).is_none());
        // And nothing reversible has an irreversible bit set.
        let r = Rights::reversible([Right::Read, Right::Append, Right::Grant]).unwrap();
        assert!(!r.has_irreversible());
    }

    /// CONFORMANCE: attenuation is a meet. Widening scope or adding a right is
    /// rejected; the result is always ≤ the parent; idempotent at a fixed point.
    #[test]
    fn attenuation_is_a_meet() {
        let parent = lattice_cap(
            SetScope(vec!["a", "b", "c"]),
            Rights::reversible([Right::Read, Right::Append]).unwrap(),
        );

        // Narrowing scope + dropping rights: OK, result ≤ parent.
        let child = parent
            .attenuate(SetScope(vec!["a"]), Rights::READ)
            .expect("narrowing must succeed");
        assert!(child.scope.within(&parent.scope));
        assert!(child.rights.subset_of(parent.rights));

        // Widening scope: rejected.
        assert_eq!(
            parent.attenuate(SetScope(vec!["a", "b", "c", "d"]), Rights::READ),
            Err(AttenuateError::ScopeWidened)
        );

        // Adding a right (superset): rejected. parent has {Read,Append}; ask for
        // {Read,Append,Grant}.
        let superset = Rights::reversible([Right::Read, Right::Append, Right::Grant]).unwrap();
        assert_eq!(
            parent.attenuate(SetScope(vec!["a"]), superset),
            Err(AttenuateError::RightsWidened)
        );

        // Idempotent at a fixed point: attenuate to itself succeeds and is equal.
        let same = parent
            .attenuate(parent.scope.clone(), parent.rights)
            .unwrap();
        assert_eq!(same.scope, parent.scope);
        assert_eq!(same.rights, parent.rights);
    }

    /// CONFORMANCE (the negative agent-safety vector): starting from ANY reversible
    /// capability, no sequence of `attenuate` yields a capability that authorizes a
    /// purge op. `attenuate` only drops rights, and the parent never had Purge —
    /// because no public constructor can put it there. True by construction.
    #[test]
    fn no_local_path_to_purge_or_control() {
        let agent = lattice_cap(
            SetScope(vec!["x", "y"]),
            Rights::reversible([Right::Read, Right::Append, Right::Grant]).unwrap(),
        );
        assert!(!agent.rights.has_irreversible());

        // Try every single-step attenuation that could conceivably add a right.
        // Each must either fail or produce a cap with no irreversible right.
        for scope in [SetScope(vec!["x"]), SetScope(vec!["x", "y"]), SetScope(vec![])] {
            for rights in [
                Rights::NONE,
                Rights::READ,
                Rights::READ_APPEND,
                Rights::reversible([Right::Grant]).unwrap(),
                Rights::reversible([Right::Read, Right::Append, Right::Grant]).unwrap(),
            ] {
                if let Ok(child) = agent.attenuate(scope.clone(), rights) {
                    assert!(
                        !child.rights.has_irreversible(),
                        "attenuation produced an irreversible right"
                    );
                    // And it never authorizes a Purge/Control op (whether it fails
                    // on scope or on the missing right, it must never be Ok).
                    assert_ne!(
                        authorizes(&child, "agent", &Environment::Prod, &"x", Right::Purge),
                        Ok(())
                    );
                    assert_ne!(
                        authorizes(&child, "agent", &Environment::Prod, &"x", Right::Control),
                        Ok(())
                    );
                }
            }
        }
    }

    /// CONFORMANCE: warden mint is scope+action bound. `settle` yields a capability
    /// whose scope, owner, holder, env, and right equal the approval's; it
    /// authorizes the approved purge but not a different owner/right.
    #[test]
    fn warden_mint_is_bound() {
        let witness = warden::ApprovalWitness::from_granite(
            Environment::Prod,
            SetScope(vec!["db_42"]),
            "owner_alice".into(),
            "operator".into(),
            "appr_123".into(),
            warden::Irreversible::Purge,
        );
        let cap = warden::settle(witness, 1_780_000_000);

        // Bound to the approval's identity.
        assert_eq!(cap.id, CapId("appr_123".into()));
        assert_eq!(cap.owner, "owner_alice");
        assert_eq!(cap.holder, "operator");
        assert_eq!(cap.environment, Environment::Prod);
        assert_eq!(cap.scope, SetScope(vec!["db_42"]));

        // Carries exactly the approved irreversible right, nothing reversible.
        assert!(cap.rights.contains(Right::Purge));
        assert!(!cap.rights.contains(Right::Control));
        assert!(!cap.rights.contains(Right::Read));

        // Authorizes the approved purge on the approved scope...
        assert_eq!(
            authorizes(&cap, "operator", &Environment::Prod, &"db_42", Right::Purge),
            Ok(())
        );
        // ...but not a different scope (action-bound),
        assert_eq!(
            authorizes(&cap, "operator", &Environment::Prod, &"db_99", Right::Purge),
            Err(CapError::OutOfScope)
        );
        // ...nor a different right it was not minted for,
        assert_eq!(
            authorizes(&cap, "operator", &Environment::Prod, &"db_42", Right::Control),
            Err(CapError::MissingRight)
        );
        // ...nor a different holder,
        assert_eq!(
            authorizes(&cap, "someone_else", &Environment::Prod, &"db_42", Right::Purge),
            Err(CapError::WrongHolder)
        );
        // ...nor a cross-environment caller.
        assert_eq!(
            authorizes(
                &cap,
                "operator",
                &test_env("t1"),
                &"db_42",
                Right::Purge
            ),
            Err(CapError::EnvironmentMismatch)
        );
    }

    /// A Control mint maps to the Control right (and only it).
    #[test]
    fn warden_mint_control() {
        let witness = warden::ApprovalWitness::from_granite(
            Environment::Prod,
            SetScope(vec!["ns_root"]),
            "owner".into(),
            "operator".into(),
            "appr_ctl".into(),
            warden::Irreversible::Control,
        );
        let cap = warden::settle(witness, 1);
        assert!(cap.rights.contains(Right::Control));
        assert!(!cap.rights.contains(Right::Purge));
    }

    /// CONFORMANCE: `authorizes` precedence — revoked or wrong-env never authorizes
    /// regardless of scope/right, and the rights step is LAST (after scope).
    #[test]
    fn authorizes_precedence_revocation_env_first_rights_last() {
        // Revoked beats everything, including a missing right.
        let revoked = Capability {
            status: Status::Revoked,
            ..lattice_cap(SetScope(vec!["a"]), Rights::READ)
        };
        assert_eq!(
            authorizes(&revoked, "wrong", &test_env("t1"), &"nope", Right::Purge),
            Err(CapError::Revoked)
        );

        // Wrong env beats holder, scope, and rights.
        let wrong_env = Capability {
            environment: test_env("t1"),
            ..lattice_cap(SetScope(vec!["a"]), Rights::READ)
        };
        assert_eq!(
            authorizes(&wrong_env, "wrong", &Environment::Prod, &"nope", Right::Purge),
            Err(CapError::EnvironmentMismatch)
        );

        // Rights checked AFTER scope: an out-of-scope request with a missing right
        // reports OutOfScope, not MissingRight.
        let ok_env = lattice_cap(SetScope(vec!["a"]), Rights::READ);
        assert_eq!(
            authorizes(&ok_env, "agent", &Environment::Prod, &"nope", Right::Purge),
            Err(CapError::OutOfScope)
        );
        // In scope but missing the right: MissingRight (the new last step).
        assert_eq!(
            authorizes(&ok_env, "agent", &Environment::Prod, &"a", Right::Purge),
            Err(CapError::MissingRight)
        );
        // In scope and holding the right: OK.
        assert_eq!(
            authorizes(&ok_env, "agent", &Environment::Prod, &"a", Right::Read),
            Ok(())
        );
    }

    /// `subset_of` is the rights lattice order.
    #[test]
    fn rights_subset_order() {
        let ra = Rights::READ_APPEND;
        assert!(Rights::READ.subset_of(ra));
        assert!(Rights::NONE.subset_of(Rights::READ));
        assert!(!ra.subset_of(Rights::READ));
        assert!(ra.subset_of(ra));
    }
}
