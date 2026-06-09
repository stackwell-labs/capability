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

/// Liveness of a capability. `verify` reads this first, so flipping a stored cap to
/// `Revoked` is an instant, global "off" switch — the whole point of the pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Status {
    Active,
    Revoked,
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
    /// Live revocation state.
    pub status: Status,
    /// Unix seconds at issuance.
    pub created_at: i64,
}

/// A service-defined scope answers exactly one question: does what I hold cover
/// what's being requested? `Request` is the service's "requested action" type.
pub trait Scope {
    type Request;
    fn covers(&self, requested: &Self::Request) -> bool;
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
}
