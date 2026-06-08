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
//! (a) be rejected if revoked, (b) only honor the rightful holder, (c) stay within
//! scope — checked in exactly that order, so a revoked cap is dead before holder or
//! scope are even examined.
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
    /// The presenter is not the capability's `holder`.
    WrongHolder,
    /// The requested action falls outside the capability's scope.
    OutOfScope,
}

impl fmt::Display for CapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            CapError::Revoked => "capability has been revoked",
            CapError::WrongHolder => "capability presented by the wrong holder",
            CapError::OutOfScope => "requested action is outside the capability's scope",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for CapError {}

/// THE check. Every "may X do Y" in every service goes through this. Order matters:
/// revocation first (so a revoked cap is dead before anything else is examined),
/// then holder, then scope.
pub fn verify<S: Scope>(
    cap: &Capability<S>,
    presented_by: &str,
    requested: &S::Request,
) -> Result<(), CapError> {
    match cap.status {
        Status::Revoked => return Err(CapError::Revoked),
        Status::Active => {}
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

    fn cap(holder: &str, status: Status, scope: OneOf) -> Capability<OneOf> {
        Capability {
            id: CapId("cap_1".into()),
            owner: "owner_alice".into(),
            holder: holder.into(),
            scope,
            status,
            created_at: 1_780_000_000,
        }
    }

    #[test]
    fn happy_path_ok() {
        let c = cap("holder_app", Status::Active, OneOf("read"));
        assert_eq!(verify(&c, "holder_app", &"read"), Ok(()));
    }

    #[test]
    fn revoked_is_revoked() {
        let c = cap("holder_app", Status::Revoked, OneOf("read"));
        assert_eq!(verify(&c, "holder_app", &"read"), Err(CapError::Revoked));
    }

    #[test]
    fn wrong_holder_is_wrong_holder() {
        let c = cap("holder_app", Status::Active, OneOf("read"));
        assert_eq!(
            verify(&c, "someone_else", &"read"),
            Err(CapError::WrongHolder)
        );
    }

    #[test]
    fn out_of_scope_is_out_of_scope() {
        let c = cap("holder_app", Status::Active, OneOf("read"));
        assert_eq!(verify(&c, "holder_app", &"write"), Err(CapError::OutOfScope));
    }

    /// The load-bearing ordering property: a revoked cap that ALSO has the wrong
    /// holder (and would be out of scope) still reports `Revoked` — revocation is
    /// checked before anything else, so a dead cap never leaks holder/scope info.
    #[test]
    fn revocation_checked_before_holder_and_scope() {
        let c = cap("holder_app", Status::Revoked, OneOf("read"));
        // Wrong holder AND out of scope, yet revocation wins.
        assert_eq!(
            verify(&c, "someone_else", &"write"),
            Err(CapError::Revoked)
        );
    }

    /// And holder is checked before scope: a wrong holder with an out-of-scope
    /// request reports `WrongHolder`, not `OutOfScope`.
    #[test]
    fn holder_checked_before_scope() {
        let c = cap("holder_app", Status::Active, OneOf("read"));
        assert_eq!(
            verify(&c, "someone_else", &"write"),
            Err(CapError::WrongHolder)
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn capability_roundtrips_when_scope_is_serde() {
        // A serde-able scope so the whole Capability is serde-able.
        #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
        struct UnitScope;
        impl Scope for UnitScope {
            type Request = ();
            fn covers(&self, _requested: &()) -> bool {
                true
            }
        }
        let c = Capability {
            id: CapId("cap_42".into()),
            owner: "owner".into(),
            holder: "holder".into(),
            scope: UnitScope,
            status: Status::Active,
            created_at: 7,
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: Capability<UnitScope> = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }
}
