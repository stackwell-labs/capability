# `capability` — one primitive for the four grant systems

**Status:** Accepted (2026-06-08). Reference impl: postbox; live services migrate incrementally.

## Why

Drive grants, postbox relay-handles, Granite's issued grants, and social-graph
contacts are four hand-rolled versions of one idea: *a scoped, revocable
permission the resource owner issued, the actor presents, the resource checks
**live**.* The duplication isn't the point — the point is the **invariant**: a
capability check must (a) be rejected if revoked, (b) only honor the rightful
holder, (c) stay within scope. Four implementations = four chances to forget one
(esp. (a), the live-revocation that makes "unsubscribe" real). One shared check
makes those true **by construction**.

## What it is (thin, by design)

A tiny crate: the capability **type** + the **one audited check**. It does NOT
own storage or issuance — services keep those (their DB, their consent flow,
their scope shape). The crate owns only the rule everyone must obey.

```rust
pub struct CapId(pub String);                 // opaque capability id (a handle / grant_id)
pub enum Status { Active, Revoked }

pub struct Capability<S> {
    pub id: CapId,
    pub owner: String,     // who issued it (the resource owner / recipient)
    pub holder: String,    // who may present it (the acting app/agent id, or sub)
    pub scope: S,          // service-defined
    pub status: Status,
    pub created_at: i64,
}

/// A service-defined scope answers exactly one question: does what I hold cover
/// what's being requested?
pub trait Scope { type Request; fn covers(&self, requested: &Self::Request) -> bool; }

pub enum CapError { Revoked, WrongHolder, OutOfScope }

/// THE check. Every "may X do Y" in every service goes through this. Order
/// matters: revocation first, so a revoked cap is dead before anything else.
pub fn verify<S: Scope>(
    cap: &Capability<S>,
    presented_by: &str,
    requested: &S::Request,
) -> Result<(), CapError> {
    match cap.status { Status::Revoked => return Err(CapError::Revoked), Status::Active => {} }
    if cap.holder != presented_by { return Err(CapError::WrongHolder); }
    if !cap.scope.covers(requested) { return Err(CapError::OutOfScope); }
    Ok(())
}
```

Revoke is just `status = Revoked` in the service's store; because `verify` reads
status first and lives at the gate, revocation is instant for everyone.

## What stays in each service (NOT shared)

- **Issuance** — Drive's request→approve, postbox's consent-mint, SG's OAuth,
  Granite's approval UI + decision lifecycle. The primitive only models the
  *result* (an issued `Capability`), never how it's granted.
- **Storage** — each service persists `Capability<S>` in its own DB (DynamoDB /
  libsql), mapping its existing grant row onto the type.
- **Scope + extra policy** — Drive's `drive.write on resource`, postbox's
  recipient + **cadence cap** (cadence is a rate-limit, not scope — postbox keeps
  its counter alongside the cap), Granite's scopes, SG's tag filters.

## Migration order (each a separate, gated step)

1. **postbox** (reference, low-risk, mine): `relay_grant` → `Capability<RelayScope>`
   (`owner = recipient_sub`, `holder = app_id`, `RelayScope` covers the recipient);
   send path = fetch by handle → `verify` → cadence check → deliver; revoke = status.
2. **social-graph** `graph_app_grants` → `Capability<GraphScope>` (tags/scopes).
3. **Drive** grants → `Capability<DriveScope>` (`drive.write` on a resource) — live
   + load-bearing, migrate carefully behind its tests.
4. **Granite**: only the **issued grant** becomes `Capability<...>`; the approval
   *request/decision* lifecycle is NOT a capability and stays as-is.

Each step is behind the service's tests + a gated redeploy; no big-bang.

## What it deliberately is NOT (yet)

Capability **chains / attenuation / vouching** (the pigeon-mail / north-star
model) are out of scope for v1 — this is the flat "owner issues to holder" core.
`verify` is the seam those extend later (a chain verifies each link with the
same rule).
