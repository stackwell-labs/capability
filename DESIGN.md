# `capability` — one primitive for the four grant systems

**Status:** Accepted (2026-06-08). Reference impl: postbox; live services migrate incrementally.

## Why

Drive grants, postbox relay-handles, Granite's issued grants, and social-graph
contacts are four hand-rolled versions of one idea: *a scoped, revocable
permission the resource owner issued, the actor presents, the resource checks
**live**.* The duplication isn't the point — the point is the **invariant**: a
capability check must (a) be rejected if revoked, (b) only be honored in the
environment it was minted in, (c) only honor the rightful holder, (d) stay
within scope. Four implementations = four chances to forget one (esp. (a), the
live-revocation that makes "unsubscribe" real). One shared check makes those
true **by construction**.

## What it is (thin, by design)

A tiny crate: the capability **type** + the **one audited check**. It does NOT
own storage or issuance — services keep those (their DB, their consent flow,
their scope shape). The crate owns only the rule everyone must obey.

```rust
pub struct CapId(pub String);                 // opaque capability id (a handle / grant_id)
pub enum Status { Active, Revoked }
pub enum Environment { Prod, Test { tenant: String } }   // which world the cap belongs to

pub struct Capability<S> {
    pub id: CapId,
    pub owner: String,            // who issued it (the resource owner / recipient)
    pub holder: String,           // who may present it (the acting app/agent id, or sub)
    pub environment: Environment, // world it was minted in (from the granter's verified token)
    pub scope: S,                 // service-defined
    pub status: Status,
    pub created_at: i64,
}

/// A service-defined scope answers exactly one question: does what I hold cover
/// what's being requested?
pub trait Scope { type Request; fn covers(&self, requested: &Self::Request) -> bool; }

pub enum CapError { Revoked, EnvironmentMismatch, WrongHolder, OutOfScope }

/// THE check. Every "may X do Y" in every service goes through this. Order
/// matters: revocation first (a dead cap leaks nothing), then environment (a
/// cross-environment cap leaks nothing about holder/scope), then holder, scope.
pub fn verify<S: Scope>(
    cap: &Capability<S>,
    presented_by: &str,
    presenter_env: &Environment,
    requested: &S::Request,
) -> Result<(), CapError> {
    match cap.status { Status::Revoked => return Err(CapError::Revoked), Status::Active => {} }
    if cap.environment != *presenter_env { return Err(CapError::EnvironmentMismatch); }
    if cap.holder != presented_by { return Err(CapError::WrongHolder); }
    if !cap.scope.covers(requested) { return Err(CapError::OutOfScope); }
    Ok(())
}
```

Revoke is just `status = Revoked` in the service's store; because `verify` reads
status first and lives at the gate, revocation is instant for everyone.

## Environment (v0.2): test authority cannot launder into prod

Chirp's keyset separation makes prod-vs-test unforgeable at the *token* layer
(`ChirpVerifiedToken.environment` is derived from which keyset verified the
token). Grants are the platform's second authority currency — without an
environment on the cap, a test identity could mint a grant that later verifies
against prod data. v0.2 closes that:

- **Mint**: set `environment` from the *granter's* verified token. `Test`
  carries the chirp test tenant, so test tenants are isolated from each other
  too.
- **Verify**: takes the *presenter's* verified environment and rejects on
  mismatch. Both signature changes are deliberately compile-breaking — services
  can't forget to thread the bit, only deliberately fake it.
- **Persistence**: the field has **no serde default**. A legacy record without
  it fails loudly at deserialize; adopting services backfill `Prod` in an
  explicit one-time migration (correct: everything persisted pre-v0.2 was
  prod-minted), never via a standing default that would let a future bug
  silently mint prod credentials.

This is the *checked* half of environment isolation. The *structural* half —
partitioning grant **storage** by the verified environment (e.g. a
`test#{tenant}#` key prefix derived from the request's token, so a test cap is
unreachable from a prod request even if every check were skipped) — lives in
each service's store, per the no-storage rule above. Do it where stakes are
highest (Drive, Granite) as services migrate.

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

## The Warden seal (v0.5): what is sealed, and what is a convention

`Purge`/`Control` are the irreversible rights. What the crate guarantees, and
where that guarantee stops:

**Sealed by the type** (no code outside the crate can get around it):

- `attenuate` only drops rights, so no attenuation adds `Purge`/`Control`.
- Every public `Rights` constructor (`NONE`, `READ`, `READ_APPEND`,
  `reversible`) rejects or omits the irreversible bits.
- **Deserialization** (v0.5) accepts only `{Read, Append, Grant}` bits. A stored
  row edited to `{"bits":8}`, or any irreversible or unknown bit, fails to load,
  so mutable storage cannot mint a `Purge` right. A settled cap can be
  serialized for an audit log, but it cannot be read back as authority.

**A trusted seam, not a type fact:**

- `ApprovalWitness::from_granite` is `pub`. The leaf crate cannot check a
  Granite approval (that would need a crypto or granite dependency), so any
  crate *can* call it. Call it only right after a verified Granite settle.
  Each call site is an audit point. There are two in-tree today: Drive's
  `erase_owner_settle` and amber-serve's `authorize_warden_purge`.
- `Capability`'s fields are `pub` and `Rights` is `Copy`, so code holding a
  settled cap can copy its `rights` into a struct literal with another scope.
  The scope binding holds by convention. A settled cap must be used at once and
  never persisted.

"An agent cannot destroy data" therefore rests on the type seal above **plus**
those two audited call sites. Making the seam itself unforgeable (private
fields, and a witness that `capability` can verify) would break struct-literal
construction across the consumers and needs a cross-repo witness-verification
design. It is deferred.

## What it deliberately is NOT (yet)

Capability **chains / attenuation / vouching** (the pigeon-mail / north-star
model) are out of scope for v1 — this is the flat "owner issues to holder" core.
`verify` is the seam those extend later (a chain verifies each link with the
same rule).
