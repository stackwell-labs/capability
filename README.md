# capability

One primitive for a revocable-grant pattern: the capability type, and the single
`verify` rule that checks it.

Drive grants, relay-handles, issued approval grants and social-graph contacts are
four hand-rolled versions of one idea — *a scoped, revocable permission the
resource owner issued, the actor presents, and the resource checks live*. This
crate owns only that rule. It does **not** own storage or issuance: services keep
their own database, consent flow, and scope shape.

```rust
pub fn verify<S: Scope>(
    cap: &Capability<S>,
    presented_by: &str,
    presenter_env: &Environment,
    requested: &S::Request,
) -> Result<(), CapError>
```

The order of the checks is the invariant, not an implementation detail:

1. **Revoked** — a revoked capability is dead before anything else is examined
2. **Environment** — only honored in the `Environment` it was minted in, so a
   `Test { tenant }` grant can never settle against production
3. **Holder** — only the rightful holder
4. **Scope** — and only within scope

Because environment is checked before holder and scope, a cross-environment
capability leaks nothing about who holds it or what it covers.

No I/O, no storage, no network, no crypto. One optional dependency (`serde`),
and `#![forbid(unsafe_code)]`.

`Environment` is re-exported by the platform's client crates so there is exactly
one definition of the prod/test boundary rather than a tenant-less fork in each
consumer.

See [`DESIGN.md`](DESIGN.md) for the rationale and the deliberately deferred
chain/attenuation extension.

## License

MIT OR Apache-2.0, at your option.
