# go-uma

A Go implementation of
**User-Managed Access 2.0** —
[UMA 2.0 Grant for OAuth 2.0](https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html)
and
[UMA 2.0 Federated Authorization for OAuth 2.0](https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-fedauthz-2.0.html)
— the Kantara Initiative protocol that lets a Resource Owner authorize
asynchronous access to their resources by a Requesting Party, mediated by
an Authorization Server.

`go-uma` will provide:

- A typed HTTP client for the Requesting Party (RqP) side of the
  protocol — UMA-ticket grant redemption at the AS, and the
  claims-gathering interaction.
- A typed HTTP client for the Resource Server (RS) side — permission
  registration, token introspection, and resource set management
  against the AS's Federated Authorization endpoints.
- `http.Handler` constructors for the AS role (over an `AS` interface)
  and the RS role (over an `RS` interface), following an
  embed-and-override pattern for partial implementations.
- The full type surface for every spec-defined message — the
  UMA-ticket grant on `/token`, `/permission`, `/resource_set`,
  `/introspection` (with UMA's `permissions` extension), the 401 +
  `WWW-Authenticate: UMA` challenge, and the `need_info` /
  `request_submitted` / `not_authorized` error envelopes.
- `/.well-known/uma2-configuration` metadata document support with
  mix-up validation on the client side and capability-based endpoint
  advertisement on the server side.

The library is **library-vendor-neutral**: it implements the spec,
nothing more. It does not include a policy engine, an opinion about
how parties authenticate to the AS, an RPT format, or any specific
claims-gathering UI. Those belong in downstream consumers.

## Status

**Pre-publication.** The first tagged release will be `v0.1.0`. The
library tracks **UMA 2.0** (Kantara Initiative Recommendation,
2018-01), exposed as `uma.SpecVersion`. See
[`CHANGELOG.md`](CHANGELOG.md) for what has landed.

UMA 2.0 adoption is modest relative to plain OAuth 2.0. `go-uma`
exists as a reference Go implementation for the user-managed-
authorization model — useful where a Resource Owner needs to
authorize access to their data by parties they don't directly
interact with at request time, including federated AI and
data-cooperative scenarios where that pattern is gaining renewed
attention.

The path to `v1.0.0` is open external integration and continued wire
fidelity; see the **Stability** section for what changes between minor
versions and what does not.

## Compatibility

- **Go**: 1.26+
- **Runtime dependencies**: none. Standard library only.
- **Test dependencies**: none. Standard `testing` package with
  table-driven patterns.
- **Spec**: UMA 2.0 Grant + Federated Authorization (Kantara
  Recommendations, 2018-01).

## Stability

Until `v1.0.0`, expect minor API churn at the Go-surface level —
constructor signatures, option ordering, exported helper names. The
**wire types** are pinned to the UMA 2.0 spec and will not change
without a spec change; a client, AS, or RS built against an earlier
`v0.x` will continue to interoperate over the wire across upgrades,
even when source-level renames force a small code edit.

Breaking changes are documented in [`CHANGELOG.md`](CHANGELOG.md) with
migration notes. Per the
[`go-jose` precedent](https://pkg.go.dev/github.com/go-jose/go-jose/v4),
major bumps after `v1.0.0` will live on `vN` branches with `vN`
embedded in the module path — no versioned subdirectories.

The `signed_metadata` field on the metadata document is round-tripped
as opaque JWS bytes in `v0.x`; verification and signing land in a
later release along with a JOSE dependency.

## Contributing

Contributions welcome. See [`AGENTS.md`](AGENTS.md) for contributor
conventions — they're written as guidance for AI coding assistants,
but humans will find the same conventions useful.

The short version: standard Go style (`gofmt`, `go vet`,
`staticcheck`, `golangci-lint` all run in CI), zero non-test runtime
dependencies, table-driven tests, and a strong preference for wire
fidelity over ergonomic shortcuts. New exported API surface and new
dependencies go through review.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
