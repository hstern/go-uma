# Changelog

All notable changes to `go-uma` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project adheres to [Semantic Versioning](https://semver.org/).

The library SemVer is independent of the UMA spec version it
implements. UMA 2.0 has been stable as a Kantara Recommendation since
2018-01; library versions advance with the Go surface, not the wire.

## [Unreleased]

### Added

- **`examples/as-rs-demo`**: runnable end-to-end demo program under
  `examples/` that brings up an in-process AS and RS, registers a
  resource set, and drives the full UMA flow (401 challenge →
  permission ticket → `/token` redemption → introspection) as a
  requesting-party client. The example lives in its own Go module
  with a `replace` directive pointing at the library, so it stays
  outside the library's dependency graph.

## [0.1.0] - 2026-05-25

First tagged release. Implements **User-Managed Access 2.0** — the
Kantara Initiative
[Grant](https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html)
and
[Federated Authorization](https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-fedauthz-2.0.html)
Recommendations, finalized 2018-01. Tracked in source as
`uma.SpecVersion = "2.0"`.

### Added

- **Wire types** for every spec-defined message: `TokenRequest` /
  `TokenResponse` (UMA-ticket grant on `/token`), `PermissionRequest` /
  `PermissionResponse` (with `PermissionRequests` for the array form),
  `IntrospectionRequest` / `IntrospectionResponse` (RFC 7662 +
  `permissions` extension), `ResourceSet` (CRUD on `/resource_set`),
  `OAuthError` / `NeedInfoError` / `ValidationError`, `RequiredClaim`
  and `ClaimTokenFormat`, `Metadata` configuration document. Open-
  extension `RawMessage` fields round-trip byte-stably;
  `DecodeJSON` and `EncodeJSON` bridge them to typed Go values.
  `UMATicketGrantType` constant. Endpoint path constants and the
  `WWWAuthenticate` header name. Per-type `Validate()` methods on
  request types surface missing required fields at the marshal
  boundary with typed `*ValidationError`.

- **`client/` package**: `Client` interface (10 methods) covering the
  full requesting-party and protection-API surface — `Token`,
  `Permission`, `Introspect`, `CreateResourceSet` / `ReadResourceSet` /
  `UpdateResourceSet` / `DeleteResourceSet` / `ListResourceSets`,
  `FetchMetadata`, plus `BaseURL()`. `NewClient(asBaseURL, opts...)`
  returns the default HTTP-backed implementation; consumer tests
  substitute their own type satisfying the interface. Options:
  `WithHTTPDoer`, `WithPAT`, `WithMetadataTTL`,
  `WithRelaxedMetadataValidation`. Optional middleware: `NewPATDoer`
  for Authorization-header injection, `NewRetryDoer` for exponential
  backoff on 502/503/504. `*MixUpError` typed error from
  `FetchMetadata` when the document's `Issuer` does not match the
  configured base URL (the Grant §1.3.2 / RFC 8252 §6 mix-up
  defense, hard-fail by default).

- **`server/` package**: `AS` interface (4 methods: `Token`,
  `Permission`, `Introspect`, `ResourceSet`) with `NotImplementedAS`
  zero-value for the embed-and-override pattern. `NewASHandler`
  multiplexes the spec-defined HTTP routes and maps typed errors to
  the right wire response (`*NeedInfoError` → 403, `*ValidationError`
  → 400, `*OAuthError` → status per code, `ErrNotImplemented` → 501).
  `RS` interface (single `ProtectedRequest` method) with
  `NotImplementedRS`, the `Decision` enum, and `*TicketRequired`
  typed error. Helpers: `WriteTicketResponse` and
  `WriteTicketRequired` emit the 401 + `WWW-Authenticate: UMA`
  challenge (load-bearing: ticket lives in the header, NOT the
  body); `ExtractBearerToken` parses the Authorization header.
  `BuildMetadata` probes the AS for implemented endpoints and
  publishes only those in the `/.well-known/uma2-configuration`
  document; `NewMetadataHandler` serves the document.
  `HandlerOption` hooks: `WithLogger` for structured request logs,
  `WithMetrics` for Prometheus-style counter callbacks.

- **`conformance/` package**: 10 JSON fixtures derived from the
  spec example figures (`testdata/<spec>-<section>-<short-name>.json`)
  plus a fixtures_test.go that asserts byte-stable round-trip per
  fixture. A `//go:build conformance` scenario test drives the full
  Grant + Federated Authz flow through a synthetic AS + RS pair
  built on the library's own server constructors — discovery →
  401-with-ticket → /token redemption → introspection → allow, plus
  the `need_info`, `not_authorized`, and inactive-RPT branches and
  a resource-set CRUD round-trip.

- **CI**: `static` / `test` / `lint` / `conformance` jobs on GitHub
  Actions, Go 1.26.3 + golangci-lint v2.12.1 + govulncheck v1.1.4
  pinned. Strict linter set: errcheck, errorlint, govet, ineffassign,
  staticcheck (SA/ST/QF/S/U1000 with `-ST1000`), unused, gocritic,
  misspell, revive, plus gofumpt as the formatter. Daily
  `govulncheck` workflow against `main`.

- **Documentation**: `README.md` with AS / RS / Client quickstarts,
  typed-extension examples, and metadata-document section.
  `AGENTS.md` for contributor conventions. godoc on every exported
  symbol naming the spec section it implements, with `Example*` test
  functions for `AS`, `RS`, `NotImplementedAS`, `NewASHandler`,
  `BuildMetadata`, `WriteTicketResponse`, and `Client.Token`.

### Compatibility

- Go 1.26+.
- Zero non-test runtime dependencies; standard library only.
- Tracks UMA 2.0 (Kantara Recommendation, 2018-01).

### Deferred to a future release

- `signed_metadata` parse / verify (currently round-trips as opaque
  `json.RawMessage`); the JOSE dependency the verification needs
  lands in `v0.2.0`.
- A JWT-typed RPT helper for ASs that mint JWT-formatted requesting-
  party tokens (the library treats the access_token field as opaque
  in v0.1).
- `bodyclose` linter (would need a test-helper restructuring across
  the existing `post` / `redeemUMATicket` / `postToken` call sites).
- Possible gRPC or MCP-Tool-Authorization-profile bindings as sibling
  packages.

Tracks UMA 2.0 Grant + Federated Authorization (Kantara
Recommendations, 2018-01).
