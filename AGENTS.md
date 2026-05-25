# AGENTS.md

Guidance for AI coding agents (Claude Code, Cursor, Aider, Copilot
Workspace, etc.) working on `go-uma`. Human contributors will get
more out of `CONTRIBUTING.md` once it exists; this file captures the
things that are easy for an agent to get wrong if it doesn't know them
up front.

## What this project is

`go-uma` is a Go implementation of **User-Managed Access 2.0** —
the
[UMA 2.0 Grant](https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html)
and
[UMA 2.0 Federated Authorization](https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-fedauthz-2.0.html)
Kantara Recommendations. The library is **library-vendor-neutral**:
it implements the spec, nothing more. It provides:

- HTTP client for the RqP-side (UMA-ticket grant) and RS-side
  (permission, introspection, resource_set) surfaces.
- `http.Handler` constructors over an `AS` interface (four AS
  endpoints) and an `RS` interface (single `ProtectedRequest` method).
- Full type surface for every spec-defined message — the UMA-ticket
  grant fields, the 401 + `WWW-Authenticate: UMA` challenge, the
  Federated Authorization permission ticket lifecycle, and the
  `need_info` / `request_submitted` / `not_authorized` error
  envelopes.
- `/.well-known/uma2-configuration` metadata document support.

It does NOT provide a policy engine, an opinion about how parties
authenticate to the AS (the Protection API Token / PAT story is the
consumer's), an RPT format, or any claims-gathering UI. Those belong
in downstream consumers.

Spec version: **UMA 2.0**, finalized 2018-01 by the Kantara Initiative
UMA WG. Tracked in source as `const SpecVersion = "2.0"`.

## Repository scope rules

These rules are absolute. They are not preferences; they're correctness
constraints for what lands in the repo.

1. **The library is the subject.** Code, comments, docs, commit
   messages, and CI artifacts describe what the library does for an
   anonymous Go developer who found it via a search engine. They do not
   describe what the maintainer is using it for, where it is being
   developed, who is tracking which task, or how it relates to anything
   outside this repository.
2. **No private infrastructure references.** No internal hostnames,
   internal Git hosts, internal issue trackers, internal documentation
   sites, or any URL pointing at non-public infrastructure. If you find
   yourself wanting to cite `*.someprivate.tld`, the answer is: don't.
3. **No private-tracker identifiers.** Ticket short-codes, project
   IDs, page UUIDs, board names from any private tracker — none of it
   in source, README, CHANGELOG, or commit messages. When public issue
   tracking exists (GitHub Issues), reference its public URL only.
4. **No interim hosting paths.** `go.mod` declares the eventual
   publication module path. The interim location of the repo during
   private development MUST NOT appear in `go.mod`, README, comments,
   or CI configuration.
5. **No references to sibling private libraries.** "Matches the
   pattern in [internal-library-X]" is fine framing in a private
   conversation but MUST NOT land in the repo. Public libraries
   (`go-jose`, `go-yaml`, `golang.org/x/oauth2`) may be cited by name.

If you are unsure whether something is safe to write, default to
omitting it and ask. The cost of asking is low; the cost of leaking
context that can't be deleted from git history is high.

## Go conventions for this codebase

### Dependencies

**Zero non-test runtime dependencies.** Standard library only. This is
load-bearing for adoption: a standards-implementing library that pulls
in `jsoniter` / `go-json` / a logger / a metrics SDK forces those
choices on every consumer. The library exposes interfaces; consumers
plug their own implementations.

Exceptions, with explicit rationale documented at the import site:

- Test-only dependencies are fine; keep them under `_test.go` files.
- A JOSE library will be added when `signed_metadata` end-to-end
  support lands (post-`v0.1`). In `v0.1` the field round-trips as
  opaque bytes.

### Style

- `gofmt`, `go vet`, `staticcheck`, `golangci-lint` all run in CI and
  must pass.
- Receivers: short, lowercase, consistent within a type.
- Errors: lowercase sentence, no trailing punctuation, wrap with
  `%w` when adding context.
- Exported symbols have godoc comments. Short, link-rich. Where the
  symbol implements a specific spec clause, the godoc cites the
  section (e.g. "implements Grant §3.3.1").
- Examples live in `_test.go` as `Example*` functions and render in
  godoc.

### Validation posture

Lenient on unmarshal, strict at the marshal boundary. The library
validates required fields when a message is being sent over the wire,
not when it's being received. Consumers who want stricter input
validation call the explicit `Validate(...)` helpers.

Do not add `NewTokenRequest(...)` constructor functions as the only
way to build a message. Exported struct literals are the idiomatic Go
construction pattern.

### JSON / wire fidelity

- Open extension fields are `json.RawMessage`, NOT `map[string]any`.
  Reason: byte-stable round-trip; Go's map iteration order is
  randomized and interop scenarios pin exact JSON bytes.
- The permission ticket is opaque to the client — typed as `string`,
  never decoded by the library.
- The 401 ticket lives in the `WWW-Authenticate` header, NOT the
  response body. `WriteTicketResponse` emits both correctly; do not
  serialize the ticket into the body.
- `need_info` is HTTP 403 with a typed JSON body — NOT a transport
  error. The client returns a typed `*NeedInfoError` for
  `errors.As`-style matching.
- `active: false` from introspection is NOT a transport error — the
  client returns the response with `Active: false` and `nil` error.
- `/token` is form-encoded (`application/x-www-form-urlencoded`);
  everything else is JSON.
- The metadata `issuer` field MUST equal the fetched URL —
  hard-failed by the client's `FetchMetadata` by default. An
  explicit, opt-in `WithRelaxedMetadataValidation()` is the only
  escape hatch.

### Interfaces vs structs

- Two interfaces, not one: `AS` (Authorization Server, four methods —
  one per endpoint) and `RS` (Resource Server, a single
  `ProtectedRequest` method). Different actors, different lifecycles.
- Consumers embed `NotImplementedAS` / `NotImplementedRS` (zero-value
  types whose methods all return `ErrNotImplemented`) and override
  the methods they support. Unimplemented endpoints map to HTTP 501
  at the handler boundary.
- Transport is pluggable via an `HTTPDoer` interface (shape:
  `Do(*http.Request) (*http.Response, error)`) — same contract
  `golang.org/x/oauth2` uses. Server side ships `http.Handler` only;
  no framework adapters in the core library.

## Testing

- Table-driven tests for wire round-trips. Each spec-defined message
  has a round-trip test against hand-crafted JSON from the spec's
  example figures (Grant §3.3, Federated Authorization §2 / §4 / §5).
- `httptest.NewServer` for handler tests; `httptest.NewRecorder` is
  fine for unit tests that don't need a full server.
- An internal conformance scenario exercises an AS + RS + Client trio
  end-to-end against the library's own server constructors, gated
  behind a `//go:build conformance` tag. UMA has no Kantara-run
  interop event today, so the library defines the Go-native
  conformance criteria.
- `go test -race -shuffle=on ./...` is the CI test invocation.
- No network calls in unit tests by default.

## Commit messages

- Imperative present tense ("add metadata document support", not
  "added").
- Reference public artifacts only — public RFC numbers, spec section
  numbers, public PRs / issues, public commit SHAs. Do not reference
  private trackers (see rule 3 above).
- Detailed bodies for non-trivial changes. State what changed, why
  now, what was considered and rejected, and any known follow-ups.
  Single-line commit messages are reserved for the truly trivial
  (typo fixes, dependency-version bumps with no API impact).
- One logical change per commit.

## CI

GitHub Actions, two workflows:

- `.github/workflows/ci.yml` — fan-out into parallel jobs (`static`,
  `test`, `lint`). One CI run surfaces every failure at once, not
  just the first. A `conformance` job lands once the internal
  conformance scenario is in place.
- `.github/workflows/vuln.yml` — separate, non-blocking, runs on
  `main` + daily cron. `govulncheck` opens deduped GitHub issues per
  affecting vulnerability and auto-closes them when resolved.

Required checks on every `pull_request`:

- `static`: `gofmt -l`, `go vet ./...`, `go mod tidy -diff`
- `test`: `go test -race -shuffle=on ./...`
- `lint`: `golangci-lint run ./...`

## When to ask vs when to proceed

- Bug fix, refactor, doc tweak, test addition for an existing feature:
  proceed. Reference the spec section that motivates the change in the
  commit message.
- New exported API surface, new dependency, change to an interface
  signature, anything that affects backwards compatibility: ask first.
  These are forever-decisions once the library is published.
- Anything that might cross the scope rules above (1–5): ask. The
  cost of a quick check is far less than the cost of force-pushing
  history after a leak.
