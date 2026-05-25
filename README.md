# go-uma

A Go implementation of
**User-Managed Access 2.0** —
[UMA 2.0 Grant for OAuth 2.0](https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html)
and
[UMA 2.0 Federated Authorization for OAuth 2.0](https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-fedauthz-2.0.html)
— the Kantara Initiative protocol that lets a Resource Owner authorize
asynchronous access to their resources by a Requesting Party, mediated by
an Authorization Server.

`go-uma` provides:

- A typed HTTP client for both the Requesting Party (RqP) side of the
  protocol (UMA-ticket grant redemption, claims-gathering) and the
  Resource Server (RS) side (permission registration, token
  introspection, resource-set CRUD against the AS's Federated
  Authorization endpoints).
- `http.Handler` constructors for the AS role (over an `AS` interface)
  and helpers for the RS role (over an `RS` interface), with an
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

## Quickstart

### Authorization Server

An AS implementation embeds `server.NotImplementedAS` and overrides
only the endpoints it serves. The handler maps unimplemented methods
to HTTP 501 and returns the right wire error for each typed error
the implementation can produce.

```go
package main

import (
    "context"
    "log"
    "net/http"

    "github.com/hstern/go-uma"
    "github.com/hstern/go-uma/server"
)

type myAS struct {
    server.NotImplementedAS
    // ticket store, RPT store, policy backend …
}

func (a *myAS) Token(ctx context.Context, r *uma.TokenRequest) (*uma.TokenResponse, error) {
    // Look up r.Ticket → (resource_id, scopes).
    // Apply policy. If insufficient claims, return *uma.NeedInfoError.
    // If approved, mint an RPT (format is your choice) and return.
    return &uma.TokenResponse{
        AccessToken: "opaque-rpt",
        TokenType:   "Bearer",
        ExpiresIn:   3600,
    }, nil
}

func main() {
    as := &myAS{}
    log.Fatal(http.ListenAndServe(":8080", server.NewASHandler(as)))
}
```

Embed-and-override means a partial AS that only implements `Token`
returns 501 for `/permission`, `/introspection`, and `/resource_set`
automatically — and the metadata document `server.BuildMetadata`
produces advertises only the implemented endpoints.

### Resource Server

The RS interface has a single `ProtectedRequest` method. The library
contributes the policy-decision interface, the `WriteTicketResponse`
helper that emits the 401 + `WWW-Authenticate: UMA` challenge, and
the `ExtractBearerToken` helper for pulling the RPT off the
incoming request. Routing stays in consumer hands.

```go
package main

import (
    "context"
    "errors"
    "log"
    "net/http"

    "github.com/hstern/go-uma"
    "github.com/hstern/go-uma/client"
    "github.com/hstern/go-uma/server"
)

type myRS struct {
    asClient client.Client
    asURL    string
}

func (rs *myRS) ProtectedRequest(
    ctx context.Context, r *http.Request, rsid string, scopes []string,
) (server.Decision, error) {
    rpt, ok := server.ExtractBearerToken(r)
    if !ok {
        return server.DecisionUnknown, rs.ticket(ctx, rsid, scopes)
    }
    ir, err := rs.asClient.Introspect(ctx, &uma.IntrospectionRequest{Token: rpt})
    if err != nil || !ir.Active {
        return server.DecisionUnknown, rs.ticket(ctx, rsid, scopes)
    }
    return server.DecisionAllow, nil
}

func (rs *myRS) ticket(ctx context.Context, rsid string, scopes []string) error {
    pr, _ := rs.asClient.Permission(ctx, &uma.PermissionRequest{
        ResourceID: rsid, ResourceScopes: scopes,
    })
    return &server.TicketRequired{Ticket: pr.Ticket, ASURL: rs.asURL, Realm: "my-app"}
}

func handler(rs *myRS) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        d, err := rs.ProtectedRequest(r.Context(), r, "photo-1", []string{"view"})
        var tr *server.TicketRequired
        if errors.As(err, &tr) {
            server.WriteTicketRequired(w, tr)
            return
        }
        if err != nil || d != server.DecisionAllow {
            w.WriteHeader(http.StatusForbidden)
            return
        }
        log.Println("authorized")
        // serve the protected resource …
    })
}
```

### Requesting-Party Client

The client targets one AS. The full ticket → token → introspect flow
is three method calls, each surfacing the typed error the library
documents.

```go
package main

import (
    "context"
    "errors"
    "log"

    "github.com/hstern/go-uma"
    "github.com/hstern/go-uma/client"
)

func main() {
    c, err := client.NewClient("https://as.example.com")
    if err != nil {
        log.Fatal(err)
    }
    // Step 1: redeem the ticket the RS handed out.
    tr, err := c.Token(context.Background(), &uma.TokenRequest{
        Ticket: "tkt-from-rs-401-challenge",
    })
    var ne *uma.NeedInfoError
    if errors.As(err, &ne) {
        // Gather the required claims and retry with claim_token populated:
        //   c.Token(ctx, uma.NewPushedClaimsTokenRequest(ne.Ticket, idToken, uma.ClaimTokenFormatIDToken))
        log.Fatalf("claims required: %+v", ne.RequiredClaims)
    }
    if err != nil {
        log.Fatalf("token: %v", err) // *uma.OAuthError or transport error
    }
    // Step 2: use the RPT.
    log.Printf("got RPT, expires in %d seconds", tr.ExpiresIn)
}
```

A `need_info` 403 from the AS is **not** a transport error — it's a
typed `*uma.NeedInfoError` carrying a fresh ticket and the claims the
AS still needs. Pattern-match with `errors.As` and retry. Same for
`active: false` from `Client.Introspect`: that's a successful 200
response indicating the token is unknown / revoked / expired, not a
transport failure; consumers branch on `IntrospectionResponse.Active`
themselves.

### Typed extensions on `Permission.Claims`

The `Permission` entries in an introspection response may carry an
optional `claims` object. The library exposes it as
`json.RawMessage` so the bytes round-trip verbatim regardless of key
order. Bridge to a typed Go value with the package-level
`DecodeJSON` / `EncodeJSON` helpers:

```go
type AccessContext struct {
    Department string `json:"department"`
    Tier       string `json:"tier"`
}

// Reading: RawMessage → typed.
for _, p := range ir.Permissions {
    var ctx AccessContext
    if err := uma.DecodeJSON(p.Claims, &ctx); err != nil {
        return err
    }
    log.Printf("permission claims: %+v", ctx)
}

// Writing: typed → RawMessage.
claims, _ := uma.EncodeJSON(AccessContext{Department: "eng", Tier: "gold"})
p := uma.Permission{
    ResourceID:     "photo-1",
    ResourceScopes: []string{"view"},
    Claims:         claims,
}
```

`DecodeJSON` treats a nil or empty `RawMessage` as "no extension
present" (no error, the typed value is left at its zero value), so
call sites do not need a nil-guard.

## Metadata document

The library implements `/.well-known/uma2-configuration` (Grant
§1.3.2) on both sides:

- **Server**: `server.BuildMetadata(asURL, as, opts...)` introspects
  the `AS` by probing each method with a sentinel zero-value request
  and publishes only the endpoints the AS actually implements. Serve
  the result with `server.NewMetadataHandler` mounted at
  `uma.MetadataPath`.
- **Client**: `Client.FetchMetadata(ctx)` fetches and validates the
  document. **Mix-up protection is on by default** — a fetched
  `Issuer` field that does not match the configured base URL produces
  a typed `*client.MixUpError`, the spec's defense (Grant §1.3.2 +
  RFC 8252 §6) against a confused-deputy attack swapping in a
  hostile AS's document. Opt out with `client.WithRelaxedMetadataValidation()`
  only when a TLS terminator or path rewriter legitimately produces a
  configured URL distinct from the published one.
- **Caching**: `Client.FetchMetadata` honors the response's
  `Cache-Control: max-age` directive; absent that, it falls back to
  a configurable default (one hour). Override with
  `client.WithMetadataTTL(d)`. The cache lives on the `Client`, not
  globally — different clients hold different documents.
- **Signed metadata** (`signed_metadata`, a JWS per RFC 7515) is
  round-tripped as opaque bytes in `v0.x` so existing deployments
  survive upgrades without churn. Verification and signing land in a
  later release along with a JOSE dependency.

## PAT acquisition is out of scope

UMA's protection-API endpoints (`/permission`, `/introspection`,
`/resource_set`) are PAT-authenticated — the Resource Server sends an
OAuth 2.0 access token in the `Authorization: Bearer` header on every
call. **How the RS obtains the PAT is out of scope for this library.**
The conventional path is the OAuth 2.0 client-credentials grant
against the same AS, which a consumer wires through their own OAuth
library and surfaces here via `client.WithPAT(token)` or by composing
`client.NewPATDoer` into the `HTTPDoer` chain.

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

## Examples

Runnable examples live under [`examples/`](examples/), each in its own
Go module outside the library's dependency graph. The
[`as-rs-demo`](examples/as-rs-demo/) program brings up an in-process
AS and RS and drives the full UMA flow — resource-set registration,
401 challenge, permission ticket, `/token` redemption, introspection
— end to end in a single binary. The example's README walks through
each wire interaction.

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
