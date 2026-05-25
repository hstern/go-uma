# as-rs-demo — end-to-end UMA 2.0 flow in one binary

This example runs the full User-Managed Access 2.0 protocol — from
unauthenticated request through resource-set registration, permission
ticket, token exchange, and introspection — against an in-process
Authorization Server and Resource Server, both built on `go-uma`.

The point of the demo is to show what the library does and does not
own. The wire interactions (challenge header parsing on one side,
401-with-`WWW-Authenticate: UMA` emission on the other, ticket
redemption with the UMA-ticket grant, introspection of the resulting
RPT) all go through the library's `client` and `server` packages. The
demo contributes only the small amount of policy glue UMA leaves to
consumers: an in-memory ticket and RPT store on the AS, a per-route
map from incoming request to `(resource_id, scopes)` on the RS, and
the stub Protection API Token (PAT) that authenticates the RS to the
AS's protection endpoints.

## Run it

From this directory:

```sh
go run .
```

Expected output (IDs and ports vary):

```
AS listening at http://127.0.0.1:53996
Step 1: RS obtained PAT (stubbed).
Step 2: registered resource set with AS; _id=…
RS listening at http://127.0.0.1:53998
Step 5: RS returned 401 with ticket=… scopes="view" as_uri=…
Step 6: AS issued RPT (token_type=Bearer, expires_in=3600)
Step 7: retry succeeded; RS returned 60 bytes
Step 8: introspection: active=true permissions=1
         permission: resource_id=… scopes=[view]
Demo complete.
```

The demo exits cleanly when the flow completes. There is no long-
running server to leave behind.

## What happens, step by step

The numbered steps below match the comment headers in `main.go`.

### 1. RS acquires a PAT — stubbed

The RS's calls to the AS's protection-API endpoints
(`/permission`, `/introspection`, `/resource_set`) are
PAT-authenticated. The PAT is a regular OAuth 2.0 access token that
the RS obtains via — typically — the OAuth 2.0 client-credentials
grant against the same AS that hosts the UMA endpoints.

`go-uma` does **not** implement the client-credentials grant or any
other PAT-acquisition flow. Consumers wire that through their existing
OAuth library and surface the resulting access token to `go-uma` in
one of two ways:

- `client.WithPAT(token)` at `NewClient` time, which the library
  attaches to every protection-API request automatically.
- `client.NewPATDoer(inner, token)` to compose a PAT-injecting
  middleware into an `HTTPDoer` chain — useful when the PAT is
  short-lived and refreshed on its own clock.

The demo hard-codes a fixed string so the wire trace stays focused on
UMA itself.

### 2. RS registers a resource set with the AS

The AS does not know about protected resources until the RS tells it.
The `/resource_set` endpoint (Federated Authz §2) is the mechanism:
the RS POSTs a `ResourceSet` describing the resource (name, type, the
scopes the AS may issue tickets for), and the AS allocates an opaque
identifier returned as `_id`. The RS uses that identifier in every
subsequent `/permission` registration.

In the demo, the RS registers a single fake photo album:

```go
created, err := rsClient.CreateResourceSet(ctx, &uma.ResourceSet{
    Name:           "Alice's Photo Album",
    Type:           "https://example.com/types/photoalbum",
    ResourceScopes: []string{"view", "edit"},
})
// created.ID is the AS-assigned _id, used in step 5.
```

The RS then maps its protected route (`/album`) to that resource id
and the scopes the route requires (`["view"]`).

### 3. Requesting-party client issues an unauthenticated GET

An end user — represented in the demo by a `http.Get` against the
RS's `/album` route with no `Authorization` header — asks the RS for
the protected resource without yet holding an RPT.

### 4. RS responds with 401 + UMA challenge

Inside the RS's handler, `ProtectedRequest` runs:

1. `server.ExtractBearerToken(r)` finds no token.
2. The RS calls `Client.Permission` against the AS to register a
   permission for `(resource_id, ["view"])`. The AS mints a fresh
   opaque ticket bound to that tuple and returns it.
3. The RS wraps the ticket in a `*server.TicketRequired` and returns
   it as the error. The handler unwraps the error with `errors.As`
   and calls `server.WriteTicketRequired(w, tr)`, which emits a 401
   response carrying

   ```
   WWW-Authenticate: UMA realm="go-uma-demo",
     as_uri="http://127.0.0.1:53996",
     ticket="…", scope="view"
   ```

The load-bearing point: the ticket lives in the `WWW-Authenticate`
header, **not** the response body. A client that looks for it in the
body produces a non-conforming implementation.

### 5. Client redeems the ticket at `/token`

The requesting-party client receives the 401, parses the
`WWW-Authenticate: UMA …` header to extract the `ticket` and
`as_uri` parameters, and POSTs to the AS's `/token` endpoint with

```
grant_type=urn:ietf:params:oauth:grant-type:uma-ticket
ticket=<ticket-from-RS>
```

(Form-encoded; the library wraps the wire details inside
`Client.Token`.)

The AS looks up the ticket, applies whatever policy the consumer has
configured (the demo grants unconditionally), and either issues an
RPT — returned as a normal `TokenResponse` — or returns a typed
error:

| Wire shape                                            | Library type                                             | What it means                                                                                                                                          |
| ----------------------------------------------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| HTTP 403, `error: "need_info"`                        | `*uma.NeedInfoError` (returned via `errors.As`)          | The AS needs additional claims. The error carries an upgraded ticket and the claims it requires. The client retries `/token` with `claim_token` set.   |
| HTTP 403, `error: "not_authorized"`                   | `*uma.OAuthError`, matches `errors.Is(err, ErrNotAuthorized)` | Policy denied the request outright. No retry is possible.                                                                                              |
| HTTP 403, `error: "request_submitted"`                | `*uma.OAuthError`, matches `errors.Is(err, ErrRequestSubmitted)` | The AS has queued the request for asynchronous Resource Owner action; the client should poll.                                                          |
| HTTP 400, `error: "invalid_grant"`                    | `*uma.OAuthError`, matches `errors.Is(err, ErrInvalidGrant)` | The ticket is unknown, expired, or already consumed.                                                                                                   |
| transport / network error                             | Go-native error from `net/http`                          | DNS failure, connection refused, TLS error, etc.                                                                                                       |

The implementer pin: a `need_info` 403 is **not** a transport error.
It is a documented branch of the protocol. Pattern-match with
`errors.As(err, &needInfo)` and retry with claims pushed via
`uma.NewPushedClaimsTokenRequest`.

The demo grants unconditionally, so step 5 returns a `TokenResponse`
with an opaque RPT in `AccessToken`.

### 6. Client retries the protected request with the RPT

The client repeats the GET against the RS's `/album` route, this time
sending `Authorization: Bearer <rpt>`. Inside `ProtectedRequest` the
RS now:

1. Extracts the bearer token successfully.
2. Calls `Client.Introspect` against the AS with the token.
3. Receives `IntrospectionResponse{Active: true, Permissions: [{ResourceID, ResourceScopes: ["view"]}]}`.
4. Verifies the permission covers the route's `(resource_id, scopes)`
   tuple and returns `server.DecisionAllow`.

The handler then serves the protected response body.

A second implementer pin: `Active: false` from the introspection
endpoint is **not** a transport error. It's a successful 200 OK
response indicating the token is unknown, revoked, or expired. The
RS branches on the `Active` field; the library does not raise an
error for inactive tokens.

### 7. Introspect the RPT directly

The demo finishes by calling `Introspect` from the client side as
well, to show the wire shape on its own. In real deployments the RS
introspects on every protected request; the requesting-party client
typically does not, since it already holds the RPT.

## What the demo does **not** do

The example is intentionally minimal so the protocol fits on one
screen. Several real-world concerns are deliberately out of scope:

- **PAT acquisition.** The stub PAT bypasses the OAuth 2.0 client-
  credentials grant the RS would normally run. A production RS wires
  this through its existing OAuth library.
- **TLS termination, CORS, request logging, rate limiting.** All
  handled by the consumer's HTTP stack — the library is transport-
  layer-agnostic. The demo uses `httptest.NewServer` for both AS and
  RS, which is plain HTTP on a loopback address.
- **Persistent storage.** Tickets, RPTs, and resource-set records all
  live in `map`s for the lifetime of the process. A production AS
  needs durable stores with the appropriate replay and revocation
  semantics.
- **Policy.** The demo's AS grants every ticket-redemption request.
  A real AS consults policy at `Token`-time and returns a typed
  `*uma.NeedInfoError` or `*uma.OAuthError` when the requesting party
  is missing required claims or fails policy.
- **Claims-gathering.** UMA supports two claims-gathering styles:
  pushed claims (client retries `/token` with `claim_token` set) and
  AS-pulled claims (AS returns a `redirect_user` URL, the client
  follows it through an interactive flow, then retries). The demo
  exercises neither; the parent `README.md` covers both shapes.
- **Metadata document and mix-up validation.** The library implements
  `/.well-known/uma2-configuration` and the spec's mix-up defenses
  (`server.BuildMetadata`, `Client.FetchMetadata`). The demo connects
  the client directly to a known AS URL and skips discovery. A
  production deployment fetches metadata first and routes through
  the published endpoints.

## Layout

```
examples/as-rs-demo/
├── README.md     (this file)
├── go.mod        (separate module — see below)
└── main.go       (the demo)
```

The example lives in **its own Go module**, separate from the
library's module at the repository root. The two modules are wired
together with a `replace` directive in this directory's `go.mod`:

```
module github.com/hstern/go-uma/examples/as-rs-demo

go 1.26

require github.com/hstern/go-uma v0.0.0

replace github.com/hstern/go-uma => ../..
```

The separate-module structure keeps the example's dependency footprint
out of the library's `go.mod`. `go-uma` itself has zero non-test
runtime dependencies; that property is preserved even if the example
grows future dependencies (a CLI flag parser, a structured logger,
etc.). Consumers running `go get github.com/hstern/go-uma` will never
pull in the example's transitive dependencies, even today when there
are none, because the example is not under the library's module
graph.

The `replace` directive points the `require` at the in-repo copy of
the library, so `go run .` works against unreleased changes and
continues to work once `v0.1.0` is tagged and published.
