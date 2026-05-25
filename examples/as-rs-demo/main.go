// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

// Command as-rs-demo runs an end-to-end UMA 2.0 flow against an
// in-process Authorization Server and Resource Server, both built on
// the go-uma library.
//
// The demo is a single binary that:
//
//  1. Starts an in-memory AS at a localhost address.
//  2. Starts an in-memory RS at a separate localhost address. The RS
//     authenticates to the AS with a stub PAT — real deployments
//     obtain the PAT via the OAuth 2.0 client-credentials grant; that
//     acquisition is outside UMA's scope and outside this library's
//     scope. The demo uses a fixed string so the wire trace stays
//     focused on UMA itself.
//  3. Registers one resource set (a fake photo album) with the AS via
//     the Federated Authorization /resource_set endpoint.
//  4. Acts as a requesting-party client that:
//     a. issues an unauthenticated GET to the RS,
//     b. parses the 401 + WWW-Authenticate: UMA challenge to extract
//     the permission ticket and as_uri,
//     c. redeems the ticket at the AS's /token endpoint with the
//     urn:ietf:params:oauth:grant-type:uma-ticket grant,
//     d. retries the protected request with the resulting RPT, and
//     e. asks the AS to introspect the RPT to confirm the wire
//     shape on the way back.
//
// All five wire interactions go through the library's [client] and
// [server] packages. The demo contributes only the small amount of
// policy glue UMA leaves to consumers — the AS's in-memory ticket and
// RPT stores, and the RS's per-route mapping from incoming request to
// (resource_id, scopes).
//
// Run with `go run .` from this directory. Output is a step-by-step
// trace of each request/response on stdout.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hstern/go-uma"
	"github.com/hstern/go-uma/client"
	"github.com/hstern/go-uma/server"
)

// Stub PAT the RS sends on its calls to the AS protection API. Real
// deployments obtain this via the client-credentials grant; the demo
// hard-codes it so the AS can accept it unconditionally.
const stubPAT = "demo-pat-do-not-use-in-production"

// Realm advertised in the WWW-Authenticate: UMA challenge.
const demoRealm = "go-uma-demo"

func main() {
	if err := run(); err != nil {
		log.Fatalf("demo failed: %v", err)
	}
}

func run() error {
	logf := func(format string, args ...any) {
		// Ignore the int+error return — stdout failures on a demo
		// program have no useful recovery path.
		_, _ = fmt.Fprintf(os.Stdout, format+"\n", args...)
	}

	// ----------------------------------------------------------------
	// Step 0 — bring up the AS.
	// ----------------------------------------------------------------
	as := newDemoAS()
	asSrv := httptest.NewServer(server.NewASHandler(as))
	defer asSrv.Close()
	logf("AS listening at %s", asSrv.URL)

	// The RS keeps a Client pointed at the AS so it can register
	// permissions, introspect RPTs, and (in this demo) register
	// resource sets. WithPAT injects the stub PAT into every request
	// the RS sends to the protection API.
	rsClient, err := client.NewClient(asSrv.URL, client.WithPAT(stubPAT))
	if err != nil {
		return fmt.Errorf("rs client: %w", err)
	}

	// ----------------------------------------------------------------
	// Step 1 — RS acquires its PAT.
	//
	// In a real deployment the RS performs an OAuth 2.0 client-
	// credentials grant against the AS to obtain a PAT. The PAT is the
	// RS's identity for the protection-API endpoints
	// (/permission, /introspection, /resource_set). go-uma does not
	// implement that grant — consumers wire it through their existing
	// OAuth library and surface the resulting access token to the
	// library via client.WithPAT (above) or client.NewPATDoer.
	//
	// The demo treats the PAT as already-in-hand.
	// ----------------------------------------------------------------
	logf("Step 1: RS obtained PAT (stubbed).")

	// ----------------------------------------------------------------
	// Step 2 — RS registers a resource set with the AS.
	//
	// The /resource_set endpoint is the Federated Authorization
	// mechanism by which the RS tells the AS "this object exists and
	// I'm willing to defer authorization decisions about it to you."
	// The AS allocates an opaque identifier, returned as `_id`; the RS
	// uses that identifier in subsequent /permission registrations.
	// ----------------------------------------------------------------
	rs := &demoRS{
		asClient:  rsClient,
		asURL:     asSrv.URL,
		resources: map[string]protectedResource{},
	}
	created, err := rsClient.CreateResourceSet(context.Background(), &uma.ResourceSet{
		Name:           "Alice's Photo Album",
		Type:           "https://example.com/types/photoalbum",
		ResourceScopes: []string{"view", "edit"},
	})
	if err != nil {
		return fmt.Errorf("CreateResourceSet: %w", err)
	}
	logf("Step 2: registered resource set with AS; _id=%s", created.ID)

	// Map the RS's protected route to the registered resource set.
	// /album requires the "view" scope; the (resource_id, scopes) tuple
	// is what the RS hands to /permission when an unauthorized request
	// arrives.
	rs.resources["/album"] = protectedResource{
		ResourceID: created.ID,
		Scopes:     []string{"view"},
	}

	// ----------------------------------------------------------------
	// Step 3 — bring up the RS.
	// ----------------------------------------------------------------
	rsSrv := httptest.NewServer(rs.handler())
	defer rsSrv.Close()
	logf("RS listening at %s", rsSrv.URL)

	// ----------------------------------------------------------------
	// Step 4 — requesting-party client.
	//
	// This client targets the AS for the ticket-redemption side of the
	// flow. It needs no PAT — it authenticates by presenting the
	// permission ticket the RS issued.
	// ----------------------------------------------------------------
	rqp, err := client.NewClient(asSrv.URL)
	if err != nil {
		return fmt.Errorf("rqp client: %w", err)
	}

	// ----------------------------------------------------------------
	// Step 5 — unauthenticated GET to the RS → 401 + UMA ticket.
	//
	// The challenge is in the WWW-Authenticate header — NOT the
	// response body. The header carries the AS URL (as_uri), the
	// permission ticket, the requested scopes, and a realm.
	// ----------------------------------------------------------------
	resp, err := http.Get(rsSrv.URL + "/album")
	if err != nil {
		return fmt.Errorf("initial GET: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("step 5: expected 401 from RS, got %d", resp.StatusCode)
	}
	ticket, asURL, scopes := parseChallenge(resp.Header.Get("WWW-Authenticate"))
	if ticket == "" {
		return fmt.Errorf("step 5: RS did not return a ticket in WWW-Authenticate: %q",
			resp.Header.Get("WWW-Authenticate"))
	}
	logf("Step 5: RS returned 401 with ticket=%s scopes=%q as_uri=%s",
		shortID(ticket), scopes, asURL)

	// ----------------------------------------------------------------
	// Step 6 — redeem the ticket at the AS for an RPT.
	//
	// Grant type: urn:ietf:params:oauth:grant-type:uma-ticket. A
	// `need_info` response from the AS is NOT a transport error — it
	// arrives as a typed *uma.NeedInfoError that carries a fresh
	// ticket and the claims the AS still needs. The demo's AS grants
	// unconditionally, so we expect a successful TokenResponse.
	// ----------------------------------------------------------------
	tr, err := rqp.Token(context.Background(), &uma.TokenRequest{Ticket: ticket})
	if err != nil {
		// In a richer demo we'd inspect *uma.NeedInfoError here and
		// retry with claim_token populated; see the README's
		// "Claims-gathering" section.
		var ne *uma.NeedInfoError
		if errors.As(err, &ne) {
			return fmt.Errorf("AS requested claims (not configured in demo): %+v", ne.RequiredClaims)
		}
		return fmt.Errorf("Token: %w", err)
	}
	logf("Step 6: AS issued RPT (token_type=%s, expires_in=%d)", tr.TokenType, tr.ExpiresIn)

	// ----------------------------------------------------------------
	// Step 7 — retry the protected request with the RPT.
	//
	// The RS's ProtectedRequest method (called from inside its handler)
	// extracts the bearer token, introspects it at the AS to confirm
	// it's active and covers the requested (resource_id, scopes), and
	// returns DecisionAllow.
	// ----------------------------------------------------------------
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, rsSrv.URL+"/album", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+tr.AccessToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("retry GET: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("step 7: expected 200, got %d (body=%s)", resp.StatusCode, body)
	}
	logf("Step 7: retry succeeded; RS returned %d bytes", len(body))

	// ----------------------------------------------------------------
	// Step 8 — introspect the RPT directly.
	//
	// The RS already introspects on every call (inside step 7's
	// handler); the demo calls introspection from the client side as
	// well to show the wire shape. Note that an `active: false`
	// response is a 200 OK, NOT a transport error — it indicates the
	// token is unknown / revoked / expired, and consumers branch on
	// the Active field themselves.
	// ----------------------------------------------------------------
	ir, err := rsClient.Introspect(context.Background(), &uma.IntrospectionRequest{
		Token: tr.AccessToken,
	})
	if err != nil {
		return fmt.Errorf("Introspect: %w", err)
	}
	logf("Step 8: introspection: active=%t permissions=%d", ir.Active, len(ir.Permissions))
	for _, p := range ir.Permissions {
		logf("         permission: resource_id=%s scopes=%v", p.ResourceID, p.ResourceScopes)
	}

	logf("Demo complete.")
	return nil
}

// ----------------------------------------------------------------------
// Authorization Server.
// ----------------------------------------------------------------------

// demoAS is a tiny in-memory AS. It embeds server.NotImplementedAS so
// any UMA endpoint it does not override (none, in this demo) returns
// 501 via the library's status-mapping rules.
//
// It implements:
//
//   - ResourceSet: minimal CRUD over an in-memory map, enough to honor
//     a Create on startup.
//   - Permission: mints a fresh opaque ticket bound to (resource_id,
//     scopes).
//   - Token: looks up the ticket, marks it consumed, mints a fresh
//     opaque RPT bound to the same (resource_id, scopes).
//   - Introspect: returns active=true plus the bound permissions for a
//     known RPT; active=false for an unknown one (per spec, 200 OK
//     either way).
//
// Policy is intentionally absent — the demo grants unconditionally so
// the wire trace stays small. The same shape extends to a real AS by
// branching on the request inside Token and returning a typed
// *uma.NeedInfoError or *uma.OAuthError when policy denies.
type demoAS struct {
	server.NotImplementedAS

	mu        sync.Mutex
	resources map[string]*uma.ResourceSet
	tickets   map[string]*demoTicket
	rpts      map[string]*demoRPT
}

type demoTicket struct {
	ResourceID string
	Scopes     []string
}

type demoRPT struct {
	ResourceID string
	Scopes     []string
	IssuedAt   time.Time
}

func newDemoAS() *demoAS {
	return &demoAS{
		resources: map[string]*uma.ResourceSet{},
		tickets:   map[string]*demoTicket{},
		rpts:      map[string]*demoRPT{},
	}
}

// ResourceSet handles all five CRUD operations multiplexed through the
// single AS.ResourceSet method. The demo implements Create only; the
// other ops return ErrNotImplemented and the library maps that to 501.
func (a *demoAS) ResourceSet(_ context.Context, r *server.ResourceSetRequest) (*server.ResourceSetResponse, error) {
	if r.Op != uma.OpCreate {
		return nil, uma.ErrNotImplemented
	}
	if r.Body == nil {
		return nil, &uma.ValidationError{Type: "ResourceSet", Field: "body", Message: "missing"}
	}
	id := randomID()
	a.mu.Lock()
	a.resources[id] = r.Body
	a.mu.Unlock()
	return &server.ResourceSetResponse{
		Single: &uma.ResourceSet{
			ID:             id,
			Name:           r.Body.Name,
			Type:           r.Body.Type,
			ResourceScopes: r.Body.ResourceScopes,
		},
	}, nil
}

func (a *demoAS) Permission(_ context.Context, r *uma.PermissionRequest) (*uma.PermissionResponse, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	id := randomID()
	a.mu.Lock()
	a.tickets[id] = &demoTicket{ResourceID: r.ResourceID, Scopes: r.ResourceScopes}
	a.mu.Unlock()
	return &uma.PermissionResponse{Ticket: id}, nil
}

func (a *demoAS) Token(_ context.Context, r *uma.TokenRequest) (*uma.TokenResponse, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	tkt, ok := a.tickets[r.Ticket]
	if ok {
		delete(a.tickets, r.Ticket) // single-use
	}
	a.mu.Unlock()
	if !ok {
		return nil, &uma.OAuthError{
			ErrorCode:        uma.ErrorCodeInvalidGrant,
			ErrorDescription: "ticket unknown or already consumed",
		}
	}
	rpt := randomID()
	a.mu.Lock()
	a.rpts[rpt] = &demoRPT{ResourceID: tkt.ResourceID, Scopes: tkt.Scopes, IssuedAt: time.Now()}
	a.mu.Unlock()
	return &uma.TokenResponse{
		AccessToken: rpt,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}, nil
}

func (a *demoAS) Introspect(_ context.Context, r *uma.IntrospectionRequest) (*uma.IntrospectionResponse, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	rpt, ok := a.rpts[r.Token]
	a.mu.Unlock()
	if !ok {
		return &uma.IntrospectionResponse{Active: false}, nil
	}
	return &uma.IntrospectionResponse{
		Active: true,
		Permissions: []uma.Permission{
			{ResourceID: rpt.ResourceID, ResourceScopes: rpt.Scopes},
		},
	}, nil
}

// ----------------------------------------------------------------------
// Resource Server.
// ----------------------------------------------------------------------

// demoRS is a small RS that protects a single route, /album. It is
// configured at startup with a Client pointed at the AS (so it can
// register permissions and introspect RPTs), the AS's URL (for the 401
// challenge), and a per-route map naming the resource set and the
// scopes that route requires.
type demoRS struct {
	asClient  client.Client
	asURL     string
	resources map[string]protectedResource
}

type protectedResource struct {
	ResourceID string
	Scopes     []string
}

// ProtectedRequest is the single decision point UMA's RS role exposes.
// The library does not own routing — the consumer's handler knows
// which (resource_id, scopes) tuple a given request maps to and passes
// it in.
func (rs *demoRS) ProtectedRequest(
	ctx context.Context, r *http.Request, rsid string, scopes []string,
) (server.Decision, error) {
	rpt, ok := server.ExtractBearerToken(r)
	if !ok {
		return server.DecisionUnknown, rs.askForTicket(ctx, rsid, scopes)
	}
	ir, err := rs.asClient.Introspect(ctx, &uma.IntrospectionRequest{Token: rpt})
	if err != nil {
		return server.DecisionUnknown, fmt.Errorf("introspect: %w", err)
	}
	if !ir.Active {
		return server.DecisionUnknown, rs.askForTicket(ctx, rsid, scopes)
	}
	for _, p := range ir.Permissions {
		if p.ResourceID == rsid && containsAll(p.ResourceScopes, scopes) {
			return server.DecisionAllow, nil
		}
	}
	return server.DecisionUnknown, rs.askForTicket(ctx, rsid, scopes)
}

// askForTicket calls the AS's /permission endpoint and wraps the
// ticket in a *server.TicketRequired so the handler can render the
// 401 + WWW-Authenticate: UMA challenge.
func (rs *demoRS) askForTicket(ctx context.Context, rsid string, scopes []string) error {
	pr, err := rs.asClient.Permission(ctx, &uma.PermissionRequest{
		ResourceID:     rsid,
		ResourceScopes: scopes,
	})
	if err != nil {
		return fmt.Errorf("permission: %w", err)
	}
	return &server.TicketRequired{
		Ticket: pr.Ticket,
		ASURL:  rs.asURL,
		Scopes: strings.Join(scopes, " "),
		Realm:  demoRealm,
	}
}

// handler returns the RS's http.Handler. For each route, it consults
// the per-route resource map, calls ProtectedRequest, branches on the
// result, and on DecisionAllow serves a placeholder response body.
func (rs *demoRS) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/album", func(w http.ResponseWriter, r *http.Request) {
		res, ok := rs.resources[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		d, err := rs.ProtectedRequest(r.Context(), r, res.ResourceID, res.Scopes)
		var tr *server.TicketRequired
		if errors.As(err, &tr) {
			server.WriteTicketRequired(w, tr)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if d != server.DecisionAllow {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"album":"Alice's Photo Album","photos":[{"id":1},{"id":2}]}`)
	})
	return mux
}

// ----------------------------------------------------------------------
// Helpers.
// ----------------------------------------------------------------------

// parseChallenge pulls the ticket, as_uri, and scope params out of a
// WWW-Authenticate: UMA … challenge header. Returns empty strings for
// any param the header omits.
func parseChallenge(header string) (ticket, asURL, scope string) {
	if !strings.HasPrefix(header, "UMA ") {
		return "", "", ""
	}
	return paramValue(header, "ticket"),
		paramValue(header, "as_uri"),
		paramValue(header, "scope")
}

// paramValue extracts a quoted parameter value from an HTTP challenge
// header. The challenge is a comma-separated list of key="value"
// pairs; this routine is deliberately minimal — production code should
// use a tested parser — but it handles the shape go-uma's
// WriteTicketResponse emits.
func paramValue(header, key string) string {
	needle := key + `="`
	i := strings.Index(header, needle)
	if i < 0 {
		return ""
	}
	rest := header[i+len(needle):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// shortID returns the first eight characters of s for logging. The
// demo deals only with opaque 32-character hex IDs, so truncating to
// eight makes the trace readable without ambiguity.
func shortID(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8] + "…"
}

// randomID returns a 32-character hex string. The AS uses it for
// permission tickets, RPTs, and resource_set _ids alike — they are
// all opaque-to-the-client identifiers and the demo does not need to
// distinguish their formats.
func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// containsAll returns true iff every element of want appears in have.
// Empty want is satisfied trivially.
func containsAll(have, want []string) bool {
	set := make(map[string]struct{}, len(have))
	for _, s := range have {
		set[s] = struct{}{}
	}
	for _, s := range want {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}
