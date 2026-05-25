// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

// End-to-end AS + RS + Client round-trip tests — the phase-4
// acceptance gate.
//
// Each test stands up:
//   - an AS via NewASHandler + httptest.NewServer, backed by an
//     in-memory ticket store and an in-memory RPT store with
//     introspection support;
//   - an RS as a plain http.HandlerFunc that calls the AS via the
//     library's Client, uses ExtractBearerToken + Client.Introspect
//     to validate any presented RPT, and uses Client.Permission +
//     WriteTicketResponse to emit a 401 with a fresh ticket when the
//     RPT is missing or insufficient;
//   - a requesting-party Client targeting the AS.
//
// The library's own Client and server packages do all the wire
// handling; the test contributes only the small amount of policy
// glue (the AS's RPT store, the RS's per-route scope mapping) the
// library does not own.

package server_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hstern/go-uma"
	"github.com/hstern/go-uma/client"
	"github.com/hstern/go-uma/server"
)

// e2eAS implements every UMA endpoint the round-trip flow needs.
//
//	Permission → mint a ticket bound to (resource_id, scopes)
//	Token      → exchange ticket for RPT, with policy hooks
//	Introspect → look up RPT, return active + permissions
//
// Tests configure the policy hook to drive the outcomes the
// scenarios assert against.
type e2eAS struct {
	server.NotImplementedAS
	mu      sync.Mutex
	tickets map[string]*e2eTicket
	rpts    map[string]*e2eRPT

	// policyHook is consulted from Token. Returning nil grants the
	// ticket; returning a typed error (e.g. *uma.NeedInfoError or
	// *uma.OAuthError) drives the matching wire response.
	policyHook func(ctx context.Context, r *uma.TokenRequest, ticket *e2eTicket) error
}

type e2eTicket struct {
	resourceID string
	scopes     []string
	consumed   bool
}

type e2eRPT struct {
	resourceID string
	scopes     []string
	active     bool
}

func newE2EAS() *e2eAS {
	return &e2eAS{
		tickets: map[string]*e2eTicket{},
		rpts:    map[string]*e2eRPT{},
	}
}

func (a *e2eAS) randID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

func (a *e2eAS) Permission(_ context.Context, r *uma.PermissionRequest) (*uma.PermissionResponse, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	id := a.randID()
	a.mu.Lock()
	a.tickets[id] = &e2eTicket{resourceID: r.ResourceID, scopes: r.ResourceScopes}
	a.mu.Unlock()
	return &uma.PermissionResponse{Ticket: id}, nil
}

func (a *e2eAS) Token(ctx context.Context, r *uma.TokenRequest) (*uma.TokenResponse, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	tkt, ok := a.tickets[r.Ticket]
	a.mu.Unlock()
	if !ok {
		return nil, &uma.OAuthError{
			ErrorCode:        uma.ErrorCodeInvalidGrant,
			ErrorDescription: "unknown ticket",
		}
	}
	if a.policyHook != nil {
		if err := a.policyHook(ctx, r, tkt); err != nil {
			return nil, err
		}
	}
	a.mu.Lock()
	tkt.consumed = true
	rptID := a.randID()
	a.rpts[rptID] = &e2eRPT{resourceID: tkt.resourceID, scopes: tkt.scopes, active: true}
	a.mu.Unlock()
	return &uma.TokenResponse{
		AccessToken: rptID,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}, nil
}

func (a *e2eAS) Introspect(_ context.Context, r *uma.IntrospectionRequest) (*uma.IntrospectionResponse, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	rpt, ok := a.rpts[r.Token]
	if !ok || !rpt.active {
		// Spec: active=false is a 200 OK response, not an error.
		return &uma.IntrospectionResponse{Active: false}, nil
	}
	return &uma.IntrospectionResponse{
		Active: true,
		Permissions: []uma.Permission{
			{ResourceID: rpt.resourceID, ResourceScopes: rpt.scopes},
		},
	}, nil
}

// e2eRS wraps a protected resource — here a fixed "you are
// authorized" body — with the library's introspection-based RPT
// validation and 401-with-ticket emission.
type e2eRS struct {
	asClient client.Client
	asURL    string

	// resourceID and resourceScopes name the resource and the scopes
	// the protected route is asking about; the RS registers a
	// permission with the AS for this tuple whenever a request
	// arrives without sufficient authorization.
	resourceID     string
	resourceScopes []string
	realm          string
}

func (rs *e2eRS) ProtectedRequest(
	ctx context.Context, r *http.Request, rsid string, scopes []string,
) (server.Decision, error) {
	rpt, ok := server.ExtractBearerToken(r)
	if !ok {
		return server.DecisionUnknown, rs.requestTicket(ctx)
	}
	ir, err := rs.asClient.Introspect(ctx, &uma.IntrospectionRequest{Token: rpt})
	if err != nil {
		return server.DecisionUnknown, err
	}
	if !ir.Active {
		return server.DecisionUnknown, rs.requestTicket(ctx)
	}
	// Verify the RPT covers (rsid, scopes).
	for _, p := range ir.Permissions {
		if p.ResourceID != rsid {
			continue
		}
		if hasAllScopes(p.ResourceScopes, scopes) {
			return server.DecisionAllow, nil
		}
	}
	return server.DecisionUnknown, rs.requestTicket(ctx)
}

// requestTicket calls the AS's /permission endpoint and returns a
// *TicketRequired wrapping the fresh ticket — the handler converts
// this to the 401 + WWW-Authenticate.
func (rs *e2eRS) requestTicket(ctx context.Context) error {
	pr, err := rs.asClient.Permission(ctx, &uma.PermissionRequest{
		ResourceID:     rs.resourceID,
		ResourceScopes: rs.resourceScopes,
	})
	if err != nil {
		return err
	}
	return &server.TicketRequired{
		Ticket: pr.Ticket,
		ASURL:  rs.asURL,
		Scopes: strings.Join(rs.resourceScopes, " "),
		Realm:  rs.realm,
	}
}

// hasAllScopes returns true if granted contains every entry in
// requested. Empty requested is satisfied trivially.
func hasAllScopes(granted, requested []string) bool {
	g := map[string]bool{}
	for _, s := range granted {
		g[s] = true
	}
	for _, s := range requested {
		if !g[s] {
			return false
		}
	}
	return true
}

// rsHandler wraps the RS as an http.Handler that invokes
// ProtectedRequest, branches on the result, and serves the protected
// content on allow.
func rsHandler(rs *e2eRS, rsid string, scopes []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d, err := rs.ProtectedRequest(r.Context(), r, rsid, scopes)
		var tr *server.TicketRequired
		if errors.As(err, &tr) {
			server.WriteTicketRequired(w, tr)
			return
		}
		if err != nil || d != server.DecisionAllow {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
}

// startE2E sets up the AS + RS + Client trio. Returns the AS handle
// (so tests can flip the policy hook), the RS handle (so tests can
// inspect state), and the requesting-party client.
func startE2E(t *testing.T) (*e2eAS, *e2eRS, client.Client, *httptest.Server, *httptest.Server) {
	t.Helper()
	as := newE2EAS()
	asSrv := httptest.NewServer(server.NewASHandler(as))
	t.Cleanup(asSrv.Close)

	asClient, err := client.NewClient(asSrv.URL, client.WithPAT("rs-pat"))
	if err != nil {
		t.Fatalf("client.NewClient: %v", err)
	}
	rs := &e2eRS{
		asClient:       asClient,
		asURL:          asSrv.URL,
		resourceID:     "photoalbum-1",
		resourceScopes: []string{"view"},
		realm:          "photoz",
	}
	rsSrv := httptest.NewServer(rsHandler(rs, rs.resourceID, rs.resourceScopes))
	t.Cleanup(rsSrv.Close)

	// The requesting-party client (separate from the RS-side client)
	// targets the AS to redeem its ticket.
	rqpClient, err := client.NewClient(asSrv.URL)
	if err != nil {
		t.Fatalf("rqpClient.NewClient: %v", err)
	}
	return as, rs, rqpClient, asSrv, rsSrv
}

// readBearerChallenge issues a GET to rsURL with no Authorization
// header and returns the ticket the RS embeds in the
// WWW-Authenticate challenge. Fatal on any other shape.
func readBearerChallenge(t *testing.T, rsURL string) (ticket, asURL string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, rsURL, http.NoBody)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("RS request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("RS status = %d, want 401", resp.StatusCode)
	}
	hdr := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(hdr, "UMA ") {
		t.Fatalf("WWW-Authenticate = %q, want UMA prefix", hdr)
	}
	ticket = extractParam(hdr, "ticket")
	asURL = extractParam(hdr, "as_uri")
	if ticket == "" || asURL == "" {
		t.Fatalf("WWW-Authenticate missing ticket or as_uri: %q", hdr)
	}
	return ticket, asURL
}

// extractParam pulls a quoted parameter value out of a WWW-Authenticate
// header. Returns the empty string when the key is missing.
func extractParam(header, key string) string {
	prefix := key + `="`
	i := strings.Index(header, prefix)
	if i < 0 {
		return ""
	}
	rest := header[i+len(prefix):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// callProtectedResource hits the RS with the given RPT and returns
// the response. Fatal on network error.
func callProtectedResource(t *testing.T, rsURL, rpt string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, rsURL, http.NoBody)
	if rpt != "" {
		req.Header.Set("Authorization", "Bearer "+rpt)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("RS request: %v", err)
	}
	return resp
}

func TestE2E_HappyPath(t *testing.T) {
	_, _, rqpClient, _, rsSrv := startE2E(t)

	// Step 1: unauthenticated request → 401 + ticket.
	ticket, _ := readBearerChallenge(t, rsSrv.URL)

	// Step 2: client redeems ticket at AS /token.
	tr, err := rqpClient.Token(context.Background(), &uma.TokenRequest{Ticket: ticket})
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tr.AccessToken == "" {
		t.Fatal("Token returned empty access_token")
	}

	// Step 3: client retries RS with the RPT → 200.
	resp := callProtectedResource(t, rsSrv.URL, tr.AccessToken)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("RS with RPT: status = %d, want 200; body=%s", resp.StatusCode, body)
	}
}

func TestE2E_NeedInfoBranch(t *testing.T) {
	as, _, rqpClient, _, rsSrv := startE2E(t)
	// Configure the AS policy to require a pushed ID-token claim on
	// the first /token call, then grant on the retry.
	var policyAttempt int
	as.policyHook = func(_ context.Context, r *uma.TokenRequest, _ *e2eTicket) error {
		policyAttempt++
		if r.ClaimToken == "" {
			return &uma.NeedInfoError{
				OAuthError: uma.OAuthError{ErrorCode: uma.ErrorCodeNeedInfo},
				Ticket:     r.Ticket,
				RequiredClaims: []uma.RequiredClaim{
					{
						ClaimTokenFormat: []uma.ClaimTokenFormat{uma.ClaimTokenFormatIDToken},
						ClaimType:        "urn:oid:1.3.6.1.5.5.7.9.1",
						FriendlyName:     "email",
					},
				},
			}
		}
		return nil
	}

	ticket, _ := readBearerChallenge(t, rsSrv.URL)

	// First /token: need_info.
	_, err := rqpClient.Token(context.Background(), &uma.TokenRequest{Ticket: ticket})
	var ne *uma.NeedInfoError
	if !errors.As(err, &ne) {
		t.Fatalf("first Token err = %T (%v), want *NeedInfoError", err, err)
	}

	// Retry with pushed claim → RPT.
	tr, err := rqpClient.Token(context.Background(), uma.NewPushedClaimsTokenRequest(
		ne.Ticket,
		"fake-id-token",
		uma.ClaimTokenFormatIDToken,
	))
	if err != nil {
		t.Fatalf("retry Token: %v", err)
	}
	if tr.AccessToken == "" {
		t.Fatal("retry Token returned empty access_token")
	}

	resp := callProtectedResource(t, rsSrv.URL, tr.AccessToken)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("RS with RPT after pushed claim: status = %d, want 200", resp.StatusCode)
	}
}

func TestE2E_NotAuthorizedBranch(t *testing.T) {
	as, _, rqpClient, _, rsSrv := startE2E(t)
	as.policyHook = func(context.Context, *uma.TokenRequest, *e2eTicket) error {
		return &uma.OAuthError{
			ErrorCode:        uma.ErrorCodeNotAuthorized,
			ErrorDescription: "policy denied",
		}
	}

	ticket, _ := readBearerChallenge(t, rsSrv.URL)
	_, err := rqpClient.Token(context.Background(), &uma.TokenRequest{Ticket: ticket})
	if err == nil {
		t.Fatal("Token returned nil error; want *OAuthError")
	}
	if !errors.Is(err, uma.ErrNotAuthorized) {
		t.Errorf("errors.Is(err, ErrNotAuthorized) = false; err = %v", err)
	}
}

func TestE2E_InactiveRPTReturnsTo401(t *testing.T) {
	// A client presenting an unknown (or revoked) RPT to the RS
	// triggers introspection, which returns Active=false. The RS
	// MUST treat that as a fresh-ticket-required case — not an
	// authorization decision in either direction.
	_, _, _, _, rsSrv := startE2E(t)
	resp := callProtectedResource(t, rsSrv.URL, "never-issued-rpt")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("RS with invalid RPT: status = %d, want 401", resp.StatusCode)
	}
	if !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "UMA ") {
		t.Errorf("WWW-Authenticate missing UMA prefix: %q", resp.Header.Get("WWW-Authenticate"))
	}
}

func TestE2E_TicketRoundTripsCorrectScopes(t *testing.T) {
	// The ticket the RS receives in step 1 must carry the resource
	// id and scopes the RS asked /permission about. After RPT
	// issuance, /introspection returns the same (resource_id,
	// resource_scopes) tuple to the RS.
	as, _, rqpClient, _, rsSrv := startE2E(t)
	ticket, _ := readBearerChallenge(t, rsSrv.URL)
	as.mu.Lock()
	tkt := as.tickets[ticket]
	as.mu.Unlock()
	if tkt.resourceID != "photoalbum-1" {
		t.Errorf("ticket.resourceID = %q, want photoalbum-1", tkt.resourceID)
	}
	if len(tkt.scopes) != 1 || tkt.scopes[0] != "view" {
		t.Errorf("ticket.scopes = %v, want [view]", tkt.scopes)
	}
	tr, err := rqpClient.Token(context.Background(), &uma.TokenRequest{Ticket: ticket})
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	resp := callProtectedResource(t, rsSrv.URL, tr.AccessToken)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}
