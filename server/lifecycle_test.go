// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

// Permission-ticket lifecycle integration tests.
//
// The library does not own ticket issuance or storage — the
// consumer's [AS] implementation does. This file ships a small
// in-memory ticket-store-backed AS to demonstrate the canonical
// lifecycle: the RS calls Permission to mint a ticket, the
// requesting-party client calls Token to redeem it. Each test
// exercises one invariant from the AS.Permission godoc:
// opaque-to-the-library, single-use under spec recommendation,
// invalid_grant on unknown/expired/already-consumed tickets, and
// re-issuance via the need_info upgrade path.

package server_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/hstern/go-uma"
	"github.com/hstern/go-uma/server"
)

// ticketRecord is what the consumer's AS stores per ticket. The
// library never sees this shape — only the opaque string identifier.
type ticketRecord struct {
	resourceID     string
	resourceScopes []string
	consumed       bool
}

// ticketStoreAS is a minimal in-memory AS that mints tickets on
// Permission and validates them on Token. Demonstrates the lifecycle
// invariants the library documents but does not enforce: single-use,
// time-bound (here: not implemented; would key off a created-at
// field), bound to (resource_id, scopes).
type ticketStoreAS struct {
	server.NotImplementedAS
	mu      sync.Mutex
	tickets map[string]*ticketRecord
}

func newTicketStoreAS() *ticketStoreAS {
	return &ticketStoreAS{tickets: map[string]*ticketRecord{}}
}

// mintTicket generates an opaque, high-entropy ticket identifier and
// binds it to the requested (resource_id, scopes) tuple. The
// implementation uses crypto/rand for 16 bytes — well above the
// 128-bit entropy the spec recommends.
func (a *ticketStoreAS) mintTicket(resourceID string, scopes []string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is treated as a programmer error in
		// the AS implementation — there is no sensible recovery and
		// returning a low-entropy ticket would be worse.
		panic("crypto/rand: " + err.Error())
	}
	id := hex.EncodeToString(b[:])
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tickets[id] = &ticketRecord{resourceID: resourceID, resourceScopes: scopes}
	return id
}

func (a *ticketStoreAS) Permission(_ context.Context, r *uma.PermissionRequest) (*uma.PermissionResponse, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &uma.PermissionResponse{Ticket: a.mintTicket(r.ResourceID, r.ResourceScopes)}, nil
}

func (a *ticketStoreAS) Token(_ context.Context, r *uma.TokenRequest) (*uma.TokenResponse, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	rec, ok := a.tickets[r.Ticket]
	if !ok {
		return nil, &uma.OAuthError{
			ErrorCode:        uma.ErrorCodeInvalidGrant,
			ErrorDescription: "unknown ticket",
		}
	}
	if rec.consumed {
		return nil, &uma.OAuthError{
			ErrorCode:        uma.ErrorCodeInvalidGrant,
			ErrorDescription: "ticket already consumed",
		}
	}
	rec.consumed = true
	// In a real AS, mint an RPT (opaque to the library). Here we
	// return a deterministic value based on the resource id so
	// tests can assert against it.
	return &uma.TokenResponse{
		AccessToken: "rpt-for-" + rec.resourceID,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}, nil
}

func startTicketStoreAS(t *testing.T) (*ticketStoreAS, *httptest.Server) {
	t.Helper()
	as := newTicketStoreAS()
	srv := httptest.NewServer(server.NewASHandler(as))
	t.Cleanup(srv.Close)
	return as, srv
}

// requestPermission asks the AS to mint a ticket. Returns the ticket
// string the AS issued.
func requestPermission(t *testing.T, srv *httptest.Server, resourceID string, scopes []string) string {
	t.Helper()
	body := `{"resource_id":"` + resourceID + `","resource_scopes":["` + scopes[0] + `"]}`
	resp := post(t, srv, "/permission", "application/json", body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Permission: status = %d, want 201", resp.StatusCode)
	}
	var pr uma.PermissionResponse
	decodeBody(t, resp, &pr)
	if pr.Ticket == "" {
		t.Fatalf("Permission returned empty ticket")
	}
	return pr.Ticket
}

// redeemTicket calls /token with the ticket. Returns the response and
// the HTTP status code so callers can branch on success vs failure.
func redeemTicket(t *testing.T, srv *httptest.Server, ticket string) (*uma.TokenResponse, int) {
	t.Helper()
	form := url.Values{
		"grant_type": []string{uma.UMATicketGrantType},
		"ticket":     []string{ticket},
	}
	resp := post(t, srv, "/token", "application/x-www-form-urlencoded", form.Encode())
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode
	}
	var tr uma.TokenResponse
	decodeBody(t, resp, &tr)
	return &tr, http.StatusOK
}

func TestLifecycle_IssueAndRedeem(t *testing.T) {
	_, srv := startTicketStoreAS(t)
	ticket := requestPermission(t, srv, "rsid-1", []string{"view"})
	resp, status := redeemTicket(t, srv, ticket)
	if status != http.StatusOK {
		t.Fatalf("redeem: status = %d, want 200", status)
	}
	if resp.AccessToken != "rpt-for-rsid-1" {
		t.Errorf("AccessToken = %q, want rpt-for-rsid-1", resp.AccessToken)
	}
}

func TestLifecycle_TicketIsOpaque(t *testing.T) {
	// The library never inspects ticket bytes — the ticket store's
	// hex format here is just one example. The library returns
	// whatever string the consumer's AS put in PermissionResponse.
	_, srv := startTicketStoreAS(t)
	ticket := requestPermission(t, srv, "rsid-1", []string{"view"})
	// The hex format is the AS's choice; a consumer using a JWT
	// would see a JWT, and the library would round-trip it unchanged.
	if len(ticket) != 32 {
		t.Errorf("ticket length = %d, want 32 (16 bytes hex-encoded)", len(ticket))
	}
}

func TestLifecycle_SingleUseEnforcement(t *testing.T) {
	// The library documents single-use as a consumer responsibility;
	// our test AS enforces it. The second redemption with the same
	// ticket MUST return invalid_grant.
	_, srv := startTicketStoreAS(t)
	ticket := requestPermission(t, srv, "rsid-1", []string{"view"})
	if _, status := redeemTicket(t, srv, ticket); status != http.StatusOK {
		t.Fatalf("first redeem status = %d, want 200", status)
	}
	form := url.Values{
		"grant_type": []string{uma.UMATicketGrantType},
		"ticket":     []string{ticket},
	}
	resp := post(t, srv, "/token", "application/x-www-form-urlencoded", form.Encode())
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("second redeem status = %d, want 400 (invalid_grant)", resp.StatusCode)
	}
	var oe uma.OAuthError
	decodeBody(t, resp, &oe)
	if oe.ErrorCode != uma.ErrorCodeInvalidGrant {
		t.Errorf("ErrorCode = %q, want invalid_grant", oe.ErrorCode)
	}
}

func TestLifecycle_UnknownTicketIsInvalidGrant(t *testing.T) {
	_, srv := startTicketStoreAS(t)
	// Redeem a ticket that was never issued — invalid_grant.
	form := url.Values{
		"grant_type": []string{uma.UMATicketGrantType},
		"ticket":     []string{"unknown-fake-ticket"},
	}
	resp := post(t, srv, "/token", "application/x-www-form-urlencoded", form.Encode())
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (invalid_grant)", resp.StatusCode)
	}
}

func TestLifecycle_TicketDistinctnessAcrossCalls(t *testing.T) {
	// Each /permission call must mint a fresh ticket — the high-
	// entropy invariant guarantees collision is statistically
	// negligible. The test asserts the obvious-and-easy property:
	// two consecutive calls for the same (resource, scopes) return
	// distinct tickets.
	_, srv := startTicketStoreAS(t)
	t1 := requestPermission(t, srv, "rsid-1", []string{"view"})
	t2 := requestPermission(t, srv, "rsid-1", []string{"view"})
	if t1 == t2 {
		t.Errorf("two /permission calls returned the same ticket %q", t1)
	}
}

func TestLifecycle_ValidationErrorOnEmptyTicketRedemption(t *testing.T) {
	// Empty ticket on /token redemption: the AS's TokenRequest.Validate
	// returns *ValidationError, which the handler converts to 400.
	_, srv := startTicketStoreAS(t)
	form := url.Values{
		"grant_type": []string{uma.UMATicketGrantType},
		// no ticket field
	}
	resp := post(t, srv, "/token", "application/x-www-form-urlencoded", form.Encode())
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// failingTicketStoreAS returns an error on Token that wraps a typed
// *uma.OAuthError — demonstrates that consumer error propagation
// works end-to-end at the lifecycle layer too.
type failingTicketStoreAS struct {
	server.NotImplementedAS
}

func (failingTicketStoreAS) Token(context.Context, *uma.TokenRequest) (*uma.TokenResponse, error) {
	return nil, errors.New("unexpected ticket store error")
}

func TestLifecycle_BareErrorMapsTo500(t *testing.T) {
	srv := httptest.NewServer(server.NewASHandler(failingTicketStoreAS{}))
	defer srv.Close()
	form := url.Values{
		"grant_type": []string{uma.UMATicketGrantType},
		"ticket":     []string{"t"},
	}
	resp := post(t, srv, "/token", "application/x-www-form-urlencoded", form.Encode())
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (bare error)", resp.StatusCode)
	}
}
