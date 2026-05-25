// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

// Claims-gathering interaction tests.
//
// UMA Grant §3.3.6 specifies two complementary styles for collecting
// the claims an AS needs to authorize an RPT issuance:
//
//   1. CLIENT-PUSHED CLAIMS — the AS's first /token response is a
//      403 need_info with required_claims. The requesting-party
//      client acquires a claim token out-of-band (e.g. an OpenID
//      Connect ID token) and retries /token with claim_token +
//      claim_token_format populated. The AS validates the pushed
//      claim, accumulates it into the ticket state, and either
//      mints the RPT or returns another need_info if more claims
//      remain.
//
//   2. AS-PULLED CLAIMS — the AS's need_info includes a
//      redirect_user URL. The requesting-party client redirects
//      its end-user's browser to that URL; the AS interactively
//      gathers claims (e.g. logs the user in, collects consent),
//      upgrades the ticket on its side, and returns the user-agent
//      to a client-supplied resumption URL with the upgraded
//      ticket. The client then retries /token with the new ticket.
//
// The library ships the wire shapes for both — NeedInfoError's
// RequiredClaims and RedirectUser fields, TokenRequest's
// ClaimToken / ClaimTokenFormat, the *NeedInfoError → 403 mapping —
// but does NOT own the browser-side orchestration of style 2. These
// tests demonstrate the wire interactions; the redirect itself is
// out of scope.

package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/hstern/go-uma"
	"github.com/hstern/go-uma/server"
)

// claimsGatheringAS implements both styles of claims-gathering. On a
// first /token call with no claim_token, it returns *NeedInfoError
// requesting an email claim plus a redirect_user URL. On a retry that
// carries a pushed ID token, it grants the RPT. On a retry that
// carries an upgraded ticket (simulating the AS-pulled style), it
// also grants the RPT.
type claimsGatheringAS struct {
	server.NotImplementedAS
	mu          sync.Mutex
	upgradedSet map[string]bool // tickets the AS has upgraded via the pull style
}

func newClaimsAS() *claimsGatheringAS {
	return &claimsGatheringAS{upgradedSet: map[string]bool{}}
}

// upgradeForPullStyle marks a ticket as having received its claims
// via the pulled-claims redirect. The "browser flow" in our tests
// calls this directly to simulate the upgrade the AS would perform
// when its UI completes.
func (a *claimsGatheringAS) upgradeForPullStyle(ticket string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.upgradedSet[ticket] = true
}

func (a *claimsGatheringAS) Token(_ context.Context, r *uma.TokenRequest) (*uma.TokenResponse, error) {
	a.mu.Lock()
	upgraded := a.upgradedSet[r.Ticket]
	a.mu.Unlock()
	switch {
	case r.ClaimToken != "" && r.ClaimTokenFormat == string(uma.ClaimTokenFormatIDToken):
		// Client-pushed claim accepted.
		return &uma.TokenResponse{
			AccessToken: "rpt-pushed",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}, nil
	case upgraded:
		// AS-pulled claims: the ticket was upgraded via the redirect
		// flow before this /token call. Grant.
		return &uma.TokenResponse{
			AccessToken: "rpt-pulled",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}, nil
	default:
		// First call (no claim_token and no AS-side upgrade): return
		// need_info with both the required_claims for style 1 and the
		// redirect_user for style 2. The client picks which path to
		// follow.
		return nil, &uma.NeedInfoError{
			OAuthError: uma.OAuthError{ErrorCode: uma.ErrorCodeNeedInfo},
			Ticket:     r.Ticket + "-upgraded",
			RequiredClaims: []uma.RequiredClaim{
				{
					ClaimTokenFormat: []uma.ClaimTokenFormat{uma.ClaimTokenFormatIDToken},
					ClaimType:        "urn:oid:1.3.6.1.5.5.7.9.1",
					FriendlyName:     "email",
					Issuer:           []string{"https://op.example.com"},
				},
			},
			RedirectUser: "https://as.example.com/uma/claims_redirect?ticket=" + r.Ticket + "-upgraded",
		}
	}
}

func postToken(t *testing.T, srvURL string, form url.Values) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srvURL+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	body, _ := readAllAndClose(t, resp)
	return resp, body
}

func TestClaimsGathering_PushedStyle(t *testing.T) {
	// Style 1: client retries /token with claim_token populated.
	as := newClaimsAS()
	srv := newTestAS(t, as)

	// Step 1: first call with no claims → 403 need_info.
	form := url.Values{
		"grant_type": []string{uma.UMATicketGrantType},
		"ticket":     []string{"tkt-1"},
	}
	resp, body := postToken(t, srv.URL, form)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("first call: status = %d, want 403", resp.StatusCode)
	}
	var ne uma.NeedInfoError
	if err := json.Unmarshal(body, &ne); err != nil {
		t.Fatalf("decode need_info: %v", err)
	}
	if ne.Ticket != "tkt-1-upgraded" {
		t.Errorf("need_info.ticket = %q, want tkt-1-upgraded", ne.Ticket)
	}
	if len(ne.RequiredClaims) != 1 {
		t.Fatalf("required_claims len = %d, want 1", len(ne.RequiredClaims))
	}
	rc := ne.RequiredClaims[0]
	if rc.FriendlyName != "email" {
		t.Errorf("required claim friendly_name = %q, want email", rc.FriendlyName)
	}
	if len(rc.ClaimTokenFormat) != 1 || rc.ClaimTokenFormat[0] != uma.ClaimTokenFormatIDToken {
		t.Errorf("claim_token_format = %v, want [IDToken]", rc.ClaimTokenFormat)
	}

	// Step 2: client retries with the upgraded ticket + a pushed
	// claim token in the requested format. The library's
	// NewPushedClaimsTokenRequest constructor wraps the necessary
	// fields; here we build the form directly to demonstrate the
	// wire shape.
	form2 := url.Values{
		"grant_type":         []string{uma.UMATicketGrantType},
		"ticket":             []string{ne.Ticket},
		"claim_token":        []string{"eyJhbGciOi-fake-id-token"},
		"claim_token_format": []string{string(uma.ClaimTokenFormatIDToken)},
	}
	resp2, body2 := postToken(t, srv.URL, form2)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("second call: status = %d, want 200; body=%s", resp2.StatusCode, body2)
	}
	var tr uma.TokenResponse
	if err := json.Unmarshal(body2, &tr); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if tr.AccessToken != "rpt-pushed" {
		t.Errorf("AccessToken = %q, want rpt-pushed", tr.AccessToken)
	}
}

func TestClaimsGathering_PulledStyle(t *testing.T) {
	// Style 2: client redirects browser to redirect_user; the AS
	// upgrades the ticket; client retries /token with the upgraded
	// ticket. The redirect itself is out of scope for the library;
	// this test simulates the AS-side upgrade via a direct call to
	// upgradeForPullStyle, demonstrating the wire shape on either
	// side of the browser hop.
	as := newClaimsAS()
	srv := newTestAS(t, as)

	// Step 1: first call → 403 need_info with redirect_user.
	form := url.Values{
		"grant_type": []string{uma.UMATicketGrantType},
		"ticket":     []string{"tkt-2"},
	}
	resp, body := postToken(t, srv.URL, form)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("first call: status = %d, want 403", resp.StatusCode)
	}
	var ne uma.NeedInfoError
	if err := json.Unmarshal(body, &ne); err != nil {
		t.Fatalf("decode need_info: %v", err)
	}
	if ne.RedirectUser == "" {
		t.Error("redirect_user empty; expected an AS-hosted URL")
	}
	upgradedTicket := ne.Ticket

	// Step 2 (out-of-scope for the library): the client's browser
	// would visit ne.RedirectUser. The AS interactively gathers
	// whatever claims it needs and marks the ticket upgraded. We
	// short-circuit that browser flow by calling upgradeForPullStyle
	// directly — the library doesn't own this side of the protocol.
	as.upgradeForPullStyle(upgradedTicket)

	// Step 3: client retries /token with the upgraded ticket. No
	// claim_token field — the AS already has what it needs.
	form2 := url.Values{
		"grant_type": []string{uma.UMATicketGrantType},
		"ticket":     []string{upgradedTicket},
	}
	resp2, body2 := postToken(t, srv.URL, form2)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("second call: status = %d, want 200; body=%s", resp2.StatusCode, body2)
	}
	var tr uma.TokenResponse
	if err := json.Unmarshal(body2, &tr); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if tr.AccessToken != "rpt-pulled" {
		t.Errorf("AccessToken = %q, want rpt-pulled", tr.AccessToken)
	}
}

func TestClaimsGathering_NeedInfoFieldsRoundTripExactly(t *testing.T) {
	// Wire-shape invariant: the need_info body the AS emits is the
	// same NeedInfoError shape the client decodes. Defensive against
	// a future change that subtly drops or renames a field.
	as := newClaimsAS()
	srv := newTestAS(t, as)
	form := url.Values{
		"grant_type": []string{uma.UMATicketGrantType},
		"ticket":     []string{"tkt-3"},
	}
	resp, body := postToken(t, srv.URL, form)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	// Decode into a generic map first to assert the JSON keys are
	// exactly what the spec names.
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("decode generic: %v", err)
	}
	for _, k := range []string{"error", "ticket", "required_claims", "redirect_user"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("body missing JSON key %q; body=%s", k, body)
		}
	}
	rc, ok := raw["required_claims"].([]any)
	if !ok || len(rc) != 1 {
		t.Fatalf("required_claims wrong shape or len; body=%s", body)
	}
	entry, ok := rc[0].(map[string]any)
	if !ok {
		t.Fatalf("required_claims[0] not an object; body=%s", body)
	}
	for _, k := range []string{"claim_token_format", "claim_type", "friendly_name", "issuer"} {
		if _, ok := entry[k]; !ok {
			t.Errorf("required_claims[0] missing JSON key %q; body=%s", k, body)
		}
	}
}

func TestClaimsGathering_ConstructorBuildsCorrectForm(t *testing.T) {
	// Demonstrates that uma.NewPushedClaimsTokenRequest builds a
	// TokenRequest whose .Values() carries exactly the fields the
	// AS expects on retry — claim_token and claim_token_format.
	req := uma.NewPushedClaimsTokenRequest(
		"tkt-upgraded",
		"eyJhbGciOi-fake-id-token",
		uma.ClaimTokenFormatIDToken,
	)
	v := req.Values()
	if v.Get("ticket") != "tkt-upgraded" {
		t.Errorf("ticket = %q", v.Get("ticket"))
	}
	if v.Get("claim_token") != "eyJhbGciOi-fake-id-token" {
		t.Errorf("claim_token = %q", v.Get("claim_token"))
	}
	if v.Get("claim_token_format") != string(uma.ClaimTokenFormatIDToken) {
		t.Errorf("claim_token_format = %q", v.Get("claim_token_format"))
	}
	if v.Get("grant_type") != uma.UMATicketGrantType {
		t.Errorf("grant_type = %q", v.Get("grant_type"))
	}
}
