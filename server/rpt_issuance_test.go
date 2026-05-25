// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

// RPT-issuance-flow demonstration tests.
//
// The AS's Token method (Grant §3.3) implements a six-row outcome
// matrix when invoked under the UMA-ticket grant. The library does
// not enforce the policy logic — that is the consumer's choice — but
// it does map every recognized outcome to the correct wire response.
// This file exercises each outcome via the public AS interface +
// NewASHandler and asserts the wire response shape.
//
// The matrix:
//
//   Outcome                          | AS return                                | HTTP
//   ---------------------------------+------------------------------------------+-----
//   Approved → RPT issued            | (*TokenResponse, nil)                    | 200
//   Insufficient claims              | (nil, *uma.NeedInfoError)                | 403 + need_info
//   Policy-deny                      | (nil, *OAuthError{not_authorized})       | 403
//   Queued for RO action             | (nil, *OAuthError{request_submitted})    | 403
//   Unknown / expired ticket         | (nil, *OAuthError{invalid_grant})        | 400
//   Missing ticket / required field  | (nil, *ValidationError)                  | 400

package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/hstern/go-uma"
	"github.com/hstern/go-uma/server"
)

// scriptedAS is an AS whose Token method returns a pre-configured
// (response, error) pair. Useful for exercising the wire mapping of
// each outcome without needing a real policy engine.
type scriptedAS struct {
	server.NotImplementedAS
	tokenResp *uma.TokenResponse
	tokenErr  error
}

func (s *scriptedAS) Token(context.Context, *uma.TokenRequest) (*uma.TokenResponse, error) {
	return s.tokenResp, s.tokenErr
}

func redeemUMATicket(t *testing.T, srv interface{ Close() }, baseURL, ticket string) (*http.Response, []byte) {
	t.Helper()
	form := url.Values{
		"grant_type": []string{uma.UMATicketGrantType},
		"ticket":     []string{ticket},
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		baseURL+"/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	body, _ := readAllAndClose(t, resp)
	return resp, body
}

func TestRPTIssuance_Approved(t *testing.T) {
	// Outcome 1: AS returns *TokenResponse with no error → 200 + the
	// RPT in the access_token field. The library does not constrain
	// the RPT format (Grant §3.3.5 leaves it to the AS).
	as := &scriptedAS{tokenResp: &uma.TokenResponse{
		AccessToken: "opaque-rpt-deadbeef",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}}
	srv := newTestAS(t, as)
	resp, body := redeemUMATicket(t, srv, srv.URL, "tkt-1")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	var tr uma.TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if tr.AccessToken != "opaque-rpt-deadbeef" {
		t.Errorf("AccessToken = %q, want opaque-rpt-deadbeef", tr.AccessToken)
	}
	if tr.ExpiresIn != 3600 {
		t.Errorf("ExpiresIn = %d, want 3600", tr.ExpiresIn)
	}
}

func TestRPTIssuance_NeedInfo(t *testing.T) {
	// Outcome 2: AS returns *NeedInfoError → 403 with the typed
	// need_info envelope carrying ticket + required_claims +
	// optional redirect_user.
	as := &scriptedAS{tokenErr: &uma.NeedInfoError{
		OAuthError: uma.OAuthError{ErrorCode: uma.ErrorCodeNeedInfo},
		Ticket:     "tkt-upgraded",
		RequiredClaims: []uma.RequiredClaim{
			{
				ClaimTokenFormat: []uma.ClaimTokenFormat{uma.ClaimTokenFormatIDToken},
				ClaimType:        "urn:oid:1.3.6.1.5.5.7.9.1",
				FriendlyName:     "email",
				Issuer:           []string{"https://op.example.com"},
			},
		},
		RedirectUser: "https://as.example.com/claims_redirect?ticket=tkt-upgraded",
	}}
	srv := newTestAS(t, as)
	resp, body := redeemUMATicket(t, srv, srv.URL, "tkt-1")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", resp.StatusCode, body)
	}
	var ne uma.NeedInfoError
	if err := json.Unmarshal(body, &ne); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ne.ErrorCode != uma.ErrorCodeNeedInfo {
		t.Errorf("ErrorCode = %q, want need_info", ne.ErrorCode)
	}
	if ne.Ticket != "tkt-upgraded" {
		t.Errorf("Ticket = %q, want tkt-upgraded", ne.Ticket)
	}
	if len(ne.RequiredClaims) != 1 {
		t.Errorf("RequiredClaims len = %d, want 1", len(ne.RequiredClaims))
	}
	if ne.RedirectUser == "" {
		t.Error("RedirectUser empty")
	}
}

func TestRPTIssuance_NotAuthorized(t *testing.T) {
	// Outcome 3: policy deny → 403 with not_authorized.
	as := &scriptedAS{tokenErr: &uma.OAuthError{
		ErrorCode:        uma.ErrorCodeNotAuthorized,
		ErrorDescription: "policy denied",
	}}
	srv := newTestAS(t, as)
	resp, body := redeemUMATicket(t, srv, srv.URL, "tkt-1")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	var oe uma.OAuthError
	if err := json.Unmarshal(body, &oe); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oe.ErrorCode != uma.ErrorCodeNotAuthorized {
		t.Errorf("ErrorCode = %q, want not_authorized", oe.ErrorCode)
	}
}

func TestRPTIssuance_RequestSubmitted(t *testing.T) {
	// Outcome 4: queued for resource-owner action → 403 with
	// request_submitted. The client retries later; the library does
	// not implement polling.
	as := &scriptedAS{tokenErr: &uma.OAuthError{
		ErrorCode:        uma.ErrorCodeRequestSubmitted,
		ErrorDescription: "awaiting owner approval",
	}}
	srv := newTestAS(t, as)
	resp, body := redeemUMATicket(t, srv, srv.URL, "tkt-1")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	var oe uma.OAuthError
	if err := json.Unmarshal(body, &oe); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oe.ErrorCode != uma.ErrorCodeRequestSubmitted {
		t.Errorf("ErrorCode = %q, want request_submitted", oe.ErrorCode)
	}
}

func TestRPTIssuance_InvalidGrant(t *testing.T) {
	// Outcome 5: unknown / expired / revoked ticket → 400 with
	// invalid_grant (RFC 6749 §5.2).
	as := &scriptedAS{tokenErr: &uma.OAuthError{
		ErrorCode:        uma.ErrorCodeInvalidGrant,
		ErrorDescription: "ticket expired",
	}}
	srv := newTestAS(t, as)
	resp, body := redeemUMATicket(t, srv, srv.URL, "tkt-1")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	var oe uma.OAuthError
	if err := json.Unmarshal(body, &oe); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oe.ErrorCode != uma.ErrorCodeInvalidGrant {
		t.Errorf("ErrorCode = %q, want invalid_grant", oe.ErrorCode)
	}
}

func TestRPTIssuance_ValidationError(t *testing.T) {
	// Outcome 6: missing required field in the TokenRequest. The AS's
	// Validate call surfaces *uma.ValidationError, which the library
	// maps to 400.
	as := &scriptedAS{tokenErr: &uma.ValidationError{
		Type: "TokenRequest", Field: "ticket", Message: "required",
	}}
	srv := newTestAS(t, as)
	resp, body := redeemUMATicket(t, srv, srv.URL, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", resp.StatusCode, body)
	}
}

func TestRPTIssuance_GrantTypeIsLoadBearing(t *testing.T) {
	// The AS handler's ParseTokenRequest accepts any form body —
	// grant_type is not enforced at the handler boundary because the
	// /token endpoint can multiplex other OAuth grants too. A real AS
	// MUST check grant_type itself and return invalid_grant on
	// non-uma-ticket values. The test asserts the wire path: a
	// scripted AS that returns invalid_grant produces the expected
	// 400 even when grant_type was wrong from the client.
	as := &scriptedAS{tokenErr: &uma.OAuthError{
		ErrorCode:        uma.ErrorCodeInvalidGrant,
		ErrorDescription: "unsupported grant_type",
	}}
	srv := newTestAS(t, as)
	form := url.Values{
		"grant_type": []string{"password"},
		"ticket":     []string{"tkt-1"},
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// readAllAndClose reads the full response body and closes it. Returns
// the body bytes and a possibly-nil error.
func readAllAndClose(t *testing.T, resp *http.Response) ([]byte, error) {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			b.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	return []byte(b.String()), nil
}
