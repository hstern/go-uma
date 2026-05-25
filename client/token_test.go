// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hstern/go-uma"
	"github.com/hstern/go-uma/client"
)

// readForm reads an x-www-form-urlencoded request body and returns
// parsed values. Test-only helper.
func readForm(t *testing.T, r *http.Request) url.Values {
	t.Helper()
	if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", got)
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	v, err := url.ParseQuery(string(b))
	if err != nil {
		t.Fatalf("parse body: %v", err)
	}
	return v
}

func newTestClient(t *testing.T, h http.HandlerFunc) (client.Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := client.NewClient(srv.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c, srv
}

func TestToken_Success(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			t.Errorf("path = %q, want /token", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		v := readForm(t, r)
		if v.Get("grant_type") != uma.UMATicketGrantType {
			t.Errorf("grant_type = %q, want %q", v.Get("grant_type"), uma.UMATicketGrantType)
		}
		if v.Get("ticket") != "tkt-1" {
			t.Errorf("ticket = %q, want tkt-1", v.Get("ticket"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{"access_token":"rpt-new","token_type":"Bearer","expires_in":3600}`)
	})
	resp, err := c.Token(context.Background(), &uma.TokenRequest{Ticket: "tkt-1"})
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if resp.AccessToken != "rpt-new" {
		t.Errorf("AccessToken = %q, want rpt-new", resp.AccessToken)
	}
	if resp.ExpiresIn != 3600 {
		t.Errorf("ExpiresIn = %d, want 3600", resp.ExpiresIn)
	}
}

func TestToken_NeedInfo403_TypedError(t *testing.T) {
	// The load-bearing implementer pin: need_info 403 is NOT a
	// transport error. The client returns a typed *NeedInfoError that
	// callers can extract with errors.As and act on (gather claims,
	// redirect, retry the /token call with the fresh ticket).
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprintln(w, `{
			"error":"need_info",
			"ticket":"tkt-2-upgraded",
			"required_claims":[
				{"claim_token_format":["http://openid.net/specs/openid-connect-core-1_0.html#IDToken"],
				 "claim_type":"urn:oid:1.3.6.1.5.5.7.9.1",
				 "friendly_name":"email",
				 "issuer":["https://example.com/op"]}
			],
			"redirect_user":"https://as.example.com/uma/claims_redirect?ticket=tkt-2-upgraded"
		}`)
	})
	resp, err := c.Token(context.Background(), &uma.TokenRequest{Ticket: "tkt-1"})
	if resp != nil {
		t.Errorf("Token returned non-nil response on need_info: %+v", resp)
	}
	if err == nil {
		t.Fatal("Token returned nil error on need_info; want *NeedInfoError")
	}
	var ne *uma.NeedInfoError
	if !errors.As(err, &ne) {
		t.Fatalf("errors.As(*NeedInfoError) on err = %T failed", err)
	}
	if ne.Ticket != "tkt-2-upgraded" {
		t.Errorf("Ticket = %q, want tkt-2-upgraded", ne.Ticket)
	}
	if len(ne.RequiredClaims) != 1 {
		t.Errorf("RequiredClaims len = %d, want 1", len(ne.RequiredClaims))
	}
	if ne.RedirectUser == "" {
		t.Error("RedirectUser empty")
	}
	// errors.Is against the sentinel matches by code.
	if !errors.Is(err, uma.ErrNeedInfo) {
		t.Error("errors.Is(err, ErrNeedInfo) = false, want true")
	}
}

func TestToken_NotAuthorized403_OAuthError(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprintln(w, `{"error":"not_authorized","error_description":"policy denied"}`)
	})
	resp, err := c.Token(context.Background(), &uma.TokenRequest{Ticket: "tkt-1"})
	if resp != nil {
		t.Errorf("Token returned non-nil response on not_authorized: %+v", resp)
	}
	if err == nil {
		t.Fatal("Token returned nil error on not_authorized")
	}
	var oe *uma.OAuthError
	if !errors.As(err, &oe) {
		t.Fatalf("errors.As(*OAuthError) on err = %T failed", err)
	}
	if oe.ErrorCode != uma.ErrorCodeNotAuthorized {
		t.Errorf("ErrorCode = %q, want not_authorized", oe.ErrorCode)
	}
	if !errors.Is(err, uma.ErrNotAuthorized) {
		t.Error("errors.Is(err, ErrNotAuthorized) = false, want true")
	}
}

func TestToken_InvalidGrant400(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintln(w, `{"error":"invalid_grant","error_description":"ticket expired"}`)
	})
	_, err := c.Token(context.Background(), &uma.TokenRequest{Ticket: "tkt-stale"})
	if !errors.Is(err, uma.ErrInvalidGrant) {
		t.Errorf("errors.Is(err, ErrInvalidGrant) = false; want true; err = %v", err)
	}
}

func TestToken_NilRequest(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("server should not be hit for nil request")
	})
	_, err := c.Token(context.Background(), nil)
	if err == nil {
		t.Fatal("Token(nil) = nil error, want non-nil")
	}
}

// failingDoer simulates a transport-level failure.
type failingDoer struct{ err error }

func (f failingDoer) Do(*http.Request) (*http.Response, error) { return nil, f.err }

func TestToken_TransportError(t *testing.T) {
	want := errors.New("dial tcp: simulated")
	c, err := client.NewClient("https://as.example.com", client.WithHTTPDoer(failingDoer{err: want}))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = c.Token(context.Background(), &uma.TokenRequest{Ticket: "tkt-1"})
	if err == nil {
		t.Fatal("Token returned nil error on transport failure")
	}
	if !errors.Is(err, want) {
		t.Errorf("errors.Is on transport error = false; err = %v", err)
	}
}

func TestToken_MalformedJSONIn200(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{ not json`)
	})
	_, err := c.Token(context.Background(), &uma.TokenRequest{Ticket: "tkt-1"})
	if err == nil {
		t.Fatal("Token returned nil error on malformed JSON")
	}
	if !strings.Contains(err.Error(), "decode 200 body") {
		t.Errorf("err should mention decode failure: %v", err)
	}
}

func TestToken_NonOAuthBodyFallsBackToOpaque(t *testing.T) {
	// A non-2xx that isn't a recognizable OAuth envelope (e.g. an
	// HTML error page from a misconfigured reverse proxy) should
	// produce an opaque error rather than a misleading typed one.
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = fmt.Fprintln(w, `<html><body>Bad Gateway</body></html>`)
	})
	_, err := c.Token(context.Background(), &uma.TokenRequest{Ticket: "tkt-1"})
	if err == nil {
		t.Fatal("Token returned nil error on 502 with HTML body")
	}
	var oe *uma.OAuthError
	if errors.As(err, &oe) {
		t.Errorf("err should NOT decode as *OAuthError for an HTML body; got %+v", oe)
	}
	if !strings.Contains(err.Error(), "502") {
		t.Errorf("err should mention the status code: %v", err)
	}
}

func TestToken_ContextCancel(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		// The handler never gets to respond because the client cancels.
		<-r.Context().Done()
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled before the call
	_, err := c.Token(ctx, &uma.TokenRequest{Ticket: "tkt-1"})
	if err == nil {
		t.Fatal("Token with cancelled context returned nil error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("errors.Is(err, context.Canceled) = false; err = %v", err)
	}
}

func TestToken_FormBodyIncludesEveryField(t *testing.T) {
	// Spec-fidelity: every optional field the caller populates lands
	// in the form body with the canonical JSON wire name.
	var captured url.Values
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		captured = readForm(t, r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{"access_token":"x"}`)
	})
	_, err := c.Token(context.Background(), &uma.TokenRequest{
		Ticket:           "tkt-1",
		ClaimToken:       "id.token",
		ClaimTokenFormat: string(uma.ClaimTokenFormatIDToken),
		PCT:              "pct-1",
		RPT:              "rpt-old",
		Scope:            "read write",
	})
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	want := map[string]string{
		"grant_type":         uma.UMATicketGrantType,
		"ticket":             "tkt-1",
		"claim_token":        "id.token",
		"claim_token_format": string(uma.ClaimTokenFormatIDToken),
		"pct":                "pct-1",
		"rpt":                "rpt-old",
		"scope":              "read write",
	}
	for k, v := range want {
		if got := captured.Get(k); got != v {
			t.Errorf("form[%q] = %q, want %q", k, got, v)
		}
	}
}
