// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hstern/go-uma"
	"github.com/hstern/go-uma/server"
)

func TestDecision_String(t *testing.T) {
	tests := []struct {
		d    server.Decision
		want string
	}{
		{server.DecisionUnknown, "unknown"},
		{server.DecisionAllow, "allow"},
		{server.DecisionDeny, "deny"},
	}
	for _, tc := range tests {
		if got := tc.d.String(); got != tc.want {
			t.Errorf("%d.String() = %q, want %q", tc.d, got, tc.want)
		}
	}
	if got := server.Decision(99).String(); got != "Decision(99)" {
		t.Errorf("Decision(99).String() = %q, want Decision(99)", got)
	}
}

func TestDecision_ZeroValueIsUnknown(t *testing.T) {
	// var d server.Decision must be DecisionUnknown, NOT DecisionAllow.
	var d server.Decision
	if d != server.DecisionUnknown {
		t.Errorf("zero value = %v, want DecisionUnknown", d)
	}
}

func TestTicketRequired_Error(t *testing.T) {
	tr := &server.TicketRequired{
		Ticket: "tkt-1",
		ASURL:  "https://as.example.com",
		Realm:  "example",
	}
	got := tr.Error()
	if !strings.Contains(got, "https://as.example.com") {
		t.Errorf("Error() should mention ASURL: %q", got)
	}
	if !strings.Contains(got, "example") {
		t.Errorf("Error() should mention Realm: %q", got)
	}
}

func TestTicketRequired_NilReceiverNoPanic(t *testing.T) {
	var tr *server.TicketRequired
	if got := tr.Error(); got == "" {
		t.Errorf("nil *TicketRequired.Error() = empty string")
	}
}

func TestTicketRequired_ErrorsAs(t *testing.T) {
	// The typed-error contract: a consumer returning *TicketRequired
	// can be matched by errors.As at the call site.
	src := &server.TicketRequired{Ticket: "tkt-1", ASURL: "https://as.example.com"}
	var err error = src
	var got *server.TicketRequired
	if !errors.As(err, &got) {
		t.Fatalf("errors.As(*TicketRequired) failed")
	}
	if got.Ticket != "tkt-1" {
		t.Errorf("Ticket = %q, want tkt-1", got.Ticket)
	}
}

func TestNotImplementedRS(t *testing.T) {
	rs := server.NotImplementedRS{}
	d, err := rs.ProtectedRequest(context.Background(), nil, "r1", []string{"view"})
	if d != server.DecisionUnknown {
		t.Errorf("decision = %v, want DecisionUnknown", d)
	}
	if !errors.Is(err, uma.ErrNotImplemented) {
		t.Errorf("err = %v, want ErrNotImplemented", err)
	}
}

func TestWriteTicketResponse_HeaderAndStatus(t *testing.T) {
	w := httptest.NewRecorder()
	server.WriteTicketResponse(w, "tkt-1", "https://as.example.com", "view edit", "example")
	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	got := resp.Header.Get("WWW-Authenticate")
	want := `UMA realm="example", as_uri="https://as.example.com", ticket="tkt-1", scope="view edit"`
	if got != want {
		t.Errorf("WWW-Authenticate:\n  got:  %s\n  want: %s", got, want)
	}
}

func TestWriteTicketResponse_TicketInHeaderNotBody(t *testing.T) {
	// The load-bearing implementer pin: the ticket lives in the
	// header, NOT the body. The body must be empty.
	w := httptest.NewRecorder()
	server.WriteTicketResponse(w, "tkt-load-bearing", "https://as.example.com", "", "example")
	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()
	body := w.Body.String()
	if strings.Contains(body, "tkt-load-bearing") {
		t.Errorf("ticket leaked into body: %s", body)
	}
	if body != "" {
		t.Errorf("body = %q, want empty", body)
	}
}

func TestWriteTicketRequired_Convenience(t *testing.T) {
	w := httptest.NewRecorder()
	server.WriteTicketRequired(w, &server.TicketRequired{
		Ticket: "tkt-2",
		ASURL:  "https://as.example.com",
		Scopes: "view",
		Realm:  "example",
	})
	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("WWW-Authenticate"), `ticket="tkt-2"`) {
		t.Errorf("header missing ticket: %s", resp.Header.Get("WWW-Authenticate"))
	}
}

func TestWriteTicketRequired_NilWritesEmpty401(t *testing.T) {
	// Defensive: a nil *TicketRequired writes a 401 with no
	// WWW-Authenticate. The result is non-conforming but the safer
	// behavior than panicking — consumer can catch the missing header
	// in their own observability.
	w := httptest.NewRecorder()
	server.WriteTicketRequired(w, nil)
	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if resp.Header.Get("WWW-Authenticate") != "" {
		t.Errorf("WWW-Authenticate should be empty on nil *TicketRequired")
	}
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		wantToken string
		wantOK    bool
	}{
		{"absent", "", "", false},
		{"only scheme", "Bearer", "", false},
		{"empty token", "Bearer ", "", false},
		{"lowercase scheme", "bearer rpt-1", "rpt-1", true},
		{"uppercase scheme", "BEARER rpt-1", "rpt-1", true},
		{"mixed scheme", "BeArEr rpt-1", "rpt-1", true},
		{"normal", "Bearer rpt-abc-def", "rpt-abc-def", true},
		{"other scheme", "Basic dXNlcjpwYXNz", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://x", http.NoBody)
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}
			tok, ok := server.ExtractBearerToken(r)
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v", ok, tc.wantOK)
			}
			if tok != tc.wantToken {
				t.Errorf("token = %q, want %q", tok, tc.wantToken)
			}
		})
	}
}

func TestExtractBearerToken_NilRequest(t *testing.T) {
	tok, ok := server.ExtractBearerToken(nil)
	if ok || tok != "" {
		t.Errorf("nil request = (%q, %v), want (\"\", false)", tok, ok)
	}
}

// stubRS demonstrates a consumer's typical RS implementation shape
// using the public surface: ExtractBearerToken to pull the RPT, then
// branch on whether the token is present and "valid" (this stub
// fakes introspection).
type stubRS struct {
	validRPTs map[string]bool
}

func (s *stubRS) ProtectedRequest(
	_ context.Context, r *http.Request, _ string, _ []string,
) (server.Decision, error) {
	rpt, ok := server.ExtractBearerToken(r)
	if !ok || !s.validRPTs[rpt] {
		return server.DecisionUnknown, &server.TicketRequired{
			Ticket: "fresh-ticket",
			ASURL:  "https://as.example.com",
			Realm:  "example",
		}
	}
	return server.DecisionAllow, nil
}

func TestStubRS_DemonstratesShape(t *testing.T) {
	rs := &stubRS{validRPTs: map[string]bool{"good-rpt": true}}
	// Without a token → TicketRequired error.
	r, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://x", http.NoBody)
	d, err := rs.ProtectedRequest(context.Background(), r, "rsid-1", []string{"view"})
	if d != server.DecisionUnknown {
		t.Errorf("no-token decision = %v, want Unknown", d)
	}
	var tr *server.TicketRequired
	if !errors.As(err, &tr) {
		t.Fatalf("err = %v, want *TicketRequired", err)
	}
	// With a valid token → Allow.
	r2, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://x", http.NoBody)
	r2.Header.Set("Authorization", "Bearer good-rpt")
	d2, err := rs.ProtectedRequest(context.Background(), r2, "rsid-1", []string{"view"})
	if err != nil {
		t.Errorf("valid token err = %v, want nil", err)
	}
	if d2 != server.DecisionAllow {
		t.Errorf("valid-token decision = %v, want Allow", d2)
	}
}
