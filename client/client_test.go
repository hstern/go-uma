// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/hstern/go-uma"
	"github.com/hstern/go-uma/client"
)

func TestNewClient_OK(t *testing.T) {
	c, err := client.NewClient("https://as.example.com")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c == nil {
		t.Fatal("NewClient returned nil Client with nil error")
	}
	base := c.BaseURL()
	if base.Scheme != "https" || base.Host != "as.example.com" {
		t.Errorf("BaseURL = %s, want https://as.example.com", base.String())
	}
}

func TestNewClient_RejectsRelativeAndEmpty(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"relative path", "/uma"},
		{"scheme only", "https://"},
		{"host only", "//as.example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.NewClient(tc.in)
			if err == nil {
				t.Errorf("NewClient(%q) = nil error, want rejection", tc.in)
			}
		})
	}
}

func TestNewClient_RejectsMalformedURL(t *testing.T) {
	_, err := client.NewClient("://not a url")
	if err == nil {
		t.Errorf("NewClient with malformed URL = nil error, want a wrapped parse error")
	}
}

func TestNewClient_AcceptsHTTPForTesting(t *testing.T) {
	// Production deployments use HTTPS, but the library does not
	// enforce TLS here so 127.0.0.1 test setups work.
	c, err := client.NewClient("http://127.0.0.1:8080")
	if err != nil {
		t.Fatalf("NewClient(http://127.0.0.1...): %v", err)
	}
	if c.BaseURL().Scheme != "http" {
		t.Errorf("scheme = %q, want http", c.BaseURL().Scheme)
	}
}

// recordingDoer captures every request that flows through it so tests
// can assert the Client wired the doer correctly.
type recordingDoer struct {
	requests []*http.Request
	resp     *http.Response
	err      error
}

func (d *recordingDoer) Do(req *http.Request) (*http.Response, error) {
	d.requests = append(d.requests, req)
	return d.resp, d.err
}

func TestWithHTTPDoer_Smoke(t *testing.T) {
	// The Client's doer is exercised by per-endpoint methods landing
	// in follow-up commits. Here we assert the option installs without
	// error in both the populated and nil-reset paths.
	d := &recordingDoer{}
	if _, err := client.NewClient("https://as.example.com", client.WithHTTPDoer(d)); err != nil {
		t.Errorf("NewClient with WithHTTPDoer(recordingDoer): %v", err)
	}
	if _, err := client.NewClient("https://as.example.com", client.WithHTTPDoer(nil)); err != nil {
		t.Errorf("NewClient with WithHTTPDoer(nil): %v", err)
	}
}

func TestWithPAT(t *testing.T) {
	// WithPAT is wired by every protection-API method. Here we just
	// confirm the option does not panic and accepts both populated
	// and empty strings.
	tests := []struct {
		name  string
		token string
	}{
		{"populated", "pat-abc"},
		{"empty disables", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.NewClient(
				"https://as.example.com",
				client.WithPAT(tc.token),
			)
			if err != nil {
				t.Errorf("NewClient with WithPAT(%q): %v", tc.token, err)
			}
		})
	}
}

func TestWithMetadataTTL(t *testing.T) {
	// WithMetadataTTL is consulted by FetchMetadata in a later phase.
	// Smoke test: it does not panic on positive, zero, or negative
	// values.
	tests := []struct {
		name string
		d    time.Duration
	}{
		{"positive", 5 * time.Minute},
		{"zero disables", 0},
		{"negative disables", -1 * time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.NewClient(
				"https://as.example.com",
				client.WithMetadataTTL(tc.d),
			)
			if err != nil {
				t.Errorf("NewClient with WithMetadataTTL(%v): %v", tc.d, err)
			}
		})
	}
}

func TestNewClient_DefaultsApply(t *testing.T) {
	// A Client constructed with no options uses sensible defaults —
	// the http.DefaultClient transport and a one-hour metadata TTL.
	// The defaults are not directly observable through the exported
	// surface; the assertion is that the Client constructs without
	// error.
	if _, err := client.NewClient("https://as.example.com"); err != nil {
		t.Errorf("NewClient with no options: %v", err)
	}
}

func TestNewClient_OptionsOrderIndependent(t *testing.T) {
	// Options are commutative — applying the same set in either order
	// produces an equivalent Client. The test checks via two
	// constructions returning successfully; per-endpoint tests cover
	// observable behavior.
	d := &recordingDoer{}
	_, err1 := client.NewClient(
		"https://as.example.com",
		client.WithPAT("pat-1"),
		client.WithHTTPDoer(d),
		client.WithMetadataTTL(2*time.Hour),
	)
	_, err2 := client.NewClient(
		"https://as.example.com",
		client.WithMetadataTTL(2*time.Hour),
		client.WithHTTPDoer(d),
		client.WithPAT("pat-1"),
	)
	if err1 != nil || err2 != nil {
		t.Errorf("option ordering should not affect construction: %v / %v", err1, err2)
	}
}

// stubClient is the kind of test double consumers can write against
// the [Client] interface. The test below exercises it as a sanity
// check that the interface contract is genuinely substitutable.
type stubClient struct {
	base url.URL
}

func (s stubClient) BaseURL() url.URL { return s.base }

func (s stubClient) Token(context.Context, *uma.TokenRequest) (*uma.TokenResponse, error) {
	return nil, errors.New("stubClient: Token not implemented")
}

func (s stubClient) Permission(context.Context, *uma.PermissionRequest) (*uma.PermissionResponse, error) {
	return nil, errors.New("stubClient: Permission not implemented")
}

func (s stubClient) Introspect(context.Context, *uma.IntrospectionRequest) (*uma.IntrospectionResponse, error) {
	return nil, errors.New("stubClient: Introspect not implemented")
}

func TestClient_InterfaceIsSubstitutable(t *testing.T) {
	want := url.URL{Scheme: "https", Host: "stub.example.com"}
	var c client.Client = stubClient{base: want}
	if got := c.BaseURL(); got != want {
		t.Errorf("stub.BaseURL() = %v, want %v", got, want)
	}
}
