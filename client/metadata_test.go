// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hstern/go-uma"
	"github.com/hstern/go-uma/client"
)

// metaResponse writes a JSON metadata response with the given Issuer
// and Cache-Control header. fakeAS-style helper.
func metaResponse(w http.ResponseWriter, issuer, cacheControl string) {
	if cacheControl != "" {
		w.Header().Set("Cache-Control", cacheControl)
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{
		"issuer":%q,
		"token_endpoint":"%s/token",
		"introspection_endpoint":"%s/introspection",
		"permission_endpoint":"%s/permission",
		"resource_registration_endpoint":"%s/resource_set"
	}`, issuer, issuer, issuer, issuer, issuer)
}

func TestFetchMetadata_HappyPath(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != uma.MetadataPath {
			t.Errorf("path = %q, want %q", r.URL.Path, uma.MetadataPath)
		}
		// Use the test server's URL as the Issuer so mix-up
		// validation passes.
		metaResponse(w, "http://"+r.Host, "")
	}))
	defer srv.Close()
	c, err := client.NewClient(srv.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	m, err := c.FetchMetadata(context.Background())
	if err != nil {
		t.Fatalf("FetchMetadata: %v", err)
	}
	if m.Issuer != srv.URL {
		t.Errorf("Issuer = %q, want %q", m.Issuer, srv.URL)
	}
	if m.TokenEndpoint != srv.URL+"/token" {
		t.Errorf("TokenEndpoint = %q", m.TokenEndpoint)
	}
	if calls.Load() != 1 {
		t.Errorf("server hits = %d, want 1", calls.Load())
	}
}

func TestFetchMetadata_MixUpDefaultHardFail(t *testing.T) {
	// Server returns a document with the WRONG issuer — the client
	// MUST hard-fail with *MixUpError and MUST NOT cache.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		metaResponse(w, "https://attacker.example.com", "")
	}))
	defer srv.Close()
	c, err := client.NewClient(srv.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = c.FetchMetadata(context.Background())
	if err == nil {
		t.Fatal("FetchMetadata returned nil error on issuer mismatch")
	}
	var me *client.MixUpError
	if !errors.As(err, &me) {
		t.Fatalf("err = %T (%v), want *MixUpError", err, err)
	}
	if me.Configured != srv.URL {
		t.Errorf("Configured = %q, want %q", me.Configured, srv.URL)
	}
	if me.Issuer != "https://attacker.example.com" {
		t.Errorf("Issuer = %q, want https://attacker.example.com", me.Issuer)
	}
	if !client.IsMixUpError(err) {
		t.Errorf("IsMixUpError = false, want true")
	}
}

func TestFetchMetadata_MixUpNotCached(t *testing.T) {
	// A mix-up response MUST NOT populate the cache — a subsequent
	// FetchMetadata call must re-fetch and see the same error.
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		metaResponse(w, "https://attacker.example.com", "")
	}))
	defer srv.Close()
	c, _ := client.NewClient(srv.URL)
	_, _ = c.FetchMetadata(context.Background())
	_, _ = c.FetchMetadata(context.Background())
	if calls.Load() != 2 {
		t.Errorf("server hits = %d, want 2 (mix-up should not cache)", calls.Load())
	}
}

func TestFetchMetadata_RelaxedOptOut(t *testing.T) {
	// WithRelaxedMetadataValidation skips the issuer check —
	// useful only when a TLS terminator or path rewriter
	// legitimately produces a different configured URL.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		metaResponse(w, "https://internal.example.com", "")
	}))
	defer srv.Close()
	c, err := client.NewClient(srv.URL, client.WithRelaxedMetadataValidation())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	m, err := c.FetchMetadata(context.Background())
	if err != nil {
		t.Fatalf("relaxed FetchMetadata: %v", err)
	}
	if m.Issuer != "https://internal.example.com" {
		t.Errorf("Issuer = %q", m.Issuer)
	}
}

func TestFetchMetadata_CacheHonorsMaxAge(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		metaResponse(w, "http://"+r.Host, "max-age=60")
	}))
	defer srv.Close()
	c, _ := client.NewClient(srv.URL)
	for i := 0; i < 3; i++ {
		if _, err := c.FetchMetadata(context.Background()); err != nil {
			t.Fatalf("iter %d FetchMetadata: %v", i, err)
		}
	}
	if calls.Load() != 1 {
		t.Errorf("server hits = %d, want 1 (max-age caches)", calls.Load())
	}
}

func TestFetchMetadata_CacheUsesFallbackTTL(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		metaResponse(w, "http://"+r.Host, "") // no Cache-Control
	}))
	defer srv.Close()
	c, _ := client.NewClient(srv.URL, client.WithMetadataTTL(time.Hour))
	for i := 0; i < 3; i++ {
		if _, err := c.FetchMetadata(context.Background()); err != nil {
			t.Fatalf("iter %d FetchMetadata: %v", i, err)
		}
	}
	if calls.Load() != 1 {
		t.Errorf("server hits = %d, want 1 (fallback TTL caches)", calls.Load())
	}
}

func TestFetchMetadata_CacheDisabledByZeroTTL(t *testing.T) {
	// A non-positive WithMetadataTTL value disables caching when the
	// response also has no max-age — every call hits the server.
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		metaResponse(w, "http://"+r.Host, "")
	}))
	defer srv.Close()
	c, _ := client.NewClient(srv.URL, client.WithMetadataTTL(0))
	for i := 0; i < 3; i++ {
		if _, err := c.FetchMetadata(context.Background()); err != nil {
			t.Fatalf("iter %d FetchMetadata: %v", i, err)
		}
	}
	if calls.Load() != 3 {
		t.Errorf("server hits = %d, want 3 (TTL=0 disables caching)", calls.Load())
	}
}

func TestFetchMetadata_MaxAgeOverridesFallback(t *testing.T) {
	// Cache-Control: max-age=0 disables caching even when the
	// configured fallback is non-zero. Spec-defined precedence.
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		metaResponse(w, "http://"+r.Host, "max-age=0")
	}))
	defer srv.Close()
	c, _ := client.NewClient(srv.URL, client.WithMetadataTTL(time.Hour))
	for i := 0; i < 2; i++ {
		if _, err := c.FetchMetadata(context.Background()); err != nil {
			t.Fatalf("iter %d FetchMetadata: %v", i, err)
		}
	}
	if calls.Load() != 2 {
		t.Errorf("server hits = %d, want 2 (max-age=0 overrides fallback)", calls.Load())
	}
}

func TestFetchMetadata_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not_found"}`))
	}))
	defer srv.Close()
	c, _ := client.NewClient(srv.URL)
	_, err := c.FetchMetadata(context.Background())
	if err == nil {
		t.Fatal("FetchMetadata returned nil error on 404")
	}
}

func TestFetchMetadata_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not json`))
	}))
	defer srv.Close()
	c, _ := client.NewClient(srv.URL)
	_, err := c.FetchMetadata(context.Background())
	if err == nil {
		t.Fatal("FetchMetadata returned nil error on malformed JSON")
	}
}

func TestFetchMetadata_TrailingSlashNormalized(t *testing.T) {
	// Issuer "http://srv.url/" and configured "http://srv.url" must
	// be treated as equivalent (trailing-slash normalization).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metaResponse(w, "http://"+r.Host+"/", "")
	}))
	defer srv.Close()
	c, _ := client.NewClient(srv.URL) // srv.URL has no trailing slash
	if _, err := c.FetchMetadata(context.Background()); err != nil {
		t.Errorf("FetchMetadata: %v", err)
	}
}

func TestFetchMetadata_TransportError(t *testing.T) {
	want := errors.New("dial tcp: simulated")
	c, err := client.NewClient("https://as.example.com",
		client.WithHTTPDoer(failingDoer{err: want}))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = c.FetchMetadata(context.Background())
	if !errors.Is(err, want) {
		t.Errorf("errors.Is on transport error = false; err = %v", err)
	}
}

func TestMixUpError_NilReceiverNoPanic(t *testing.T) {
	var e *client.MixUpError
	if got := e.Error(); got == "" {
		t.Errorf("nil *MixUpError.Error() = empty string")
	}
}

func TestMixUpError_String(t *testing.T) {
	e := &client.MixUpError{
		Configured: "https://configured.example.com",
		Issuer:     "https://issuer.example.com",
	}
	got := e.Error()
	if !strings.Contains(got, "configured.example.com") {
		t.Errorf("Error() should mention Configured: %q", got)
	}
	if !strings.Contains(got, "issuer.example.com") {
		t.Errorf("Error() should mention Issuer: %q", got)
	}
}
