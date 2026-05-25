// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/hstern/go-uma"
	"github.com/hstern/go-uma/server"
)

// newTestASWithOpts is the option-accepting variant of newTestAS in
// as_test.go. Builds an http.Handler over `as` with the given
// HandlerOptions applied and serves it via httptest.NewServer.
func newTestASWithOpts(t *testing.T, as server.AS, opts ...server.HandlerOption) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(server.NewASHandler(as, opts...))
	t.Cleanup(srv.Close)
	return srv
}

func TestWithLogger_FiresOncePerRequest(t *testing.T) {
	var (
		mu     sync.Mutex
		events []server.LogEvent
	)
	logger := func(_ context.Context, e server.LogEvent) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, e)
	}

	as := &recordingAS{tokenOut: &uma.TokenResponse{AccessToken: "rpt", TokenType: "Bearer"}}
	srv := newTestASWithOpts(t, as, server.WithLogger(logger))

	form := url.Values{"grant_type": []string{uma.UMATicketGrantType}, "ticket": []string{"t"}}
	resp := post(t, srv, "/token", "application/x-www-form-urlencoded", form.Encode())
	defer func() { _ = resp.Body.Close() }()

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 1 {
		t.Fatalf("log events = %d, want 1", len(events))
	}
	e := events[0]
	if e.Method != http.MethodPost {
		t.Errorf("Method = %q, want POST", e.Method)
	}
	if e.Path != "/token" {
		t.Errorf("Path = %q, want /token", e.Path)
	}
	if e.Endpoint != "/token" {
		t.Errorf("Endpoint = %q, want /token", e.Endpoint)
	}
	if e.Status != http.StatusOK {
		t.Errorf("Status = %d, want 200", e.Status)
	}
	if e.Duration <= 0 {
		t.Errorf("Duration = %v, want > 0", e.Duration)
	}
}

func TestWithLogger_CapturesErrorStatus(t *testing.T) {
	// Handlers that emit a 4xx via writeError still surface in the
	// log hook.
	var seen server.LogEvent
	as := &recordingAS{tokenErr: &uma.OAuthError{ErrorCode: uma.ErrorCodeNotAuthorized}}
	srv := newTestASWithOpts(t, as, server.WithLogger(func(_ context.Context, e server.LogEvent) {
		seen = e
	}))
	form := url.Values{"grant_type": []string{uma.UMATicketGrantType}, "ticket": []string{"t"}}
	resp := post(t, srv, "/token", "application/x-www-form-urlencoded", form.Encode())
	defer func() { _ = resp.Body.Close() }()
	if seen.Status != http.StatusForbidden {
		t.Errorf("Status = %d, want 403", seen.Status)
	}
}

func TestWithMetrics_FiresOncePerRequest(t *testing.T) {
	type entry struct {
		endpoint string
		status   int
	}
	var (
		mu      sync.Mutex
		entries []entry
	)
	metric := func(_ context.Context, endpoint string, status int) {
		mu.Lock()
		defer mu.Unlock()
		entries = append(entries, entry{endpoint, status})
	}

	as := &recordingAS{
		tokenOut: &uma.TokenResponse{AccessToken: "rpt", TokenType: "Bearer"},
		permOut:  &uma.PermissionResponse{Ticket: "t"},
	}
	srv := newTestASWithOpts(t, as, server.WithMetrics(metric))

	form := url.Values{"grant_type": []string{uma.UMATicketGrantType}, "ticket": []string{"t"}}
	resp1 := post(t, srv, "/token", "application/x-www-form-urlencoded", form.Encode())
	_ = resp1.Body.Close()
	resp2 := post(t, srv, "/permission", "application/json", `{"resource_id":"r","resource_scopes":["v"]}`)
	_ = resp2.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(entries) != 2 {
		t.Fatalf("metric entries = %d, want 2; %v", len(entries), entries)
	}
	wantEntries := []entry{
		{"/token", http.StatusOK},
		{"/permission", http.StatusCreated},
	}
	for i, want := range wantEntries {
		if entries[i] != want {
			t.Errorf("entry %d = %+v, want %+v", i, entries[i], want)
		}
	}
}

func TestWithMetrics_ResourceSetEndpointStable(t *testing.T) {
	// Resource-set CRUD paths vary by id (/resource_set/r1,
	// /resource_set/r2 …) — the endpoint label MUST stay stable at
	// "/resource_set" so metric cardinality doesn't explode.
	var seen string
	metric := func(_ context.Context, endpoint string, _ int) {
		seen = endpoint
	}
	as := &recordingAS{rsOut: &server.ResourceSetResponse{Single: &uma.ResourceSet{ID: "r1", Name: "n", ResourceScopes: []string{"v"}}}}
	srv := newTestASWithOpts(t, as, server.WithMetrics(metric))
	resp := doReq(t, srv, http.MethodGet, "/resource_set/r1", "")
	_ = resp.Body.Close()
	if seen != "/resource_set" {
		t.Errorf("endpoint = %q, want /resource_set (stable across per-id paths)", seen)
	}
}

func TestWithLogger_NilIsNoOp(t *testing.T) {
	// Passing nil to WithLogger leaves the hook unset — the
	// instrument wrapper degrades to a direct call, no allocations
	// for the hook path. A handler still serves the request.
	as := &recordingAS{tokenOut: &uma.TokenResponse{AccessToken: "rpt", TokenType: "Bearer"}}
	srv := newTestASWithOpts(t, as,
		server.WithLogger(nil),
		server.WithMetrics(nil),
	)
	form := url.Values{"grant_type": []string{uma.UMATicketGrantType}, "ticket": []string{"t"}}
	resp := post(t, srv, "/token", "application/x-www-form-urlencoded", form.Encode())
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestWithLogger_DurationIsMeasured(t *testing.T) {
	// The Duration field measures wall-clock time the handler held
	// the request. A handler that artificially sleeps should produce
	// a Duration >= the sleep.
	const minDur = 20 * time.Millisecond
	var seenDur time.Duration
	as := &slowAS{delay: minDur}
	srv := newTestASWithOpts(t, as, server.WithLogger(func(_ context.Context, e server.LogEvent) {
		seenDur = e.Duration
	}))
	form := url.Values{"grant_type": []string{uma.UMATicketGrantType}, "ticket": []string{"t"}}
	resp := post(t, srv, "/token", "application/x-www-form-urlencoded", form.Encode())
	_ = resp.Body.Close()
	if seenDur < minDur {
		t.Errorf("Duration = %v, want >= %v", seenDur, minDur)
	}
}

// slowAS sleeps before returning a TokenResponse so the Duration
// assertion can compare against a known floor.
type slowAS struct {
	server.NotImplementedAS
	delay time.Duration
}

func (s *slowAS) Token(context.Context, *uma.TokenRequest) (*uma.TokenResponse, error) {
	time.Sleep(s.delay)
	return &uma.TokenResponse{AccessToken: "rpt", TokenType: "Bearer"}, nil
}
