// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

// Cross-cutting client behavior tests — the matrix coverage that the
// per-file _test.go files don't fully provide. Each method gets the
// same treatment for the load-bearing failure modes: transport-error
// propagation and context-cancellation handling. Failure of any one
// row catches a regression in the shared plumbing
// (endpointURL / authorize / doer.Do wiring) that the per-method
// happy-path tests might miss.

package client_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hstern/go-uma"
	"github.com/hstern/go-uma/client"
)

// methodCall is a thin closure that invokes one Client method against
// a configured Client. Used by the matrix tests below so a single
// table covers every method uniformly.
type methodCall struct {
	name string
	call func(ctx context.Context, c client.Client) error
}

// allMethodCalls returns every Client interface method as a
// (name, closure) pair so the test matrix below stays in lockstep
// with the interface. Each closure constructs a minimally-valid
// argument set — a Token call has a Ticket, a Permission call has a
// ResourceID + ResourceScopes, etc. — and returns the method's error
// (or wraps a (resp, error) return to drop the value).
func allMethodCalls() []methodCall {
	rs := &uma.ResourceSet{Name: "n", ResourceScopes: []string{"v"}}
	return []methodCall{
		{"Token", func(ctx context.Context, c client.Client) error {
			_, err := c.Token(ctx, &uma.TokenRequest{Ticket: "tkt-1"})
			return err
		}},
		{"Permission", func(ctx context.Context, c client.Client) error {
			_, err := c.Permission(ctx, &uma.PermissionRequest{
				ResourceID: "r1", ResourceScopes: []string{"v"},
			})
			return err
		}},
		{"Introspect", func(ctx context.Context, c client.Client) error {
			_, err := c.Introspect(ctx, &uma.IntrospectionRequest{Token: "rpt-1"})
			return err
		}},
		{"CreateResourceSet", func(ctx context.Context, c client.Client) error {
			_, err := c.CreateResourceSet(ctx, rs)
			return err
		}},
		{"ReadResourceSet", func(ctx context.Context, c client.Client) error {
			_, err := c.ReadResourceSet(ctx, "x")
			return err
		}},
		{"UpdateResourceSet", func(ctx context.Context, c client.Client) error {
			_, err := c.UpdateResourceSet(ctx, "x", rs)
			return err
		}},
		{"DeleteResourceSet", func(ctx context.Context, c client.Client) error {
			return c.DeleteResourceSet(ctx, "x")
		}},
		{"ListResourceSets", func(ctx context.Context, c client.Client) error {
			_, err := c.ListResourceSets(ctx)
			return err
		}},
	}
}

func TestFlows_TransportErrorPropagation(t *testing.T) {
	// Every method must wrap and propagate transport-level failures
	// from the underlying HTTPDoer. errors.Is against the inner error
	// recovers the original.
	want := errors.New("dial tcp: simulated")
	c, err := client.NewClient(
		"https://as.example.com",
		client.WithHTTPDoer(failingDoer{err: want}),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	for _, tc := range allMethodCalls() {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.call(context.Background(), c)
			if got == nil {
				t.Fatalf("%s returned nil error, want wrapped transport error", tc.name)
			}
			if !errors.Is(got, want) {
				t.Errorf("%s: errors.Is on transport error = false; got = %v", tc.name, got)
			}
		})
	}
}

// slowHandler responds after a delay long enough that a 50ms context
// deadline expires first. The server still completes the response
// after the delay so its connections close cleanly when the test ends
// — using `<-r.Context().Done()` here would block srv.Close until the
// underlying conn drops, racing the test deadline.
func slowHandler(w http.ResponseWriter, _ *http.Request) {
	time.Sleep(500 * time.Millisecond)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"access_token":"x"}`))
}

func TestFlows_ContextCancelPropagation(t *testing.T) {
	// Every method must honor context cancellation. We start a server
	// that responds slowly (500ms) and give each call a 50ms deadline
	// — the client must return a context error before the server
	// gets a chance to reply.
	srv := httptest.NewServer(http.HandlerFunc(slowHandler))
	defer srv.Close()
	c, err := client.NewClient(srv.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	for _, tc := range allMethodCalls() {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			got := tc.call(ctx, c)
			if got == nil {
				t.Fatalf("%s returned nil error after context expired", tc.name)
			}
			if !errors.Is(got, context.DeadlineExceeded) && !errors.Is(got, context.Canceled) {
				t.Errorf("%s: error not a context cancellation: %v", tc.name, got)
			}
		})
	}
}

func TestFlows_OAuthErrorMatrix(t *testing.T) {
	// Every method that decodes an OAuth error envelope must produce
	// a typed *uma.OAuthError matchable against the sentinels via
	// errors.Is. Test rows pair a method with the AS response we want
	// to surface (status + envelope body) and the sentinel the
	// returned error should match.
	//
	// DeleteResourceSet is omitted from this matrix because its
	// per-file test already covers an OAuth-error path on 404. The
	// other methods have happy-path coverage but lighter error
	// coverage in their own files; this matrix is the one that
	// fails noisily if a future refactor breaks decodeOAuthError
	// for any of them.
	tests := []struct {
		method   string
		status   int
		body     string
		sentinel *uma.OAuthError
		call     func(ctx context.Context, c client.Client) error
	}{
		{
			method:   "Token",
			status:   http.StatusForbidden,
			body:     `{"error":"not_authorized","error_description":"policy"}`,
			sentinel: uma.ErrNotAuthorized,
			call: func(ctx context.Context, c client.Client) error {
				_, err := c.Token(ctx, &uma.TokenRequest{Ticket: "tkt-1"})
				return err
			},
		},
		{
			method:   "Permission",
			status:   http.StatusBadRequest,
			body:     `{"error":"invalid_scope"}`,
			sentinel: uma.ErrInvalidScope,
			call: func(ctx context.Context, c client.Client) error {
				_, err := c.Permission(ctx, &uma.PermissionRequest{
					ResourceID: "r1", ResourceScopes: []string{"v"},
				})
				return err
			},
		},
		{
			method:   "Introspect",
			status:   http.StatusUnauthorized,
			body:     `{"error":"invalid_token"}`,
			sentinel: uma.ErrInvalidToken,
			call: func(ctx context.Context, c client.Client) error {
				_, err := c.Introspect(ctx, &uma.IntrospectionRequest{Token: "rpt-1"})
				return err
			},
		},
		{
			method:   "CreateResourceSet",
			status:   http.StatusBadRequest,
			body:     `{"error":"invalid_scope"}`,
			sentinel: uma.ErrInvalidScope,
			call: func(ctx context.Context, c client.Client) error {
				_, err := c.CreateResourceSet(ctx, &uma.ResourceSet{
					Name: "n", ResourceScopes: []string{"v"},
				})
				return err
			},
		},
		{
			method:   "ReadResourceSet",
			status:   http.StatusUnauthorized,
			body:     `{"error":"invalid_token"}`,
			sentinel: uma.ErrInvalidToken,
			call: func(ctx context.Context, c client.Client) error {
				_, err := c.ReadResourceSet(ctx, "x")
				return err
			},
		},
		{
			method:   "UpdateResourceSet",
			status:   http.StatusBadRequest,
			body:     `{"error":"invalid_scope"}`,
			sentinel: uma.ErrInvalidScope,
			call: func(ctx context.Context, c client.Client) error {
				_, err := c.UpdateResourceSet(ctx, "x", &uma.ResourceSet{
					Name: "n", ResourceScopes: []string{"v"},
				})
				return err
			},
		},
		{
			method:   "ListResourceSets",
			status:   http.StatusUnauthorized,
			body:     `{"error":"invalid_token"}`,
			sentinel: uma.ErrInvalidToken,
			call: func(ctx context.Context, c client.Client) error {
				_, err := c.ListResourceSets(ctx)
				return err
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.method, func(t *testing.T) {
			body := tc.body
			status := tc.status
			c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_, _ = w.Write([]byte(body))
			})
			err := tc.call(context.Background(), c)
			if err == nil {
				t.Fatalf("expected an error matching %s; got nil", tc.sentinel.ErrorCode)
			}
			if !errors.Is(err, tc.sentinel) {
				t.Errorf("errors.Is(err, %s) = false; err = %v", tc.sentinel.ErrorCode, err)
			}
			var oe *uma.OAuthError
			if !errors.As(err, &oe) {
				t.Errorf("errors.As(*OAuthError) failed; err = %T (%v)", err, err)
			}
		})
	}
}

func TestFlows_NetworkErrorWithRealHTTPClient(t *testing.T) {
	// One final belt-and-suspenders check: a Client backed by
	// http.DefaultClient pointed at an unroutable port produces a
	// transport error, not a panic. This is the path consumers see
	// in misconfigured-environment production failures.
	c, err := client.NewClient("http://127.0.0.1:1")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, err = c.Token(ctx, &uma.TokenRequest{Ticket: "tkt-1"})
	if err == nil {
		t.Fatal("Token against unroutable port returned nil error")
	}
}
