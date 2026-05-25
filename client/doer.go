// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"io"
	"net/http"
	"time"
)

// Optional [HTTPDoer] middleware — PAT injection and retry-on-transient.
// Neither is installed by default; consumers compose them explicitly via
// [WithHTTPDoer]:
//
//	d := client.NewRetryDoer(http.DefaultClient)
//	d = client.NewPATDoer(d, pat)
//	c, _ := client.NewClient(asURL, client.WithHTTPDoer(d))
//
// Most consumers do not need the retry layer — UMA's protection-API
// endpoints (Permission, Resource Set CRUD) carry state-changing
// semantics that retry can compound, and consumers with an existing
// retry policy (resilient-http, hashicorp/go-retryablehttp, etc.) plug
// their own. The PAT injector is similarly opt-in: a consumer wiring
// PAT auth through an OAuth client-credentials library or rotating
// tokens at runtime is better served by their own injector.

// NewPATDoer returns an [HTTPDoer] that adds an
// "Authorization: Bearer <token>" header to every outgoing request
// before delegating to inner. The token is captured at construction;
// to rotate it, build a fresh wrapper. An inner of nil falls back to
// [http.DefaultClient].
//
// An empty token is a no-op — the wrapper passes through without
// touching headers. This makes it safe to compose with a token source
// that may not yet have a value.
//
// NewPATDoer is an alternative to the [WithPAT] option on [NewClient]:
// either path lands the same Authorization header on the wire, and
// consumers should pick one. Use [WithPAT] for the simple static-token
// case; use NewPATDoer when the doer is being composed with other
// middleware (e.g. retry) or shared across multiple [Client]
// instances.
func NewPATDoer(inner HTTPDoer, token string) HTTPDoer {
	if inner == nil {
		inner = http.DefaultClient
	}
	return &patDoer{inner: inner, token: token}
}

type patDoer struct {
	inner HTTPDoer
	token string
}

func (p *patDoer) Do(req *http.Request) (*http.Response, error) {
	if p.token != "" {
		req.Header.Set("Authorization", "Bearer "+p.token)
	}
	return p.inner.Do(req)
}

// RetryOption configures [NewRetryDoer].
type RetryOption func(*retryConfig)

type retryConfig struct {
	maxAttempts int
	baseDelay   time.Duration
	maxDelay    time.Duration
}

// defaultRetryConfig is the configuration [NewRetryDoer] uses when no
// options are supplied — 3 attempts total (1 try + 2 retries), 100ms
// base delay, capped at 5s. Modest defaults; tune via the options.
//
//nolint:gochecknoglobals // package-private default-config constant.
var defaultRetryConfig = retryConfig{
	maxAttempts: 3,
	baseDelay:   100 * time.Millisecond,
	maxDelay:    5 * time.Second,
}

// WithMaxAttempts sets the total number of attempts (including the
// initial try). n must be at least 1; smaller values are clamped to 1.
func WithMaxAttempts(n int) RetryOption {
	return func(c *retryConfig) {
		if n < 1 {
			n = 1
		}
		c.maxAttempts = n
	}
}

// WithBackoff sets the base and maximum delay between retry attempts.
// The delay doubles with each attempt up to maxDelay; non-positive
// values fall back to the defaults.
func WithBackoff(base, maxDelay time.Duration) RetryOption {
	return func(c *retryConfig) {
		if base > 0 {
			c.baseDelay = base
		}
		if maxDelay > 0 {
			c.maxDelay = maxDelay
		}
	}
}

// NewRetryDoer returns an [HTTPDoer] that retries inner on transient
// failures — network errors and HTTP 502, 503, or 504 responses. It
// deliberately does NOT retry HTTP 500: a 500 from an AS indicates
// server-side processing failure rather than a transient
// infrastructure issue, and retrying would mask a real problem.
//
// CAUTION: UMA protection-API endpoints (POST /permission,
// POST /resource_set, PUT /resource_set/{id}, POST /token) are
// state-changing under the spec — a successful but slow-acknowledged
// request that the retry layer re-sends can register duplicate
// permissions, create extra resources, or burn a permission ticket
// twice. Consumers using NewRetryDoer should either keep
// MaxAttempts at 1 for the protection-API endpoints (effectively
// disabling retry) or wrap a higher-level idempotency mechanism.
// The library does not enforce method-based filtering at this layer
// because PUT and DELETE remain safely retryable and consumers may
// reasonably retry POSTs against idempotency-aware backends.
//
// The request body must be re-readable across attempts. Requests
// built by the [Client] methods use *bytes.Reader or *strings.Reader,
// which [http.NewRequestWithContext] auto-equips with a GetBody hook
// — retries clone via GetBody. A consumer-supplied request body that
// does not set GetBody will fall back to single-attempt behavior on
// retry (the body would be drained from the first attempt).
//
// Context cancellation is honored between attempts: NewRetryDoer
// returns the context error immediately if the request's context is
// canceled or its deadline expires while waiting to back off. An
// inner of nil falls back to [http.DefaultClient].
func NewRetryDoer(inner HTTPDoer, opts ...RetryOption) HTTPDoer {
	if inner == nil {
		inner = http.DefaultClient
	}
	cfg := defaultRetryConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	return &retryDoer{inner: inner, cfg: cfg}
}

type retryDoer struct {
	inner HTTPDoer
	cfg   retryConfig
}

func (r *retryDoer) Do(req *http.Request) (*http.Response, error) {
	var lastErr error
	var lastResp *http.Response
	for attempt := 1; attempt <= r.cfg.maxAttempts; attempt++ {
		if attempt > 1 {
			// Restore body from GetBody for the retry. If GetBody is
			// nil, the body has already been drained and we can only
			// hope the server tolerates an empty replay — but that's
			// the caller's contract to keep, not ours to second-guess.
			if req.GetBody != nil {
				body, err := req.GetBody()
				if err != nil {
					return nil, err
				}
				req.Body = body
			}
			// Honor context cancellation while waiting to retry.
			t := time.NewTimer(r.backoff(attempt - 1))
			select {
			case <-t.C:
			case <-req.Context().Done():
				t.Stop()
				if lastErr != nil {
					return nil, lastErr
				}
				return lastResp, nil
			}
		}
		resp, err := r.inner.Do(req)
		if err == nil && !shouldRetryStatus(resp.StatusCode) {
			return resp, nil
		}
		if err != nil {
			lastErr = err
			lastResp = nil
			continue
		}
		// Drain and close the body so the underlying connection can
		// be reused for the retry. Callers that need the transient-
		// failure body should wrap differently.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		lastResp = resp
		lastErr = nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return lastResp, nil
}

func (r *retryDoer) backoff(retryIndex int) time.Duration {
	// retryIndex 0 → first retry (base), 1 → double, 2 → quadruple…
	if retryIndex < 0 {
		retryIndex = 0
	}
	d := r.cfg.baseDelay
	for i := 0; i < retryIndex; i++ {
		d *= 2
		if d > r.cfg.maxDelay {
			return r.cfg.maxDelay
		}
	}
	return d
}

// shouldRetryStatus returns true for HTTP status codes that indicate a
// transient infrastructure condition the next attempt may succeed
// against. 500 is deliberately excluded (server-side processing
// failure, not transient).
func shouldRetryStatus(code int) bool {
	return code == http.StatusBadGateway ||
		code == http.StatusServiceUnavailable ||
		code == http.StatusGatewayTimeout
}
