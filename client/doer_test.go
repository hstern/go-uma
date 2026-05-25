// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hstern/go-uma/client"
)

// countingDoer records every Do invocation. Returns the configured
// response/error.
type countingDoer struct {
	calls atomic.Int64
	resp  *http.Response
	err   error
}

func (d *countingDoer) Do(*http.Request) (*http.Response, error) {
	d.calls.Add(1)
	return d.resp, d.err
}

// sequenceDoer returns each (resp, err) pair from results in order;
// once exhausted, returns the final entry.
type sequenceDoer struct {
	idx     atomic.Int64
	results []struct {
		resp *http.Response
		err  error
	}
}

func (d *sequenceDoer) Do(*http.Request) (*http.Response, error) {
	i := int(d.idx.Add(1) - 1)
	if i >= len(d.results) {
		i = len(d.results) - 1
	}
	return d.results[i].resp, d.results[i].err
}

func okResp() *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       http.NoBody,
		Header:     http.Header{},
	}
}

func transientResp(code int) *http.Response {
	return &http.Response{
		StatusCode: code,
		Body:       http.NoBody,
		Header:     http.Header{},
	}
}

func TestNewPATDoer_SetsBearerHeader(t *testing.T) {
	var captured string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	})
	doer := client.NewPATDoer(httpHandlerToDoer(inner), "pat-abc")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://x", http.NoBody)
	resp, err := doer.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if captured != "Bearer pat-abc" {
		t.Errorf("Authorization = %q, want Bearer pat-abc", captured)
	}
}

func TestNewPATDoer_EmptyTokenNoOp(t *testing.T) {
	var captured string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	})
	doer := client.NewPATDoer(httpHandlerToDoer(inner), "")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://x", http.NoBody)
	resp, err := doer.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if captured != "" {
		t.Errorf("Authorization = %q, want empty (no-op)", captured)
	}
}

func TestNewPATDoer_NilInnerFallsBack(t *testing.T) {
	doer := client.NewPATDoer(nil, "pat-abc")
	if doer == nil {
		t.Fatal("NewPATDoer(nil, ...) returned nil")
	}
}

func TestNewRetryDoer_NoRetryOn200(t *testing.T) {
	c := &countingDoer{resp: okResp()}
	d := client.NewRetryDoer(c)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://x", http.NoBody)
	resp, err := d.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := c.calls.Load(); got != 1 {
		t.Errorf("inner.Do called %d times, want 1", got)
	}
}

func TestNewRetryDoer_RetriesOn503ThenSucceeds(t *testing.T) {
	d := client.NewRetryDoer(
		&sequenceDoer{results: []struct {
			resp *http.Response
			err  error
		}{
			{resp: transientResp(http.StatusServiceUnavailable)},
			{resp: transientResp(http.StatusBadGateway)},
			{resp: okResp()},
		}},
		client.WithMaxAttempts(3),
		client.WithBackoff(time.Microsecond, time.Microsecond),
	)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://x", http.NoBody)
	resp, err := d.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
}

func TestNewRetryDoer_DoesNotRetry500(t *testing.T) {
	// 500 is server-side processing failure, not transient — retrying
	// would mask a real problem.
	c := &countingDoer{resp: transientResp(http.StatusInternalServerError)}
	d := client.NewRetryDoer(c, client.WithMaxAttempts(5), client.WithBackoff(time.Microsecond, time.Microsecond))
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://x", http.NoBody)
	resp, err := d.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := c.calls.Load(); got != 1 {
		t.Errorf("inner.Do called %d times on 500, want 1 (no retry)", got)
	}
}

func TestNewRetryDoer_GivesUpAfterMaxAttempts(t *testing.T) {
	c := &countingDoer{resp: transientResp(http.StatusServiceUnavailable)}
	d := client.NewRetryDoer(c,
		client.WithMaxAttempts(3),
		client.WithBackoff(time.Microsecond, time.Microsecond),
	)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://x", http.NoBody)
	resp, err := d.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := c.calls.Load(); got != 3 {
		t.Errorf("inner.Do called %d times, want exactly 3", got)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("final status = %d, want 503", resp.StatusCode)
	}
}

func TestNewRetryDoer_RetriesOnTransportErrorThenSucceeds(t *testing.T) {
	d := client.NewRetryDoer(
		&sequenceDoer{results: []struct {
			resp *http.Response
			err  error
		}{
			{err: errors.New("dial tcp: simulated")},
			{resp: okResp()},
		}},
		client.WithMaxAttempts(2),
		client.WithBackoff(time.Microsecond, time.Microsecond),
	)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://x", http.NoBody)
	resp, err := d.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
}

func TestWithMaxAttempts_ClampsToOne(t *testing.T) {
	// A zero or negative MaxAttempts setting clamps to 1 — the
	// guarantee is that the inner doer runs at least once.
	c := &countingDoer{resp: transientResp(http.StatusServiceUnavailable)}
	d := client.NewRetryDoer(c, client.WithMaxAttempts(0))
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://x", http.NoBody)
	resp, err := d.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := c.calls.Load(); got != 1 {
		t.Errorf("inner.Do called %d times, want 1 (MaxAttempts clamps to 1)", got)
	}
}

func TestNewRetryDoer_ContextCancelDuringBackoff(t *testing.T) {
	c := &countingDoer{resp: transientResp(http.StatusServiceUnavailable)}
	d := client.NewRetryDoer(c,
		client.WithMaxAttempts(5),
		client.WithBackoff(time.Second, time.Second), // long enough to be cancelled
	)
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://x", http.NoBody)
	// Cancel after the first attempt finishes and before the second can.
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	resp, err := d.Do(req)
	_ = err
	if resp != nil {
		_ = resp.Body.Close()
	}
	// At minimum we must have made the first attempt; the cancel
	// should prevent further attempts.
	if got := c.calls.Load(); got > 2 {
		t.Errorf("inner.Do called %d times, want at most 2 (cancel cuts retries short)", got)
	}
}

func TestNewRetryDoer_NilInnerFallsBack(t *testing.T) {
	d := client.NewRetryDoer(nil)
	if d == nil {
		t.Fatal("NewRetryDoer(nil) returned nil")
	}
}

func TestRetryAndPAT_Composable(t *testing.T) {
	// The two wrappers compose — PAT injection runs once per attempt
	// because the inner is called once per attempt.
	var captured []string
	c := &recordingHeaderDoer{onCall: func(req *http.Request) {
		captured = append(captured, req.Header.Get("Authorization"))
	}, statuses: []int{http.StatusServiceUnavailable, http.StatusOK}}
	composed := client.NewPATDoer(
		client.NewRetryDoer(c,
			client.WithMaxAttempts(2),
			client.WithBackoff(time.Microsecond, time.Microsecond),
		),
		"pat-xyz",
	)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://x", http.NoBody)
	resp, err := composed.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	for i, got := range captured {
		if got != "Bearer pat-xyz" {
			t.Errorf("attempt %d Authorization = %q, want Bearer pat-xyz", i, got)
		}
	}
	if len(captured) != 2 {
		t.Errorf("inner called %d times, want 2 (one retry)", len(captured))
	}
}

// recordingHeaderDoer captures headers per call and returns a sequence
// of HTTP status codes.
type recordingHeaderDoer struct {
	idx      atomic.Int64
	statuses []int
	onCall   func(*http.Request)
}

func (d *recordingHeaderDoer) Do(req *http.Request) (*http.Response, error) {
	if d.onCall != nil {
		d.onCall(req)
	}
	i := int(d.idx.Add(1) - 1)
	if i >= len(d.statuses) {
		i = len(d.statuses) - 1
	}
	return &http.Response{
		StatusCode: d.statuses[i],
		Body:       http.NoBody,
		Header:     http.Header{},
	}, nil
}

// httpHandlerToDoer adapts an http.Handler to the HTTPDoer interface
// for testing the PAT injector against a recording handler.
func httpHandlerToDoer(h http.Handler) client.HTTPDoer {
	return doerFunc(func(req *http.Request) (*http.Response, error) {
		w := &captureWriter{header: http.Header{}}
		h.ServeHTTP(w, req)
		return &http.Response{
			StatusCode: w.status,
			Body:       io.NopCloser(strings.NewReader(w.body.String())),
			Header:     w.header,
		}, nil
	})
}

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

type captureWriter struct {
	header http.Header
	body   strings.Builder
	status int
}

func (w *captureWriter) Header() http.Header         { return w.header }
func (w *captureWriter) Write(b []byte) (int, error) { return w.body.Write(b) }
func (w *captureWriter) WriteHeader(code int)        { w.status = code }
