// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"time"
)

// LogEvent is the structured-logging payload [LogHook] receives for
// each handled request. The fields are stable and additive — future
// versions of the library may add new fields, but existing ones will
// not change shape. Consumer code that pattern-matches on specific
// fields stays forward-compatible.
//
// Method and Path are the raw HTTP request line; Endpoint is the
// library's logical name for the route ("/token", "/permission",
// "/introspection", "/resource_set") and is what should drive
// metric cardinality. Status is the response status code captured
// after the handler returns; Duration is the wall-clock time the
// handler held the request, measured from the start of the
// instrumentation wrapper to its return.
type LogEvent struct {
	Method   string
	Path     string
	Endpoint string
	Status   int
	Duration time.Duration
}

// LogHook is the function signature [WithLogger] expects. Called
// exactly once per request after the handler returns, with a
// fully-populated [LogEvent]. The context is the request context;
// hook implementations should NOT block on I/O that could outlive
// the request (the handler has already returned the response to
// the client by the time the hook runs).
//
// A nil LogHook is valid and equivalent to not configuring the
// option at all.
type LogHook func(ctx context.Context, e LogEvent)

// WithLogger installs a structured-logging hook that fires once
// after each handled request returns. Useful for slog / zap / zerolog
// adapters and for test instrumentation. Multiple calls overwrite —
// the last [WithLogger] in the option list wins, which mirrors the
// "options are independent and order-insensitive" contract for
// every other field except where order is the only sensible
// composition.
func WithLogger(h LogHook) HandlerOption {
	return func(c *handlerConfig) {
		c.log = h
	}
}

// MetricHook is the function signature [WithMetrics] expects.
// Called exactly once per request after the handler returns, with
// the library's logical endpoint name (one of "/token",
// "/permission", "/introspection", "/resource_set") and the
// captured HTTP status code.
//
// The endpoint argument is the bounded-cardinality label suitable
// for use as a Prometheus dimension; passing r.URL.Path directly
// to a counter would explode cardinality on the resource-set
// per-id paths (one new dimension per ResourceSet ID ever seen).
//
// A nil MetricHook is valid and equivalent to not configuring the
// option at all.
type MetricHook func(ctx context.Context, endpoint string, status int)

// WithMetrics installs a metrics hook that fires once after each
// handled request returns. Wire it to a Prometheus counter, an
// OpenTelemetry meter, or a test fixture; the library has no
// opinion about the metric backend. Multiple calls overwrite.
func WithMetrics(h MetricHook) HandlerOption {
	return func(c *handlerConfig) {
		c.metric = h
	}
}

// instrument wraps h with the structured-logging and metrics hooks
// configured on cfg. When neither hook is set the wrapper degrades
// to a direct call — no allocation, no overhead.
//
// endpoint is the library's logical name for the route, kept stable
// across the resource-set per-id paths so metric cardinality stays
// bounded.
func instrument(cfg *handlerConfig, endpoint string, h http.HandlerFunc) http.HandlerFunc {
	if cfg.log == nil && cfg.metric == nil {
		return h
	}
	return func(w http.ResponseWriter, r *http.Request) {
		sw := &statusCapture{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		h(sw, r)
		if cfg.log != nil {
			cfg.log(r.Context(), LogEvent{
				Method:   r.Method,
				Path:     r.URL.Path,
				Endpoint: endpoint,
				Status:   sw.status,
				Duration: time.Since(start),
			})
		}
		if cfg.metric != nil {
			cfg.metric(r.Context(), endpoint, sw.status)
		}
	}
}

// statusCapture wraps an [http.ResponseWriter] so the instrument
// helper can recover the response status code after the handler
// returns. Handlers that never call WriteHeader explicitly leave
// the status at its default of 200; statusCapture mirrors that
// default to avoid attributing a phantom 0 to such requests.
type statusCapture struct {
	http.ResponseWriter
	status   int
	captured bool
}

// WriteHeader captures the status code before delegating to the
// wrapped writer. Multiple WriteHeader calls are illegal per Go's
// http package; the wrapper records the first one only.
func (s *statusCapture) WriteHeader(code int) {
	if !s.captured {
		s.status = code
		s.captured = true
	}
	s.ResponseWriter.WriteHeader(code)
}
