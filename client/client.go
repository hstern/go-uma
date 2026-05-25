// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

// Package client implements the requesting-party-client and resource-
// server sides of UMA 2.0's HTTP wire protocol. A single [Client]
// interface covers both roles — the protocol distinguishes them by
// which endpoint the caller hits, not by which client they hold:
//
//   - The requesting-party client calls Client.Token to redeem a
//     permission ticket the RS handed it for an RPT.
//   - The Resource Server calls Client.Permission, Client.Introspect,
//     and the Client.CreateResourceSet family against the AS's
//     protection API. These endpoints require a PAT (Protection API
//     Token); supply it with [WithPAT] or wrap the underlying
//     transport with [NewPATDoer] from this package.
//
// Construct the default HTTP-backed implementation with [NewClient]
// pointing at the AS's base URL. The default transport is
// [http.DefaultClient]; swap it with [WithHTTPDoer] for retry, auth,
// instrumentation, or test scenarios.
//
// [Client] is an interface so consumer tests can substitute a stub
// implementation without standing up a real HTTP server. Production
// code SHOULD use [NewClient]; the only intended alternative
// implementations are test doubles.
//
// The library's implementer pins for the client side, all enforced in
// the per-endpoint methods, are:
//
//   - A `need_info` HTTP 403 on /token is NOT a transport error.
//     Client.Token returns a typed [*uma.NeedInfoError] that callers
//     extract via [errors.As].
//   - An `active: false` introspection response is NOT a transport
//     error. Client.Introspect returns the [*uma.IntrospectionResponse]
//     with Active=false and a nil error.
//   - The permission ticket and the RPT are opaque strings the library
//     never decodes.
package client

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// HTTPDoer is the interface the client requires of its underlying
// transport — a single Do method matching the shape of
// [http.Client.Do]. Consumers can plug retry, auth-injecting, and
// instrumented transports by wrapping an [http.Client] (or any other
// HTTPDoer) and passing the wrapper via [WithHTTPDoer]. This is the
// same shape [golang.org/x/oauth2] uses.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client is a handle to an UMA Authorization Server. Construct the
// default HTTP-backed implementation with [NewClient]; substitute a
// test double in consumer tests by writing a type that satisfies this
// interface.
//
// Per-endpoint methods land in follow-up commits — Client.Token in
// the next phase-3 commit, the protection-API surface
// (Client.Permission, Client.Introspect, the resource-set CRUD family)
// after that. Each new method extends both this interface and the
// underlying [NewClient] implementation in lockstep.
//
// Implementations are expected to be safe for concurrent use by
// multiple goroutines.
type Client interface {
	// BaseURL returns the absolute base URL the client was constructed
	// against. Returned by value so callers cannot mutate the client's
	// internal state by writing back to the URL.
	BaseURL() url.URL
}

// defaultClient is the HTTP-backed implementation of [Client] that
// [NewClient] returns. The type is intentionally unexported — the only
// exported surface is the [Client] interface and the per-endpoint
// methods it carries. Tests and adapter-pattern wrappers satisfy the
// interface directly without depending on this concrete type.
type defaultClient struct {
	baseURL *url.URL
	doer    HTTPDoer

	// pat is the Protection API Token used to authenticate RS-side
	// protection-API calls (/permission, /introspection, /resource_set).
	// Empty when the consumer has wired authentication via a different
	// path (e.g. an HTTPDoer that injects the PAT itself, or mTLS).
	pat string

	// metaDefaultTTL is the fallback metadata-document cache lifetime
	// when the AS's response carries no Cache-Control: max-age.
	// FetchMetadata (landing in a later phase alongside the metadata
	// document support) consults this field; it is plumbed here at
	// construction time so the option set is settled before any
	// network call.
	metaDefaultTTL time.Duration
}

// BaseURL implements [Client.BaseURL].
func (c *defaultClient) BaseURL() url.URL { return *c.baseURL }

// Option customizes a [defaultClient] at construction. The parameter
// type is unexported so consumers cannot construct their own Option
// values — they compose the library's [WithHTTPDoer], [WithPAT], and
// [WithMetadataTTL] options instead. The constructor [NewClient]
// applies them in order; all options are independent and order-
// insensitive.
type Option func(*defaultClient)

// NewClient returns the default HTTP-backed implementation of [Client]
// targeting the UMA Authorization Server at asBaseURL. asBaseURL must
// be an absolute URL with a scheme and host (a relative path or an
// empty string is rejected). The library does not enforce HTTPS here
// so http://127.0.0.1:NNN URLs work in tests; production deployments
// SHOULD pass an https:// URL.
//
// The default transport is [http.DefaultClient] and the default
// metadata cache TTL is one hour. Override with [WithHTTPDoer] and
// [WithMetadataTTL] respectively.
func NewClient(asBaseURL string, opts ...Option) (Client, error) {
	u, err := url.Parse(asBaseURL)
	if err != nil {
		return nil, fmt.Errorf("uma client: parse asBaseURL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, errors.New("uma client: asBaseURL must be an absolute URL with scheme and host")
	}
	c := &defaultClient{
		baseURL:        u,
		doer:           http.DefaultClient,
		metaDefaultTTL: time.Hour,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// WithHTTPDoer swaps the default [Client]'s underlying transport. d
// may be any value implementing [HTTPDoer] — an [http.Client] with a
// tuned Timeout, a retry-wrapping Doer (see [NewRetryDoer]), an auth-
// injecting Doer (see [NewPATDoer]), an OTel-instrumented client, or
// a test fixture.
//
// Passing nil resets to the default ([http.DefaultClient]).
func WithHTTPDoer(d HTTPDoer) Option {
	return func(c *defaultClient) {
		if d == nil {
			c.doer = http.DefaultClient
			return
		}
		c.doer = d
	}
}

// WithPAT sets the Protection API Token the default [Client] sends in
// the Authorization: Bearer header on calls to the AS's protection-API
// endpoints — /permission, /introspection, and the /resource_set
// CRUD surface. The requesting-party /token endpoint does NOT use the
// PAT; the consumer authenticates the requesting-party client through
// a separate OAuth 2.0 client-authentication mechanism the library
// does not constrain.
//
// An empty token disables PAT injection. Equivalent to leaving WithPAT
// out of the option list; callers wiring PAT authentication through
// an HTTPDoer (e.g. via [NewPATDoer] or an external OAuth library)
// should not pass WithPAT.
func WithPAT(token string) Option {
	return func(c *defaultClient) {
		c.pat = token
	}
}

// WithMetadataTTL sets the fallback cache lifetime for the AS's
// /.well-known/uma2-configuration metadata document, used when the
// response carries no Cache-Control: max-age. The default is one hour
// — short enough that a freshly-deployed endpoint sees client uptake
// within a workday, long enough that the metadata fetch is not on
// every request's hot path. A non-positive duration disables caching
// (every FetchMetadata call hits the AS).
//
// The metadata fetcher itself lands with the AS-side metadata document
// support; this option is wired here at construction time so the
// option set is complete from the start.
func WithMetadataTTL(d time.Duration) Option {
	return func(c *defaultClient) {
		c.metaDefaultTTL = d
	}
}
