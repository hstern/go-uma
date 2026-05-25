// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/hstern/go-uma"
)

// BuildMetadata constructs a [uma.Metadata] document advertising only
// the endpoints the supplied [AS] implementation actually serves. It
// probes each method on as by calling it with a zero-value request
// and checking whether the returned error wraps
// [uma.ErrNotImplemented]; an endpoint whose probe returns
// ErrNotImplemented is omitted from the resulting document, an
// endpoint whose probe returns anything else (success,
// [*uma.ValidationError], [*uma.OAuthError], etc.) is advertised.
//
// asURL must be the AS's absolute issuer URL — it populates the
// Issuer field and is the base every endpoint URL is joined against.
// A trailing slash on asURL is stripped before joining; the endpoint
// constants already begin with "/". An empty or non-absolute asURL
// produces a Metadata with an empty Issuer; the call does not error
// (consumers who want stricter checking pre-validate).
//
// The probe uses [context.Background] and a brand-new zero-value
// request per method. AS implementations MUST return ErrNotImplemented
// BEFORE any side effect — the convention is enforced by the
// [NotImplementedAS] embedding, but a hand-rolled implementation
// that does work first and then returns ErrNotImplemented will leak
// that work on every BuildMetadata call.
//
// BuildMetadata also fills in GrantTypesSupported with the
// UMA-ticket grant URN when the AS implements Token; consumers who
// want additional grants advertised compose
// [uma.WithUMAProfilesSupported] and friends or set fields on the
// returned struct directly.
func BuildMetadata(asURL string, as AS, opts ...uma.MetadataOption) *uma.Metadata {
	m := &uma.Metadata{Issuer: asURL}
	asURL = strings.TrimRight(asURL, "/")
	ctx := context.Background()

	if as != nil {
		if _, err := as.Token(ctx, &uma.TokenRequest{}); !errors.Is(err, uma.ErrNotImplemented) {
			m.TokenEndpoint = asURL + uma.TokenEndpoint
			m.GrantTypesSupported = []string{uma.UMATicketGrantType}
		}
		if _, err := as.Permission(ctx, &uma.PermissionRequest{}); !errors.Is(err, uma.ErrNotImplemented) {
			m.PermissionEndpoint = asURL + uma.PermissionEndpoint
		}
		if _, err := as.Introspect(ctx, &uma.IntrospectionRequest{}); !errors.Is(err, uma.ErrNotImplemented) {
			m.IntrospectionEndpoint = asURL + uma.IntrospectionEndpoint
		}
		if _, err := as.ResourceSet(ctx, &ResourceSetRequest{Op: uma.OpUnknown}); !errors.Is(err, uma.ErrNotImplemented) {
			m.ResourceRegistrationEndpoint = asURL + uma.ResourceSetEndpoint
		}
	}

	for _, opt := range opts {
		opt(m)
	}
	return m
}

// NewMetadataHandler returns an [http.Handler] that serves m as
// JSON. Mount it at [uma.MetadataPath] (`/.well-known/uma2-configuration`)
// on the AS's public surface — or anywhere else, but consumers
// expect the well-known path.
//
// The handler responds 200 OK with Content-Type: application/json
// on GET requests, 200 OK with the same Content-Type and an empty
// body on HEAD, and 405 Method Not Allowed on everything else.
//
// A nil m produces a handler that always returns 500; consumers
// should validate before mounting.
func NewMetadataHandler(m *uma.Metadata) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m == nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodHead {
			return
		}
		_ = json.NewEncoder(w).Encode(m)
	})
}
