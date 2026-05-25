// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

// End-to-end signed_metadata pass-through test.
//
// Exercises the JOSE-free posture across the full BuildMetadata →
// NewMetadataHandler → Client.FetchMetadata path: the AS attaches an
// opaque JWS payload, serves it from the well-known endpoint, the
// client fetches and parses the document, and the SignedMetadata
// bytes the client receives match the bytes the AS attached.
//
// The library never inspects the payload; this test demonstrates
// that consumers can layer JOSE verification on the client side
// without changes to the library itself, and that a future v0.2
// JOSE upgrade can land without breaking existing deployments that
// already round-trip signed_metadata today.

package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hstern/go-uma"
	"github.com/hstern/go-uma/client"
	"github.com/hstern/go-uma/server"
)

func TestSignedMetadata_EndToEnd(t *testing.T) {
	// AS builds a Metadata document carrying an opaque JWS, serves
	// it on the well-known path, and the client receives the JWS
	// bytes unchanged via FetchMetadata.
	jws := json.RawMessage(`"eyJhbGciOiJSUzI1NiJ9.eyJpc3N1ZXIiOiJodHRwczovL2FzLmV4YW1wbGUuY29tIn0.fake"`)

	// Build the document — server.BuildMetadata probes the AS for
	// implemented endpoints, then the options apply on top.
	var asURL string
	asMux := newSignedMetadataAS(&asURL, jws)
	srv := httptest.NewServer(asMux)
	defer srv.Close()
	asURL = srv.URL

	c, err := client.NewClient(srv.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	got, err := c.FetchMetadata(context.Background())
	if err != nil {
		t.Fatalf("FetchMetadata: %v", err)
	}
	if !bytes.Equal(got.SignedMetadata, jws) {
		t.Errorf("SignedMetadata mismatch:\n  sent: %s\n  got:  %s",
			string(jws), string(got.SignedMetadata))
	}

	// The other fields should also be present — Issuer matches the
	// AS URL (mix-up validation succeeded), and the JOSE-free
	// payload didn't disturb the rest of the document.
	if got.Issuer != srv.URL {
		t.Errorf("Issuer = %q, want %q", got.Issuer, srv.URL)
	}
}

// newSignedMetadataAS returns an http.Handler that exposes both an
// AS endpoint surface (so BuildMetadata can probe) and the well-
// known metadata document carrying the provided JWS. The asURL
// pointer is read at request time so the handler closes over the
// test-server's eventual URL (which isn't known until httptest.NewServer
// returns).
type signedMetadataAS struct {
	server.NotImplementedAS
}

func (signedMetadataAS) Token(context.Context, *uma.TokenRequest) (*uma.TokenResponse, error) {
	return &uma.TokenResponse{}, nil
}

func newSignedMetadataAS(asURL *string, jws json.RawMessage) *signedMetadataMux {
	return &signedMetadataMux{asURL: asURL, jws: jws}
}

// signedMetadataMux serves both the AS handler and the metadata
// well-known endpoint. The metadata document is rebuilt per request
// because asURL only becomes known after httptest.NewServer starts.
type signedMetadataMux struct {
	asURL *string
	jws   json.RawMessage
}

func (m *signedMetadataMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == uma.MetadataPath {
		meta := server.BuildMetadata(*m.asURL, signedMetadataAS{},
			uma.WithSignedMetadata(m.jws),
		)
		server.NewMetadataHandler(meta).ServeHTTP(w, r)
		return
	}
	server.NewASHandler(signedMetadataAS{}).ServeHTTP(w, r)
}
