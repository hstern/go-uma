// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

// Phase-5 acceptance gate.
//
// Exercises the partial-implementation discovery flow end-to-end:
// an AS that implements only Token + Introspect via the
// NotImplementedAS embed-and-override pattern must produce a
// metadata document advertising only those two endpoints, the
// /permission and /resource_set HTTP routes must return 501, and a
// Client that fetches the metadata must see the same restricted
// endpoint set the AS published.
//
// The test stitches together every load-bearing piece of phase 5:
//
//   - server.NotImplementedAS — the zero-value implementation that
//     returns uma.ErrNotImplemented from every method.
//   - server.BuildMetadata — probes via errors.Is(err,
//     uma.ErrNotImplemented) and omits unimplemented endpoints.
//   - server.NewASHandler — maps uma.ErrNotImplemented to HTTP 501.
//   - server.NewMetadataHandler — serves the document at
//     uma.MetadataPath.
//   - client.FetchMetadata — fetches + validates the document,
//     hard-failing on mix-up.

package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hstern/go-uma"
	"github.com/hstern/go-uma/client"
	"github.com/hstern/go-uma/server"
)

// tokenIntrospectAS is the canonical partial AS: implements Token +
// Introspect, embeds NotImplementedAS to opt out of Permission and
// ResourceSet. Demonstrates the embed-and-override pattern from the
// AS interface godoc.
type tokenIntrospectAS struct {
	server.NotImplementedAS
}

func (tokenIntrospectAS) Token(context.Context, *uma.TokenRequest) (*uma.TokenResponse, error) {
	return &uma.TokenResponse{
		AccessToken: "rpt-from-partial-as",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}, nil
}

func (tokenIntrospectAS) Introspect(context.Context, *uma.IntrospectionRequest) (*uma.IntrospectionResponse, error) {
	return &uma.IntrospectionResponse{Active: true}, nil
}

// partialMux serves the AS endpoints AND the well-known metadata
// document from one httptest.Server. The metadata is rebuilt per
// request because the AS URL is only known after httptest.NewServer
// starts.
type partialMux struct {
	asURL *string
	as    server.AS
}

func (m *partialMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == uma.MetadataPath {
		meta := server.BuildMetadata(*m.asURL, m.as)
		server.NewMetadataHandler(meta).ServeHTTP(w, r)
		return
	}
	server.NewASHandler(m.as).ServeHTTP(w, r)
}

func newPartialAS(t *testing.T) (*httptest.Server, *string) {
	t.Helper()
	var asURL string
	mux := &partialMux{asURL: &asURL, as: tokenIntrospectAS{}}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	asURL = srv.URL
	return srv, &asURL
}

func TestPartial_MetadataAdvertisesOnlyImplemented(t *testing.T) {
	srv, _ := newPartialAS(t)
	c, err := client.NewClient(srv.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	m, err := c.FetchMetadata(context.Background())
	if err != nil {
		t.Fatalf("FetchMetadata: %v", err)
	}
	// Implemented:
	if m.TokenEndpoint == "" {
		t.Errorf("TokenEndpoint empty in metadata; partial AS implements Token")
	}
	if m.IntrospectionEndpoint == "" {
		t.Errorf("IntrospectionEndpoint empty; partial AS implements Introspect")
	}
	// Unimplemented:
	if m.PermissionEndpoint != "" {
		t.Errorf("PermissionEndpoint = %q, want empty (Permission unimplemented)", m.PermissionEndpoint)
	}
	if m.ResourceRegistrationEndpoint != "" {
		t.Errorf("ResourceRegistrationEndpoint = %q, want empty (ResourceSet unimplemented)", m.ResourceRegistrationEndpoint)
	}
	// GrantTypesSupported lights up when Token is implemented.
	if len(m.GrantTypesSupported) != 1 || m.GrantTypesSupported[0] != uma.UMATicketGrantType {
		t.Errorf("GrantTypesSupported = %v, want [UMATicketGrantType]", m.GrantTypesSupported)
	}
}

func TestPartial_UnimplementedEndpointReturns501(t *testing.T) {
	// The handler MUST return 501 Not Implemented for /permission
	// and the /resource_set CRUD routes even though they are not in
	// the metadata. The library's status-code mapping is the
	// load-bearing wire behavior; the metadata document is the
	// discovery layer that lets clients avoid calling those routes
	// in the first place, but the AS still needs to handle a
	// request that arrives anyway.
	srv, _ := newPartialAS(t)
	tests := []struct {
		name, method, path, body, ctype string
	}{
		{
			name:   "Permission",
			method: http.MethodPost,
			path:   "/permission",
			body:   `{"resource_id":"r","resource_scopes":["v"]}`,
			ctype:  "application/json",
		},
		{
			name:   "ResourceSet POST",
			method: http.MethodPost,
			path:   "/resource_set",
			body:   `{"name":"n","resource_scopes":["v"]}`,
			ctype:  "application/json",
		},
		{
			name:   "ResourceSet GET id",
			method: http.MethodGet,
			path:   "/resource_set/r1",
		},
		{
			name:   "ResourceSet LIST",
			method: http.MethodGet,
			path:   "/resource_set",
		},
		{
			name:   "ResourceSet DELETE",
			method: http.MethodDelete,
			path:   "/resource_set/r1",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var body *strings.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			}
			var bodyReader interface {
				Read(p []byte) (n int, err error)
			} = http.NoBody
			if body != nil {
				bodyReader = body
			}
			req, _ := http.NewRequestWithContext(context.Background(),
				tc.method, srv.URL+tc.path, bodyReader)
			if tc.ctype != "" {
				req.Header.Set("Content-Type", tc.ctype)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusNotImplemented {
				t.Errorf("%s %s: status = %d, want 501",
					tc.method, tc.path, resp.StatusCode)
			}
		})
	}
}

func TestPartial_ImplementedEndpointsRespondNormally(t *testing.T) {
	// The /token + /introspection endpoints, which the AS does
	// implement, must respond with their normal happy-path shapes
	// — not 501. Defensive guard against a future refactor that
	// accidentally short-circuits any endpoint to 501.
	srv, _ := newPartialAS(t)
	c, err := client.NewClient(srv.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	tr, err := c.Token(context.Background(), &uma.TokenRequest{Ticket: "tkt-1"})
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tr.AccessToken != "rpt-from-partial-as" {
		t.Errorf("Token AccessToken = %q", tr.AccessToken)
	}
	ir, err := c.Introspect(context.Background(), &uma.IntrospectionRequest{Token: "rpt"})
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if !ir.Active {
		t.Errorf("Introspect Active = false, want true")
	}
}

func TestPartial_FetchMetadataMixUpRejection(t *testing.T) {
	// Stand up a SECOND server that returns a metadata document with
	// the WRONG issuer (impersonating a different AS). The client
	// configured against the SECOND server's URL gets a typed
	// *MixUpError because the document claims to be issued by a
	// different AS.
	attackerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"issuer":"https://legitimate-as.example.com",
			"token_endpoint":"https://legitimate-as.example.com/token"
		}`))
	}))
	defer attackerSrv.Close()
	c, err := client.NewClient(attackerSrv.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = c.FetchMetadata(context.Background())
	if err == nil {
		t.Fatal("FetchMetadata returned nil error against mix-up document")
	}
	if !client.IsMixUpError(err) {
		t.Errorf("err = %v, want *MixUpError", err)
	}
}

func TestPartial_RelaxedSkipsMixUpCheck(t *testing.T) {
	// Verifies the WithRelaxedMetadataValidation escape hatch works
	// against a server with a deliberately different issuer — a
	// stand-in for a TLS terminator producing a configured-vs-
	// published URL mismatch.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"issuer":"https://internal-as.example.com",
			"token_endpoint":"https://internal-as.example.com/token"
		}`))
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
	if m.Issuer != "https://internal-as.example.com" {
		t.Errorf("Issuer = %q", m.Issuer)
	}
}
