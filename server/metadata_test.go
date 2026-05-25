// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/hstern/go-uma"
	"github.com/hstern/go-uma/server"
)

// fullAS implements every AS method — the canonical "implements
// everything" probe target.
type fullAS struct{}

func (fullAS) Token(context.Context, *uma.TokenRequest) (*uma.TokenResponse, error) {
	return &uma.TokenResponse{}, nil
}

func (fullAS) Permission(context.Context, *uma.PermissionRequest) (*uma.PermissionResponse, error) {
	return &uma.PermissionResponse{}, nil
}

func (fullAS) Introspect(context.Context, *uma.IntrospectionRequest) (*uma.IntrospectionResponse, error) {
	return &uma.IntrospectionResponse{}, nil
}

func (fullAS) ResourceSet(context.Context, *server.ResourceSetRequest) (*server.ResourceSetResponse, error) {
	return &server.ResourceSetResponse{}, nil
}

// tokenOnlyMetaAS implements just Token; the rest return
// ErrNotImplemented via NotImplementedAS embedding.
type tokenOnlyMetaAS struct {
	server.NotImplementedAS
}

func (tokenOnlyMetaAS) Token(context.Context, *uma.TokenRequest) (*uma.TokenResponse, error) {
	return &uma.TokenResponse{}, nil
}

func TestBuildMetadata_FullAS(t *testing.T) {
	m := server.BuildMetadata("https://as.example.com", fullAS{})
	if m.Issuer != "https://as.example.com" {
		t.Errorf("Issuer = %q", m.Issuer)
	}
	want := map[string]string{
		"TokenEndpoint":                "https://as.example.com/token",
		"PermissionEndpoint":           "https://as.example.com/permission",
		"IntrospectionEndpoint":        "https://as.example.com/introspection",
		"ResourceRegistrationEndpoint": "https://as.example.com/resource_set",
	}
	got := map[string]string{
		"TokenEndpoint":                m.TokenEndpoint,
		"PermissionEndpoint":           m.PermissionEndpoint,
		"IntrospectionEndpoint":        m.IntrospectionEndpoint,
		"ResourceRegistrationEndpoint": m.ResourceRegistrationEndpoint,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("endpoints:\n  got:  %+v\n  want: %+v", got, want)
	}
	if len(m.GrantTypesSupported) != 1 || m.GrantTypesSupported[0] != uma.UMATicketGrantType {
		t.Errorf("GrantTypesSupported = %v, want [UMATicketGrantType]", m.GrantTypesSupported)
	}
}

func TestBuildMetadata_NotImplementedAS(t *testing.T) {
	// An AS that returns ErrNotImplemented from every method
	// produces a metadata document with only the Issuer field set.
	m := server.BuildMetadata("https://as.example.com", server.NotImplementedAS{})
	if m.Issuer != "https://as.example.com" {
		t.Errorf("Issuer = %q", m.Issuer)
	}
	if m.TokenEndpoint != "" || m.PermissionEndpoint != "" ||
		m.IntrospectionEndpoint != "" || m.ResourceRegistrationEndpoint != "" {
		t.Errorf("expected all endpoints empty; got %+v", m)
	}
	if len(m.GrantTypesSupported) != 0 {
		t.Errorf("GrantTypesSupported = %v, want empty (Token unimplemented)", m.GrantTypesSupported)
	}
}

func TestBuildMetadata_PartialAS(t *testing.T) {
	// A tokenOnlyMetaAS lights up TokenEndpoint + GrantTypesSupported
	// only; the other three endpoints stay empty.
	m := server.BuildMetadata("https://as.example.com", tokenOnlyMetaAS{})
	if m.TokenEndpoint != "https://as.example.com/token" {
		t.Errorf("TokenEndpoint = %q", m.TokenEndpoint)
	}
	if m.PermissionEndpoint != "" || m.IntrospectionEndpoint != "" || m.ResourceRegistrationEndpoint != "" {
		t.Errorf("partial AS leaked endpoints: %+v", m)
	}
	if len(m.GrantTypesSupported) != 1 {
		t.Errorf("GrantTypesSupported = %v, want length 1", m.GrantTypesSupported)
	}
}

func TestBuildMetadata_TrailingSlashStripped(t *testing.T) {
	m := server.BuildMetadata("https://as.example.com/", fullAS{})
	if m.TokenEndpoint != "https://as.example.com/token" {
		t.Errorf("TokenEndpoint = %q (should not double-slash)", m.TokenEndpoint)
	}
}

func TestBuildMetadata_NilAS(t *testing.T) {
	m := server.BuildMetadata("https://as.example.com", nil)
	if m.Issuer != "https://as.example.com" {
		t.Errorf("Issuer = %q", m.Issuer)
	}
	if m.TokenEndpoint != "" {
		t.Errorf("nil AS produced TokenEndpoint = %q", m.TokenEndpoint)
	}
}

func TestBuildMetadata_Options(t *testing.T) {
	m := server.BuildMetadata("https://as.example.com", fullAS{},
		uma.WithUMAProfilesSupported("urn:example:profile1"),
		uma.WithClaimTokenFormatsSupported(uma.ClaimTokenFormatIDToken),
		uma.WithTokenEndpointAuthMethods("client_secret_basic", "private_key_jwt"),
	)
	if len(m.UMAProfilesSupported) != 1 || m.UMAProfilesSupported[0] != "urn:example:profile1" {
		t.Errorf("UMAProfilesSupported = %v", m.UMAProfilesSupported)
	}
	if len(m.ClaimTokenFormatsSupported) != 1 || m.ClaimTokenFormatsSupported[0] != string(uma.ClaimTokenFormatIDToken) {
		t.Errorf("ClaimTokenFormatsSupported = %v", m.ClaimTokenFormatsSupported)
	}
	if len(m.TokenEndpointAuthMethodsSupported) != 2 {
		t.Errorf("TokenEndpointAuthMethodsSupported = %v", m.TokenEndpointAuthMethodsSupported)
	}
}

func TestNewMetadataHandler_GET(t *testing.T) {
	m := &uma.Metadata{
		Issuer:        "https://as.example.com",
		TokenEndpoint: "https://as.example.com/token",
	}
	srv := httptest.NewServer(server.NewMetadataHandler(m))
	defer srv.Close()
	resp, err := http.Get(srv.URL + uma.MetadataPath)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var got uma.Metadata
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Issuer != "https://as.example.com" {
		t.Errorf("Issuer = %q", got.Issuer)
	}
}

func TestNewMetadataHandler_HEAD(t *testing.T) {
	m := &uma.Metadata{Issuer: "https://as.example.com"}
	srv := httptest.NewServer(server.NewMetadataHandler(m))
	defer srv.Close()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodHead, srv.URL, http.NoBody)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HEAD: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("HEAD status = %d, want 200", resp.StatusCode)
	}
}

func TestNewMetadataHandler_MethodNotAllowed(t *testing.T) {
	m := &uma.Metadata{Issuer: "https://as.example.com"}
	srv := httptest.NewServer(server.NewMetadataHandler(m))
	defer srv.Close()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL, strings.NewReader(""))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d, want 405", resp.StatusCode)
	}
	if resp.Header.Get("Allow") != "GET, HEAD" {
		t.Errorf("Allow = %q, want GET, HEAD", resp.Header.Get("Allow"))
	}
}

func TestNewMetadataHandler_NilMetadata(t *testing.T) {
	srv := httptest.NewServer(server.NewMetadataHandler(nil))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("nil metadata status = %d, want 500", resp.StatusCode)
	}
}
