// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package uma_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/hstern/go-uma"
)

func TestMetadata_JSONRoundTrip(t *testing.T) {
	orig := &uma.Metadata{
		Issuer:                       "https://as.example.com",
		TokenEndpoint:                "https://as.example.com/token",
		IntrospectionEndpoint:        "https://as.example.com/introspection",
		PermissionEndpoint:           "https://as.example.com/permission",
		ResourceRegistrationEndpoint: "https://as.example.com/resource_set",
		GrantTypesSupported:          []string{uma.UMATicketGrantType},
		UMAProfilesSupported:         []string{"urn:example:profile1"},
		ClaimTokenFormatsSupported:   []string{string(uma.ClaimTokenFormatIDToken)},
		SignedMetadata:               json.RawMessage(`"eyJ.fake.jws"`),
	}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var back uma.Metadata
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(orig, &back) {
		t.Fatalf("round-trip mismatch:\n  orig: %+v\n  back: %+v", orig, &back)
	}
}

func TestMetadata_JSON_OmitsEmptyEndpoints(t *testing.T) {
	// A document with only Issuer set must not leak null endpoints
	// on the wire.
	m := &uma.Metadata{Issuer: "https://as.example.com"}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"issuer":"https://as.example.com"}`
	if string(b) != want {
		t.Errorf("Marshal = %s, want %s", string(b), want)
	}
}

func TestMetadataOptions(t *testing.T) {
	m := &uma.Metadata{Issuer: "https://as.example.com"}
	for _, opt := range []uma.MetadataOption{
		uma.WithUMAProfilesSupported("urn:example:profile1"),
		uma.WithClaimTokenFormatsSupported(uma.ClaimTokenFormatIDToken),
		uma.WithTokenEndpointAuthMethods("client_secret_basic", "private_key_jwt"),
	} {
		opt(m)
	}
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

func TestWithSignedMetadata(t *testing.T) {
	jws := json.RawMessage(`"eyJhbGciOiJSUzI1NiJ9.fake.signature"`)
	m := &uma.Metadata{}
	uma.WithSignedMetadata(jws)(m)
	if string(m.SignedMetadata) != string(jws) {
		t.Errorf("SignedMetadata = %s, want %s", string(m.SignedMetadata), string(jws))
	}
	// Mutating the input must not corrupt the stored value —
	// WithSignedMetadata copies.
	jws[0] = '_'
	if m.SignedMetadata[0] == '_' {
		t.Error("WithSignedMetadata did not copy input; mutation leaked")
	}
}

func TestWithSignedMetadata_EmptyClears(t *testing.T) {
	m := &uma.Metadata{SignedMetadata: json.RawMessage(`"stale"`)}
	uma.WithSignedMetadata(nil)(m)
	if m.SignedMetadata != nil {
		t.Errorf("WithSignedMetadata(nil) left %s, want nil", string(m.SignedMetadata))
	}
}
