// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package uma_test

import (
	"errors"
	"testing"

	"github.com/hstern/go-uma"
)

// validator is implemented by every wire-message type that carries a
// strict-marshal Validate method. The matrix tests below treat the four
// types uniformly.
type validator interface {
	Validate() error
}

// TestValidate_MissingRequiredFields exercises the per-type Validate
// methods across every wire type that has required fields. Each row
// names a type, a constructor that produces an invalid value, the
// expected *ValidationError type and field, and the message.
func TestValidate_MissingRequiredFields(t *testing.T) {
	tests := []struct {
		name      string
		make      func() validator
		wantType  string
		wantField string
	}{
		{
			"TokenRequest missing ticket",
			func() validator { return &uma.TokenRequest{} },
			"TokenRequest", "ticket",
		},
		{
			"IntrospectionRequest missing token",
			func() validator { return &uma.IntrospectionRequest{} },
			"IntrospectionRequest", "token",
		},
		{
			"PermissionRequest missing resource_id",
			func() validator {
				return &uma.PermissionRequest{ResourceScopes: []string{"view"}}
			},
			"PermissionRequest", "resource_id",
		},
		{
			"PermissionRequest missing resource_scopes",
			func() validator {
				return &uma.PermissionRequest{ResourceID: "abc"}
			},
			"PermissionRequest", "resource_scopes",
		},
		{
			"ResourceSet missing name",
			func() validator {
				return &uma.ResourceSet{ResourceScopes: []string{"view"}}
			},
			"ResourceSet", "name",
		},
		{
			"ResourceSet missing resource_scopes",
			func() validator { return &uma.ResourceSet{Name: "My"} },
			"ResourceSet", "resource_scopes",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.make().Validate()
			if err == nil {
				t.Fatalf("Validate = nil, want *ValidationError")
			}
			var ve *uma.ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("Validate returned %T, want *ValidationError (errors.As)", err)
			}
			if ve.Type != tc.wantType {
				t.Errorf("Type = %q, want %q", ve.Type, tc.wantType)
			}
			if ve.Field != tc.wantField {
				t.Errorf("Field = %q, want %q", ve.Field, tc.wantField)
			}
			if ve.Message != "required" {
				t.Errorf("Message = %q, want %q", ve.Message, "required")
			}
		})
	}
}

func TestValidate_PopulatedReturnsNil(t *testing.T) {
	tests := []struct {
		name string
		make func() validator
	}{
		{"TokenRequest", func() validator { return &uma.TokenRequest{Ticket: "t-1"} }},
		{"IntrospectionRequest", func() validator { return &uma.IntrospectionRequest{Token: "rpt-1"} }},
		{"PermissionRequest", func() validator {
			return &uma.PermissionRequest{ResourceID: "r1", ResourceScopes: []string{"view"}}
		}},
		{"ResourceSet", func() validator {
			return &uma.ResourceSet{Name: "My Photos", ResourceScopes: []string{"view"}}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.make().Validate(); err != nil {
				t.Errorf("Validate on populated %s = %v, want nil", tc.name, err)
			}
		})
	}
}

func TestValidate_NilReceivers(t *testing.T) {
	// Nil-receiver Validate must return a typed ValidationError rather
	// than panicking — defensive against callers who forget to construct
	// the request struct.
	tests := []struct {
		name     string
		validate func() error
	}{
		{"TokenRequest", func() error { var r *uma.TokenRequest; return r.Validate() }},
		{"IntrospectionRequest", func() error { var r *uma.IntrospectionRequest; return r.Validate() }},
		{"PermissionRequest", func() error { var r *uma.PermissionRequest; return r.Validate() }},
		{"ResourceSet", func() error { var r *uma.ResourceSet; return r.Validate() }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.validate()
			if err == nil {
				t.Fatalf("nil-receiver Validate returned nil, want *ValidationError")
			}
			var ve *uma.ValidationError
			if !errors.As(err, &ve) {
				t.Errorf("nil-receiver Validate returned %T, want *ValidationError", err)
			}
		})
	}
}

func TestValidate_ErrorMessageShape(t *testing.T) {
	// The user-facing Error() rendering is contractual — log scrapers
	// and stderr-watchers pattern-match on it.
	err := (&uma.TokenRequest{}).Validate()
	want := "uma: TokenRequest.ticket: required"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}
