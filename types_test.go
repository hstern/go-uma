// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package uma_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/hstern/go-uma"
)

func TestEndpointConstants(t *testing.T) {
	// Constants pinned to the exact strings used in the Grant and Federated
	// Authorization Recommendations' examples. An edit to any of these
	// values is almost certainly a regression — the spec text is what
	// makes them load-bearing for consumers wiring their AS at the
	// canonical paths.
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"TokenEndpoint", uma.TokenEndpoint, "/token"},
		{"PermissionEndpoint", uma.PermissionEndpoint, "/permission"},
		{"IntrospectionEndpoint", uma.IntrospectionEndpoint, "/introspection"},
		{"ResourceSetEndpoint", uma.ResourceSetEndpoint, "/resource_set"},
		{"MetadataPath", uma.MetadataPath, "/.well-known/uma2-configuration"},
	}
	for _, tc := range tests {
		if tc.value != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.value, tc.want)
		}
	}
}

func TestDecodeJSON_NilAndEmpty(t *testing.T) {
	type ext struct {
		K string `json:"k"`
	}
	// Absent extension fields are the common case on the wire; treating
	// them as no-ops keeps every call site terse (no manual nil-guard
	// before every DecodeJSON).
	tests := []struct {
		name string
		raw  json.RawMessage
	}{
		{"nil", nil},
		{"empty bytes", json.RawMessage("")},
		{"whitespace", json.RawMessage("   ")},
		{"tabs and newlines", json.RawMessage("\t\n\r ")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var v ext
			if err := uma.DecodeJSON(tc.raw, &v); err != nil {
				t.Fatalf("DecodeJSON(%q) = %v, want nil", string(tc.raw), err)
			}
			if v.K != "" {
				t.Errorf("v changed on %q input: %+v", string(tc.raw), v)
			}
		})
	}
}

func TestDecodeJSON_Populated(t *testing.T) {
	type ext struct {
		Role string `json:"role"`
	}
	var v ext
	if err := uma.DecodeJSON(json.RawMessage(`{"role":"admin"}`), &v); err != nil {
		t.Fatalf("DecodeJSON: %v", err)
	}
	if v.Role != "admin" {
		t.Errorf("Role = %q, want %q", v.Role, "admin")
	}
}

func TestDecodeJSON_InvalidJSON(t *testing.T) {
	// Invalid JSON propagates the stdlib error so callers can surface it
	// — DecodeJSON only swallows the no-document case.
	var v map[string]any
	err := uma.DecodeJSON(json.RawMessage(`{not json`), &v)
	if err == nil {
		t.Fatalf("DecodeJSON(invalid) = nil, want a json.SyntaxError")
	}
	var se *json.SyntaxError
	if !errors.As(err, &se) {
		t.Fatalf("DecodeJSON(invalid) returned %T, want *json.SyntaxError (wrapped or direct)", err)
	}
}

func TestEncodeJSON_NilEmits_Nil(t *testing.T) {
	// EncodeJSON(nil) returns a nil RawMessage so the surrounding struct's
	// `omitempty` tag drops the field — the wire shape stays "field absent"
	// rather than "field present with `null`".
	got, err := uma.EncodeJSON(nil)
	if err != nil {
		t.Fatalf("EncodeJSON(nil) = err %v, want nil", err)
	}
	if got != nil {
		t.Fatalf("EncodeJSON(nil) = %s, want nil RawMessage", string(got))
	}
}

func TestEncodeJSON_Populated(t *testing.T) {
	type ext struct {
		Role string `json:"role"`
	}
	got, err := uma.EncodeJSON(ext{Role: "admin"})
	if err != nil {
		t.Fatalf("EncodeJSON: %v", err)
	}
	want := `{"role":"admin"}`
	if string(got) != want {
		t.Errorf("EncodeJSON = %s, want %s", string(got), want)
	}
}

func TestEncodeJSON_MarshalError(t *testing.T) {
	// channels are not JSON-encodable — the stdlib's UnsupportedTypeError
	// must propagate so callers can react.
	got, err := uma.EncodeJSON(make(chan int))
	if err == nil {
		t.Fatalf("EncodeJSON(chan) = %s, nil; want a *json.UnsupportedTypeError", string(got))
	}
	var ute *json.UnsupportedTypeError
	if !errors.As(err, &ute) {
		t.Fatalf("EncodeJSON(chan) returned %T, want *json.UnsupportedTypeError", err)
	}
	if got != nil {
		t.Errorf("EncodeJSON(chan) returned bytes %s on error; want nil", string(got))
	}
}

func ExampleDecodeJSON() {
	// A typical use: read a typed `claims` payload off a single permission
	// entry returned by introspection. The raw bytes arrived in the
	// IntrospectionResponse without any deserialization cost.
	raw := json.RawMessage(`{"sub":"alice@example.com","email_verified":true}`)

	var claims struct {
		Sub           string `json:"sub"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := uma.DecodeJSON(raw, &claims); err != nil {
		fmt.Println("decode:", err)
		return
	}
	fmt.Printf("sub=%s verified=%t\n", claims.Sub, claims.EmailVerified)

	// An absent extension is a no-op — the typed value stays at its
	// zero value with no error.
	var absent struct {
		Sub string `json:"sub"`
	}
	if err := uma.DecodeJSON(nil, &absent); err != nil {
		fmt.Println("decode-nil:", err)
		return
	}
	fmt.Printf("sub=%q (absent extension)\n", absent.Sub)

	// Output:
	// sub=alice@example.com verified=true
	// sub="" (absent extension)
}

func ExampleEncodeJSON() {
	// Build a typed extension payload and attach it to an open-extension
	// field as opaque bytes — useful when populating, say, a metadata
	// document's vendor-specific fields.
	type docMeta struct {
		Owner      string   `json:"owner"`
		Classifier []string `json:"classifier"`
	}
	raw, err := uma.EncodeJSON(docMeta{
		Owner:      "alice@example.com",
		Classifier: []string{"internal"},
	})
	if err != nil {
		fmt.Println("encode:", err)
		return
	}
	fmt.Println(string(raw))

	// Encoding a nil value yields a nil RawMessage so the surrounding
	// field is omitted under an `omitempty` tag.
	none, err := uma.EncodeJSON(nil)
	if err != nil {
		fmt.Println("encode-nil:", err)
		return
	}
	fmt.Printf("nil bytes? %t\n", none == nil)

	// Output:
	// {"owner":"alice@example.com","classifier":["internal"]}
	// nil bytes? true
}

func TestEncodeDecodeJSON_RoundTrip(t *testing.T) {
	// The two helpers compose: EncodeJSON → DecodeJSON should reproduce
	// the input value exactly, including struct ordering.
	type ext struct {
		Role   string   `json:"role"`
		Scopes []string `json:"scopes"`
	}
	orig := ext{Role: "admin", Scopes: []string{"read", "write"}}
	raw, err := uma.EncodeJSON(orig)
	if err != nil {
		t.Fatalf("EncodeJSON: %v", err)
	}
	var back ext
	if err := uma.DecodeJSON(raw, &back); err != nil {
		t.Fatalf("DecodeJSON: %v", err)
	}
	if !reflect.DeepEqual(orig, back) {
		t.Errorf("round-trip mismatch: orig %+v, back %+v", orig, back)
	}
}
