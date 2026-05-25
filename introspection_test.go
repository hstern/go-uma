// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package uma_test

import (
	"bytes"
	"encoding/json"
	"net/url"
	"reflect"
	"testing"

	"github.com/hstern/go-uma"
)

func TestIntrospectionRequest_Values_RoundTrip(t *testing.T) {
	orig := &uma.IntrospectionRequest{
		Token:         "rpt-abc",
		TokenTypeHint: "requesting_party_token",
	}
	v := orig.Values()
	if v.Get("token") != "rpt-abc" {
		t.Errorf("token = %q, want rpt-abc", v.Get("token"))
	}
	if v.Get("token_type_hint") != "requesting_party_token" {
		t.Errorf("token_type_hint = %q, want requesting_party_token", v.Get("token_type_hint"))
	}
	back := uma.ParseIntrospectionRequest(v)
	if !reflect.DeepEqual(orig, back) {
		t.Fatalf("round-trip mismatch:\n  orig: %+v\n  back: %+v", orig, back)
	}
}

func TestIntrospectionRequest_Values_OmitsEmpty(t *testing.T) {
	r := &uma.IntrospectionRequest{Token: "rpt-abc"}
	v := r.Values()
	if v.Has("token_type_hint") {
		t.Errorf("empty token_type_hint must be omitted, got %v", v)
	}
}

func TestParseIntrospectionRequest_NilAndUnknown(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		back := uma.ParseIntrospectionRequest(nil)
		if back == nil || *back != (uma.IntrospectionRequest{}) {
			t.Errorf("got %+v, want zero-value pointer", back)
		}
	})
	t.Run("unknown fields ignored", func(t *testing.T) {
		v := url.Values{}
		v.Set("token", "rpt-abc")
		v.Set("custom_extension", "ignored")
		back := uma.ParseIntrospectionRequest(v)
		if back.Token != "rpt-abc" {
			t.Errorf("Token = %q, want rpt-abc", back.Token)
		}
	})
}

func TestIntrospectionResponse_ActiveFalse_MinimalRoundTrip(t *testing.T) {
	// Active=false is the spec's "token unknown / revoked / expired"
	// signal — NOT a transport error. The response is otherwise valid
	// and `omitempty` should drop every other field.
	orig := uma.IntrospectionResponse{Active: false}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"active":false}`
	if string(b) != want {
		t.Errorf("Marshal(Active=false) = %s, want %s", string(b), want)
	}
	var back uma.IntrospectionResponse
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.Active {
		t.Errorf("Active = true after round-trip, want false")
	}
}

func TestIntrospectionResponse_ActiveTrue_FullRoundTrip(t *testing.T) {
	orig := uma.IntrospectionResponse{
		Active:    true,
		Scope:     "read write",
		ClientID:  "client-1",
		Username:  "alice@example.com",
		TokenType: "Bearer",
		Exp:       1256953732,
		Iat:       1256912345,
		Sub:       "alice@example.com",
		Iss:       "https://as.example.com",
		Permissions: []uma.Permission{
			{
				ResourceID:     "112210f47de98100",
				ResourceScopes: []string{"view", "http://photoz.example.com/dev/actions/print"},
				Exp:            1256953732,
			},
		},
	}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var back uma.IntrospectionResponse
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(orig, back) {
		t.Fatalf("round-trip mismatch:\n  orig: %+v\n  back: %+v", orig, back)
	}
}

func TestIntrospectionResponse_DecodeSpecFigure(t *testing.T) {
	// Federated Authz §5.1.1 example response.
	fig := `{
		"active":true,
		"exp":1256953732,
		"iat":1256912345,
		"permissions":[
			{
				"resource_id":"112210f47de98100",
				"resource_scopes":["view","http://photoz.example.com/dev/actions/print"],
				"exp":1256953732
			}
		]
	}`
	var got uma.IntrospectionResponse
	if err := json.Unmarshal([]byte(fig), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !got.Active {
		t.Errorf("Active = false, want true")
	}
	if len(got.Permissions) != 1 {
		t.Fatalf("Permissions len = %d, want 1", len(got.Permissions))
	}
	p := got.Permissions[0]
	if p.ResourceID != "112210f47de98100" {
		t.Errorf("ResourceID = %q, want 112210f47de98100", p.ResourceID)
	}
	if len(p.ResourceScopes) != 2 {
		t.Errorf("ResourceScopes len = %d, want 2", len(p.ResourceScopes))
	}
	if p.Exp != 1256953732 {
		t.Errorf("Exp = %d, want 1256953732", p.Exp)
	}
}

func TestPermission_ClaimsByteStable(t *testing.T) {
	// Claims is json.RawMessage so wire bytes round-trip verbatim — Go
	// map iteration would otherwise scramble key order on every marshal.
	rawIn := json.RawMessage(`{"z":1,"a":2,"m":3,"b":4}`)
	p := uma.Permission{
		ResourceID:     "r1",
		ResourceScopes: []string{"view"},
		Claims:         rawIn,
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Contains(b, []byte(`"claims":{"z":1,"a":2,"m":3,"b":4}`)) {
		t.Fatalf("Claims byte-order not preserved on encode: got %s", string(b))
	}
	var back uma.Permission
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !bytes.Equal(back.Claims, rawIn) {
		t.Errorf("Claims bytes after round-trip = %s, want %s", string(back.Claims), string(rawIn))
	}
}

func TestPermission_OmitsEmptyExpAndClaims(t *testing.T) {
	// A Permission entry without exp/claims renders without those keys.
	p := uma.Permission{ResourceID: "r1", ResourceScopes: []string{"view"}}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"resource_id":"r1","resource_scopes":["view"]}`
	if string(b) != want {
		t.Errorf("Marshal = %s, want %s", string(b), want)
	}
}
