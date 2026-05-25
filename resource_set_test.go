// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package uma_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/hstern/go-uma"
)

func TestResourceSet_RegisterBody_OmitsServerFields(t *testing.T) {
	// An RS building a POST /resource_set body should never leak ID or
	// user_access_policy_uri onto the wire — those are AS-assigned.
	rs := uma.ResourceSet{
		ResourceScopes: []string{"view", "edit"},
		Name:           "My Photos",
		URI:            "http://photoz.example.com/me",
		Type:           "http://www.example.com/rsrcs/photoalbum",
		IconURI:        "http://photoz.example.com/icons/album.png",
		Description:    "Alice's vacation photos",
	}
	b, err := json.Marshal(rs)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, forbidden := range []string{`"_id"`, `"user_access_policy_uri"`} {
		if contains(b, forbidden) {
			t.Errorf("register body contains AS-assigned field %s: %s", forbidden, string(b))
		}
	}
}

func TestResourceSet_CreateResponse_RoundTrip(t *testing.T) {
	// Federated Authz §2.3.1 — POST returns just _id (+ optional
	// user_access_policy_uri). Every other field empty / absent.
	body := `{"_id":"112210f47de98100","user_access_policy_uri":"https://as.example.com/uma/policy/112210f47de98100"}`
	var got uma.ResourceSet
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.ID != "112210f47de98100" {
		t.Errorf("ID = %q, want 112210f47de98100", got.ID)
	}
	if got.UserAccessPolicyURI == "" {
		t.Errorf("UserAccessPolicyURI empty after decode of POST response")
	}
	if got.Name != "" || len(got.ResourceScopes) != 0 {
		t.Errorf("POST response decode populated description fields it should not have: %+v", got)
	}
	// Re-encoding the response keeps just the AS-assigned fields.
	out, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(out) != body {
		t.Errorf("re-encode = %s, want %s", string(out), body)
	}
}

func TestResourceSet_FullGet_RoundTrip(t *testing.T) {
	// GET /resource_set/{rsid} returns the full record with _id populated.
	orig := uma.ResourceSet{
		ResourceScopes:      []string{"view", "edit"},
		Name:                "My Photos",
		URI:                 "http://photoz.example.com/me",
		Type:                "http://www.example.com/rsrcs/photoalbum",
		IconURI:             "http://photoz.example.com/icons/album.png",
		Description:         "Alice's vacation photos",
		ID:                  "112210f47de98100",
		UserAccessPolicyURI: "https://as.example.com/uma/policy/112210f47de98100",
	}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var back uma.ResourceSet
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(orig, back) {
		t.Fatalf("round-trip mismatch:\n  orig: %+v\n  back: %+v", orig, back)
	}
}

func TestResourceSet_ListResponse_StringArray(t *testing.T) {
	// LIST returns a JSON array of IDs, not an array of full records.
	// The library uses []string at the call site; this test pins the
	// wire expectation.
	body := `["abc","def","112210f47de98100"]`
	var got []string
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	want := []string{"abc", "def", "112210f47de98100"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestResourceSetOp_String(t *testing.T) {
	tests := []struct {
		op   uma.ResourceSetOp
		want string
	}{
		{uma.OpUnknown, "unknown"},
		{uma.OpCreate, "create"},
		{uma.OpRead, "read"},
		{uma.OpUpdate, "update"},
		{uma.OpDelete, "delete"},
		{uma.OpList, "list"},
	}
	for _, tc := range tests {
		if got := tc.op.String(); got != tc.want {
			t.Errorf("%d.String() = %q, want %q", tc.op, got, tc.want)
		}
	}
}

func TestResourceSetOp_String_OutOfRange(t *testing.T) {
	// Defensive: an out-of-range op renders as ResourceSetOp(N) rather
	// than panicking.
	got := uma.ResourceSetOp(99).String()
	want := "ResourceSetOp(99)"
	if got != want {
		t.Errorf("ResourceSetOp(99).String() = %q, want %q", got, want)
	}
}

func TestResourceSetOp_ZeroValueIsUnknown(t *testing.T) {
	// A var op ResourceSetOp must be OpUnknown, NOT OpCreate. This is
	// the load-bearing reason OpUnknown sits at iota 0.
	var op uma.ResourceSetOp
	if op != uma.OpUnknown {
		t.Errorf("zero value = %v, want OpUnknown", op)
	}
}

// contains is a small helper that avoids importing strings.Contains just
// for this file's byte-search tests.
func contains(b []byte, s string) bool {
	bs := []byte(s)
	for i := 0; i+len(bs) <= len(b); i++ {
		match := true
		for j := range bs {
			if b[i+j] != bs[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
