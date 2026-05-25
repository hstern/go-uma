// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package uma_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/hstern/go-uma"
)

func TestPermissionRequest_JSON_RoundTrip(t *testing.T) {
	orig := uma.PermissionRequest{
		ResourceID:     "112210f47de98100",
		ResourceScopes: []string{"view", "http://photoz.example.com/dev/actions/print"},
	}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var back uma.PermissionRequest
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(orig, back) {
		t.Fatalf("round-trip mismatch:\n  orig: %+v\n  back: %+v", orig, back)
	}
}

func TestPermissionRequests_MarshalsAsArray(t *testing.T) {
	// Marshal always emits the array form, even for a single entry —
	// forward-compatible with a future spec revision that drops the
	// bare-object form.
	p := uma.PermissionRequests{{
		ResourceID:     "112210f47de98100",
		ResourceScopes: []string{"view"},
	}}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.HasPrefix(bytes.TrimSpace(b), []byte("[")) {
		t.Errorf("MarshalJSON should emit array form, got %s", string(b))
	}
	want := `[{"resource_id":"112210f47de98100","resource_scopes":["view"]}]`
	if string(b) != want {
		t.Errorf("Marshal = %s, want %s", string(b), want)
	}
}

func TestPermissionRequests_MarshalEmptyAndNil(t *testing.T) {
	// Both nil and empty marshal to `[]` — the wire form for "no
	// permissions registered in this call." The spec doesn't prescribe
	// this case (a real RS sends at least one permission) but the type
	// stays consistent under any input.
	tests := []struct {
		name string
		in   uma.PermissionRequests
	}{
		{"nil", nil},
		{"empty", uma.PermissionRequests{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.in)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if string(b) != "[]" {
				t.Errorf("Marshal(%s) = %s, want []", tc.name, string(b))
			}
		})
	}
}

func TestPermissionRequests_UnmarshalArrayForm(t *testing.T) {
	in := []byte(`[
		{"resource_id":"r1","resource_scopes":["view"]},
		{"resource_id":"r2","resource_scopes":["edit","delete"]}
	]`)
	var got uma.PermissionRequests
	if err := json.Unmarshal(in, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	want := uma.PermissionRequests{
		{ResourceID: "r1", ResourceScopes: []string{"view"}},
		{ResourceID: "r2", ResourceScopes: []string{"edit", "delete"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestPermissionRequests_UnmarshalSingleObjectForm(t *testing.T) {
	// Federated Authz §4.1 example uses the bare-object form.
	in := []byte(`{"resource_id":"112210f47de98100","resource_scopes":["view"]}`)
	var got uma.PermissionRequests
	if err := json.Unmarshal(in, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	want := uma.PermissionRequests{
		{ResourceID: "112210f47de98100", ResourceScopes: []string{"view"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestPermissionRequests_UnmarshalNull(t *testing.T) {
	// JSON null clears the slice to nil — matches stdlib slice
	// unmarshalling semantics. Without this branch, our UnmarshalJSON
	// would route `null` through the single-object decoder and produce
	// a one-entry slice with a zero PermissionRequest.
	got := uma.PermissionRequests{{ResourceID: "stale"}}
	if err := json.Unmarshal([]byte("null"), &got); err != nil {
		t.Fatalf("Unmarshal(null): %v", err)
	}
	if got != nil {
		t.Errorf("Unmarshal(null) left %+v, want nil", got)
	}
}

func TestPermissionRequests_UnmarshalInvalidJSON(t *testing.T) {
	// Malformed input propagates the stdlib error rather than silently
	// producing an empty slice.
	var got uma.PermissionRequests
	err := json.Unmarshal([]byte(`{not json`), &got)
	if err == nil {
		t.Fatalf("Unmarshal(invalid) = nil, want a json error")
	}
}

func TestPermissionRequests_UnmarshalArrayWithStaleSeed(t *testing.T) {
	// Defensive: ensure Unmarshal replaces, not appends, when the
	// destination slice already has elements.
	got := uma.PermissionRequests{{ResourceID: "stale"}}
	in := []byte(`[{"resource_id":"r1","resource_scopes":["view"]}]`)
	if err := json.Unmarshal(in, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(got) != 1 || got[0].ResourceID != "r1" {
		t.Errorf("got %+v, want exactly one entry r1", got)
	}
}

func TestPermissionRequests_RoundTrip_ArrayPreserved(t *testing.T) {
	// Even when the wire input was a single bare object, the round-trip
	// out should emit the array form — the library normalizes the
	// representation.
	orig := []byte(`{"resource_id":"r1","resource_scopes":["view"]}`)
	var decoded uma.PermissionRequests
	if err := json.Unmarshal(orig, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	re, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `[{"resource_id":"r1","resource_scopes":["view"]}]`
	if string(re) != want {
		t.Errorf("re-encode = %s, want %s", string(re), want)
	}
}

func TestPermissionResponse_JSON_RoundTrip(t *testing.T) {
	orig := uma.PermissionResponse{Ticket: "016f84e8-f9b9-11e0-bd6f-0021cc6004de"}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var back uma.PermissionResponse
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(orig, back) {
		t.Fatalf("round-trip mismatch:\n  orig: %+v\n  back: %+v", orig, back)
	}
	// The Federated Authz §4.2 example.
	want := `{"ticket":"016f84e8-f9b9-11e0-bd6f-0021cc6004de"}`
	if string(b) != want {
		t.Errorf("Marshal = %s, want %s", string(b), want)
	}
}
