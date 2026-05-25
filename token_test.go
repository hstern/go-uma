// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package uma_test

import (
	"encoding/json"
	"net/url"
	"reflect"
	"testing"

	"github.com/hstern/go-uma"
)

func TestUMATicketGrantType(t *testing.T) {
	// IANA-registered URN — an edit is almost certainly a regression.
	want := "urn:ietf:params:oauth:grant-type:uma-ticket"
	if uma.UMATicketGrantType != want {
		t.Errorf("UMATicketGrantType = %q, want %q", uma.UMATicketGrantType, want)
	}
}

func TestTokenRequest_Values_AlwaysEmitsGrantType(t *testing.T) {
	r := &uma.TokenRequest{Ticket: "tkt-1"}
	v := r.Values()
	if got := v.Get("grant_type"); got != uma.UMATicketGrantType {
		t.Errorf("grant_type = %q, want %q", got, uma.UMATicketGrantType)
	}
}

func TestTokenRequest_Values_OmitsEmptyOptionalFields(t *testing.T) {
	// Optional fields that are empty must not appear in the encoded form.
	// A pure-grant-type encoding has just two keys: grant_type + ticket.
	r := &uma.TokenRequest{Ticket: "tkt-1"}
	v := r.Values()
	wantKeys := map[string]bool{"grant_type": true, "ticket": true}
	for k := range v {
		if !wantKeys[k] {
			t.Errorf("unexpected key in form: %q (value %q)", k, v.Get(k))
		}
	}
	if len(v) != len(wantKeys) {
		t.Errorf("form has %d keys, want %d (keys: %v)", len(v), len(wantKeys), v)
	}
}

func TestTokenRequest_Values_AllFields(t *testing.T) {
	r := &uma.TokenRequest{
		Ticket:           "tkt-1",
		ClaimToken:       "id.token.value",
		ClaimTokenFormat: "http://openid.net/specs/openid-connect-core-1_0.html#IDToken",
		PCT:              "pct-1",
		RPT:              "rpt-old",
		Scope:            "read write",
	}
	v := r.Values()
	for _, c := range []struct{ key, want string }{
		{"grant_type", uma.UMATicketGrantType},
		{"ticket", "tkt-1"},
		{"claim_token", "id.token.value"},
		{"claim_token_format", "http://openid.net/specs/openid-connect-core-1_0.html#IDToken"},
		{"pct", "pct-1"},
		{"rpt", "rpt-old"},
		{"scope", "read write"},
	} {
		if got := v.Get(c.key); got != c.want {
			t.Errorf("%s = %q, want %q", c.key, got, c.want)
		}
	}
}

func TestParseTokenRequest_RoundTrip(t *testing.T) {
	orig := &uma.TokenRequest{
		Ticket:           "tkt-1",
		ClaimToken:       "id.token.value",
		ClaimTokenFormat: "http://openid.net/specs/openid-connect-core-1_0.html#IDToken",
		PCT:              "pct-1",
		RPT:              "rpt-old",
		Scope:            "read write",
	}
	back := uma.ParseTokenRequest(orig.Values())
	if !reflect.DeepEqual(orig, back) {
		t.Fatalf("round-trip mismatch:\n  orig: %+v\n  back: %+v", orig, back)
	}
}

func TestParseTokenRequest_NilValues(t *testing.T) {
	// Parsing a nil url.Values must produce a zero-value TokenRequest
	// rather than dereferencing nil — matches net/url's "empty form".
	back := uma.ParseTokenRequest(nil)
	if back == nil {
		t.Fatalf("ParseTokenRequest(nil) = nil pointer, want zero-value *TokenRequest")
	}
	if (*back) != (uma.TokenRequest{}) {
		t.Errorf("ParseTokenRequest(nil) = %+v, want zero value", *back)
	}
}

func TestParseTokenRequest_IgnoresUnknown(t *testing.T) {
	// Forward-compatible: unknown form fields are silently dropped.
	v := url.Values{}
	v.Set("ticket", "tkt-1")
	v.Set("custom_extension_field", "ignored")
	back := uma.ParseTokenRequest(v)
	if back.Ticket != "tkt-1" {
		t.Errorf("Ticket = %q, want tkt-1", back.Ticket)
	}
}

func TestTokenResponse_JSON_RoundTrip(t *testing.T) {
	orig := uma.TokenResponse{
		AccessToken:  "rpt-new",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "rft-1",
		Upgraded:     true,
		PCT:          "pct-1",
	}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var back uma.TokenResponse
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(orig, back) {
		t.Fatalf("round-trip mismatch:\n  orig: %+v\n  back: %+v", orig, back)
	}
}

func TestTokenResponse_JSON_OmitsZeroFields(t *testing.T) {
	// Only access_token is required by the spec — the rest carry
	// omitempty so a minimal response stays minimal on the wire.
	r := uma.TokenResponse{AccessToken: "rpt-new"}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"access_token":"rpt-new"}`
	if string(b) != want {
		t.Errorf("Marshal = %s, want %s", string(b), want)
	}
}

func TestTokenResponse_JSON_DecodeSpecFigure(t *testing.T) {
	// Grant §3.3.5 example response.
	fig := `{
		"access_token":"sbjsbhs(/SSJHBSUSSJHVhjsgvhsgvshgsv",
		"token_type":"Bearer",
		"expires_in":3600,
		"refresh_token":"SSJHBSUSSJHVhjsgvhsgvshgsv",
		"upgraded":true,
		"pct":"sbjsbhs(/SSJHBSUSSJHVhjsgvhsgvshgsv"
	}`
	var got uma.TokenResponse
	if err := json.Unmarshal([]byte(fig), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.AccessToken == "" {
		t.Errorf("AccessToken empty after decode of spec figure: %+v", got)
	}
	if got.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want Bearer", got.TokenType)
	}
	if !got.Upgraded {
		t.Errorf("Upgraded = false, want true")
	}
}
