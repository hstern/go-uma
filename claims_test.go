// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package uma_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/hstern/go-uma"
)

func TestClaimTokenFormatIDToken(t *testing.T) {
	// The OpenID Connect ID token URN is the canonical example in
	// Grant §3.3.1 — pinning it here so an accidental edit is a
	// regression.
	want := "http://openid.net/specs/openid-connect-core-1_0.html#IDToken"
	if string(uma.ClaimTokenFormatIDToken) != want {
		t.Errorf("ClaimTokenFormatIDToken = %q, want %q", uma.ClaimTokenFormatIDToken, want)
	}
}

func TestRequiredClaim_RoundTrip(t *testing.T) {
	// Spec §3.3.6 example entry shape.
	orig := uma.RequiredClaim{
		ClaimTokenFormat: []uma.ClaimTokenFormat{uma.ClaimTokenFormatIDToken},
		ClaimType:        "urn:oid:1.3.6.1.5.5.7.9.1",
		FriendlyName:     "email",
		Issuer:           []string{"https://example.com/op"},
	}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var back uma.RequiredClaim
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(orig, back) {
		t.Fatalf("round-trip mismatch:\n  orig: %+v\n  back: %+v", orig, back)
	}
}

func TestRequiredClaim_DecodeSpecFigure(t *testing.T) {
	// Grant §3.3.6 example (with claim_token_format as a single-entry
	// array, the spec-mandated shape).
	fig := `{
		"claim_token_format":["http://openid.net/specs/openid-connect-core-1_0.html#IDToken"],
		"claim_type":"urn:oid:1.3.6.1.5.5.7.9.1",
		"friendly_name":"email",
		"issuer":["https://example.com/op"]
	}`
	var got uma.RequiredClaim
	if err := json.Unmarshal([]byte(fig), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(got.ClaimTokenFormat) != 1 || got.ClaimTokenFormat[0] != uma.ClaimTokenFormatIDToken {
		t.Errorf("ClaimTokenFormat = %v, want [IDToken]", got.ClaimTokenFormat)
	}
	if got.ClaimType != "urn:oid:1.3.6.1.5.5.7.9.1" {
		t.Errorf("ClaimType = %q, want OID", got.ClaimType)
	}
	if got.FriendlyName != "email" {
		t.Errorf("FriendlyName = %q, want email", got.FriendlyName)
	}
	if len(got.Issuer) != 1 || got.Issuer[0] != "https://example.com/op" {
		t.Errorf("Issuer = %v, want [example.com/op]", got.Issuer)
	}
}

func TestRequiredClaim_OmitsEmptyFields(t *testing.T) {
	// A zero RequiredClaim marshals to `{}`, not to a soup of empty
	// arrays and strings.
	r := uma.RequiredClaim{}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(b) != "{}" {
		t.Errorf("zero RequiredClaim = %s, want {}", string(b))
	}
}

func TestNewPushedClaimsTokenRequest(t *testing.T) {
	got := uma.NewPushedClaimsTokenRequest(
		"tkt-1",
		"id.token.value",
		uma.ClaimTokenFormatIDToken,
	)
	want := &uma.TokenRequest{
		Ticket:           "tkt-1",
		ClaimToken:       "id.token.value",
		ClaimTokenFormat: string(uma.ClaimTokenFormatIDToken),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("NewPushedClaimsTokenRequest:\n  got:  %+v\n  want: %+v", got, want)
	}
	// The resulting Values() form carries claim_token + claim_token_format.
	v := got.Values()
	if v.Get("claim_token") != "id.token.value" {
		t.Errorf("claim_token in form = %q, want id.token.value", v.Get("claim_token"))
	}
	if v.Get("claim_token_format") != string(uma.ClaimTokenFormatIDToken) {
		t.Errorf("claim_token_format in form = %q, want IDToken URN", v.Get("claim_token_format"))
	}
}
