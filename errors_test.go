// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package uma_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/hstern/go-uma"
)

func TestErrorCodes_PinnedToSpec(t *testing.T) {
	// Every error code is normatively defined; an edit is almost
	// certainly a regression.
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"InvalidGrant", uma.ErrorCodeInvalidGrant, "invalid_grant"},
		{"InvalidScope", uma.ErrorCodeInvalidScope, "invalid_scope"},
		{"InvalidToken", uma.ErrorCodeInvalidToken, "invalid_token"},
		{"NeedInfo", uma.ErrorCodeNeedInfo, "need_info"},
		{"RequestSubmitted", uma.ErrorCodeRequestSubmitted, "request_submitted"},
		{"NotAuthorized", uma.ErrorCodeNotAuthorized, "not_authorized"},
	}
	for _, tc := range tests {
		if tc.got != tc.want {
			t.Errorf("ErrorCode%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

func TestOAuthError_String(t *testing.T) {
	tests := []struct {
		name string
		err  *uma.OAuthError
		want string
	}{
		{
			"with description",
			&uma.OAuthError{ErrorCode: "invalid_grant", ErrorDescription: "ticket expired"},
			"invalid_grant: ticket expired",
		},
		{
			"code only",
			&uma.OAuthError{ErrorCode: "not_authorized"},
			"not_authorized",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.want {
				t.Errorf("Error() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestOAuthError_Is_MatchesByCode(t *testing.T) {
	// A freshly-constructed *OAuthError with the same code matches the
	// sentinel via errors.Is — that's the load-bearing property of
	// (*OAuthError).Is.
	returned := &uma.OAuthError{
		ErrorCode:        uma.ErrorCodeNeedInfo,
		ErrorDescription: "claims required",
	}
	if !errors.Is(returned, uma.ErrNeedInfo) {
		t.Errorf("errors.Is(returned, ErrNeedInfo) = false, want true (codes match)")
	}
	// Different code = no match.
	if errors.Is(returned, uma.ErrNotAuthorized) {
		t.Errorf("errors.Is(need_info-err, ErrNotAuthorized) = true, want false")
	}
	// Non-*OAuthError target = no match.
	other := errors.New("some other error")
	if errors.Is(returned, other) {
		t.Errorf("errors.Is(uma.OAuthError, errors.New) = true, want false")
	}
}

func TestOAuthError_JSON_RoundTrip(t *testing.T) {
	orig := uma.OAuthError{
		ErrorCode:        "invalid_grant",
		ErrorDescription: "permission ticket expired",
		ErrorURI:         "https://as.example.com/errors/invalid_grant",
	}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var back uma.OAuthError
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(orig, back) {
		t.Fatalf("round-trip mismatch:\n  orig: %+v\n  back: %+v", orig, back)
	}
}

func TestOAuthError_JSON_OmitsEmptyOptional(t *testing.T) {
	e := uma.OAuthError{ErrorCode: "not_authorized"}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"error":"not_authorized"}`
	if string(b) != want {
		t.Errorf("Marshal = %s, want %s", string(b), want)
	}
}

func TestNeedInfoError_JSON_DecodeSpecFigure(t *testing.T) {
	// Grant §3.3.6 example need_info response.
	fig := `{
		"error":"need_info",
		"ticket":"abc-def-ghi",
		"required_claims":[
			{
				"claim_token_format":["http://openid.net/specs/openid-connect-core-1_0.html#IDToken"],
				"claim_type":"urn:oid:1.3.6.1.5.5.7.9.1",
				"friendly_name":"email",
				"issuer":["https://example.com/op"]
			}
		],
		"redirect_user":"https://as.example.com/uma/claims_redirect?ticket=abc-def-ghi"
	}`
	var got uma.NeedInfoError
	if err := json.Unmarshal([]byte(fig), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.ErrorCode != "need_info" {
		t.Errorf("ErrorCode = %q, want need_info", got.ErrorCode)
	}
	if got.Ticket != "abc-def-ghi" {
		t.Errorf("Ticket = %q, want abc-def-ghi", got.Ticket)
	}
	if len(got.RequiredClaims) != 1 {
		t.Fatalf("RequiredClaims len = %d, want 1", len(got.RequiredClaims))
	}
	if got.RedirectUser == "" {
		t.Errorf("RedirectUser empty, want set")
	}
}

func TestNeedInfoError_RoundTrip(t *testing.T) {
	orig := uma.NeedInfoError{
		OAuthError: uma.OAuthError{
			ErrorCode:        uma.ErrorCodeNeedInfo,
			ErrorDescription: "claims required",
		},
		Ticket: "abc-def-ghi",
		RequiredClaims: []uma.RequiredClaim{
			{
				ClaimTokenFormat: []uma.ClaimTokenFormat{uma.ClaimTokenFormatIDToken},
				ClaimType:        "urn:oid:1.3.6.1.5.5.7.9.1",
				FriendlyName:     "email",
				Issuer:           []string{"https://example.com/op"},
			},
		},
		RedirectUser: "https://as.example.com/uma/claims_redirect?ticket=abc-def-ghi",
	}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var back uma.NeedInfoError
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(orig, back) {
		t.Fatalf("round-trip mismatch:\n  orig: %+v\n  back: %+v", orig, back)
	}
}

func TestNeedInfoError_ErrorsAs(t *testing.T) {
	// errors.As against *NeedInfoError must unwrap a wrapped need-info.
	ne := &uma.NeedInfoError{
		OAuthError: uma.OAuthError{ErrorCode: uma.ErrorCodeNeedInfo},
		Ticket:     "abc",
	}
	var err error = ne
	var extracted *uma.NeedInfoError
	if !errors.As(err, &extracted) {
		t.Fatalf("errors.As(*NeedInfoError) = false, want true")
	}
	if extracted.Ticket != "abc" {
		t.Errorf("extracted.Ticket = %q, want abc", extracted.Ticket)
	}
}

func TestNeedInfoError_IsMatchesNeedInfoSentinel(t *testing.T) {
	// errors.Is(needInfo, ErrNeedInfo) works via the embedded
	// OAuthError.Is (promoted method).
	ne := &uma.NeedInfoError{OAuthError: uma.OAuthError{ErrorCode: uma.ErrorCodeNeedInfo}}
	if !errors.Is(ne, uma.ErrNeedInfo) {
		t.Errorf("errors.Is(*NeedInfoError, ErrNeedInfo) = false, want true (embedded OAuthError.Is)")
	}
}

func TestNeedInfoError_PromotedErrorMethod(t *testing.T) {
	// The embedded OAuthError's Error() string method is promoted, so
	// *NeedInfoError satisfies the error interface without an explicit
	// (*NeedInfoError).Error.
	ne := &uma.NeedInfoError{
		OAuthError: uma.OAuthError{
			ErrorCode:        uma.ErrorCodeNeedInfo,
			ErrorDescription: "claims required",
		},
	}
	var _ error = ne // compile-time assertion
	want := "need_info: claims required"
	if got := ne.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestErrNotImplemented(t *testing.T) {
	// ErrNotImplemented is the simple-sentinel form (errors.New),
	// matched by errors.Is via stdlib pointer-equality.
	if uma.ErrNotImplemented == nil {
		t.Fatal("ErrNotImplemented is nil")
	}
	if uma.ErrNotImplemented.Error() != "uma: endpoint not implemented" {
		t.Errorf("ErrNotImplemented = %q, want \"uma: endpoint not implemented\"", uma.ErrNotImplemented.Error())
	}
	if !errors.Is(uma.ErrNotImplemented, uma.ErrNotImplemented) {
		t.Errorf("errors.Is(ErrNotImplemented, ErrNotImplemented) = false")
	}
}

func TestValidationError_Error(t *testing.T) {
	tests := []struct {
		name string
		err  *uma.ValidationError
		want string
	}{
		{
			"with message",
			&uma.ValidationError{Type: "TokenRequest", Field: "ticket", Message: "required"},
			"uma: TokenRequest.ticket: required",
		},
		{
			"without message",
			&uma.ValidationError{Type: "ResourceSet", Field: "name"},
			"uma: ResourceSet.name: invalid",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.want {
				t.Errorf("Error() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNilReceiverNoPanic(t *testing.T) {
	// Defensive: nil receivers on the standalone types (*OAuthError and
	// *ValidationError) return a sentinel string rather than panicking.
	// *NeedInfoError's Error() comes via promotion through the embedded
	// OAuthError and panics on a nil outer pointer — that is the
	// standard behavior for promoted methods and callers should not
	// invoke Error() on an unchecked nil error value.
	var e *uma.OAuthError
	if got := e.Error(); got == "" {
		t.Errorf("nil *OAuthError.Error() = empty string; want a non-empty sentinel")
	}
	var ve *uma.ValidationError
	if got := ve.Error(); got == "" {
		t.Errorf("nil *ValidationError.Error() = empty string; want a non-empty sentinel")
	}
}
