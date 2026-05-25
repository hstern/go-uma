// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package uma

// ClaimTokenFormat is the typed URN identifying a pushed-claim token's
// format (Grant §3.3.1 — `claim_token_format` field on a [TokenRequest],
// and `claim_token_format` on each entry of a [RequiredClaim]).
//
// Format URNs form an open registry — the spec enumerates none. The
// constants below name the only convention well-established enough to
// be useful out of the box; consumers register additional URNs at the
// call site.
type ClaimTokenFormat string

const (
	// ClaimTokenFormatIDToken is the URN identifying an OpenID Connect
	// 1.0 ID token (Grant §3.3.1 example). The most common pushed-claim
	// format in deployments today.
	ClaimTokenFormatIDToken ClaimTokenFormat = "http://openid.net/specs/openid-connect-core-1_0.html#IDToken"
)

// RequiredClaim is a single entry in the `required_claims` array of an
// AS's `need_info` error response (Grant §3.3.6). The AS uses it to tell
// a requesting-party client which claims it must obtain and present in a
// subsequent /token request — by either pushing a claim token of the
// indicated format or following the `redirect_user` URL on the parent
// error envelope for AS-driven claims gathering.
//
// ClaimTokenFormat is an array because the AS may accept any of several
// equivalent formats for the same logical claim — e.g. an OpenID Connect
// ID token or a SAML assertion both convey "the user's email is verified".
// Issuer is an array because more than one issuer may be acceptable.
type RequiredClaim struct {
	// ClaimTokenFormat lists the URNs of token formats the AS will
	// accept for this claim. At least one entry should be set; empty
	// means "any format the AS recognizes."
	ClaimTokenFormat []ClaimTokenFormat `json:"claim_token_format,omitempty"`

	// ClaimType is the URN identifying the type of claim required —
	// e.g. an X.509 OID like "urn:oid:1.3.6.1.5.5.7.9.1" for date of
	// birth, or a URN naming an application-specific concept.
	ClaimType string `json:"claim_type,omitempty"`

	// FriendlyName is a human-readable string the client may render to
	// the requesting party while gathering the claim.
	FriendlyName string `json:"friendly_name,omitempty"`

	// Issuer lists the URLs of issuers from which the AS will accept
	// this claim. An empty list means "any issuer the AS trusts."
	Issuer []string `json:"issuer,omitempty"`
}

// NewPushedClaimsTokenRequest builds a [TokenRequest] carrying a single
// pushed claim token in the named format. The function exists to surface
// the typed [ClaimTokenFormat] constants at the call site — directly
// setting [TokenRequest.ClaimToken] and [TokenRequest.ClaimTokenFormat]
// is equally valid.
func NewPushedClaimsTokenRequest(ticket, claimToken string, format ClaimTokenFormat) *TokenRequest {
	return &TokenRequest{
		Ticket:           ticket,
		ClaimToken:       claimToken,
		ClaimTokenFormat: string(format),
	}
}
