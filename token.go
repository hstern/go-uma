// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package uma

import (
	"net/url"
)

// UMATicketGrantType is the URN identifying the UMA ticket grant, sent in
// the form-encoded `grant_type` parameter of every [TokenRequest] (Grant
// §3.3.1). The URN is IANA-registered in the OAuth Parameters registry; it
// is the discriminator that lets a vanilla OAuth 2.0 token endpoint route
// the request to the UMA grant handler.
const UMATicketGrantType = "urn:ietf:params:oauth:grant-type:uma-ticket"

// TokenRequest is the body of a POST to the AS's [TokenEndpoint] under the
// UMA ticket grant (Grant §3.3.1). Unlike the JSON-shaped messages elsewhere
// in this package, /token requests are form-encoded — the OAuth 2.0
// convention. Build the wire form with [TokenRequest.Values]; parse one
// coming the other way with [ParseTokenRequest].
//
// Ticket is the only field that is always required. The other fields are
// optional in combination — claim_token / claim_token_format come together
// when the client is pushing claims, pct echoes a persisted claims token
// from a prior /token exchange, rpt carries an existing RPT being
// upgraded, and scope narrows the requested scope set.
//
// grant_type is not exposed as a Go field: the encoder always emits
// UMATicketGrantType and the decoder enforces that exact URN. A consumer
// who wants to use a non-UMA grant on the same endpoint should reach for
// their OAuth 2.0 library, not this type.
type TokenRequest struct {
	// Ticket is the opaque permission ticket the RS issued in its 401
	// WWW-Authenticate challenge. Required.
	Ticket string

	// ClaimToken is a pushed claim token (e.g. an OpenID Connect ID token)
	// the client is offering to satisfy required-claims. Optional; paired
	// with ClaimTokenFormat.
	ClaimToken string

	// ClaimTokenFormat is the URN identifying ClaimToken's format. See
	// [ClaimTokenFormatIDToken] and friends for the conventional values.
	ClaimTokenFormat string

	// PCT is the persisted claims token returned in a prior [TokenResponse],
	// echoed back so the AS can resume any claims it had previously
	// accumulated.
	PCT string

	// RPT is an existing requesting-party token being upgraded with
	// additional scopes or claims. When present, a successful response
	// MAY set [TokenResponse.Upgraded] = true.
	RPT string

	// Scope narrows the requested permission scope set, space-separated
	// per RFC 6749. Optional; when absent the AS issues the full ticket
	// scope set.
	Scope string
}

// Values renders r as application/x-www-form-urlencoded values. The
// grant_type parameter is always set to UMATicketGrantType; empty optional
// fields are omitted so the URL-encoded body stays minimal.
func (r *TokenRequest) Values() url.Values {
	v := url.Values{}
	v.Set("grant_type", UMATicketGrantType)
	if r.Ticket != "" {
		v.Set("ticket", r.Ticket)
	}
	if r.ClaimToken != "" {
		v.Set("claim_token", r.ClaimToken)
	}
	if r.ClaimTokenFormat != "" {
		v.Set("claim_token_format", r.ClaimTokenFormat)
	}
	if r.PCT != "" {
		v.Set("pct", r.PCT)
	}
	if r.RPT != "" {
		v.Set("rpt", r.RPT)
	}
	if r.Scope != "" {
		v.Set("scope", r.Scope)
	}
	return v
}

// ParseTokenRequest decodes a form-encoded TokenRequest from v. It is lenient
// in the sense of the library's overall validation posture: unknown fields
// are ignored, and a missing ticket does not fail the parse (use the
// per-type validator at marshal time if strict checking is wanted). The
// only invariant ParseTokenRequest enforces is that grant_type, when set,
// matches UMATicketGrantType — anything else is not this grant.
//
// A nil v parses to a zero-value TokenRequest, mirroring net/url's
// treatment of an empty form body.
func ParseTokenRequest(v url.Values) *TokenRequest {
	if v == nil {
		return &TokenRequest{}
	}
	return &TokenRequest{
		Ticket:           v.Get("ticket"),
		ClaimToken:       v.Get("claim_token"),
		ClaimTokenFormat: v.Get("claim_token_format"),
		PCT:              v.Get("pct"),
		RPT:              v.Get("rpt"),
		Scope:            v.Get("scope"),
	}
}

// TokenResponse is the JSON 200 OK body returned by the AS on successful
// redemption of a [TokenRequest] (Grant §3.3.5). AccessToken is the
// requesting-party token (RPT) — opaque to consumers of this library; the
// AS chooses whether to issue a reference token or a JWT, and that choice
// does not change the wire shape.
//
// Upgraded is true when the response refreshes or extends an RPT the
// client sent in [TokenRequest.RPT]; clients can use that bit to know
// whether the new RPT supersedes the old or augments it. PCT echoes the
// persisted claims token so the client may pass it back on a future
// /token exchange.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Upgraded     bool   `json:"upgraded,omitempty"`
	PCT          string `json:"pct,omitempty"`
}
