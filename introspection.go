// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package uma

import (
	"encoding/json"
	"net/url"
)

// IntrospectionRequest is the form-encoded body of a POST to the AS's
// [IntrospectionEndpoint] (Federated Authz §5.1). The shape is identical
// to RFC 7662 §2.1 — UMA does not extend the request side of token
// introspection; it only extends the response with the permissions array.
//
// Token is the requesting-party token being introspected. TokenTypeHint
// is the optional hint defined by RFC 7662 §2.1; consumers may set it to
// `pct` or `requesting_party_token` when known, but the AS is free to
// ignore it.
type IntrospectionRequest struct {
	Token         string
	TokenTypeHint string
}

// Values renders r as application/x-www-form-urlencoded values. Empty
// optional fields are omitted.
func (r *IntrospectionRequest) Values() url.Values {
	v := url.Values{}
	if r.Token != "" {
		v.Set("token", r.Token)
	}
	if r.TokenTypeHint != "" {
		v.Set("token_type_hint", r.TokenTypeHint)
	}
	return v
}

// ParseIntrospectionRequest decodes a form-encoded IntrospectionRequest
// from v. A nil v yields a zero-value IntrospectionRequest; unknown form
// keys are silently dropped per RFC 6749 forward-compatibility.
func ParseIntrospectionRequest(v url.Values) *IntrospectionRequest {
	if v == nil {
		return &IntrospectionRequest{}
	}
	return &IntrospectionRequest{
		Token:         v.Get("token"),
		TokenTypeHint: v.Get("token_type_hint"),
	}
}

// Validate checks the required-field invariants on r and returns a typed
// *ValidationError when one is missing. Token is the only required field
// per RFC 7662 §2.1; TokenTypeHint is optional.
func (r *IntrospectionRequest) Validate() error {
	if r == nil || r.Token == "" {
		return &ValidationError{Type: "IntrospectionRequest", Field: "token", Message: "required"}
	}
	return nil
}

// IntrospectionResponse is the JSON body returned by the AS in response to
// an introspection request (Federated Authz §5.1.1). It carries the
// standard RFC 7662 §2.2 fields plus the UMA-specific Permissions array.
//
// Active is the load-bearing field: an Active=false response is NOT a
// transport error — the AS is reporting that the token is unknown,
// revoked, or expired, and the response is otherwise valid. Consumers
// must branch on Active rather than treating the response as a failure.
//
// When Active is true the AS MAY include any of the RFC 7662 fields
// (Sub, ClientID, Username, exp/iat/nbf, scope, aud, iss, jti, etc.) and
// UMA layers its Permissions array on top. The library exposes every
// optional field with `omitempty` so an AS that returns a minimal
// response — just {"active":true} — round-trips byte-stable.
type IntrospectionResponse struct {
	// Active is the only required field. Per RFC 7662 a false value
	// indicates the token is not currently active for any reason —
	// unknown, revoked, expired, or not yet valid.
	Active bool `json:"active"`

	// Permissions is the UMA-specific extension (Federated Authz §5.1.1):
	// the set of resource permissions the RPT currently grants. May be
	// empty even on an active token.
	Permissions []Permission `json:"permissions,omitempty"`

	// The following are the RFC 7662 §2.2 optional fields, included
	// verbatim so the library is a drop-in for plain OAuth introspection
	// against a UMA-aware AS.
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Nbf       int64  `json:"nbf,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Aud       string `json:"aud,omitempty"`
	Iss       string `json:"iss,omitempty"`
	JTI       string `json:"jti,omitempty"`
}

// Permission is a single entry in an [IntrospectionResponse.Permissions]
// array (Federated Authz §5.1.1). It pairs a resource identifier with
// the scopes the RPT grants on that resource, optionally narrowed by an
// expiry timestamp and an open-extension claims payload the AS may
// include when claims-based access decisions are part of the issued
// permission.
//
// The Claims field is [json.RawMessage] so it round-trips byte-stably
// regardless of key order. Bridge it to a typed Go value with
// [DecodeJSON] and [EncodeJSON].
//
// Permission shares fields with [PermissionRequest] but is a separate
// type: PermissionRequest is what the RS sends to the AS at registration
// time (just resource_id + resource_scopes), while Permission is what
// the AS returns at introspection time (plus exp + claims).
type Permission struct {
	ResourceID     string          `json:"resource_id"`
	ResourceScopes []string        `json:"resource_scopes"`
	Exp            int64           `json:"exp,omitempty"`
	Claims         json.RawMessage `json:"claims,omitempty"`
}
