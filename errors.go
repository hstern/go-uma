// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package uma

import (
	"errors"
	"fmt"
)

// OAuth 2.0 error codes used across UMA's wire surface. The first three
// are inherited verbatim from RFC 6749 §5.2 / RFC 7662 §2.3; the
// remaining three are the UMA Grant §3.3.6 additions that signal the
// claims-gathering and policy-deny outcomes specific to the UMA-ticket
// grant.
const (
	// ErrorCodeInvalidGrant is the RFC 6749 §5.2 code returned on
	// /token when the permission ticket is unknown, expired, or
	// revoked.
	ErrorCodeInvalidGrant = "invalid_grant"

	// ErrorCodeInvalidScope is the RFC 6749 §5.2 code returned when
	// the requested scope set is not allowed for the resource.
	ErrorCodeInvalidScope = "invalid_scope"

	// ErrorCodeInvalidToken is the RFC 7662 §2.3 code returned by the
	// AS's introspection endpoint when the introspected token is
	// invalid in a way that itself constitutes an error (as opposed
	// to merely inactive — that case rides on
	// IntrospectionResponse.Active=false with no transport error).
	ErrorCodeInvalidToken = "invalid_token"

	// ErrorCodeNeedInfo is the UMA Grant §3.3.6 code returned when the
	// AS cannot decide authorization with the information it has and
	// the client must gather more claims. The accompanying response
	// body carries a fresh permission ticket and a list of required
	// claims; decode it into [NeedInfoError] via [errors.As].
	ErrorCodeNeedInfo = "need_info"

	// ErrorCodeRequestSubmitted is the UMA Grant §3.3.6 code returned
	// when the AS has queued the access request for the resource
	// owner to approve out-of-band. The client's next /token call
	// will succeed once the owner has acted.
	ErrorCodeRequestSubmitted = "request_submitted"

	// ErrorCodeNotAuthorized is the UMA Grant §3.3.6 code returned
	// when policy has denied the request and no further claims will
	// change the outcome.
	ErrorCodeNotAuthorized = "not_authorized"
)

// OAuthError is the OAuth 2.0 error envelope (RFC 6749 §5.2) returned
// by the AS on any wire failure. UMA does not change the envelope
// shape; it adds specific values for the ErrorCode field (see the
// ErrorCode* constants) and the typed [NeedInfoError] extension for
// claims-gathering responses.
//
// The type is named OAuthError rather than the bare "Error" because
// Go conflates a struct named Error with the Error() method that
// makes a type satisfy the error interface — naming the type Error
// would prevent [NeedInfoError] from embedding it cleanly. The wire
// shape is unaffected; the JSON key is "error" regardless of the Go
// name.
//
// Two equality semantics are wired in: pointer equality against the
// sentinels below (e.g. [ErrNeedInfo]) works because each sentinel is
// addressable, and code-based matching via [errors.Is] works because
// (*OAuthError).Is compares ErrorCode rather than the pointer.
type OAuthError struct {
	// ErrorCode is the OAuth 2.0 / UMA machine-readable error code,
	// one of the ErrorCode* constants in this file or a string the AS
	// has defined for its own extensions.
	ErrorCode string `json:"error"`

	// ErrorDescription is a human-readable description of the error.
	// RFC 6749 §5.2 requires it be a single ASCII line, but consumers
	// should not rely on that — round-trip the bytes the AS sent.
	ErrorDescription string `json:"error_description,omitempty"`

	// ErrorURI is an optional URI to a human-readable page providing
	// more information about the error.
	ErrorURI string `json:"error_uri,omitempty"`
}

// Error implements the error interface, rendering as
// "error_code: description" when ErrorDescription is set and just
// "error_code" otherwise.
func (e *OAuthError) Error() string {
	if e == nil {
		return "<nil *uma.OAuthError>"
	}
	if e.ErrorDescription != "" {
		return e.ErrorCode + ": " + e.ErrorDescription
	}
	return e.ErrorCode
}

// Is matches another *OAuthError by ErrorCode rather than by pointer.
// This is what makes `errors.Is(err, ErrNeedInfo)` work when err is a
// freshly-constructed *OAuthError with the same ErrorCode but a
// different pointer.
func (e *OAuthError) Is(target error) bool {
	if e == nil {
		return false
	}
	other, ok := target.(*OAuthError)
	if !ok || other == nil {
		return false
	}
	return e.ErrorCode == other.ErrorCode
}

// NeedInfoError is the typed extension to the OAuth error envelope the
// AS emits when ErrorCode is [ErrorCodeNeedInfo] (Grant §3.3.6). It
// carries the additional fields the client needs to satisfy the claims
// requirement: a fresh permission ticket bound to the partial claims
// already accumulated, the list of additional claims the AS requires,
// and an optional redirect_user URL for AS-driven claims gathering.
//
// The embedded [OAuthError] provides the standard envelope fields and
// the promoted Error() / Is() methods. Use [errors.As] to extract a
// *NeedInfoError from any error returned by the client's
// token-endpoint methods.
type NeedInfoError struct {
	OAuthError

	// Ticket is a fresh permission ticket the client should redeem in
	// a follow-up /token call after gathering the required claims.
	// It carries the partial claims state already accumulated, so
	// previous /token exchanges in this claims-gathering sequence
	// are not lost.
	Ticket string `json:"ticket,omitempty"`

	// RequiredClaims is the list of claims the AS needs the client to
	// supply. Each entry names a claim type, the acceptable token
	// formats, and the acceptable issuers; see [RequiredClaim].
	RequiredClaims []RequiredClaim `json:"required_claims,omitempty"`

	// RedirectUser is the URL the client should redirect the
	// requesting party's browser to for AS-driven claims gathering
	// (e.g. an interactive consent flow at the AS). Optional —
	// present when the AS supports interactive gathering for the
	// missing claims.
	RedirectUser string `json:"redirect_user,omitempty"`
}

// Sentinel error values for the load-bearing UMA / OAuth error codes.
// These are addressable so they survive `errors.Is` matching by code
// against a freshly-constructed *OAuthError with the same ErrorCode
// (the (*OAuthError).Is method compares codes, not pointers). A
// returned error always carries the full envelope (description, URI)
// — the sentinels are for the consumer's matching side.
//
//nolint:gochecknoglobals // Sentinel errors are an idiomatic exception.
var (
	// ErrNeedInfo matches any *OAuthError or *NeedInfoError whose
	// ErrorCode is [ErrorCodeNeedInfo].
	ErrNeedInfo = &OAuthError{ErrorCode: ErrorCodeNeedInfo}

	// ErrRequestSubmitted matches the queued-for-owner case.
	ErrRequestSubmitted = &OAuthError{ErrorCode: ErrorCodeRequestSubmitted}

	// ErrNotAuthorized matches a policy-deny.
	ErrNotAuthorized = &OAuthError{ErrorCode: ErrorCodeNotAuthorized}

	// ErrInvalidGrant matches a bad / expired / revoked permission
	// ticket on /token.
	ErrInvalidGrant = &OAuthError{ErrorCode: ErrorCodeInvalidGrant}

	// ErrInvalidScope matches a requested-scope-not-allowed.
	ErrInvalidScope = &OAuthError{ErrorCode: ErrorCodeInvalidScope}

	// ErrInvalidToken matches an invalid token at the introspection
	// endpoint (distinct from active=false, which is not an error).
	ErrInvalidToken = &OAuthError{ErrorCode: ErrorCodeInvalidToken}

	// ErrNotImplemented is returned by the NotImplemented zero-value
	// AS and RS embeddings (server/as.go, server/rs.go) when a method
	// is left unimplemented. The handler maps it to HTTP 501.
	ErrNotImplemented = errors.New("uma: endpoint not implemented")
)

// ValidationError is returned by per-type Validate methods when a
// required field is missing or invalid at the marshal boundary. The
// library's overall posture is lenient on unmarshal and strict only
// when the consumer opts in by calling Validate; ValidationError is
// the typed result of an opt-in check.
//
// Type names the struct being validated (e.g. "TokenRequest"). Field
// names the JSON field that failed (e.g. "ticket"). Message is the
// optional human-readable explanation.
type ValidationError struct {
	Type    string
	Field   string
	Message string
}

// Error implements the error interface, rendering as
// "uma: TokenRequest.ticket: required" or similar.
func (e *ValidationError) Error() string {
	if e == nil {
		return "<nil *uma.ValidationError>"
	}
	if e.Message != "" {
		return fmt.Sprintf("uma: %s.%s: %s", e.Type, e.Field, e.Message)
	}
	return fmt.Sprintf("uma: %s.%s: invalid", e.Type, e.Field)
}
