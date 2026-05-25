// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

// Package uma implements User-Managed Access 2.0 — the Kantara Initiative
// Grant and Federated Authorization Recommendations finalized 2018-01.
//
// The library provides typed wire shapes, an HTTP client, and http.Handler
// constructors for both the Authorization Server and Resource Server roles.
// See the package documentation in subsequent files for the per-symbol
// godoc; this file carries the package-level metadata.
package uma

import "strings"

// SpecVersion is the version of the User-Managed Access specification this
// library implements. UMA 2.0 was finalized as a Kantara Recommendation in
// January 2018 and has not been revised since; library upgrades will not
// change this value without a corresponding spec change.
const SpecVersion = "2.0"

// HTTP header names used across UMA's wire surface. Exported as constants
// so consumers wiring their own HTTP layer can reference them by name
// rather than re-typing the canonical header form.
const (
	// WWWAuthenticate is the name of the HTTP authentication-challenge
	// response header (RFC 7235 §4.1) the Resource Server sets on a
	// 401 response when the resource requires UMA authorization. The
	// UMA challenge value uses the "UMA" auth-scheme — build the value
	// with [BuildUMAChallenge].
	WWWAuthenticate = "WWW-Authenticate"
)

// BuildUMAChallenge returns the WWW-Authenticate header value the
// Resource Server includes in its 401 challenge to a requesting-party
// client lacking sufficient authorization (Federated Authz §3.1). The
// returned string has the form
//
//	UMA realm="...", as_uri="...", ticket="..."
//
// and is suitable for direct assignment to a Header().Set on an
// http.ResponseWriter. The challenge tells the client:
//
//   - that the auth-scheme is UMA,
//   - the protection-space (realm) the resource sits in,
//   - the AS the client should redeem the ticket at (as_uri), and
//   - the permission ticket itself.
//
// The four arguments map directly to those fields. realm and ticket are
// required by the spec, asURL is the AS's issuer URL (e.g. as published
// in the metadata document's `issuer` field), and scopes is an optional
// space-separated list of scopes the AS is requesting; when scopes is
// empty the `scope` parameter is omitted from the header value.
//
// The function does not escape quotes in the inputs. The realm, asURL,
// ticket, and scope values that real ASs / RSs emit do not contain
// double-quote characters — realm is a free-form short string,
// asURL / scope are URLs / scope strings drawn from constrained
// character sets, and ticket is an opaque AS-assigned value that
// implementers conventionally make printable-ASCII-safe. Consumers
// passing arbitrary input should pre-validate.
func BuildUMAChallenge(asURL, ticket, scopes, realm string) string {
	var sb strings.Builder
	sb.Grow(len(realm) + len(asURL) + len(ticket) + len(scopes) + 48)
	sb.WriteString(`UMA realm="`)
	sb.WriteString(realm)
	sb.WriteString(`", as_uri="`)
	sb.WriteString(asURL)
	sb.WriteString(`", ticket="`)
	sb.WriteString(ticket)
	sb.WriteString(`"`)
	if scopes != "" {
		sb.WriteString(`, scope="`)
		sb.WriteString(scopes)
		sb.WriteString(`"`)
	}
	return sb.String()
}
