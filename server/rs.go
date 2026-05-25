// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hstern/go-uma"
)

// RS is the one-method interface a Resource Server's policy layer
// satisfies. The consumer's HTTP handler calls ProtectedRequest on
// every incoming request that touches a UMA-protected resource; the
// implementation typically extracts the Bearer RPT from the
// Authorization header, calls [github.com/hstern/go-uma/client.Client.Introspect]
// to validate it, and returns one of the documented outcomes.
//
// The interface intentionally does NOT own the HTTP routing — the RS
// owns its own handlers and decides per-route which (rsid, scopes)
// the incoming request is asking about. This library contributes the
// policy-decision interface and the 401-with-ticket emitter; the
// routing and the application response on a successful decision stay
// in consumer hands.
//
// Return-value matrix:
//
//   - (DecisionAllow, nil) — the request carries a valid RPT with
//     sufficient permissions. The consumer's handler proceeds to
//     serve the protected resource.
//   - (DecisionDeny, nil) — policy denies the request for reasons
//     unrelated to UMA token state (e.g. a blocked user, a tenant
//     boundary). The consumer's handler writes 403 with whatever
//     body its policy prescribes. The library is uninvolved.
//   - (DecisionUnknown, *TicketRequired) — the request lacks a
//     sufficient RPT and the RS has registered a permission with
//     the AS to obtain a fresh ticket. The consumer's handler
//     converts this into a 401 + WWW-Authenticate challenge via
//     [WriteTicketResponse] or the [WriteTicketRequired] convenience.
//   - (DecisionUnknown, error) — any other error (introspection
//     failure, network error to the AS, programming bug). The
//     consumer's handler writes 500 or whatever its error layer
//     prescribes; the library is uninvolved.
type RS interface {
	ProtectedRequest(
		ctx context.Context,
		r *http.Request,
		rsid string,
		scopes []string,
	) (Decision, error)
}

// Decision is the outcome of an [RS.ProtectedRequest] call.
// DecisionUnknown is the zero-value sentinel so a method that
// returns an error before reaching its real decision path produces
// an obviously-uninitialized Decision rather than a misleading
// DecisionAllow.
type Decision int

const (
	// DecisionUnknown is the zero value — a method that returned an
	// error before reaching its real decision path should leave the
	// Decision field at this value.
	DecisionUnknown Decision = iota

	// DecisionAllow signals the request carries a valid RPT with
	// sufficient permissions. The consumer's handler proceeds to
	// serve the protected resource.
	DecisionAllow

	// DecisionDeny signals policy denies the request for reasons
	// other than missing/insufficient UMA authorization (e.g. a
	// blocked user, a tenant boundary). The consumer's handler
	// writes 403; the library is uninvolved.
	DecisionDeny
)

// String returns the human-readable name of d.
func (d Decision) String() string {
	switch d {
	case DecisionUnknown:
		return "unknown"
	case DecisionAllow:
		return "allow"
	case DecisionDeny:
		return "deny"
	}
	return fmt.Sprintf("Decision(%d)", int(d))
}

// TicketRequired is the typed error an [RS] returns when the
// requesting-party client must obtain (or upgrade) a permission
// ticket at the AS before the request can be authorized. The
// consumer's handler converts this to a 401 response carrying the
// UMA WWW-Authenticate challenge via [WriteTicketResponse] or
// [WriteTicketRequired].
//
// The fields map directly to the challenge parameters: Ticket is the
// permission ticket the AS minted (or the RS already holds for the
// failed authorization scope), ASURL is the AS's issuer URL the
// client should redeem the ticket at, Scopes is the optional space-
// separated scope set the AS is requesting, and Realm is the
// protection-space identifier.
type TicketRequired struct {
	Ticket string
	ASURL  string
	Scopes string
	Realm  string
}

// Error implements the error interface. The string form is for
// logging and debugging; the wire-format challenge is built by
// [WriteTicketResponse] / [WriteTicketRequired].
func (e *TicketRequired) Error() string {
	if e == nil {
		return "<nil *server.TicketRequired>"
	}
	return fmt.Sprintf("uma: ticket required (as_uri=%s realm=%s)", e.ASURL, e.Realm)
}

// NotImplementedRS is a zero-value [RS] implementation whose
// ProtectedRequest method always returns (DecisionUnknown,
// [uma.ErrNotImplemented]). Embed it in a partial-implementation
// struct to opt out of the RS surface — useful in tests, in
// scaffolds, and for adapters that wrap an existing authorization
// layer without yet wiring up UMA.
type NotImplementedRS struct{}

// ProtectedRequest implements [RS.ProtectedRequest]; always returns
// (DecisionUnknown, [uma.ErrNotImplemented]).
func (NotImplementedRS) ProtectedRequest(
	context.Context, *http.Request, string, []string,
) (Decision, error) {
	return DecisionUnknown, uma.ErrNotImplemented
}

// WriteTicketResponse writes a 401 Unauthorized response carrying
// the UMA challenge header (Federated Authz §3.1). The header value
// is built by [uma.BuildUMAChallenge]; the response body is empty.
//
// This is the load-bearing implementer pin: the ticket lives in the
// WWW-Authenticate header, NOT in the response body. A consumer that
// emits the ticket in the body produces a non-conforming response
// that no UMA-compliant client will recognize.
//
// Pass the empty string for scopes when the AS is not narrowing the
// scope set; the `scope` parameter is omitted from the header value
// in that case.
func WriteTicketResponse(w http.ResponseWriter, ticket, asURL, scopes, realm string) {
	w.Header().Set(uma.WWWAuthenticate, uma.BuildUMAChallenge(asURL, ticket, scopes, realm))
	w.WriteHeader(http.StatusUnauthorized)
}

// WriteTicketRequired is the [*TicketRequired]-shaped convenience
// over [WriteTicketResponse]. A nil tr writes a 401 with an empty
// WWW-Authenticate header — non-conforming, but the right safety
// behavior for a defensive caller.
func WriteTicketRequired(w http.ResponseWriter, tr *TicketRequired) {
	if tr == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	WriteTicketResponse(w, tr.Ticket, tr.ASURL, tr.Scopes, tr.Realm)
}

// ExtractBearerToken extracts a Bearer token from the
// Authorization header of r. Returns the token value (without the
// "Bearer " prefix) and ok=true on a well-formed header, or "" and
// ok=false on missing / malformed inputs.
//
// The check is case-insensitive on the scheme name per RFC 7235 §2.1
// but case-sensitive on the token value. An empty token after the
// scheme returns ok=false.
//
// ExtractBearerToken is exposed as a building block — most RS
// implementations call it as the first step of ProtectedRequest to
// recover the RPT they then pass to introspection.
func ExtractBearerToken(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) {
		return "", false
	}
	for i := range prefix {
		c := h[i]
		// Case-insensitive ASCII match on the scheme.
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		want := prefix[i]
		if want >= 'A' && want <= 'Z' {
			want += 'a' - 'A'
		}
		if c != want {
			return "", false
		}
	}
	token := h[len(prefix):]
	if token == "" {
		return "", false
	}
	return token, true
}
