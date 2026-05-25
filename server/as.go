// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

// Package server implements the Authorization Server and Resource
// Server sides of UMA 2.0's HTTP wire protocol. Two interfaces cover
// the two roles:
//
//   - [AS] is the four-method interface a UMA Authorization Server
//     satisfies — one method per endpoint (Token, Permission,
//     Introspect, ResourceSet). Wire it into an http.Handler with
//     [NewASHandler]. Consumers embed [NotImplementedAS] to get
//     ErrNotImplemented for free on the methods they don't implement;
//     the handler maps ErrNotImplemented to HTTP 501.
//   - [RS] is the one-method interface a Resource Server's policy
//     layer satisfies. The library exposes helpers around it rather
//     than wrapping it with its own HTTP handler — the RS owns its
//     own routing, this package contributes the 401-with-ticket
//     emission and the introspection plumbing.
//
// The two interfaces are intentionally separate: the AS and the RS
// have different lifecycles, different trust boundaries, and (almost
// always) different deployments. Collapsing them into one type would
// blur a security-load-bearing distinction.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/hstern/go-uma"
)

// AS is the four-method interface a UMA Authorization Server
// implementation satisfies. Each method corresponds to one of the
// AS's spec-defined HTTP endpoints; [NewASHandler] multiplexes
// incoming requests to the appropriate method.
//
// An AS implementation does not need to support every endpoint. A
// minimal AS that only redeems UMA tickets implements Token and
// returns [uma.ErrNotImplemented] from the rest — the simplest path
// is to embed [NotImplementedAS] and override only the methods the
// consumer cares about.
//
// All four methods take a context and a typed request; all return a
// typed response and an error. The error semantics for the handler
// boundary are:
//
//   - nil err + non-nil response → the handler emits the endpoint's
//     happy-path status (200 for Token/Introspect/Read/Update/List,
//     201 for Permission/Create, 204 for Delete).
//   - errors.Is(err, [uma.ErrNotImplemented]) → 501 Not Implemented.
//   - errors.As-matched [*uma.ValidationError] → 400 Bad Request.
//   - errors.As-matched [*uma.NeedInfoError] → 403 Forbidden with
//     the typed need_info envelope body.
//   - errors.As-matched [*uma.OAuthError] → status derived from the
//     ErrorCode (invalid_grant/invalid_scope → 400, invalid_token →
//     401, need_info/not_authorized/request_submitted → 403).
//   - anything else → 500 Internal Server Error with no body.
//
// AS implementations should return the most specific error type that
// applies. Returning a bare error gets a 500 and is almost always a
// bug.
type AS interface {
	// Token redeems a permission ticket for a requesting-party token
	// (Grant §3.3). Implementations recover the (resource_id, scopes)
	// bundle the ticket points at, apply policy, and either issue an
	// RPT (return *TokenResponse, nil) or signal a typed failure —
	// *uma.NeedInfoError for "more claims required", a *uma.OAuthError
	// with ErrorCode = "not_authorized" for policy-deny,
	// "request_submitted" for queued-for-owner-action, "invalid_grant"
	// for an unknown / expired ticket, etc.
	Token(ctx context.Context, r *uma.TokenRequest) (*uma.TokenResponse, error)

	// Permission registers a permission and returns the AS-minted
	// permission ticket (Federated Authz §4). Implementations bind
	// the ticket to (resource_id, scopes) and choose its format;
	// the library treats it as opaque.
	//
	// Ticket requirements (Federated Authz §4 + §6.2):
	//
	//   - Opaque to clients. The library never inspects ticket
	//     bytes; consumers MUST NOT rely on any internal structure.
	//   - High-entropy and unguessable. A ticket is a bearer
	//     credential for one redemption; an attacker who guesses a
	//     valid ticket can redeem it. The OAuth threat model (RFC
	//     6819 §3.5) applies — at least 128 bits of entropy,
	//     ideally produced by a cryptographic RNG.
	//   - Single-use semantics. The spec recommends a ticket be
	//     redeemable exactly once; the consumer's AS is responsible
	//     for enforcing this. The library does NOT track ticket
	//     state — consumer code MUST mark a ticket as consumed on
	//     first /token redemption.
	//   - Time-bound. A ticket SHOULD expire after a short window
	//     (the spec is silent on the exact duration; minutes is a
	//     common choice). An expired ticket returns
	//     invalid_grant on /token redemption.
	//   - Re-issuance on need_info. When the AS returns a
	//     [*uma.NeedInfoError], the embedded Ticket field carries
	//     an UPGRADED ticket bound to the partial claims already
	//     accumulated. Consumers MUST mint a fresh ticket for this
	//     case, not reuse the original — the upgraded ticket
	//     carries claims state the original does not.
	//
	// The library's own permission-ticket lifecycle test (see
	// lifecycle_test.go) demonstrates the issuance → redemption
	// round-trip and documents the single-use invariant the
	// consumer is responsible for.
	Permission(ctx context.Context, r *uma.PermissionRequest) (*uma.PermissionResponse, error)

	// Introspect inspects an RPT (Federated Authz §5, extending
	// RFC 7662). Implementations look up the token, return Active=true
	// + the permission set, OR Active=false (which is NOT an error —
	// it's a successful 200 response with Active=false). An invalid
	// PAT or otherwise-malformed request returns a *uma.OAuthError
	// with ErrorCode = "invalid_token".
	Introspect(ctx context.Context, r *uma.IntrospectionRequest) (*uma.IntrospectionResponse, error)

	// ResourceSet handles the resource-set CRUD endpoints
	// (Federated Authz §2). The handler routes POST/GET/PUT/DELETE
	// against /resource_set and /resource_set/{id} into a single
	// method call, with the op + id + body bundled into the
	// [ResourceSetRequest]. The response is bundled similarly: a
	// single ResourceSet for Create/Read/Update, an array of IDs for
	// List, an empty response for Delete.
	ResourceSet(ctx context.Context, r *ResourceSetRequest) (*ResourceSetResponse, error)
}

// ResourceSetRequest bundles the inputs to [AS.ResourceSet] across
// all five op variants. Op selects the operation; ID is the
// AS-assigned resource id for Read/Update/Delete and empty for
// Create/List; Body carries the new description for Create/Update
// and is nil for Read/Delete/List.
type ResourceSetRequest struct {
	Op   uma.ResourceSetOp
	ID   string
	Body *uma.ResourceSet
}

// ResourceSetResponse bundles the outputs of [AS.ResourceSet]. Exactly
// one field is populated per op:
//
//   - Create / Read / Update → Single is the resource record;
//     IDs is nil.
//   - List → IDs is the list of resource ids; Single is nil.
//   - Delete → both nil (the handler writes 204 with no body).
type ResourceSetResponse struct {
	Single *uma.ResourceSet
	IDs    []string
}

// NotImplementedAS is a zero-value [AS] implementation whose four
// methods all return [uma.ErrNotImplemented]. Embed it in a partial-
// implementation struct to opt out of methods the consumer's AS does
// not support — the handler maps ErrNotImplemented to HTTP 501 so the
// missing endpoints surface as a clean "Not Implemented" response.
type NotImplementedAS struct{}

// Token implements [AS.Token]; always returns [uma.ErrNotImplemented].
func (NotImplementedAS) Token(context.Context, *uma.TokenRequest) (*uma.TokenResponse, error) {
	return nil, uma.ErrNotImplemented
}

// Permission implements [AS.Permission]; always returns [uma.ErrNotImplemented].
func (NotImplementedAS) Permission(context.Context, *uma.PermissionRequest) (*uma.PermissionResponse, error) {
	return nil, uma.ErrNotImplemented
}

// Introspect implements [AS.Introspect]; always returns [uma.ErrNotImplemented].
func (NotImplementedAS) Introspect(context.Context, *uma.IntrospectionRequest) (*uma.IntrospectionResponse, error) {
	return nil, uma.ErrNotImplemented
}

// ResourceSet implements [AS.ResourceSet]; always returns [uma.ErrNotImplemented].
func (NotImplementedAS) ResourceSet(context.Context, *ResourceSetRequest) (*ResourceSetResponse, error) {
	return nil, uma.ErrNotImplemented
}

// HandlerOption customizes an [AS] handler at construction. The
// option set is intentionally small at this layer — additional hooks
// (structured logging, metrics) land in a later commit. Options
// applied are independent and order-insensitive.
type HandlerOption func(*handlerConfig)

type handlerConfig struct{}

// NewASHandler returns an [http.Handler] that routes incoming HTTP
// requests against the AS's spec-defined paths to the corresponding
// method on as.
//
// Routing table:
//
//	POST   /token                         → AS.Token
//	POST   /permission                    → AS.Permission
//	POST   /introspection                 → AS.Introspect
//	POST   /resource_set                  → AS.ResourceSet (OpCreate)
//	GET    /resource_set                  → AS.ResourceSet (OpList)
//	GET    /resource_set/{id}             → AS.ResourceSet (OpRead)
//	PUT    /resource_set/{id}             → AS.ResourceSet (OpUpdate)
//	DELETE /resource_set/{id}             → AS.ResourceSet (OpDelete)
//
// Other paths and other methods return 404 / 405. Mount the handler at
// the AS's base path with [http.ServeMux] or any router that proxies
// to it.
func NewASHandler(as AS, _ ...HandlerOption) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(uma.TokenEndpoint, methodOnly(http.MethodPost, handleToken(as)))
	mux.Handle(uma.PermissionEndpoint, methodOnly(http.MethodPost, handlePermission(as)))
	mux.Handle(uma.IntrospectionEndpoint, methodOnly(http.MethodPost, handleIntrospect(as)))
	mux.Handle(uma.ResourceSetEndpoint, handleResourceSetRoot(as))
	mux.Handle(uma.ResourceSetEndpoint+"/", handleResourceSetID(as))
	return mux
}

// methodOnly wraps inner so it only runs for the matched HTTP method;
// every other verb returns 405 Method Not Allowed with an Allow
// header naming the accepted method.
func methodOnly(method string, inner http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		inner(w, r)
	}
}

func handleToken(as AS) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeError(w, &uma.OAuthError{
				ErrorCode:        uma.ErrorCodeInvalidGrant,
				ErrorDescription: "could not parse form body",
			})
			return
		}
		req := uma.ParseTokenRequest(r.PostForm)
		resp, err := as.Token(r.Context(), req)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handlePermission(as AS) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			writeError(w, &uma.OAuthError{
				ErrorCode:        uma.ErrorCodeInvalidGrant,
				ErrorDescription: "could not read body",
			})
			return
		}
		var batch uma.PermissionRequests
		if err := json.Unmarshal(body, &batch); err != nil {
			writeError(w, &uma.OAuthError{
				ErrorCode:        uma.ErrorCodeInvalidGrant,
				ErrorDescription: "could not parse JSON body",
			})
			return
		}
		// The AS interface is a single PermissionRequest; consumers
		// who need to handle batch registration call AS.Permission
		// per entry. The spec allows but does not require the AS to
		// register multiple permissions atomically; the library
		// follows the simpler interpretation and lets the consumer
		// loop if they want.
		if len(batch) == 0 {
			writeError(w, &uma.ValidationError{
				Type: "PermissionRequest", Field: "resource_id", Message: "required",
			})
			return
		}
		req := batch[0]
		resp, err := as.Permission(r.Context(), &req)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, resp)
	}
}

func handleIntrospect(as AS) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeError(w, &uma.OAuthError{
				ErrorCode:        uma.ErrorCodeInvalidToken,
				ErrorDescription: "could not parse form body",
			})
			return
		}
		req := uma.ParseIntrospectionRequest(r.PostForm)
		resp, err := as.Introspect(r.Context(), req)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleResourceSetRoot(as AS) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			body, rs, ok := decodeResourceSetBody(w, r)
			if !ok {
				return
			}
			_ = body
			resp, err := as.ResourceSet(r.Context(), &ResourceSetRequest{
				Op: uma.OpCreate, Body: rs,
			})
			if err != nil {
				writeError(w, err)
				return
			}
			writeJSON(w, http.StatusCreated, resp.Single)
		case http.MethodGet:
			resp, err := as.ResourceSet(r.Context(), &ResourceSetRequest{Op: uma.OpList})
			if err != nil {
				writeError(w, err)
				return
			}
			if resp.IDs == nil {
				resp.IDs = []string{}
			}
			writeJSON(w, http.StatusOK, resp.IDs)
		default:
			w.Header().Set("Allow", "GET, POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

func handleResourceSetID(as AS) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, uma.ResourceSetEndpoint+"/")
		if id == "" || strings.Contains(id, "/") {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			resp, err := as.ResourceSet(r.Context(), &ResourceSetRequest{Op: uma.OpRead, ID: id})
			if err != nil {
				writeError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, resp.Single)
		case http.MethodPut:
			_, rs, ok := decodeResourceSetBody(w, r)
			if !ok {
				return
			}
			resp, err := as.ResourceSet(r.Context(), &ResourceSetRequest{Op: uma.OpUpdate, ID: id, Body: rs})
			if err != nil {
				writeError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, resp.Single)
		case http.MethodDelete:
			_, err := as.ResourceSet(r.Context(), &ResourceSetRequest{Op: uma.OpDelete, ID: id})
			if err != nil {
				writeError(w, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.Header().Set("Allow", "GET, PUT, DELETE")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

// decodeResourceSetBody reads the JSON body of a POST or PUT
// /resource_set request and returns the raw bytes plus the decoded
// *uma.ResourceSet. On failure it writes a 400 OAuth error and
// returns ok=false; the caller stops.
func decodeResourceSetBody(w http.ResponseWriter, r *http.Request) ([]byte, *uma.ResourceSet, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeError(w, &uma.OAuthError{
			ErrorCode:        uma.ErrorCodeInvalidGrant,
			ErrorDescription: "could not read body",
		})
		return nil, nil, false
	}
	var rs uma.ResourceSet
	if err := json.Unmarshal(body, &rs); err != nil {
		writeError(w, &uma.OAuthError{
			ErrorCode:        uma.ErrorCodeInvalidGrant,
			ErrorDescription: "could not parse JSON body",
		})
		return nil, nil, false
	}
	return body, &rs, true
}

// writeJSON writes a JSON-encoded value to w with the given status
// code. A nil value writes the status with no body — useful for
// 204 No Content.
func writeJSON(w http.ResponseWriter, status int, v any) {
	if v == nil {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError maps an AS-returned error to the appropriate HTTP
// response, in order of specificity:
//
//   - *uma.NeedInfoError → 403 with the typed need_info envelope.
//   - *uma.ValidationError → 400 with an invalid_request envelope.
//   - *uma.OAuthError → status derived from the ErrorCode, body =
//     the envelope verbatim.
//   - errors.Is(err, uma.ErrNotImplemented) → 501 with no body.
//   - anything else → 500 with no body.
func writeError(w http.ResponseWriter, err error) {
	var ne *uma.NeedInfoError
	if errors.As(err, &ne) {
		writeJSON(w, http.StatusForbidden, ne)
		return
	}
	var ve *uma.ValidationError
	if errors.As(err, &ve) {
		writeJSON(w, http.StatusBadRequest, &uma.OAuthError{
			ErrorCode:        uma.ErrorCodeInvalidGrant,
			ErrorDescription: ve.Error(),
		})
		return
	}
	var oe *uma.OAuthError
	if errors.As(err, &oe) {
		writeJSON(w, statusForCode(oe.ErrorCode), oe)
		return
	}
	if errors.Is(err, uma.ErrNotImplemented) {
		w.WriteHeader(http.StatusNotImplemented)
		return
	}
	w.WriteHeader(http.StatusInternalServerError)
}

// statusForCode maps an OAuth / UMA error code to the corresponding
// HTTP status. Unknown codes default to 400 — extensions defined by
// an AS but not the spec stay safely in 4xx territory rather than
// becoming a 500.
func statusForCode(code string) int {
	switch code {
	case uma.ErrorCodeInvalidToken:
		return http.StatusUnauthorized
	case uma.ErrorCodeNeedInfo,
		uma.ErrorCodeNotAuthorized,
		uma.ErrorCodeRequestSubmitted:
		return http.StatusForbidden
	default:
		// invalid_grant, invalid_scope, and any consumer-defined
		// extension code we don't recognize.
		return http.StatusBadRequest
	}
}
