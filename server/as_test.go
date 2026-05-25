// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hstern/go-uma"
	"github.com/hstern/go-uma/server"
)

// recordingAS is a programmable AS test double — each method captures
// its inputs and returns the configured response/error.
type recordingAS struct {
	server.NotImplementedAS

	tokenIn       *uma.TokenRequest
	tokenOut      *uma.TokenResponse
	tokenErr      error
	permIn        *uma.PermissionRequest
	permOut       *uma.PermissionResponse
	permErr       error
	introspectIn  *uma.IntrospectionRequest
	introspectOut *uma.IntrospectionResponse
	introspectErr error
	rsIn          *server.ResourceSetRequest
	rsOut         *server.ResourceSetResponse
	rsErr         error
}

func (a *recordingAS) Token(_ context.Context, r *uma.TokenRequest) (*uma.TokenResponse, error) {
	a.tokenIn = r
	return a.tokenOut, a.tokenErr
}

func (a *recordingAS) Permission(_ context.Context, r *uma.PermissionRequest) (*uma.PermissionResponse, error) {
	a.permIn = r
	return a.permOut, a.permErr
}

func (a *recordingAS) Introspect(_ context.Context, r *uma.IntrospectionRequest) (*uma.IntrospectionResponse, error) {
	a.introspectIn = r
	return a.introspectOut, a.introspectErr
}

func (a *recordingAS) ResourceSet(_ context.Context, r *server.ResourceSetRequest) (*server.ResourceSetResponse, error) {
	a.rsIn = r
	return a.rsOut, a.rsErr
}

func newTestAS(t *testing.T, as server.AS) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(server.NewASHandler(as))
	t.Cleanup(srv.Close)
	return srv
}

func post(t *testing.T, srv *httptest.Server, path, contentType, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	return resp
}

func doReq(t *testing.T, srv *httptest.Server, method, path, body string) *http.Response {
	t.Helper()
	var br io.Reader
	if body != "" {
		br = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, srv.URL+path, br)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	return resp
}

func decodeBody(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decode: %v", err)
	}
}

func TestASHandler_TokenHappy(t *testing.T) {
	as := &recordingAS{tokenOut: &uma.TokenResponse{AccessToken: "rpt-new", TokenType: "Bearer"}}
	srv := newTestAS(t, as)
	form := url.Values{
		"grant_type": []string{uma.UMATicketGrantType},
		"ticket":     []string{"tkt-1"},
	}
	resp := post(t, srv, "/token", "application/x-www-form-urlencoded", form.Encode())
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	var tr uma.TokenResponse
	decodeBody(t, resp, &tr)
	if tr.AccessToken != "rpt-new" {
		t.Errorf("AccessToken = %q, want rpt-new", tr.AccessToken)
	}
	if as.tokenIn == nil || as.tokenIn.Ticket != "tkt-1" {
		t.Errorf("AS.Token received %+v, want ticket=tkt-1", as.tokenIn)
	}
}

func TestASHandler_TokenNeedInfo(t *testing.T) {
	ne := &uma.NeedInfoError{
		OAuthError: uma.OAuthError{ErrorCode: uma.ErrorCodeNeedInfo},
		Ticket:     "tkt-upgraded",
		RequiredClaims: []uma.RequiredClaim{
			{ClaimType: "urn:oid:1.3.6.1.5.5.7.9.1", FriendlyName: "email"},
		},
	}
	as := &recordingAS{tokenErr: ne}
	srv := newTestAS(t, as)
	resp := post(t, srv, "/token", "application/x-www-form-urlencoded", "grant_type="+uma.UMATicketGrantType+"&ticket=t")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	var got uma.NeedInfoError
	decodeBody(t, resp, &got)
	if got.Ticket != "tkt-upgraded" {
		t.Errorf("Ticket = %q, want tkt-upgraded", got.Ticket)
	}
	if len(got.RequiredClaims) != 1 {
		t.Errorf("RequiredClaims len = %d, want 1", len(got.RequiredClaims))
	}
}

func TestASHandler_TokenOAuthError(t *testing.T) {
	tests := []struct {
		code   string
		status int
	}{
		{uma.ErrorCodeInvalidGrant, http.StatusBadRequest},
		{uma.ErrorCodeInvalidScope, http.StatusBadRequest},
		{uma.ErrorCodeNotAuthorized, http.StatusForbidden},
		{uma.ErrorCodeRequestSubmitted, http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.code, func(t *testing.T) {
			as := &recordingAS{tokenErr: &uma.OAuthError{ErrorCode: tc.code}}
			srv := newTestAS(t, as)
			resp := post(t, srv, "/token", "application/x-www-form-urlencoded", "grant_type="+uma.UMATicketGrantType+"&ticket=t")
			if resp.StatusCode != tc.status {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.status)
			}
			_ = resp.Body.Close()
		})
	}
}

func TestASHandler_NotImplemented(t *testing.T) {
	// NotImplementedAS as the bare AS — every endpoint returns 501.
	srv := newTestAS(t, server.NotImplementedAS{})
	tests := []struct {
		method, path, body, ctype string
	}{
		{http.MethodPost, "/token", "grant_type=" + uma.UMATicketGrantType, "application/x-www-form-urlencoded"},
		{http.MethodPost, "/permission", `{"resource_id":"r","resource_scopes":["v"]}`, "application/json"},
		{http.MethodPost, "/introspection", "token=t", "application/x-www-form-urlencoded"},
		{http.MethodPost, "/resource_set", `{"name":"n","resource_scopes":["v"]}`, "application/json"},
		{http.MethodGet, "/resource_set", "", ""},
		{http.MethodGet, "/resource_set/r1", "", ""},
		{http.MethodPut, "/resource_set/r1", `{"name":"n","resource_scopes":["v"]}`, "application/json"},
		{http.MethodDelete, "/resource_set/r1", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			var body io.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			}
			req, _ := http.NewRequestWithContext(context.Background(), tc.method, srv.URL+tc.path, body)
			if tc.ctype != "" {
				req.Header.Set("Content-Type", tc.ctype)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusNotImplemented {
				t.Errorf("%s %s: status = %d, want 501", tc.method, tc.path, resp.StatusCode)
			}
		})
	}
}

func TestASHandler_PermissionHappy(t *testing.T) {
	as := &recordingAS{permOut: &uma.PermissionResponse{Ticket: "tkt-new"}}
	srv := newTestAS(t, as)
	resp := post(t, srv, "/permission", "application/json", `{"resource_id":"r1","resource_scopes":["view"]}`)
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want 201", resp.StatusCode)
	}
	var pr uma.PermissionResponse
	decodeBody(t, resp, &pr)
	if pr.Ticket != "tkt-new" {
		t.Errorf("Ticket = %q, want tkt-new", pr.Ticket)
	}
}

func TestASHandler_PermissionArrayBody(t *testing.T) {
	// The library accepts the array form on the AS side too.
	as := &recordingAS{permOut: &uma.PermissionResponse{Ticket: "tkt-new"}}
	srv := newTestAS(t, as)
	resp := post(t, srv, "/permission", "application/json", `[{"resource_id":"r1","resource_scopes":["view"]}]`)
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want 201", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestASHandler_IntrospectActiveFalse(t *testing.T) {
	as := &recordingAS{introspectOut: &uma.IntrospectionResponse{Active: false}}
	srv := newTestAS(t, as)
	resp := post(t, srv, "/introspection", "application/x-www-form-urlencoded", "token=rpt-1")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 even for active=false", resp.StatusCode)
	}
	var ir uma.IntrospectionResponse
	decodeBody(t, resp, &ir)
	if ir.Active {
		t.Errorf("Active = true, want false")
	}
}

func TestASHandler_ResourceSetCreate(t *testing.T) {
	as := &recordingAS{rsOut: &server.ResourceSetResponse{Single: &uma.ResourceSet{ID: "x"}}}
	srv := newTestAS(t, as)
	resp := post(t, srv, "/resource_set", "application/json", `{"name":"n","resource_scopes":["view"]}`)
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want 201", resp.StatusCode)
	}
	if as.rsIn.Op != uma.OpCreate {
		t.Errorf("op = %v, want OpCreate", as.rsIn.Op)
	}
	if as.rsIn.Body == nil || as.rsIn.Body.Name != "n" {
		t.Errorf("body name = %q, want n", as.rsIn.Body.Name)
	}
}

func TestASHandler_ResourceSetList(t *testing.T) {
	as := &recordingAS{rsOut: &server.ResourceSetResponse{IDs: []string{"a", "b"}}}
	srv := newTestAS(t, as)
	resp := doReq(t, srv, http.MethodGet, "/resource_set", "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if as.rsIn.Op != uma.OpList {
		t.Errorf("op = %v, want OpList", as.rsIn.Op)
	}
	var ids []string
	decodeBody(t, resp, &ids)
	if len(ids) != 2 {
		t.Errorf("len(ids) = %d, want 2", len(ids))
	}
}

func TestASHandler_ResourceSetRead(t *testing.T) {
	as := &recordingAS{rsOut: &server.ResourceSetResponse{Single: &uma.ResourceSet{ID: "r1", Name: "n"}}}
	srv := newTestAS(t, as)
	resp := doReq(t, srv, http.MethodGet, "/resource_set/r1", "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if as.rsIn.Op != uma.OpRead || as.rsIn.ID != "r1" {
		t.Errorf("op/id = %v/%q, want OpRead/r1", as.rsIn.Op, as.rsIn.ID)
	}
	_ = resp.Body.Close()
}

func TestASHandler_ResourceSetUpdate(t *testing.T) {
	as := &recordingAS{rsOut: &server.ResourceSetResponse{Single: &uma.ResourceSet{ID: "r1", Name: "updated"}}}
	srv := newTestAS(t, as)
	resp := doReq(t, srv, http.MethodPut, "/resource_set/r1", `{"name":"updated","resource_scopes":["v"]}`)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if as.rsIn.Op != uma.OpUpdate {
		t.Errorf("op = %v, want OpUpdate", as.rsIn.Op)
	}
	_ = resp.Body.Close()
}

func TestASHandler_ResourceSetDelete(t *testing.T) {
	as := &recordingAS{rsOut: &server.ResourceSetResponse{}}
	srv := newTestAS(t, as)
	resp := doReq(t, srv, http.MethodDelete, "/resource_set/r1", "")
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}
	if as.rsIn.Op != uma.OpDelete {
		t.Errorf("op = %v, want OpDelete", as.rsIn.Op)
	}
	_ = resp.Body.Close()
}

func TestASHandler_ValidationError(t *testing.T) {
	as := &recordingAS{tokenErr: &uma.ValidationError{
		Type: "TokenRequest", Field: "ticket", Message: "required",
	}}
	srv := newTestAS(t, as)
	resp := post(t, srv, "/token", "application/x-www-form-urlencoded", "grant_type="+uma.UMATicketGrantType)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestASHandler_BareError500(t *testing.T) {
	as := &recordingAS{tokenErr: io.ErrUnexpectedEOF}
	srv := newTestAS(t, as)
	resp := post(t, srv, "/token", "application/x-www-form-urlencoded", "grant_type="+uma.UMATicketGrantType+"&ticket=t")
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestASHandler_MethodNotAllowed(t *testing.T) {
	srv := newTestAS(t, server.NotImplementedAS{})
	resp := doReq(t, srv, http.MethodGet, "/token", "")
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /token status = %d, want 405", resp.StatusCode)
	}
	if resp.Header.Get("Allow") != http.MethodPost {
		t.Errorf("Allow = %q, want POST", resp.Header.Get("Allow"))
	}
	_ = resp.Body.Close()
}

func TestASHandler_PartialImplementation(t *testing.T) {
	// Demonstrates the embed-and-override pattern: a partial AS that
	// only implements Token works for /token and returns 501 for the
	// rest.
	srv := newTestAS(t, &tokenOnlyAS{})
	resp := post(t, srv, "/token", "application/x-www-form-urlencoded", "grant_type="+uma.UMATicketGrantType+"&ticket=t")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Token: status = %d, want 200", resp.StatusCode)
	}
	_ = resp.Body.Close()
	resp2 := post(t, srv, "/permission", "application/json", `{"resource_id":"r","resource_scopes":["v"]}`)
	if resp2.StatusCode != http.StatusNotImplemented {
		t.Errorf("Permission: status = %d, want 501", resp2.StatusCode)
	}
	_ = resp2.Body.Close()
}

type tokenOnlyAS struct {
	server.NotImplementedAS
}

func (tokenOnlyAS) Token(context.Context, *uma.TokenRequest) (*uma.TokenResponse, error) {
	return &uma.TokenResponse{AccessToken: "rpt-x"}, nil
}
