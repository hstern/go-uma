// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/hstern/go-uma"
	"github.com/hstern/go-uma/client"
	"github.com/hstern/go-uma/server"
)

// ExampleAS demonstrates a minimal Authorization Server: embed
// NotImplementedAS, override the one method you serve, and hand the
// result to NewASHandler. The handler maps unimplemented methods to
// HTTP 501 and surfaces typed errors to the right wire response.
type exampleAS struct {
	server.NotImplementedAS
}

func (exampleAS) Token(context.Context, *uma.TokenRequest) (*uma.TokenResponse, error) {
	return &uma.TokenResponse{
		AccessToken: "opaque-rpt",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}, nil
}

func ExampleAS() {
	srv := httptest.NewServer(server.NewASHandler(exampleAS{}))
	defer srv.Close()

	resp, _ := http.Post(
		srv.URL+uma.TokenEndpoint,
		"application/x-www-form-urlencoded",
		strings.NewReader("grant_type="+uma.UMATicketGrantType+"&ticket=t"),
	)
	defer func() { _ = resp.Body.Close() }()
	fmt.Println("Token endpoint status:", resp.StatusCode)

	// Unimplemented endpoints return 501.
	resp2, _ := http.Post(
		srv.URL+uma.PermissionEndpoint,
		"application/json",
		strings.NewReader(`{"resource_id":"r","resource_scopes":["v"]}`),
	)
	defer func() { _ = resp2.Body.Close() }()
	fmt.Println("Permission endpoint status:", resp2.StatusCode)

	// Output:
	// Token endpoint status: 200
	// Permission endpoint status: 501
}

// ExampleNotImplementedAS demonstrates the embed-and-override pattern.
// A bare NotImplementedAS{} returns 501 from every endpoint, useful
// as a test scaffold or as the base for a partial implementation.
func ExampleNotImplementedAS() {
	srv := httptest.NewServer(server.NewASHandler(server.NotImplementedAS{}))
	defer srv.Close()
	resp, _ := http.Post(
		srv.URL+uma.TokenEndpoint,
		"application/x-www-form-urlencoded",
		strings.NewReader("grant_type="+uma.UMATicketGrantType+"&ticket=t"),
	)
	defer func() { _ = resp.Body.Close() }()
	fmt.Println(resp.StatusCode)
	// Output: 501
}

// ExampleNewASHandler wraps an AS implementation in an http.Handler
// that routes the spec-defined paths to the matching interface
// method. Mount it at the AS's base URL.
func ExampleNewASHandler() {
	as := exampleAS{}
	h := server.NewASHandler(as)
	// Mount however your application wires HTTP — http.ListenAndServe,
	// http.ServeMux, a router framework, etc.
	_ = h
	// Output:
}

// ExampleBuildMetadata probes the supplied AS for implemented
// endpoints and publishes only those in the resulting Metadata
// document. The token endpoint shows up because exampleAS overrides
// Token; the others are absent because NotImplementedAS returns
// ErrNotImplemented.
func ExampleBuildMetadata() {
	m := server.BuildMetadata("https://as.example.com", exampleAS{})
	fmt.Println("issuer:", m.Issuer)
	fmt.Println("token:", m.TokenEndpoint)
	fmt.Println("permission:", m.PermissionEndpoint)
	// Output:
	// issuer: https://as.example.com
	// token: https://as.example.com/token
	// permission:
}

// ExampleRS demonstrates a Resource Server using ExtractBearerToken
// and a hypothetical introspection result to decide allow vs.
// ticket-required. The library does not own RS routing; consumers
// wrap their own http.Handler around the policy decision.
type exampleRS struct{}

func (exampleRS) ProtectedRequest(
	_ context.Context, r *http.Request, _ string, _ []string,
) (server.Decision, error) {
	rpt, ok := server.ExtractBearerToken(r)
	if !ok {
		return server.DecisionUnknown, &server.TicketRequired{
			Ticket: "fresh-ticket",
			ASURL:  "https://as.example.com",
			Realm:  "my-app",
		}
	}
	// In production: call client.Client.Introspect to validate rpt,
	// branch on Active + Permissions covering the rsid + scopes.
	_ = rpt
	return server.DecisionAllow, nil
}

func ExampleRS() {
	rs := exampleRS{}
	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d, err := rs.ProtectedRequest(r.Context(), r, "photo-1", []string{"view"})
		var tr *server.TicketRequired
		if errors.As(err, &tr) {
			server.WriteTicketRequired(w, tr)
			return
		}
		if err != nil || d != server.DecisionAllow {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Without an RPT — RS emits 401 + WWW-Authenticate.
	resp, _ := http.Get(srv.URL)
	defer func() { _ = resp.Body.Close() }()
	fmt.Println("unauthenticated:", resp.StatusCode)

	// With an RPT — RS allows (the example skips real introspection).
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
	req.Header.Set("Authorization", "Bearer some-rpt")
	resp2, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp2.Body.Close() }()
	fmt.Println("authenticated:", resp2.StatusCode)

	// Output:
	// unauthenticated: 401
	// authenticated: 200
}

// ExampleWriteTicketResponse shows the RS-side 401-with-ticket
// emission directly. The ticket lives in the WWW-Authenticate
// header, NOT the response body.
func ExampleWriteTicketResponse() {
	w := httptest.NewRecorder()
	server.WriteTicketResponse(w,
		"opaque-ticket-from-permission-endpoint",
		"https://as.example.com",
		"view",
		"my-app",
	)
	fmt.Println("Status:", w.Code)
	fmt.Println("WWW-Authenticate:", w.Header().Get("WWW-Authenticate"))
	// Output:
	// Status: 401
	// WWW-Authenticate: UMA realm="my-app", as_uri="https://as.example.com", ticket="opaque-ticket-from-permission-endpoint", scope="view"
}

// ExampleClient_Token redeems a permission ticket for an RPT. A
// need_info 403 from the AS is NOT a transport error — pattern-
// match with errors.As to extract the typed *uma.NeedInfoError,
// gather the required claims, and retry.
func ExampleClient_Token() {
	srv := httptest.NewServer(server.NewASHandler(exampleAS{}))
	defer srv.Close()

	c, _ := client.NewClient(srv.URL)
	tr, err := c.Token(context.Background(), &uma.TokenRequest{Ticket: "tkt-1"})

	var ne *uma.NeedInfoError
	switch {
	case errors.As(err, &ne):
		fmt.Println("need_info; retry with claim_token")
	case err != nil:
		fmt.Println("error:", err)
	default:
		fmt.Println("RPT:", tr.AccessToken)
	}
	// Output: RPT: opaque-rpt
}
