// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/hstern/go-uma"
	"github.com/hstern/go-uma/client"
)

func readFormBody(t *testing.T, r *http.Request) url.Values {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	v, err := url.ParseQuery(string(b))
	if err != nil {
		t.Fatalf("parse body: %v", err)
	}
	return v
}

func TestIntrospect_ActiveTrue(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/introspection" {
			t.Errorf("path = %q, want /introspection", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q, want form-urlencoded", got)
		}
		v := readFormBody(t, r)
		if v.Get("token") != "rpt-1" {
			t.Errorf("token = %q, want rpt-1", v.Get("token"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{
			"active":true,
			"sub":"alice@example.com",
			"exp":1256953732,
			"permissions":[
				{"resource_id":"112210f47de98100","resource_scopes":["view"],"exp":1256953732}
			]
		}`)
	})
	resp, err := c.Introspect(context.Background(), &uma.IntrospectionRequest{Token: "rpt-1"})
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if !resp.Active {
		t.Errorf("Active = false, want true")
	}
	if resp.Sub != "alice@example.com" {
		t.Errorf("Sub = %q, want alice@example.com", resp.Sub)
	}
	if len(resp.Permissions) != 1 {
		t.Fatalf("Permissions len = %d, want 1", len(resp.Permissions))
	}
}

func TestIntrospect_ActiveFalse_NotAnError(t *testing.T) {
	// The load-bearing implementer pin: an inactive token is reported
	// as Active=false in a 200 OK response, NOT as a transport error.
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{"active":false}`)
	})
	resp, err := c.Introspect(context.Background(), &uma.IntrospectionRequest{Token: "rpt-stale"})
	if err != nil {
		t.Fatalf("Introspect on inactive token = err %v, want nil error with Active=false", err)
	}
	if resp == nil {
		t.Fatal("Introspect returned nil response on Active=false")
	}
	if resp.Active {
		t.Errorf("Active = true, want false")
	}
}

func TestIntrospect_PATHeader(t *testing.T) {
	var sawAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{"active":true}`)
	}))
	t.Cleanup(srv.Close)
	c, err := client.NewClient(srv.URL, client.WithPAT("pat-xyz"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = c.Introspect(context.Background(), &uma.IntrospectionRequest{Token: "rpt-1"})
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	want := "Bearer pat-xyz"
	if sawAuth != want {
		t.Errorf("Authorization = %q, want %q", sawAuth, want)
	}
}

func TestIntrospect_InvalidToken401_OAuthError(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintln(w, `{"error":"invalid_token","error_description":"PAT rejected"}`)
	})
	_, err := c.Introspect(context.Background(), &uma.IntrospectionRequest{Token: "rpt-1"})
	if !errors.Is(err, uma.ErrInvalidToken) {
		t.Errorf("errors.Is(err, ErrInvalidToken) = false; err = %v", err)
	}
}

func TestIntrospect_NilRequest(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("server should not be hit for nil request")
	})
	_, err := c.Introspect(context.Background(), nil)
	if err == nil {
		t.Fatal("Introspect(nil) = nil error, want non-nil")
	}
}

func TestIntrospect_TransportError(t *testing.T) {
	want := errors.New("dial tcp: simulated")
	c, err := client.NewClient("https://as.example.com", client.WithHTTPDoer(failingDoer{err: want}))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = c.Introspect(context.Background(), &uma.IntrospectionRequest{Token: "rpt-1"})
	if !errors.Is(err, want) {
		t.Errorf("errors.Is on transport error = false; err = %v", err)
	}
}

func TestIntrospect_MalformedJSONIn200(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{not json`)
	})
	_, err := c.Introspect(context.Background(), &uma.IntrospectionRequest{Token: "rpt-1"})
	if err == nil {
		t.Fatal("Introspect returned nil error on malformed JSON")
	}
}

func TestIntrospect_FormBody_TokenAndHint(t *testing.T) {
	var captured url.Values
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		captured = readFormBody(t, r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{"active":true}`)
	})
	_, err := c.Introspect(context.Background(), &uma.IntrospectionRequest{
		Token:         "rpt-1",
		TokenTypeHint: "requesting_party_token",
	})
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if captured.Get("token") != "rpt-1" {
		t.Errorf("token = %q, want rpt-1", captured.Get("token"))
	}
	if captured.Get("token_type_hint") != "requesting_party_token" {
		t.Errorf("token_type_hint = %q, want requesting_party_token", captured.Get("token_type_hint"))
	}
}
