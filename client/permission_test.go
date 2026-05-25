// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hstern/go-uma"
	"github.com/hstern/go-uma/client"
)

func TestPermission_Success(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/permission" {
			t.Errorf("path = %q, want /permission", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}
		// Wire body MUST be the array form even for a single permission
		// — the spec allows either but PermissionRequests.MarshalJSON
		// normalizes on array.
		raw, _ := io.ReadAll(r.Body)
		var got []uma.PermissionRequest
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("body is not a JSON array of PermissionRequest: %v (body: %s)", err, string(raw))
		}
		if len(got) != 1 {
			t.Fatalf("body has %d entries, want 1; body: %s", len(got), string(raw))
		}
		if got[0].ResourceID != "r1" || len(got[0].ResourceScopes) != 1 {
			t.Errorf("decoded body = %+v, want one entry r1/view", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintln(w, `{"ticket":"016f84e8-f9b9-11e0-bd6f-0021cc6004de"}`)
	})
	resp, err := c.Permission(context.Background(), &uma.PermissionRequest{
		ResourceID:     "r1",
		ResourceScopes: []string{"view"},
	})
	if err != nil {
		t.Fatalf("Permission: %v", err)
	}
	if resp.Ticket != "016f84e8-f9b9-11e0-bd6f-0021cc6004de" {
		t.Errorf("Ticket = %q", resp.Ticket)
	}
}

func TestPermission_PATHeader(t *testing.T) {
	// WithPAT must populate the Authorization: Bearer header on
	// protection-API calls.
	var sawAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintln(w, `{"ticket":"t"}`)
	}))
	t.Cleanup(srv.Close)
	c, err := client.NewClient(srv.URL, client.WithPAT("pat-abc"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = c.Permission(context.Background(), &uma.PermissionRequest{
		ResourceID:     "r1",
		ResourceScopes: []string{"view"},
	})
	if err != nil {
		t.Fatalf("Permission: %v", err)
	}
	want := "Bearer pat-abc"
	if sawAuth != want {
		t.Errorf("Authorization = %q, want %q", sawAuth, want)
	}
}

func TestPermission_NoPATHeaderWhenUnset(t *testing.T) {
	var sawAuth string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintln(w, `{"ticket":"t"}`)
	})
	_, err := c.Permission(context.Background(), &uma.PermissionRequest{
		ResourceID:     "r1",
		ResourceScopes: []string{"view"},
	})
	if err != nil {
		t.Fatalf("Permission: %v", err)
	}
	if sawAuth != "" {
		t.Errorf("Authorization sent without PAT: %q", sawAuth)
	}
}

func TestPermission_InvalidScope_OAuthError(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintln(w, `{"error":"invalid_scope","error_description":"scope not registered"}`)
	})
	_, err := c.Permission(context.Background(), &uma.PermissionRequest{
		ResourceID:     "r1",
		ResourceScopes: []string{"badscope"},
	})
	if !errors.Is(err, uma.ErrInvalidScope) {
		t.Errorf("errors.Is(err, ErrInvalidScope) = false; err = %v", err)
	}
}

func TestPermission_NilRequest(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("server should not be hit for nil request")
	})
	_, err := c.Permission(context.Background(), nil)
	if err == nil {
		t.Fatal("Permission(nil) = nil error, want non-nil")
	}
}

func TestPermission_TransportError(t *testing.T) {
	want := errors.New("dial tcp: simulated")
	c, err := client.NewClient("https://as.example.com", client.WithHTTPDoer(failingDoer{err: want}))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = c.Permission(context.Background(), &uma.PermissionRequest{
		ResourceID:     "r1",
		ResourceScopes: []string{"view"},
	})
	if !errors.Is(err, want) {
		t.Errorf("errors.Is on transport error = false; err = %v", err)
	}
}

func TestPermission_MalformedJSONIn201(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintln(w, `{ not json`)
	})
	_, err := c.Permission(context.Background(), &uma.PermissionRequest{
		ResourceID:     "r1",
		ResourceScopes: []string{"view"},
	})
	if err == nil {
		t.Fatal("Permission returned nil error on malformed JSON")
	}
}
