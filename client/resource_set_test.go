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
	"reflect"
	"testing"

	"github.com/hstern/go-uma"
	"github.com/hstern/go-uma/client"
)

func TestCreateResourceSet_Success(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/resource_set" {
			t.Errorf("path = %q, want /resource_set", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		raw, _ := io.ReadAll(r.Body)
		var got uma.ResourceSet
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("body not a ResourceSet: %v", err)
		}
		if got.Name != "My Photos" {
			t.Errorf("Name = %q, want My Photos", got.Name)
		}
		if got.ID != "" {
			t.Errorf("request body must not carry _id; got %q", got.ID)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintln(w, `{"_id":"abc-123","user_access_policy_uri":"https://as.example.com/policy/abc-123"}`)
	})
	resp, err := c.CreateResourceSet(context.Background(), &uma.ResourceSet{
		Name:           "My Photos",
		ResourceScopes: []string{"view"},
	})
	if err != nil {
		t.Fatalf("CreateResourceSet: %v", err)
	}
	if resp.ID != "abc-123" {
		t.Errorf("ID = %q, want abc-123", resp.ID)
	}
	if resp.UserAccessPolicyURI == "" {
		t.Error("UserAccessPolicyURI empty")
	}
}

func TestCreateResourceSet_NilBody(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("server should not be hit for nil ResourceSet")
	})
	_, err := c.CreateResourceSet(context.Background(), nil)
	if err == nil {
		t.Fatal("CreateResourceSet(nil) = nil error")
	}
}

func TestReadResourceSet_Success(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		want := "/resource_set/abc-123"
		if r.URL.Path != want {
			t.Errorf("path = %q, want %q", r.URL.Path, want)
		}
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{
			"_id":"abc-123",
			"name":"My Photos",
			"resource_scopes":["view","edit"],
			"uri":"http://photoz.example.com/me",
			"user_access_policy_uri":"https://as.example.com/policy/abc-123"
		}`)
	})
	resp, err := c.ReadResourceSet(context.Background(), "abc-123")
	if err != nil {
		t.Fatalf("ReadResourceSet: %v", err)
	}
	if resp.Name != "My Photos" {
		t.Errorf("Name = %q, want My Photos", resp.Name)
	}
	if len(resp.ResourceScopes) != 2 {
		t.Errorf("ResourceScopes len = %d, want 2", len(resp.ResourceScopes))
	}
}

func TestReadResourceSet_EmptyID(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("server should not be hit for empty id")
	})
	_, err := c.ReadResourceSet(context.Background(), "")
	if err == nil {
		t.Fatal("ReadResourceSet(\"\") = nil error")
	}
}

func TestUpdateResourceSet_Success(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		want := "/resource_set/abc-123"
		if r.URL.Path != want {
			t.Errorf("path = %q, want %q", r.URL.Path, want)
		}
		if r.Method != http.MethodPut {
			t.Errorf("method = %q, want PUT", r.Method)
		}
		raw, _ := io.ReadAll(r.Body)
		var got uma.ResourceSet
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("body not a ResourceSet: %v", err)
		}
		if got.Name != "New Name" {
			t.Errorf("Name = %q, want New Name", got.Name)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{"_id":"abc-123","name":"New Name","resource_scopes":["view"]}`)
	})
	resp, err := c.UpdateResourceSet(context.Background(), "abc-123", &uma.ResourceSet{
		Name:           "New Name",
		ResourceScopes: []string{"view"},
	})
	if err != nil {
		t.Fatalf("UpdateResourceSet: %v", err)
	}
	if resp.Name != "New Name" {
		t.Errorf("Name = %q, want New Name", resp.Name)
	}
}

func TestUpdateResourceSet_EmptyArgs(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("server should not be hit for invalid args")
	})
	if _, err := c.UpdateResourceSet(context.Background(), "", &uma.ResourceSet{Name: "x"}); err == nil {
		t.Error("UpdateResourceSet with empty id = nil error")
	}
	if _, err := c.UpdateResourceSet(context.Background(), "abc", nil); err == nil {
		t.Error("UpdateResourceSet with nil ResourceSet = nil error")
	}
}

func TestDeleteResourceSet_NoContent(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		want := "/resource_set/abc-123"
		if r.URL.Path != want {
			t.Errorf("path = %q, want %q", r.URL.Path, want)
		}
		if r.Method != http.MethodDelete {
			t.Errorf("method = %q, want DELETE", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	if err := c.DeleteResourceSet(context.Background(), "abc-123"); err != nil {
		t.Fatalf("DeleteResourceSet: %v", err)
	}
}

func TestDeleteResourceSet_EmptyID(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("server should not be hit for empty id")
	})
	if err := c.DeleteResourceSet(context.Background(), ""); err == nil {
		t.Fatal("DeleteResourceSet(\"\") = nil error")
	}
}

func TestDeleteResourceSet_NotFound404(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprintln(w, `{"error":"not_found","error_description":"unknown resource"}`)
	})
	err := c.DeleteResourceSet(context.Background(), "abc-123")
	if err == nil {
		t.Fatal("DeleteResourceSet on 404 = nil error")
	}
	var oe *uma.OAuthError
	if !errors.As(err, &oe) {
		t.Errorf("errors.As(*OAuthError) failed; err = %v", err)
	}
}

func TestListResourceSets_Success(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/resource_set" {
			t.Errorf("path = %q, want /resource_set", r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `["abc-123","def-456","112210f47de98100"]`)
	})
	ids, err := c.ListResourceSets(context.Background())
	if err != nil {
		t.Fatalf("ListResourceSets: %v", err)
	}
	want := []string{"abc-123", "def-456", "112210f47de98100"}
	if !reflect.DeepEqual(ids, want) {
		t.Errorf("ids = %v, want %v", ids, want)
	}
}

func TestListResourceSets_Empty(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `[]`)
	})
	ids, err := c.ListResourceSets(context.Background())
	if err != nil {
		t.Fatalf("ListResourceSets: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("len(ids) = %d, want 0", len(ids))
	}
}

func TestResourceSet_PATHeader_OnAllMethods(t *testing.T) {
	// The PAT injection invariant holds for all five resource-set
	// methods. Each one should land "Bearer pat-xyz" in the
	// Authorization header.
	check := func(t *testing.T, label string, fn func(c client.Client, srvURL string) error) {
		t.Helper()
		var sawAuth string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sawAuth = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			switch r.Method {
			case http.MethodPost:
				w.WriteHeader(http.StatusCreated)
				_, _ = fmt.Fprintln(w, `{"_id":"x"}`)
			case http.MethodGet:
				if r.URL.Path == "/resource_set" {
					_, _ = fmt.Fprintln(w, `[]`)
				} else {
					_, _ = fmt.Fprintln(w, `{"_id":"x","name":"n","resource_scopes":["v"]}`)
				}
			case http.MethodPut:
				_, _ = fmt.Fprintln(w, `{"_id":"x","name":"n","resource_scopes":["v"]}`)
			case http.MethodDelete:
				w.WriteHeader(http.StatusNoContent)
			}
		}))
		t.Cleanup(srv.Close)
		c, err := client.NewClient(srv.URL, client.WithPAT("pat-xyz"))
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		if err := fn(c, srv.URL); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if sawAuth != "Bearer pat-xyz" {
			t.Errorf("%s: Authorization = %q, want Bearer pat-xyz", label, sawAuth)
		}
	}
	rs := &uma.ResourceSet{Name: "n", ResourceScopes: []string{"v"}}
	check(t, "Create", func(c client.Client, _ string) error {
		_, err := c.CreateResourceSet(context.Background(), rs)
		return err
	})
	check(t, "Read", func(c client.Client, _ string) error {
		_, err := c.ReadResourceSet(context.Background(), "x")
		return err
	})
	check(t, "Update", func(c client.Client, _ string) error {
		_, err := c.UpdateResourceSet(context.Background(), "x", rs)
		return err
	})
	check(t, "Delete", func(c client.Client, _ string) error {
		return c.DeleteResourceSet(context.Background(), "x")
	})
	check(t, "List", func(c client.Client, _ string) error {
		_, err := c.ListResourceSets(context.Background())
		return err
	})
}
