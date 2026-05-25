// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package uma_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hstern/go-uma"
)

func TestSpecVersion(t *testing.T) {
	// UMA 2.0 was finalized 2018-01 and has not been revised; an edit
	// here is almost certainly a regression.
	if uma.SpecVersion != "2.0" {
		t.Errorf("SpecVersion = %q, want 2.0", uma.SpecVersion)
	}
}

func TestWWWAuthenticateConstant(t *testing.T) {
	if uma.WWWAuthenticate != "WWW-Authenticate" {
		t.Errorf("WWWAuthenticate = %q, want WWW-Authenticate", uma.WWWAuthenticate)
	}
}

func TestBuildUMAChallenge_AllFields(t *testing.T) {
	got := uma.BuildUMAChallenge(
		"https://as.example.com",
		"016f84e8-f9b9-11e0-bd6f-0021cc6004de",
		"view edit",
		"example",
	)
	want := `UMA realm="example", as_uri="https://as.example.com", ticket="016f84e8-f9b9-11e0-bd6f-0021cc6004de", scope="view edit"`
	if got != want {
		t.Errorf("BuildUMAChallenge:\n  got:  %s\n  want: %s", got, want)
	}
}

func TestBuildUMAChallenge_OmitsEmptyScope(t *testing.T) {
	got := uma.BuildUMAChallenge(
		"https://as.example.com",
		"016f84e8-f9b9-11e0-bd6f-0021cc6004de",
		"",
		"example",
	)
	want := `UMA realm="example", as_uri="https://as.example.com", ticket="016f84e8-f9b9-11e0-bd6f-0021cc6004de"`
	if got != want {
		t.Errorf("BuildUMAChallenge with empty scope:\n  got:  %s\n  want: %s", got, want)
	}
}

func TestBuildUMAChallenge_UMASchemePrefix(t *testing.T) {
	// The auth-scheme prefix is exactly "UMA " — case and spelling
	// pinned. RFC 7235 §2.1 says the scheme name is case-insensitive
	// in matching, but the canonical emission is uppercase.
	got := uma.BuildUMAChallenge("https://as.example.com", "t", "", "r")
	if got[:4] != "UMA " {
		t.Errorf("BuildUMAChallenge does not start with %q: %s", "UMA ", got)
	}
}

func TestBuildUMAChallenge_OnHTTPResponseWriter(t *testing.T) {
	// Integration-shaped: the resulting string slots into a real
	// http.ResponseWriter exactly as a 401 challenge.
	w := httptest.NewRecorder()
	w.Header().Set(uma.WWWAuthenticate, uma.BuildUMAChallenge(
		"https://as.example.com",
		"t-1",
		"view",
		"my-realm",
	))
	w.WriteHeader(http.StatusUnauthorized)
	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()
	got := resp.Header.Get("WWW-Authenticate")
	want := `UMA realm="my-realm", as_uri="https://as.example.com", ticket="t-1", scope="view"`
	if got != want {
		t.Errorf("response header WWW-Authenticate:\n  got:  %s\n  want: %s", got, want)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func ExampleBuildUMAChallenge() {
	header := uma.BuildUMAChallenge(
		"https://as.example.com",
		"016f84e8-f9b9-11e0-bd6f-0021cc6004de",
		"view",
		"example",
	)
	fmt.Println(header)

	// Output:
	// UMA realm="example", as_uri="https://as.example.com", ticket="016f84e8-f9b9-11e0-bd6f-0021cc6004de", scope="view"
}
