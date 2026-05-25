// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

// Demonstration tests for the signed_metadata pass-through.
//
// UMA configuration documents MAY carry a `signed_metadata` JWS
// field per RFC 7515 (the same mechanism OpenID Connect Discovery
// 1.0 §3 defines). v0.1 of this library stays JOSE-free: the
// SignedMetadata field is a json.RawMessage that round-trips opaque
// bytes through encode and decode without parsing or verifying. A
// future release adds the JOSE dependency for verification and
// signing; until then consumers that want either decode the JWS
// with their own JOSE library.
//
// These tests pin the pass-through invariant from two angles:
//
//  1. struct → encode → decode → struct preserves the bytes exactly,
//     including the JOSE-compact "header.payload.signature" form
//     and any other shape a consumer chooses to put in there.
//  2. The wire JSON renders signed_metadata verbatim — no
//     re-quoting, no normalization, no inspection.

package uma_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hstern/go-uma"
)

// fakeJWS is a representative JOSE compact-serialization payload
// the test uses to stand in for a real signed_metadata value. It's
// shaped like a real JWS (three base64url segments) but the bytes
// are not a valid signature — the point of these tests is the
// pass-through behavior, not any JOSE semantics.
const fakeJWS = `"eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xIn0.` +
	`eyJpc3MiOiJodHRwczovL2FzLmV4YW1wbGUuY29tIn0.` +
	`fake-signature-bytes"`

func TestSignedMetadata_StructRoundTrip(t *testing.T) {
	// The exact JWS bytes the consumer hands to WithSignedMetadata
	// must come back unchanged from BuildMetadata's output and from
	// a subsequent JSON encode → decode cycle.
	jws := json.RawMessage(fakeJWS)

	m := &uma.Metadata{Issuer: "https://as.example.com"}
	uma.WithSignedMetadata(jws)(m)
	if !bytes.Equal(m.SignedMetadata, jws) {
		t.Fatalf("WithSignedMetadata stored != input:\n  in:  %s\n  got: %s",
			string(jws), string(m.SignedMetadata))
	}

	encoded, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(encoded), fakeJWS) {
		t.Errorf("encoded document does not contain JWS verbatim:\n  enc:  %s\n  want: %s",
			string(encoded), fakeJWS)
	}

	var back uma.Metadata
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !bytes.Equal(back.SignedMetadata, jws) {
		t.Errorf("round-trip altered SignedMetadata:\n  orig: %s\n  back: %s",
			string(jws), string(back.SignedMetadata))
	}
}

func TestSignedMetadata_OptOutOmitsField(t *testing.T) {
	// A Metadata without SignedMetadata set must not include the
	// JSON key on the wire — consumers running JOSE-free
	// deployments should see no trace of the field.
	m := &uma.Metadata{Issuer: "https://as.example.com"}
	encoded, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(encoded), "signed_metadata") {
		t.Errorf("encoded document leaks signed_metadata key when unset: %s", string(encoded))
	}
}

func TestSignedMetadata_AcceptsObjectForm(t *testing.T) {
	// The spec specifies a JWS, which is normally a string in
	// compact serialization. But the JSON serialization form is an
	// object. The library does not constrain the shape — whatever
	// json.RawMessage the consumer passes through round-trips
	// verbatim. This test pins that flexibility.
	jws := json.RawMessage(`{
		"protected":"eyJhbGciOiJSUzI1NiJ9",
		"payload":"eyJpc3MiOiJodHRwczovL2FzLmV4YW1wbGUuY29tIn0",
		"signature":"fake"
	}`)
	m := &uma.Metadata{Issuer: "https://as.example.com"}
	uma.WithSignedMetadata(jws)(m)
	encoded, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var back uma.Metadata
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	// json.Marshal compacts whitespace, so we compare semantic
	// equivalence by decoding the round-tripped RawMessage into a
	// map and re-encoding. The bytes need not be byte-identical
	// across whitespace; what matters is the structural payload
	// the consumer's downstream verifier receives.
	var orig, got map[string]any
	_ = json.Unmarshal(jws, &orig)
	_ = json.Unmarshal(back.SignedMetadata, &got)
	for k, v := range orig {
		if got[k] != v {
			t.Errorf("SignedMetadata[%q]: orig %v, back %v", k, v, got[k])
		}
	}
}

func TestSignedMetadata_LibraryDoesNotParse(t *testing.T) {
	// A deliberately-malformed signed_metadata payload (not valid
	// JWS, not valid JSON object) still round-trips — the library
	// treats it as opaque bytes. A consumer's JOSE verifier would
	// reject it; the library does not pre-empt that decision.
	jws := json.RawMessage(`"this is not a real JWS"`)
	m := &uma.Metadata{Issuer: "https://as.example.com"}
	uma.WithSignedMetadata(jws)(m)
	encoded, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("Marshal on malformed payload: %v", err)
	}
	var back uma.Metadata
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !bytes.Equal(back.SignedMetadata, jws) {
		t.Errorf("malformed payload mutated on round-trip")
	}
}
