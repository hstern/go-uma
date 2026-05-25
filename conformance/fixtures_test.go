// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

// Spec-figure-derived conformance fixtures.
//
// UMA has no Kantara-run interop event. This package's testdata/
// directory holds JSON fixtures extracted verbatim from the example
// figures in the Grant 2.0 and Federated Authorization 2.0
// Recommendations; this test loads each fixture, decodes it into
// the corresponding wire type, and asserts byte-stable round-trip:
// the library's encoder produces a canonical form that round-trips
// through a second decode unchanged.
//
// The spec figures are pretty-printed; the library's encoder is
// compact. We don't expect byte-equality between the fixture and
// the encoded form — what matters is that the structure survives
// the round-trip and that the library's encoder converges on a
// stable shape.

package conformance_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/hstern/go-uma"
)

// fixture pairs a JSON file under testdata/ with the wire type it
// decodes into. The factory returns a fresh zero value of the
// target type each call — used both for the initial decode and for
// the second-pass decode.
type fixture struct {
	name    string
	file    string
	factory func() any
}

// fixtures enumerates every JSON fixture shipped under testdata/.
// Adding a new file: drop it under testdata/ with the established
// `<spec>-<section>-<short-name>.json` filename and append a row
// here pointing at the type it decodes into.
//
//nolint:gochecknoglobals // table-driven test fixture catalog.
var fixtures = []fixture{
	{
		name:    "grant-1.3.2-metadata",
		file:    "grant-1.3.2-metadata.json",
		factory: func() any { return new(uma.Metadata) },
	},
	{
		name:    "grant-3.3.5-token-response",
		file:    "grant-3.3.5-token-response.json",
		factory: func() any { return new(uma.TokenResponse) },
	},
	{
		name:    "grant-3.3.6-need-info",
		file:    "grant-3.3.6-need-info.json",
		factory: func() any { return new(uma.NeedInfoError) },
	},
	{
		name:    "fedauthz-2.1-resource-set",
		file:    "fedauthz-2.1-resource-set.json",
		factory: func() any { return new(uma.ResourceSet) },
	},
	{
		name:    "fedauthz-2.2-resource-set-create-response",
		file:    "fedauthz-2.2-resource-set-create-response.json",
		factory: func() any { return new(uma.ResourceSet) },
	},
	{
		name:    "fedauthz-4.1-permission-request-single",
		file:    "fedauthz-4.1-permission-request-single.json",
		factory: func() any { return new(uma.PermissionRequest) },
	},
	{
		name:    "fedauthz-4.1-permission-request-array",
		file:    "fedauthz-4.1-permission-request-array.json",
		factory: func() any { return new(uma.PermissionRequests) },
	},
	{
		name:    "fedauthz-4.2-permission-response",
		file:    "fedauthz-4.2-permission-response.json",
		factory: func() any { return new(uma.PermissionResponse) },
	},
	{
		name:    "fedauthz-5.1.1-introspection-response",
		file:    "fedauthz-5.1.1-introspection-response.json",
		factory: func() any { return new(uma.IntrospectionResponse) },
	},
	{
		name:    "fedauthz-5.1.1-introspection-inactive",
		file:    "fedauthz-5.1.1-introspection-inactive.json",
		factory: func() any { return new(uma.IntrospectionResponse) },
	},
}

func TestFixtures_ByteStableRoundTrip(t *testing.T) {
	for _, fx := range fixtures {
		t.Run(fx.name, func(t *testing.T) {
			path := filepath.Join("testdata", fx.file)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}

			// Initial decode of the spec figure.
			first := fx.factory()
			if err := json.Unmarshal(raw, first); err != nil {
				t.Fatalf("first decode of %s: %v", fx.file, err)
			}

			// Encode the decoded value to the library's canonical
			// form.
			encoded1, err := json.Marshal(first)
			if err != nil {
				t.Fatalf("first encode of %s: %v", fx.name, err)
			}

			// Decode the canonical form back. The result must equal
			// the first decode — this is the structural-stability
			// half of the invariant.
			second := fx.factory()
			if err := json.Unmarshal(encoded1, second); err != nil {
				t.Fatalf("second decode of %s: %v", fx.name, err)
			}
			if !reflect.DeepEqual(first, second) {
				t.Errorf("decoded values differ after canonical-form round-trip:\n  first:  %+v\n  second: %+v",
					first, second)
			}

			// Re-encode the second decode. The bytes must equal
			// encoded1 — this is the byte-stability half of the
			// invariant: successive encodes converge on the same
			// canonical form.
			encoded2, err := json.Marshal(second)
			if err != nil {
				t.Fatalf("second encode of %s: %v", fx.name, err)
			}
			if !bytes.Equal(encoded1, encoded2) {
				t.Errorf("library encoder produced non-canonical form:\n  encoded1: %s\n  encoded2: %s",
					string(encoded1), string(encoded2))
			}
		})
	}
}

func TestFixtures_AllPresent(t *testing.T) {
	// Defensive: every fixture row in the table above MUST
	// correspond to an actual file under testdata/. Catches a typo
	// in the filename column that would otherwise produce a "read
	// error" only when the row's subtest ran.
	for _, fx := range fixtures {
		path := filepath.Join("testdata", fx.file)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("fixture %q file %q not found: %v", fx.name, fx.file, err)
		}
	}
}
