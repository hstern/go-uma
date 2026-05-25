// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package uma

import (
	"bytes"
	"encoding/json"
)

// Endpoint path constants for the UMA Authorization Server. The Grant and
// Federated Authorization Recommendations describe these paths by role, not
// by exact URI — every AS chooses its own absolute URLs and publishes them
// in the metadata document at MetadataPath. The constants below are the
// conventional paths used in the Grant §1.3.2 and Federated Authz §1.4
// examples; consumers are free to mount the [server] handler at any path.
const (
	// TokenEndpoint is the OAuth 2.0 token endpoint extended with the
	// UMA-ticket grant (Grant §3.3). Form-encoded; RqP-authenticated.
	TokenEndpoint = "/token"

	// PermissionEndpoint is the AS's permission registration endpoint, where
	// the RS exchanges a (resource_id, scopes) pair for a permission ticket
	// (Federated Authz §4). JSON; PAT-authenticated.
	PermissionEndpoint = "/permission"

	// IntrospectionEndpoint is the AS's RFC 7662 token introspection
	// endpoint, extended with UMA's permissions array (Federated Authz §5).
	// Form-encoded; PAT-authenticated.
	IntrospectionEndpoint = "/introspection"

	// ResourceSetEndpoint is the AS's resource registration endpoint, where
	// the RS performs CRUD on resource set descriptions (Federated Authz §2).
	// JSON; PAT-authenticated.
	ResourceSetEndpoint = "/resource_set"

	// MetadataPath is the conventional path for the UMA 2.0 configuration
	// document (Grant §1.3.2). Per the spec, the path is
	// `/.well-known/uma2-configuration` relative to the AS's issuer URL.
	MetadataPath = "/.well-known/uma2-configuration"
)

// DecodeJSON decodes raw into v. It treats a nil or empty raw as "no
// extension present" — v is left unchanged and the call returns nil rather
// than failing with an unexpected-EOF error. This matches the UMA wire
// convention that open extension fields (e.g. the per-permission claims
// payload in an introspection response, the open-extension fields on the
// metadata document) are optional and absent fields are normal, not
// exceptional.
//
// For any non-empty input, DecodeJSON delegates to [json.Unmarshal]. Use it
// to read a typed extension out of any [json.RawMessage] field on a UMA
// request or response.
func DecodeJSON(raw json.RawMessage, v any) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	return json.Unmarshal(raw, v)
}

// EncodeJSON encodes v into a [json.RawMessage]. If v is nil it returns a
// nil RawMessage so the encoded field is omitted under `omitempty` JSON
// tags. Otherwise it delegates to [json.Marshal].
//
// Use it to populate an open-extension field with a typed extension while
// preserving byte-stable round-trips for any other consumer that only
// reads the field as opaque bytes.
func EncodeJSON(v any) (json.RawMessage, error) {
	if v == nil {
		return nil, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return b, nil
}
