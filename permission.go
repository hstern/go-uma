// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package uma

import (
	"bytes"
	"encoding/json"
)

// PermissionRequest is a single permission entry the Resource Server
// registers with the AS at [PermissionEndpoint] (Federated Authz §4.1).
// Each entry pairs a registered resource (by its AS-assigned identifier)
// with the scopes the RS wants the AS to issue a ticket for.
//
// The wire body of a POST /permission may carry either a single
// PermissionRequest object or an array; for the array form use
// [PermissionRequests], which round-trips both wire shapes.
type PermissionRequest struct {
	// ResourceID is the AS-assigned identifier returned by the resource
	// registration endpoint when this resource was created — the `_id`
	// field of the ResourceSet response.
	ResourceID string `json:"resource_id"`

	// ResourceScopes is the set of scopes the RS wants the AS's ticket to
	// cover, drawn from the resource's registered ResourceScopes.
	ResourceScopes []string `json:"resource_scopes"`
}

// PermissionRequests is the wire body of a POST /permission when the RS
// is registering one or more permissions in a single call. The spec
// (Federated Authz §4.1) allows either a bare object or a JSON array of
// objects; the library accepts both on the wire and emits the array form
// on marshal so a future spec revision that drops the bare-object form
// will not change observable behavior for existing clients.
type PermissionRequests []PermissionRequest

// MarshalJSON emits the array form regardless of length — a single-entry
// PermissionRequests still renders as `[{...}]`, never as the bare object.
// A nil or empty PermissionRequests marshals as `[]`.
func (p PermissionRequests) MarshalJSON() ([]byte, error) {
	if p == nil {
		return []byte("[]"), nil
	}
	type alias []PermissionRequest
	return json.Marshal(alias(p))
}

// UnmarshalJSON accepts either a single PermissionRequest object or a
// JSON array of them, lifting the single form into a one-entry slice.
// This matches the spec's allowance for either wire shape and lets a
// server-side handler take either form interchangeably.
//
// A JSON null is treated as "no permissions" and clears the receiver to
// nil, matching stdlib semantics for unmarshalling null into a slice.
func (p *PermissionRequests) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if bytes.Equal(trimmed, []byte("null")) {
		*p = nil
		return nil
	}
	if len(trimmed) > 0 && trimmed[0] == '[' {
		type alias []PermissionRequest
		var arr alias
		if err := json.Unmarshal(data, &arr); err != nil {
			return err
		}
		*p = PermissionRequests(arr)
		return nil
	}
	var single PermissionRequest
	if err := json.Unmarshal(data, &single); err != nil {
		return err
	}
	*p = PermissionRequests{single}
	return nil
}

// Validate checks the required-field invariants on r and returns a typed
// *ValidationError naming the first missing field. ResourceID and
// ResourceScopes are both required by Federated Authz §4.1; an entry
// without either is not a meaningful permission registration.
func (r *PermissionRequest) Validate() error {
	if r == nil || r.ResourceID == "" {
		return &ValidationError{Type: "PermissionRequest", Field: "resource_id", Message: "required"}
	}
	if len(r.ResourceScopes) == 0 {
		return &ValidationError{Type: "PermissionRequest", Field: "resource_scopes", Message: "required"}
	}
	return nil
}

// PermissionResponse is the JSON 201 Created body returned by the AS
// in response to a permission registration (Federated Authz §4.2). It
// carries exactly one field: the permission ticket the RS includes in
// its 401 WWW-Authenticate challenge to the client.
//
// The ticket is opaque to both the RS and the requesting-party client —
// the library types it as a string and never decodes it. An AS may
// embed structured data in the ticket, but consumers must not depend
// on any internal shape.
type PermissionResponse struct {
	Ticket string `json:"ticket"`
}
