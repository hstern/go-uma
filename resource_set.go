// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package uma

import "fmt"

// ResourceSet is the protected-resource description registered by the
// Resource Server at the AS's [ResourceSetEndpoint] (Federated Authz §2.1).
// The same struct serves three wire roles:
//
//   - As the body of a POST /resource_set (register) or
//     PUT /resource_set/{rsid} (update) request, populated by the RS with
//     Name + ResourceScopes (required) and the optional metadata fields.
//     ID and UserAccessPolicyURI are AS-assigned and should be empty in
//     the request body.
//   - As the body of a GET /resource_set/{rsid} response, populated by
//     the AS with every field including ID and UserAccessPolicyURI.
//   - As the body of a POST /resource_set 201 Created response, populated
//     by the AS with ID (mandatory) and UserAccessPolicyURI (optional);
//     every other field is empty.
//
// Each field carries `omitempty` so the same struct survives all three
// roles with no leakage between them. Validate at the marshal boundary
// (the per-type Validate landing alongside [ValidationError]) catches
// the "missing required field on registration" case at the call site
// rather than as a 400 from the AS.
type ResourceSet struct {
	// ResourceScopes is the list of operations the RS wants the AS to
	// be able to issue tickets for against this resource. Required on
	// POST / PUT.
	ResourceScopes []string `json:"resource_scopes,omitempty"`

	// Name is a human-readable label for the resource. Required on
	// POST / PUT.
	Name string `json:"name,omitempty"`

	// URI is an optional endpoint URI for the resource — useful for
	// AS-side display in user-facing pages.
	URI string `json:"uri,omitempty"`

	// Type is an optional type URI categorizing the resource (e.g.
	// "http://photoz.example.com/dev/scopes/photo").
	Type string `json:"type,omitempty"`

	// IconURI is an optional URI of a graphical icon representing the
	// resource — typically rendered in AS-side authorization UIs.
	IconURI string `json:"icon_uri,omitempty"`

	// Description is an optional human-readable description of the
	// resource.
	Description string `json:"description,omitempty"`

	// ID is the AS-assigned identifier returned in the POST response
	// and echoed in GET responses. Empty when an RS is building a
	// POST / PUT body.
	ID string `json:"_id,omitempty"`

	// UserAccessPolicyURI is an optional URI the AS may return alongside
	// the ID in a POST response, pointing the RS at the AS-hosted page
	// where the Resource Owner can configure access policy for the
	// newly-registered resource.
	UserAccessPolicyURI string `json:"user_access_policy_uri,omitempty"`
}

// ResourceSetOp tags the five Federated Authz §2 resource-set CRUD
// operations. Useful as a discriminator in server-side dispatchers and
// in client-side request builders that route by op.
//
// OpUnknown is the zero value sentinel — a `var op ResourceSetOp` that
// was never explicitly assigned catches the uninitialized case rather
// than silently behaving as OpCreate.
type ResourceSetOp int

const (
	// OpUnknown is the zero-value sentinel — an unassigned ResourceSetOp
	// is OpUnknown, not OpCreate. Switch defaults that reach OpUnknown
	// should treat it as a programmer error.
	OpUnknown ResourceSetOp = iota

	// OpCreate is POST /resource_set with a ResourceSet body — the RS
	// registers a new resource with the AS.
	OpCreate

	// OpRead is GET /resource_set/{rsid} — the RS fetches the current
	// AS-side view of a previously-registered resource.
	OpRead

	// OpUpdate is PUT /resource_set/{rsid} with a ResourceSet body —
	// the RS overwrites the AS-side description.
	OpUpdate

	// OpDelete is DELETE /resource_set/{rsid} — the RS removes a
	// resource from the AS's registry.
	OpDelete

	// OpList is GET /resource_set — the AS returns the array of
	// resource IDs the RS has registered with it (just IDs, not full
	// ResourceSet objects).
	OpList
)

// String returns the human-readable name of the op, useful in log lines
// and error messages. An out-of-range ResourceSetOp renders as
// "ResourceSetOp(N)" rather than panicking.
func (o ResourceSetOp) String() string {
	switch o {
	case OpUnknown:
		return "unknown"
	case OpCreate:
		return "create"
	case OpRead:
		return "read"
	case OpUpdate:
		return "update"
	case OpDelete:
		return "delete"
	case OpList:
		return "list"
	}
	return fmt.Sprintf("ResourceSetOp(%d)", int(o))
}
