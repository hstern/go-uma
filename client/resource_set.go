// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/hstern/go-uma"
)

// CreateResourceSet registers a new protected resource with the AS at
// POST /resource_set (Federated Authz §2.2). The Resource Server
// supplies a [uma.ResourceSet] with Name + ResourceScopes (required by
// the spec, enforced by the AS — clients can pre-check via
// [uma.ResourceSet.Validate]) and the AS returns the same record
// populated with the server-assigned ID and the optional
// UserAccessPolicyURI.
//
// PAT-authenticated.
//
// Return-value matrix:
//
//   - HTTP 201 with a JSON body → returns the response *ResourceSet
//     carrying ID + UserAccessPolicyURI (any other fields are empty
//     per the spec — the 201 body does not echo the request).
//   - Any OAuth 2.0 error envelope → returns (nil, *uma.OAuthError).
//   - Transport / decode / I/O failure → returns (nil, wrapped error).
func (c *defaultClient) CreateResourceSet(ctx context.Context, rs *uma.ResourceSet) (*uma.ResourceSet, error) {
	if rs == nil {
		return nil, errors.New("uma client: nil ResourceSet")
	}
	body, err := json.Marshal(rs)
	if err != nil {
		return nil, fmt.Errorf("uma client: encode /resource_set body: %w", err)
	}
	endpoint := c.endpointURL(uma.ResourceSetEndpoint).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("uma client: build /resource_set POST request: %w", err)
	}
	return c.doResourceSet(req, http.StatusCreated, "/resource_set POST")
}

// ReadResourceSet fetches the AS-side description of a previously-
// registered resource via GET /resource_set/{rsid} (Federated Authz
// §2.3). The id argument is the AS-assigned identifier returned by
// [CreateResourceSet] in the response's ID field; an empty id returns
// an error without making any network call.
//
// PAT-authenticated. On HTTP 200 the returned [*uma.ResourceSet] is
// fully populated; the AS echoes every field plus the ID.
func (c *defaultClient) ReadResourceSet(ctx context.Context, id string) (*uma.ResourceSet, error) {
	if id == "" {
		return nil, errors.New("uma client: empty resource-set id")
	}
	endpoint := c.endpointURL(uma.ResourceSetEndpoint + "/" + id).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("uma client: build /resource_set GET request: %w", err)
	}
	return c.doResourceSet(req, http.StatusOK, "/resource_set GET")
}

// UpdateResourceSet replaces the AS-side description of a registered
// resource via PUT /resource_set/{rsid} (Federated Authz §2.4). The
// id argument selects the resource; rs supplies the new description,
// which must again carry Name + ResourceScopes.
//
// PAT-authenticated. On HTTP 200 the returned [*uma.ResourceSet] is
// the updated record.
func (c *defaultClient) UpdateResourceSet(ctx context.Context, id string, rs *uma.ResourceSet) (*uma.ResourceSet, error) {
	if id == "" {
		return nil, errors.New("uma client: empty resource-set id")
	}
	if rs == nil {
		return nil, errors.New("uma client: nil ResourceSet")
	}
	body, err := json.Marshal(rs)
	if err != nil {
		return nil, fmt.Errorf("uma client: encode /resource_set body: %w", err)
	}
	endpoint := c.endpointURL(uma.ResourceSetEndpoint + "/" + id).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("uma client: build /resource_set PUT request: %w", err)
	}
	return c.doResourceSet(req, http.StatusOK, "/resource_set PUT")
}

// DeleteResourceSet removes a registered resource from the AS via
// DELETE /resource_set/{rsid} (Federated Authz §2.5). A successful
// response carries no body (HTTP 204); the method returns nil. An
// OAuth-error envelope produces a [*uma.OAuthError] as elsewhere;
// transport / I/O failures return a wrapped error.
//
// PAT-authenticated. An empty id returns an error without making any
// network call.
func (c *defaultClient) DeleteResourceSet(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("uma client: empty resource-set id")
	}
	endpoint := c.endpointURL(uma.ResourceSetEndpoint + "/" + id).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, http.NoBody)
	if err != nil {
		return fmt.Errorf("uma client: build /resource_set DELETE request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	c.authorize(req)

	resp, err := c.doer.Do(req)
	if err != nil {
		return fmt.Errorf("uma client: /resource_set DELETE: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
		return nil
	}
	raw, _ := io.ReadAll(resp.Body)
	return decodeOAuthError(resp.StatusCode, raw)
}

// ListResourceSets returns the IDs of every resource the Resource
// Server has registered with the AS, via GET /resource_set
// (Federated Authz §2.6). The response is a JSON array of opaque
// identifier strings — NOT an array of full [uma.ResourceSet]
// records; fetch each with [ReadResourceSet] to get the description.
//
// PAT-authenticated. A 200 with an empty array returns
// (nil, nil) — no error, no ids.
func (c *defaultClient) ListResourceSets(ctx context.Context) ([]string, error) {
	endpoint := c.endpointURL(uma.ResourceSetEndpoint).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("uma client: build /resource_set LIST request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	c.authorize(req)

	resp, err := c.doer.Do(req)
	if err != nil {
		return nil, fmt.Errorf("uma client: /resource_set LIST: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("uma client: /resource_set LIST: read body: %w", err)
	}
	if resp.StatusCode == http.StatusOK {
		var ids []string
		if err := json.Unmarshal(raw, &ids); err != nil {
			return nil, fmt.Errorf("uma client: /resource_set LIST: decode 200 body: %w", err)
		}
		return ids, nil
	}
	return nil, decodeOAuthError(resp.StatusCode, raw)
}

// doResourceSet is the shared body-returning helper for the three
// resource-set methods that expect a [uma.ResourceSet] body on
// success (Create, Read, Update). req is fully populated by the
// caller except for the Authorization header (which this helper
// sets) and the Content-Type / Accept headers (which this helper
// also sets to "application/json"). wantStatus is the expected
// success status code (201 for Create, 200 for Read / Update).
func (c *defaultClient) doResourceSet(req *http.Request, wantStatus int, label string) (*uma.ResourceSet, error) {
	if req.Body != nil && req.Body != http.NoBody {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	c.authorize(req)

	resp, err := c.doer.Do(req)
	if err != nil {
		return nil, fmt.Errorf("uma client: %s: %w", label, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("uma client: %s: read body: %w", label, err)
	}
	if resp.StatusCode == wantStatus {
		var rs uma.ResourceSet
		if err := json.Unmarshal(raw, &rs); err != nil {
			return nil, fmt.Errorf("uma client: %s: decode %d body: %w", label, wantStatus, err)
		}
		return &rs, nil
	}
	return nil, decodeOAuthError(resp.StatusCode, raw)
}
