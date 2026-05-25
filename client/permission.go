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

// Permission registers a permission with the AS at /permission
// (Federated Authz §4.1) and returns the permission ticket the AS
// minted in response. The Resource Server calls Permission when a
// requesting-party client lacks sufficient authorization to a
// protected resource: the AS-side ticket is then carried back to the
// client in the RS's 401 WWW-Authenticate challenge so the client
// can redeem it at /token.
//
// Permission is PAT-authenticated. The PAT lands on the wire via the
// Authorization: Bearer header — configure it with [WithPAT] at
// construction, or wire it through an [HTTPDoer] wrapper such as
// [NewPATDoer].
//
// The wire body always renders as a JSON array of permissions even
// for the single-permission call, matching [uma.PermissionRequests]
// 's MarshalJSON. This makes the library forward-compatible against
// a future spec revision that drops the bare-object form. A 201
// Created response carries a single ticket regardless of array
// length.
//
// Return-value matrix:
//
//   - HTTP 201 with a JSON body → returns (*PermissionResponse, nil).
//   - Any OAuth 2.0 error envelope → returns (nil, *uma.OAuthError).
//   - Transport / decode / I/O failure → returns (nil, wrapped error).
//
// A nil request returns a non-nil error without making any network
// call.
func (c *defaultClient) Permission(ctx context.Context, r *uma.PermissionRequest) (*uma.PermissionResponse, error) {
	if r == nil {
		return nil, errors.New("uma client: nil PermissionRequest")
	}

	body, err := json.Marshal(uma.PermissionRequests{*r})
	if err != nil {
		return nil, fmt.Errorf("uma client: encode /permission body: %w", err)
	}

	endpoint := c.endpointURL(uma.PermissionEndpoint).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("uma client: build /permission request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	c.authorize(req)

	resp, err := c.doer.Do(req)
	if err != nil {
		return nil, fmt.Errorf("uma client: /permission: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("uma client: /permission: read body: %w", err)
	}

	if resp.StatusCode == http.StatusCreated {
		var pr uma.PermissionResponse
		if err := json.Unmarshal(raw, &pr); err != nil {
			return nil, fmt.Errorf("uma client: /permission: decode 201 body: %w", err)
		}
		return &pr, nil
	}

	return nil, decodeOAuthError(resp.StatusCode, raw)
}
