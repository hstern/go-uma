// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/hstern/go-uma"
)

// Introspect inspects a requesting-party token at the AS's
// /introspection endpoint (Federated Authz §5.1, which extends
// RFC 7662). The Resource Server calls Introspect to validate an
// RPT it has just received from a client — to learn whether the
// token is currently active, what scopes the AS authorized for it,
// and what permissions UMA layered on top.
//
// Introspect is PAT-authenticated.
//
// The load-bearing implementer pin: an Active=false response is NOT
// a transport error. The AS is reporting that the token is unknown,
// revoked, or expired, and the response is otherwise valid. The
// library returns the parsed IntrospectionResponse with Active=false
// and a nil error; consumers branch on the Active field themselves.
// A 200 with an Active=true response works the same way, returning
// the full RFC 7662 payload plus UMA's Permissions array.
//
// Return-value matrix:
//
//   - HTTP 200 with a JSON body → returns (*IntrospectionResponse, nil)
//     regardless of whether Active is true or false.
//   - Any OAuth 2.0 error envelope (RFC 7662 §2.3, e.g. invalid_token)
//     → returns (nil, *uma.OAuthError).
//   - Transport / decode / I/O failure → returns (nil, wrapped error).
//
// A nil request returns a non-nil error without making any network
// call.
func (c *defaultClient) Introspect(ctx context.Context, r *uma.IntrospectionRequest) (*uma.IntrospectionResponse, error) {
	if r == nil {
		return nil, errors.New("uma client: nil IntrospectionRequest")
	}

	body := strings.NewReader(r.Values().Encode())
	endpoint := c.endpointURL(uma.IntrospectionEndpoint).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("uma client: build /introspection request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	c.authorize(req)

	resp, err := c.doer.Do(req)
	if err != nil {
		return nil, fmt.Errorf("uma client: /introspection: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("uma client: /introspection: read body: %w", err)
	}

	if resp.StatusCode == http.StatusOK {
		var ir uma.IntrospectionResponse
		if err := json.Unmarshal(raw, &ir); err != nil {
			return nil, fmt.Errorf("uma client: /introspection: decode 200 body: %w", err)
		}
		return &ir, nil
	}

	return nil, decodeOAuthError(resp.StatusCode, raw)
}
