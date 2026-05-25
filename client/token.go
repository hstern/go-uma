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

// Token redeems a permission ticket for a requesting-party token (RPT)
// via the AS's /token endpoint under the UMA-ticket grant (Grant §3.3).
// The caller supplies a [*uma.TokenRequest] carrying at minimum the
// permission ticket it received from the RS's 401 WWW-Authenticate
// challenge; optional fields cover claim-token pushing, RPT upgrade,
// scope narrowing, and the persisted-claims-token echo.
//
// The /token endpoint does not use the PAT — the requesting-party
// client authenticates through a separate OAuth 2.0 client-
// authentication mechanism the library does not constrain. Wire that
// authentication through an [HTTPDoer] passed via [WithHTTPDoer].
//
// Return-value matrix:
//
//   - HTTP 200 with a JSON body → returns (*TokenResponse, nil).
//   - HTTP 403 with "error":"need_info" → returns
//     (nil, *uma.NeedInfoError) carrying the fresh ticket, the
//     required claims, and the optional redirect_user URL. This is
//     NOT a transport error; extract the typed value with
//     [errors.As] and act on it (gather claims, redirect, retry).
//   - Any other OAuth 2.0 error envelope (RFC 6749 §5.2) → returns
//     (nil, *uma.OAuthError). Match on the ErrorCode field or via
//     [errors.Is] against the library's sentinels
//     (e.g. [uma.ErrNotAuthorized], [uma.ErrInvalidGrant]).
//   - Transport / decode / I/O failure → returns (nil, wrapped error).
//
// A nil ctx will panic per [net/http.NewRequestWithContext]; callers
// should pass [context.Background] when no cancellation context is
// available. A nil request returns a non-nil error without making any
// network call.
func (c *defaultClient) Token(ctx context.Context, r *uma.TokenRequest) (*uma.TokenResponse, error) {
	if r == nil {
		return nil, errors.New("uma client: nil TokenRequest")
	}

	body := strings.NewReader(r.Values().Encode())
	endpoint := c.endpointURL(uma.TokenEndpoint).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("uma client: build /token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.doer.Do(req)
	if err != nil {
		return nil, fmt.Errorf("uma client: /token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("uma client: /token: read body: %w", err)
	}

	if resp.StatusCode == http.StatusOK {
		var tr uma.TokenResponse
		if err := json.Unmarshal(raw, &tr); err != nil {
			return nil, fmt.Errorf("uma client: /token: decode 200 body: %w", err)
		}
		return &tr, nil
	}

	return nil, decodeOAuthError(resp.StatusCode, raw)
}

// decodeOAuthError parses the body of a non-2xx /token response into
// the most specific UMA error type available — [*uma.NeedInfoError]
// when the body's "error" field is "need_info", [*uma.OAuthError]
// otherwise. A body that fails to parse as the OAuth envelope falls
// back to an opaque error that carries the status code and raw body
// for the caller to log.
func decodeOAuthError(status int, raw []byte) error {
	var envelope uma.OAuthError
	if err := json.Unmarshal(raw, &envelope); err != nil || envelope.ErrorCode == "" {
		return fmt.Errorf("uma client: HTTP %d: %s", status, strings.TrimSpace(string(raw)))
	}
	if envelope.ErrorCode == uma.ErrorCodeNeedInfo {
		var ne uma.NeedInfoError
		if err := json.Unmarshal(raw, &ne); err == nil {
			return &ne
		}
	}
	return &envelope
}
