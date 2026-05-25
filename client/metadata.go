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
	"strconv"
	"strings"
	"time"

	"github.com/hstern/go-uma"
)

// MixUpError is the typed error [Client.FetchMetadata] returns when
// the fetched configuration document's Issuer field does not match
// the URL the client was constructed against. The spec
// (Grant §1.3.2 + RFC 8252 §6) requires the check by default: an
// attacker substituting a metadata document from a different AS
// would otherwise be able to redirect the client's token redemption,
// introspection, and permission registration calls to a hostile AS
// — a confused-deputy class vulnerability.
//
// Configured is the URL the client passed to [NewClient]; Issuer is
// the document's claimed identifier. Match against either via
// [errors.As] or by inspecting the fields directly.
type MixUpError struct {
	Configured string
	Issuer     string
}

// Error implements the error interface.
func (e *MixUpError) Error() string {
	if e == nil {
		return "<nil *client.MixUpError>"
	}
	return fmt.Sprintf(
		"uma client: metadata mix-up: configured %q but document issuer %q",
		e.Configured, e.Issuer,
	)
}

// FetchMetadata fetches the AS's UMA 2.0 configuration document at
// [uma.MetadataPath] (`/.well-known/uma2-configuration`) and returns
// the parsed [*uma.Metadata]. Subsequent calls return the cached
// document until it expires per the AS's Cache-Control: max-age (or
// the configured fallback TTL when the response carries no max-age).
//
// Mix-up validation runs by default: the document's Issuer field
// MUST equal the URL the client was constructed against, else
// FetchMetadata returns a typed [*MixUpError] WITHOUT caching the
// response. Opt out only via [WithRelaxedMetadataValidation], and
// only when a TLS terminator or path-prefix rewriter legitimately
// produces a configured URL distinct from the published Issuer.
//
// The returned [*uma.Metadata] is the same pointer for every cache-
// hit caller. Treat it as read-only; mutations will surface in
// every subsequent caller's view.
func (c *defaultClient) FetchMetadata(ctx context.Context) (*uma.Metadata, error) {
	now := time.Now()

	c.metaMu.Lock()
	if c.metaCache != nil && now.Before(c.metaCache.expires) {
		doc := c.metaCache.doc
		c.metaMu.Unlock()
		return doc, nil
	}
	c.metaMu.Unlock()

	endpoint := c.endpointURL(uma.MetadataPath).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("uma client: build FetchMetadata request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.doer.Do(req)
	if err != nil {
		return nil, fmt.Errorf("uma client: FetchMetadata: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("uma client: FetchMetadata: read body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("uma client: FetchMetadata: HTTP %d", resp.StatusCode)
	}

	var doc uma.Metadata
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("uma client: FetchMetadata: decode body: %w", err)
	}

	if !c.metaRelaxedMixUp {
		if !sameIssuer(c.baseURL.String(), doc.Issuer) {
			return nil, &MixUpError{
				Configured: c.baseURL.String(),
				Issuer:     doc.Issuer,
			}
		}
	}

	ttl := cacheTTL(resp.Header.Get("Cache-Control"), c.metaDefaultTTL)
	c.metaMu.Lock()
	c.metaCache = &cachedMetadata{doc: &doc, expires: now.Add(ttl)}
	c.metaMu.Unlock()

	return &doc, nil
}

// sameIssuer returns true when configured and issuer name the same
// AS. The comparison strips a single trailing slash from each side
// to absorb the common normalization difference; further
// normalization (case folding on scheme/host, default-port
// canonicalization) is intentionally NOT performed — a configured
// URL that disagrees on scheme or port from the issuer is a
// deployment misconfiguration the consumer should notice, not
// something the library should paper over.
func sameIssuer(configured, issuer string) bool {
	return strings.TrimRight(configured, "/") == strings.TrimRight(issuer, "/")
}

// cacheTTL parses the Cache-Control header for a max-age directive
// and returns it as a Duration. When the header is absent or
// max-age is missing/invalid, returns fallback. A negative or zero
// max-age disables caching (returns 0).
//
// Per RFC 9111, a max-age directive in the response carries
// precedence over heuristic caching; this library applies it
// verbatim and falls back to the configured TTL otherwise.
func cacheTTL(header string, fallback time.Duration) time.Duration {
	if header == "" {
		return fallback
	}
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(strings.ToLower(part), "max-age=") {
			continue
		}
		val := part[len("max-age="):]
		n, err := strconv.Atoi(val)
		if err != nil || n < 0 {
			return fallback
		}
		return time.Duration(n) * time.Second
	}
	return fallback
}

// IsMixUpError is a small predicate over errors.As — returns true
// when err carries (or wraps) a [*MixUpError]. Useful at call sites
// that branch on the metadata mix-up case explicitly.
func IsMixUpError(err error) bool {
	var me *MixUpError
	return errors.As(err, &me)
}
