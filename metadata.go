// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

package uma

import "encoding/json"

// Metadata is the UMA 2.0 configuration document an Authorization
// Server publishes at [MetadataPath] (Grant §1.3.2). The document
// describes the AS's endpoints, supported grant types, and any
// well-known capabilities a client needs to discover before opening
// the protocol — including the [Issuer] URL the client uses for
// mix-up validation.
//
// The document is JSON-encoded; absent fields omit from the wire
// shape rather than encoding as nulls. A consumer wiring metadata
// hand-rolled (rather than via the server package's BuildMetadata)
// should populate at least Issuer and the endpoint fields that
// match the AS surface it exposes.
//
// SignedMetadata is a [json.RawMessage] pass-through. UMA inherits
// OpenID Connect Discovery 1.0 §3's signed-metadata mechanism — a
// JWS (RFC 7515) carrying the same metadata document re-signed by
// the AS. The library does NOT parse or verify it in v0.1; the
// field round-trips opaque bytes so existing deployments survive
// upgrades, and a JOSE dependency lands only when verification is
// wired in a later release.
type Metadata struct {
	// Issuer is the AS's identifier — an absolute URL with no
	// fragment. The client uses this field for mix-up protection:
	// fetching .../.well-known/uma2-configuration MUST return a
	// document whose Issuer matches the URL the client was
	// configured against, else a different AS is signing on behalf
	// of the configured one (or a confused-deputy attack is in
	// progress). Required.
	Issuer string `json:"issuer"`

	// TokenEndpoint is the absolute URL of the AS's token endpoint
	// (Grant §3.3). Omitted from the document when the AS does not
	// implement the corresponding interface method.
	TokenEndpoint string `json:"token_endpoint,omitempty"`

	// IntrospectionEndpoint is the absolute URL of the AS's
	// introspection endpoint (Federated Authz §5).
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`

	// PermissionEndpoint is the absolute URL of the AS's permission
	// registration endpoint (Federated Authz §4).
	PermissionEndpoint string `json:"permission_endpoint,omitempty"`

	// ResourceRegistrationEndpoint is the absolute URL of the AS's
	// resource-set CRUD endpoint (Federated Authz §2).
	ResourceRegistrationEndpoint string `json:"resource_registration_endpoint,omitempty"`

	// GrantTypesSupported lists the OAuth 2.0 grant_type values the
	// AS accepts at /token. For UMA-only deployments this is just
	// [UMATicketGrantType]; an AS that doubles as a general OAuth
	// server lists every grant it supports.
	GrantTypesSupported []string `json:"grant_types_supported,omitempty"`

	// ResponseTypesSupported lists the OAuth 2.0 response_type
	// values the AS supports at any authorize endpoint it exposes.
	// UMA itself does not define an authorize endpoint; consumers
	// running a combined OAuth + UMA AS list its values here.
	ResponseTypesSupported []string `json:"response_types_supported,omitempty"`

	// TokenEndpointAuthMethodsSupported lists the client
	// authentication methods the AS's /token endpoint accepts —
	// "client_secret_basic", "private_key_jwt", "none", etc.
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`

	// UMAProfilesSupported lists the URIs identifying UMA profiles
	// the AS supports. Open-extension list per Grant §1.3.2.
	UMAProfilesSupported []string `json:"uma_profiles_supported,omitempty"`

	// ClaimTokenFormatsSupported lists the URIs identifying claim-
	// token formats the AS accepts in /token requests' claim_token
	// field. See [ClaimTokenFormat] for the canonical values.
	ClaimTokenFormatsSupported []string `json:"claim_token_formats_supported,omitempty"`

	// SignedMetadata is an optional JWS (RFC 7515) carrying the
	// metadata document re-signed by the AS. v0.1 stays JOSE-free —
	// the field round-trips opaque bytes; verification and signing
	// land in a later release with a JOSE dependency. Consumers
	// that want to verify the signature today decode the JWS with
	// their own JOSE library; consumers that want to attach a
	// signature populate the RawMessage with the JWS compact-
	// serialization bytes.
	SignedMetadata json.RawMessage `json:"signed_metadata,omitempty"`
}

// MetadataOption customizes a [Metadata] document. The option set is
// independent of the construction site — consumers building a
// Metadata by hand can call MetadataOption values directly on their
// struct, and the server package's BuildMetadata calls them
// internally during AS probing.
type MetadataOption func(*Metadata)

// WithUMAProfilesSupported sets the list of UMA profile URIs the AS
// publishes in [Metadata.UMAProfilesSupported].
func WithUMAProfilesSupported(profiles ...string) MetadataOption {
	return func(m *Metadata) {
		m.UMAProfilesSupported = append([]string(nil), profiles...)
	}
}

// WithClaimTokenFormatsSupported sets the list of claim-token
// format URIs in [Metadata.ClaimTokenFormatsSupported]. Passing
// [ClaimTokenFormat] values is fine — they implicitly convert to
// string.
func WithClaimTokenFormatsSupported(formats ...ClaimTokenFormat) MetadataOption {
	return func(m *Metadata) {
		out := make([]string, len(formats))
		for i, f := range formats {
			out[i] = string(f)
		}
		m.ClaimTokenFormatsSupported = out
	}
}

// WithTokenEndpointAuthMethods sets the auth-method list for the
// /token endpoint. Values are OAuth 2.0 strings —
// "client_secret_basic", "client_secret_post", "private_key_jwt",
// "tls_client_auth", "none", etc.
func WithTokenEndpointAuthMethods(methods ...string) MetadataOption {
	return func(m *Metadata) {
		m.TokenEndpointAuthMethodsSupported = append([]string(nil), methods...)
	}
}

// WithSignedMetadata sets the opaque JWS bytes [Metadata.SignedMetadata]
// carries. The library does not parse or verify; pass whatever
// JOSE library you use to sign produces (the compact-serialization
// form). Passing a nil or empty value clears the field.
func WithSignedMetadata(jws json.RawMessage) MetadataOption {
	return func(m *Metadata) {
		if len(jws) == 0 {
			m.SignedMetadata = nil
			return
		}
		m.SignedMetadata = append(json.RawMessage(nil), jws...)
	}
}
