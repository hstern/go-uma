# Conformance fixtures

JSON fixtures extracted verbatim from the example figures in the
two UMA 2.0 Kantara Recommendations:

- [UMA 2.0 Grant for OAuth 2.0](https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html)
- [UMA 2.0 Federated Authorization for OAuth 2.0](https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-fedauthz-2.0.html)

The filename of each fixture encodes its provenance —
`<spec>-<section>-<short-name>.json`. `spec` is `grant` or
`fedauthz`; `section` is the spec section number; `short-name` is
a brief description.

Fixtures:

| File | Source | Shape |
|---|---|---|
| `grant-1.3.2-metadata.json` | Grant §1.3.2 | UMA configuration document |
| `grant-3.3.5-token-response.json` | Grant §3.3.5 | `/token` 200 OK body |
| `grant-3.3.6-need-info.json` | Grant §3.3.6 | `/token` 403 need_info body |
| `fedauthz-2.1-resource-set.json` | Federated Authz §2.1 | `ResourceSet` registration body |
| `fedauthz-2.2-resource-set-create-response.json` | Federated Authz §2.2 | `POST /resource_set` 201 body |
| `fedauthz-4.1-permission-request-single.json` | Federated Authz §4.1 | Single-permission request body |
| `fedauthz-4.1-permission-request-array.json` | Federated Authz §4.1 | Array-of-permissions request body |
| `fedauthz-4.2-permission-response.json` | Federated Authz §4.2 | `/permission` 201 body |
| `fedauthz-5.1.1-introspection-response.json` | Federated Authz §5.1.1 | `/introspection` 200 active body |
| `fedauthz-5.1.1-introspection-inactive.json` | Federated Authz §5.1.1 | `/introspection` 200 inactive body |

The accompanying `../fixtures_test.go` loads each file, decodes it
into the corresponding wire type from the root `uma` package,
re-encodes, and asserts a second decode produces the same struct.
This is the byte-stability invariant: the library's encoder and
decoder agree on a canonical form for every spec-defined wire shape.

The fixtures themselves are NOT expected to be byte-identical to
the library's encoder output — the spec figures are pretty-printed
with multi-line whitespace, and Go's `encoding/json` defaults to
compact output. The test asserts structural and post-encode-by-the-
library stability, not whitespace fidelity.

To add a new fixture for a future spec figure: drop the file under
this directory with the established filename convention and add a
row to the `fixtures` table in `../fixtures_test.go`. The test will
pick it up automatically.
