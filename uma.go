// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

// Package uma implements User-Managed Access 2.0 — the Kantara Initiative
// Grant and Federated Authorization Recommendations finalized 2018-01.
//
// The library provides typed wire shapes, an HTTP client, and http.Handler
// constructors for both the Authorization Server and Resource Server roles.
// See the package documentation in subsequent files for the per-symbol
// godoc; this file carries the package-level metadata.
package uma

// SpecVersion is the version of the User-Managed Access specification this
// library implements. UMA 2.0 was finalized as a Kantara Recommendation in
// January 2018 and has not been revised since; library upgrades will not
// change this value without a corresponding spec change.
const SpecVersion = "2.0"
