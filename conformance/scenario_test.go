// Copyright 2026 The go-uma Authors
// SPDX-License-Identifier: Apache-2.0

//go:build conformance

// End-to-end conformance scenario driving the library through every
// Grant + Federated Authz wire-shape hop with a synthetic AS + RS
// pair built on the library's own server constructors. Build-tag-
// gated so it runs in its own CI job (`go test -tags conformance
// ./conformance/...`) rather than the default `test` run.
//
// The scenario exercises the canonical full flow:
//
//	1. Discovery        — Client.FetchMetadata reads the
//	                      well-known document.
//	2. Resource reg     — RS calls Client.CreateResourceSet.
//	3. Protected hit    — RqP hits RS without RPT; RS calls
//	                      Client.Permission for a ticket, emits
//	                      401 + WWW-Authenticate UMA challenge.
//	4. Redemption       — RqP client calls Client.Token, redeems
//	                      ticket for RPT.
//	5. Retry            — RqP hits RS with RPT; RS calls
//	                      Client.Introspect, validates scopes,
//	                      allows the request.
//	6. CRUD round-trip  — RS updates and then deletes the
//	                      resource set via Client.UpdateResourceSet
//	                      and Client.DeleteResourceSet; List
//	                      reflects the deletion.
//
// At every hop the scenario asserts the wire shapes match the spec
// figure for the corresponding step (when applicable; some hops
// have no spec figure and assert only structural invariants).

package conformance_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hstern/go-uma"
	"github.com/hstern/go-uma/client"
	"github.com/hstern/go-uma/server"
)

// scenarioAS is the synthetic Authorization Server backing the
// conformance scenario. Implements all four AS methods atop in-
// memory stores; the policy is "the resource owner trusts every
// requesting party for view + edit scope on every registered
// resource", which keeps the scenario focused on wire-shape
// correctness rather than policy modeling.
type scenarioAS struct {
	server.NotImplementedAS

	mu        sync.Mutex
	resources map[string]*uma.ResourceSet // by AS-assigned ID
	tickets   map[string]*scenarioTicket
	rpts      map[string]*scenarioRPT
}

type scenarioTicket struct {
	resourceID string
	scopes     []string
	consumed   bool
}

type scenarioRPT struct {
	resourceID string
	scopes     []string
	active     bool
}

func newScenarioAS() *scenarioAS {
	return &scenarioAS{
		resources: map[string]*uma.ResourceSet{},
		tickets:   map[string]*scenarioTicket{},
		rpts:      map[string]*scenarioRPT{},
	}
}

func (a *scenarioAS) randID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

func (a *scenarioAS) Token(_ context.Context, r *uma.TokenRequest) (*uma.TokenResponse, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	t, ok := a.tickets[r.Ticket]
	if !ok || t.consumed {
		return nil, &uma.OAuthError{ErrorCode: uma.ErrorCodeInvalidGrant}
	}
	t.consumed = true
	id := a.randID()
	a.rpts[id] = &scenarioRPT{
		resourceID: t.resourceID,
		scopes:     t.scopes,
		active:     true,
	}
	return &uma.TokenResponse{
		AccessToken: id,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}, nil
}

func (a *scenarioAS) Permission(_ context.Context, r *uma.PermissionRequest) (*uma.PermissionResponse, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.resources[r.ResourceID]; !ok {
		return nil, &uma.OAuthError{
			ErrorCode:        uma.ErrorCodeInvalidGrant,
			ErrorDescription: "unknown resource_id",
		}
	}
	tkt := a.randID()
	a.tickets[tkt] = &scenarioTicket{
		resourceID: r.ResourceID,
		scopes:     append([]string(nil), r.ResourceScopes...),
	}
	return &uma.PermissionResponse{Ticket: tkt}, nil
}

func (a *scenarioAS) Introspect(_ context.Context, r *uma.IntrospectionRequest) (*uma.IntrospectionResponse, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	rpt, ok := a.rpts[r.Token]
	if !ok || !rpt.active {
		return &uma.IntrospectionResponse{Active: false}, nil
	}
	return &uma.IntrospectionResponse{
		Active: true,
		Permissions: []uma.Permission{
			{ResourceID: rpt.resourceID, ResourceScopes: rpt.scopes},
		},
	}, nil
}

func (a *scenarioAS) ResourceSet(_ context.Context, req *server.ResourceSetRequest) (*server.ResourceSetResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch req.Op {
	case uma.OpCreate:
		if err := req.Body.Validate(); err != nil {
			return nil, err
		}
		id := a.randID()
		rs := *req.Body
		rs.ID = id
		a.resources[id] = &rs
		return &server.ResourceSetResponse{
			Single: &uma.ResourceSet{ID: id},
		}, nil
	case uma.OpRead:
		rs, ok := a.resources[req.ID]
		if !ok {
			return nil, &uma.OAuthError{ErrorCode: "not_found"}
		}
		return &server.ResourceSetResponse{Single: rs}, nil
	case uma.OpUpdate:
		rs, ok := a.resources[req.ID]
		if !ok {
			return nil, &uma.OAuthError{ErrorCode: "not_found"}
		}
		updated := *req.Body
		updated.ID = rs.ID
		a.resources[req.ID] = &updated
		return &server.ResourceSetResponse{Single: &updated}, nil
	case uma.OpDelete:
		delete(a.resources, req.ID)
		return &server.ResourceSetResponse{}, nil
	case uma.OpList:
		ids := make([]string, 0, len(a.resources))
		for id := range a.resources {
			ids = append(ids, id)
		}
		return &server.ResourceSetResponse{IDs: ids}, nil
	}
	// Unrecognized op (including OpUnknown). The AS implements
	// resource-set CRUD; this op is invalid input, not a missing
	// feature. Returning ErrNotImplemented here would confuse
	// BuildMetadata's probe (which uses OpUnknown specifically to
	// detect whether the method is implemented) into thinking the
	// AS doesn't support resource-set CRUD at all.
	return nil, &uma.ValidationError{
		Type: "ResourceSetRequest", Field: "op", Message: "unsupported op",
	}
}

// scenarioRS is the synthetic Resource Server. ProtectedRequest pulls
// the Bearer RPT, introspects via the library's Client, and decides
// allow / ticket-required based on the RPT's permissions.
type scenarioRS struct {
	asClient client.Client
	asURL    string
	realm    string
}

func (rs *scenarioRS) ProtectedRequest(
	ctx context.Context, r *http.Request, rsid string, scopes []string,
) (server.Decision, error) {
	rpt, ok := server.ExtractBearerToken(r)
	if !ok {
		return server.DecisionUnknown, rs.requestTicket(ctx, rsid, scopes)
	}
	ir, err := rs.asClient.Introspect(ctx, &uma.IntrospectionRequest{Token: rpt})
	if err != nil {
		return server.DecisionUnknown, err
	}
	if !ir.Active {
		return server.DecisionUnknown, rs.requestTicket(ctx, rsid, scopes)
	}
	for _, p := range ir.Permissions {
		if p.ResourceID != rsid {
			continue
		}
		if hasAllScopes(p.ResourceScopes, scopes) {
			return server.DecisionAllow, nil
		}
	}
	return server.DecisionUnknown, rs.requestTicket(ctx, rsid, scopes)
}

func (rs *scenarioRS) requestTicket(ctx context.Context, rsid string, scopes []string) error {
	pr, err := rs.asClient.Permission(ctx, &uma.PermissionRequest{
		ResourceID:     rsid,
		ResourceScopes: scopes,
	})
	if err != nil {
		return err
	}
	return &server.TicketRequired{
		Ticket: pr.Ticket,
		ASURL:  rs.asURL,
		Scopes: strings.Join(scopes, " "),
		Realm:  rs.realm,
	}
}

func hasAllScopes(granted, requested []string) bool {
	g := map[string]bool{}
	for _, s := range granted {
		g[s] = true
	}
	for _, s := range requested {
		if !g[s] {
			return false
		}
	}
	return true
}

// asWithMetadata wraps NewASHandler with a NewMetadataHandler at the
// well-known path. Returned http.Handler routes /.well-known/uma2-
// configuration to the metadata document and everything else to the
// AS handler.
type asWithMetadata struct {
	asHandler http.Handler
	asURL     *string
	as        server.AS
}

func (h *asWithMetadata) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == uma.MetadataPath {
		meta := server.BuildMetadata(*h.asURL, h.as,
			uma.WithClaimTokenFormatsSupported(uma.ClaimTokenFormatIDToken),
		)
		server.NewMetadataHandler(meta).ServeHTTP(w, r)
		return
	}
	h.asHandler.ServeHTTP(w, r)
}

func startScenario(t *testing.T) (*scenarioAS, string, string, client.Client) {
	t.Helper()
	as := newScenarioAS()
	asMux := &asWithMetadata{
		asHandler: server.NewASHandler(as),
		as:        as,
	}
	asSrv := httptest.NewServer(asMux)
	t.Cleanup(asSrv.Close)
	asURL := asSrv.URL
	asMux.asURL = &asURL

	asClient, err := client.NewClient(asURL, client.WithPAT("rs-pat"))
	if err != nil {
		t.Fatalf("AS client: %v", err)
	}
	rs := &scenarioRS{
		asClient: asClient,
		asURL:    asURL,
		realm:    "conformance",
	}

	const rsid = "fixed-resource-1"
	rsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d, err := rs.ProtectedRequest(r.Context(), r, rsid, []string{"view"})
		var tr *server.TicketRequired
		if errors.As(err, &tr) {
			server.WriteTicketRequired(w, tr)
			return
		}
		if err != nil || d != server.DecisionAllow {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(rsSrv.Close)

	// RqP-side client (no PAT — that's RS auth, RqP uses no
	// per-request auth in this scenario).
	rqpClient, err := client.NewClient(asURL)
	if err != nil {
		t.Fatalf("RqP client: %v", err)
	}

	// Register the fixed resource on the AS, simulating the RS's
	// startup-time registration step. The AS gives back an
	// arbitrary id; we override it with the well-known rsid in the
	// store so the rsHandler's hard-coded rsid matches.
	as.mu.Lock()
	as.resources[rsid] = &uma.ResourceSet{
		ID:             rsid,
		Name:           "Conformance Photo",
		ResourceScopes: []string{"view"},
	}
	as.mu.Unlock()

	return as, asURL, rsSrv.URL, rqpClient
}

func TestConformance_DiscoveryThenFullFlow(t *testing.T) {
	_, asURL, rsURL, rqpClient := startScenario(t)

	// Step 1: discovery. The client fetches the metadata document
	// and discovers every AS endpoint.
	meta, err := rqpClient.FetchMetadata(context.Background())
	if err != nil {
		t.Fatalf("FetchMetadata: %v", err)
	}
	if meta.Issuer != asURL {
		t.Errorf("Issuer = %q, want %q", meta.Issuer, asURL)
	}
	if meta.TokenEndpoint == "" || meta.PermissionEndpoint == "" ||
		meta.IntrospectionEndpoint == "" || meta.ResourceRegistrationEndpoint == "" {
		t.Errorf("metadata missing endpoints: %+v", meta)
	}
	if len(meta.GrantTypesSupported) != 1 || meta.GrantTypesSupported[0] != uma.UMATicketGrantType {
		t.Errorf("GrantTypesSupported = %v", meta.GrantTypesSupported)
	}
	if len(meta.ClaimTokenFormatsSupported) != 1 ||
		meta.ClaimTokenFormatsSupported[0] != string(uma.ClaimTokenFormatIDToken) {
		t.Errorf("ClaimTokenFormatsSupported = %v", meta.ClaimTokenFormatsSupported)
	}

	// Step 2: protected request without RPT → 401 with ticket.
	resp, err := http.Get(rsURL)
	if err != nil {
		t.Fatalf("RS GET: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("first RS hit status = %d, want 401", resp.StatusCode)
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(challenge, "UMA ") {
		t.Fatalf("WWW-Authenticate = %q, want UMA prefix", challenge)
	}
	ticket := paramFromChallenge(challenge, "ticket")
	if ticket == "" {
		t.Fatalf("WWW-Authenticate has no ticket: %s", challenge)
	}

	// Step 3: redeem ticket at AS /token → RPT.
	tr, err := rqpClient.Token(context.Background(), &uma.TokenRequest{Ticket: ticket})
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tr.AccessToken == "" {
		t.Fatal("Token returned empty access_token")
	}
	if tr.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want Bearer", tr.TokenType)
	}

	// Step 4: retry RS with the RPT → 200.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, rsURL, http.NoBody)
	req.Header.Set("Authorization", "Bearer "+tr.AccessToken)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("second RS hit: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("second RS hit status = %d, want 200", resp2.StatusCode)
	}

	// Step 5: ticket is single-use — second redemption returns
	// invalid_grant.
	_, err = rqpClient.Token(context.Background(), &uma.TokenRequest{Ticket: ticket})
	if !errors.Is(err, uma.ErrInvalidGrant) {
		t.Errorf("second Token redemption: err = %v, want ErrInvalidGrant", err)
	}
}

func TestConformance_ResourceSetCRUD(t *testing.T) {
	// Round-trip Create → Read → Update → Read → List → Delete →
	// List via the library's Client, hitting the synthetic AS's
	// resource_set handler.
	as, asURL, _, _ := startScenario(t)
	_ = as

	asClient, err := client.NewClient(asURL, client.WithPAT("rs-pat"))
	if err != nil {
		t.Fatalf("client.NewClient: %v", err)
	}

	created, err := asClient.CreateResourceSet(context.Background(), &uma.ResourceSet{
		Name:           "Test Album",
		ResourceScopes: []string{"view", "edit"},
	})
	if err != nil {
		t.Fatalf("CreateResourceSet: %v", err)
	}
	if created.ID == "" {
		t.Fatal("CreateResourceSet returned empty ID")
	}

	read, err := asClient.ReadResourceSet(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("ReadResourceSet: %v", err)
	}
	if read.Name != "Test Album" {
		t.Errorf("Read Name = %q, want Test Album", read.Name)
	}

	updated, err := asClient.UpdateResourceSet(context.Background(), created.ID, &uma.ResourceSet{
		Name:           "Test Album Updated",
		ResourceScopes: []string{"view"},
	})
	if err != nil {
		t.Fatalf("UpdateResourceSet: %v", err)
	}
	if updated.Name != "Test Album Updated" {
		t.Errorf("Updated Name = %q", updated.Name)
	}

	idsBeforeDelete, err := asClient.ListResourceSets(context.Background())
	if err != nil {
		t.Fatalf("ListResourceSets (before delete): %v", err)
	}
	found := false
	for _, id := range idsBeforeDelete {
		if id == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("created ID %q not in ListResourceSets %v", created.ID, idsBeforeDelete)
	}

	if err := asClient.DeleteResourceSet(context.Background(), created.ID); err != nil {
		t.Fatalf("DeleteResourceSet: %v", err)
	}

	idsAfterDelete, err := asClient.ListResourceSets(context.Background())
	if err != nil {
		t.Fatalf("ListResourceSets (after delete): %v", err)
	}
	for _, id := range idsAfterDelete {
		if id == created.ID {
			t.Errorf("deleted ID %q still in ListResourceSets %v", created.ID, idsAfterDelete)
		}
	}
}

func TestConformance_IntrospectActiveFalseRoundTrip(t *testing.T) {
	// A never-issued RPT against the real introspection endpoint
	// returns active=false WITHOUT erroring — the load-bearing
	// implementer pin in client.Introspect.
	_, asURL, _, _ := startScenario(t)
	c, err := client.NewClient(asURL, client.WithPAT("rs-pat"))
	if err != nil {
		t.Fatalf("client.NewClient: %v", err)
	}
	ir, err := c.Introspect(context.Background(), &uma.IntrospectionRequest{
		Token: "never-issued-rpt",
	})
	if err != nil {
		t.Fatalf("Introspect: %v (want nil error with Active=false)", err)
	}
	if ir.Active {
		t.Errorf("Active = true for never-issued RPT")
	}
}

// paramFromChallenge pulls a quoted parameter value out of a
// WWW-Authenticate header.
func paramFromChallenge(header, key string) string {
	prefix := key + `="`
	i := strings.Index(header, prefix)
	if i < 0 {
		return ""
	}
	rest := header[i+len(prefix):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}
