// Copyright (c) CapiscIO, Inc.
// Licensed under the MIT License.

package mediation

import (
	"strconv"

	"github.com/capiscio/capiscio-core/v2/pkg/badge"
	"github.com/capiscio/capiscio-core/v2/pkg/envelope"
	"github.com/capiscio/capiscio-core/v2/pkg/trust"
)

// Context carries trust material and verified artifacts for mediation decisions.
//
// All verification against TrustMaterial happens locally — no synchronous
// network calls are permitted during mediation (RFC-001 §2.3).
type Context struct {
	// TraceID is the distributed trace identifier for observability.
	TraceID string

	// TxnID is the transaction identifier for this request.
	// Correlates all events and decisions within a single transaction.
	TxnID string

	// HopID identifies this specific hop in a delegation chain.
	// Increments at each delegation boundary.
	HopID string

	// TrustMaterial provides access to locally cached cryptographic material.
	// MUST be bootstrapped before use. All key lookups and revocation checks
	// operate against this local cache — no network calls.
	TrustMaterial *trust.MaterialManager

	// Badge is the verified trust badge for the calling agent.
	// nil if the request is unauthenticated (which mediation hooks may reject).
	Badge *badge.Claims

	// Envelope is the verified authority envelope, if present.
	// Contains the delegation chain and capability grants.
	// nil for badge-only requests (no envelope presented).
	Envelope *envelope.Token

	// ChainResult is the verified delegation chain, if Envelope was verified.
	// nil if no envelope or chain verification was skipped.
	ChainResult *envelope.ChainVerifyResult

	// RequestedCaps is the list of capabilities being requested.
	// Format depends on the capability domain (tools, files, network, etc.)
	RequestedCaps []string

	// SubjectDID is the DID of the authenticated caller.
	// Extracted from Badge.Subject for convenience.
	SubjectDID string

	// IssuerDID is the DID of the badge issuer.
	// Extracted from Badge.Issuer for convenience.
	IssuerDID string

	// TrustLevel is the badge's trust level (0-4 per RFC-002 §5).
	TrustLevel int

	// OrganizationID is the organization context for multi-tenant mediation.
	// Used for org-scoped policy evaluation.
	OrganizationID string

	// WorkspaceID is the workspace context within an organization.
	WorkspaceID string
}

// NewContext creates a mediation context from verified artifacts.
func NewContext(
	material *trust.MaterialManager,
	badgeClaims *badge.Claims,
	env *envelope.Token,
) *Context {
	ctx := &Context{
		TrustMaterial: material,
		Badge:         badgeClaims,
		Envelope:      env,
	}

	// Extract convenience fields from badge
	if badgeClaims != nil {
		ctx.SubjectDID = badgeClaims.Subject
		ctx.IssuerDID = badgeClaims.Issuer
		// Use badge trust level (vc.credentialSubject.level), not IAL
		if level := badgeClaims.TrustLevel(); level != "" {
			if parsed, err := strconv.Atoi(level); err == nil {
				ctx.TrustLevel = parsed
			}
		}
	}

	return ctx
}

// WithTracing adds trace identifiers to the context.
func (c *Context) WithTracing(traceID, txnID, hopID string) *Context {
	c.TraceID = traceID
	c.TxnID = txnID
	c.HopID = hopID
	return c
}

// WithRequestedCaps sets the capabilities being requested.
func (c *Context) WithRequestedCaps(caps ...string) *Context {
	c.RequestedCaps = caps
	return c
}

// WithOrganization sets the organization and workspace context.
func (c *Context) WithOrganization(orgID, workspaceID string) *Context {
	c.OrganizationID = orgID
	c.WorkspaceID = workspaceID
	return c
}

// HasBadge returns true if a verified badge is present.
func (c *Context) HasBadge() bool {
	return c.Badge != nil
}

// HasEnvelope returns true if a verified envelope is present.
func (c *Context) HasEnvelope() bool {
	return c.Envelope != nil
}

// HasTrustMaterial returns true if trust material is available.
func (c *Context) HasTrustMaterial() bool {
	return c.TrustMaterial != nil && c.TrustMaterial.IsBootstrapped()
}

// EffectiveCaps returns the capabilities available to this caller.
// If an envelope with verified chain is present, returns the leaf capability class.
// Otherwise returns empty (badge-only mode has no granted capabilities).
func (c *Context) EffectiveCaps() []string {
	if c.ChainResult == nil || len(c.ChainResult.Links) == 0 {
		return nil
	}

	// Get capability class from the leaf envelope in the chain
	leaf := c.ChainResult.Links[len(c.ChainResult.Links)-1]
	if leaf.Payload == nil {
		return nil
	}

	// Return capability class from the leaf's payload
	// CapabilityClass is a dot-delimited namespace (e.g. "tools.database.read")
	if leaf.Payload.CapabilityClass != "" {
		return []string{leaf.Payload.CapabilityClass}
	}
	return nil
}

// CapabilitySatisfied checks if a requested capability is granted.
// Uses RFC-008 §7.2 scoping rules: child is satisfied if it equals parent
// or is within parent's scope (e.g., "file.read" is within "file").
func (c *Context) CapabilitySatisfied(requested string) bool {
	for _, cap := range c.EffectiveCaps() {
		if envelope.IsWithinScope(requested, cap) {
			return true
		}
	}
	return false
}
