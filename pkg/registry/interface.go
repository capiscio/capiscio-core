package registry

import (
	"context"
	"crypto"
	"time"
)

// Registry defines the interface for the CapiscIO Trust Registry.
// It is responsible for resolving trusted public keys for Issuers,
// checking revocation status, and agent status.
// See RFC-002: Trust Badge Specification.
type Registry interface {
	// GetPublicKey fetches the public key for a given Issuer DID/URI.
	// Returns the public key and any error encountered.
	GetPublicKey(ctx context.Context, issuerDID string) (crypto.PublicKey, error)

	// IsRevoked checks if a specific Badge ID (jti) has been revoked.
	// Deprecated: Use GetBadgeStatus for richer information.
	IsRevoked(ctx context.Context, badgeID string) (bool, error)

	// GetBadgeStatus retrieves the status of a badge by jti.
	// Returns BadgeStatus or error if the badge is not found.
	GetBadgeStatus(ctx context.Context, issuerURL string, jti string) (*BadgeStatus, error)

	// GetAgentStatus retrieves the status of an agent by ID.
	// Returns AgentStatus or error if the agent is not found.
	GetAgentStatus(ctx context.Context, issuerURL string, agentID string) (*AgentStatus, error)

	// SyncRevocations fetches revocations since the given timestamp.
	// Used for bulk sync of revocation lists for offline verification.
	SyncRevocations(ctx context.Context, issuerURL string, since time.Time) ([]Revocation, error)
}

// BadgeStatus represents the status of a badge.
type BadgeStatus struct {
	// JTI is the badge ID.
	JTI string `json:"jti"`

	// Subject is the agent DID (sub claim).
	Subject string `json:"sub,omitempty"`

	// Revoked indicates if the badge has been revoked.
	Revoked bool `json:"revoked"`

	// Reason is the revocation reason (if revoked).
	Reason string `json:"reason,omitempty"`

	// RevokedAt is the timestamp when the badge was revoked.
	RevokedAt *time.Time `json:"revokedAt,omitempty"`

	// ExpiresAt is the badge expiry time.
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

// AgentStatus represents the status of an agent.
type AgentStatus struct {
	// ID is the agent identifier.
	ID string `json:"id"`

	// Status is the agent status: "active", "disabled", or "suspended".
	Status string `json:"status"`

	// DisabledAt is the timestamp when the agent was disabled.
	DisabledAt *time.Time `json:"disabledAt,omitempty"`

	// Reason is the reason for disabling (if disabled).
	Reason string `json:"reason,omitempty"`
}

// AgentStatusActive is the status for an active agent.
const AgentStatusActive = "active"

// AgentStatusDisabled is the status for a disabled agent.
const AgentStatusDisabled = "disabled"

// AgentStatusSuspended is the status for a suspended agent.
const AgentStatusSuspended = "suspended"

// IsActive returns true if the agent status is active.
func (s *AgentStatus) IsActive() bool {
	return s.Status == AgentStatusActive
}

// Revocation represents a single badge revocation entry.
type Revocation struct {
	// JTI is the revoked badge ID.
	JTI string `json:"jti"`

	// RevokedAt is when the badge was revoked.
	RevokedAt time.Time `json:"revokedAt"`

	// Reason is the optional revocation reason.
	Reason string `json:"reason,omitempty"`
}

