package mcp

import (
	"time"
)

// Decision represents the access decision (allow or deny)
type Decision int

const (
	DecisionUnspecified Decision = iota
	DecisionAllow
	DecisionDeny
)

// String returns the string representation of the decision
func (d Decision) String() string {
	switch d {
	case DecisionAllow:
		return "ALLOW"
	case DecisionDeny:
		return "DENY"
	default:
		return "UNSPECIFIED"
	}
}

// AuthLevel represents the authentication level of the caller
type AuthLevel int

const (
	AuthLevelUnspecified AuthLevel = iota
	AuthLevelAnonymous
	AuthLevelAPIKey
	AuthLevelBadge
)

// String returns the string representation of the auth level
func (a AuthLevel) String() string {
	switch a {
	case AuthLevelAnonymous:
		return "ANONYMOUS"
	case AuthLevelAPIKey:
		return "API_KEY"
	case AuthLevelBadge:
		return "BADGE"
	default:
		return "UNSPECIFIED"
	}
}

// ServerState represents the server classification state (RFC-007 §5.2)
// Three distinct states reflect the verification depth:
// - VERIFIED_PRINCIPAL: Badge + PoP verified (full trust)
// - DECLARED_PRINCIPAL: Badge verified, PoP not performed (partial trust)
// - UNVERIFIED_ORIGIN: No identity disclosed or verification failed
type ServerState int

const (
	ServerStateUnspecified ServerState = iota
	// ServerStateVerifiedPrincipal indicates full verification:
	// - Server DID disclosed
	// - Server badge verified by trusted CA
	// - PoP verified (server proved key ownership)
	ServerStateVerifiedPrincipal

	// ServerStateDeclaredPrincipal indicates partial verification:
	// - Server DID disclosed
	// - Server badge verified by trusted CA
	// - PoP NOT performed (key ownership not proven)
	ServerStateDeclaredPrincipal

	// ServerStateUnverifiedOrigin indicates no verification:
	// - No DID disclosed, OR
	// - No badge provided, OR
	// - Badge verification failed
	// Note: This is distinct from Trust Level 0 (self-signed did:key)
	ServerStateUnverifiedOrigin
)

// String returns the string representation of the server state
func (s ServerState) String() string {
	switch s {
	case ServerStateVerifiedPrincipal:
		return "VERIFIED_PRINCIPAL"
	case ServerStateDeclaredPrincipal:
		return "DECLARED_PRINCIPAL"
	case ServerStateUnverifiedOrigin:
		return "UNVERIFIED_ORIGIN"
	default:
		return "UNSPECIFIED"
	}
}

// CallerCredential represents the caller's authentication credential
type CallerCredential struct {
	// BadgeJWS is the full badge JWT (if badge auth)
	BadgeJWS string

	// APIKey is the API key (if API key auth)
	APIKey string

	// IsAnonymous is true if no credential was provided
	IsAnonymous bool
}

// NewBadgeCredential creates a credential from a badge JWS
func NewBadgeCredential(badgeJWS string) CallerCredential {
	return CallerCredential{BadgeJWS: badgeJWS}
}

// NewAPIKeyCredential creates a credential from an API key
func NewAPIKeyCredential(apiKey string) CallerCredential {
	return CallerCredential{APIKey: apiKey}
}

// NewAnonymousCredential creates an anonymous credential
func NewAnonymousCredential() CallerCredential {
	return CallerCredential{IsAnonymous: true}
}

// GetAuthLevel returns the authentication level for this credential
func (c CallerCredential) GetAuthLevel() AuthLevel {
	switch {
	case c.BadgeJWS != "":
		return AuthLevelBadge
	case c.APIKey != "":
		return AuthLevelAPIKey
	default:
		return AuthLevelAnonymous
	}
}

// EvaluateConfig holds configuration for tool access evaluation
type EvaluateConfig struct {
	// TrustedIssuers is a list of trusted badge issuers
	TrustedIssuers []string

	// MinTrustLevel is the minimum required trust level (0-4)
	MinTrustLevel int

	// AcceptLevelZero allows self-signed did:key badges (Trust Level 0)
	AcceptLevelZero bool

	// AllowedTools is a list of allowed tool patterns (glob patterns)
	AllowedTools []string

	// PolicyVersion is the version of the policy being applied (RFC-006 §7.2)
	PolicyVersion string
}

// EvaluateResult holds the result of tool access evaluation
type EvaluateResult struct {
	// Decision is the access decision (allow or deny)
	Decision Decision

	// DenyReason is the reason for denial (only set if Decision == DecisionDeny)
	DenyReason DenyReason

	// DenyDetail is a human-readable denial detail
	DenyDetail string

	// AgentDID is the extracted agent DID
	AgentDID string

	// BadgeJTI is the badge ID (if present)
	BadgeJTI string

	// AuthLevel is the authentication level
	AuthLevel AuthLevel

	// TrustLevel is the verified trust level (0-4)
	TrustLevel int

	// EvidenceJSON is the RFC-006 §7 compliant evidence JSON
	EvidenceJSON string

	// EvidenceID is the unique evidence record ID
	EvidenceID string

	// Timestamp is when the evaluation occurred
	Timestamp time.Time
}

// VerifyConfig holds configuration for server identity verification
type VerifyConfig struct {
	// AllowedDIDMethods is a list of allowed DID methods (e.g., "web", "key")
	AllowedDIDMethods []string

	// RequireOriginBinding enforces origin binding for did:web
	RequireOriginBinding bool

	// PoPMaxAge is the maximum age of a PoP nonce (default: 30 seconds)
	PoPMaxAge time.Duration
}

// DefaultVerifyConfig returns the default verification configuration
func DefaultVerifyConfig() *VerifyConfig {
	return &VerifyConfig{
		AllowedDIDMethods:    []string{"web", "key"},
		RequireOriginBinding: true,
		PoPMaxAge:            30 * time.Second,
	}
}

// VerifyResult holds the result of server identity verification
type VerifyResult struct {
	// State is the server classification state (RFC-007 §5.2)
	// VERIFIED_PRINCIPAL, DECLARED_PRINCIPAL, or UNVERIFIED_ORIGIN
	State ServerState

	// ServerID is the confirmed server DID
	ServerID string

	// TrustLevelStr is the verified trust level from the server badge ("0"-"4")
	// Per RFC-002 §5, trust levels are strings to avoid falsiness bugs
	TrustLevelStr string

	// BadgeJTI is the badge identifier for correlation
	BadgeJTI string

	// BadgeExpiresAt is when the server badge expires
	BadgeExpiresAt time.Time

	// PoPVerified is true if PoP verification succeeded
	PoPVerified bool

	// PoPRequired is true if PoP should be performed (badge valid, PoP not done)
	PoPRequired bool

	// ErrorCode is the error code (only set on failure)
	ErrorCode ServerErrorCode

	// ErrorDetail is a human-readable error detail
	ErrorDetail string
}

// TrustLevel returns the trust level as an int (for convenience)
// Returns 0 if the trust level string is empty or invalid
func (r *VerifyResult) TrustLevel() int {
	switch r.TrustLevelStr {
	case "0":
		return 0
	case "1":
		return 1
	case "2":
		return 2
	case "3":
		return 3
	case "4":
		return 4
	default:
		return 0
	}
}

// IsVerified returns true if the server is fully verified (VERIFIED_PRINCIPAL)
func (r *VerifyResult) IsVerified() bool {
	return r.State == ServerStateVerifiedPrincipal
}

// IsDeclared returns true if the server is partially verified (DECLARED_PRINCIPAL)
func (r *VerifyResult) IsDeclared() bool {
	return r.State == ServerStateDeclaredPrincipal
}

// HasIdentity returns true if any identity was verified (not UNVERIFIED_ORIGIN)
func (r *VerifyResult) HasIdentity() bool {
	return r.State != ServerStateUnverifiedOrigin
}

// GetServerID returns the server's DID
func (r *VerifyResult) GetServerID() string {
	return r.ServerID
}

// ParsedIdentity holds parsed server identity information (RFC-007 §6)
type ParsedIdentity struct {
	// ServerDID is the extracted server DID
	ServerDID string

	// ServerBadgeJWS is the extracted server Trust Badge (JWS)
	ServerBadgeJWS string
}

// EvidenceRecord represents an RFC-006 §7 compliant evidence record.
// Field names use dot notation per RFC-006 §7.2 JSON schema.
type EvidenceRecord struct {
	// EventName MUST be "capiscio.tool_invocation" per RFC-006 §7.2
	EventName string `json:"event.name"`

	// AgentDID is the agent DID or equivalent principal
	AgentDID string `json:"capiscio.agent.did"`

	// BadgeJTI is the badge identifier, if present
	BadgeJTI string `json:"capiscio.badge.jti,omitempty"`

	// AuthLevel is "badge", "apikey", or "anonymous"
	AuthLevel string `json:"capiscio.auth.level"`

	// Target is the tool identifier
	Target string `json:"capiscio.target"`

	// PolicyVersion is the policy version used
	PolicyVersion string `json:"capiscio.policy_version"`

	// Decision is "ALLOW" or "DENY"
	Decision string `json:"capiscio.decision"`

	// ParamsHash is the SHA-256 hash of canonicalized tool parameters (optional)
	ParamsHash string `json:"capiscio.tool.params_hash,omitempty"`

	// DenyReason is the error code when decision is DENY (optional)
	DenyReason string `json:"capiscio.deny_reason,omitempty"`

	// Non-RFC fields for internal use
	ID           string    `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	TrustLevel   int       `json:"trust_level"`
	ServerOrigin string    `json:"server_origin,omitempty"`
}
