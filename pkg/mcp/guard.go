package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"time"

	"github.com/google/uuid"

	"github.com/capiscio/capiscio-core/v2/pkg/badge"
)

// Guard implements RFC-006 tool access evaluation with atomic evidence emission.
type Guard struct {
	badgeVerifier *badge.Verifier
	evidenceStore EvidenceStore
}

// EvidenceStore is the interface for storing evidence records
type EvidenceStore interface {
	// Store saves an evidence record
	Store(ctx context.Context, record EvidenceRecord) error
}

// NoOpEvidenceStore is a no-op evidence store for testing
type NoOpEvidenceStore struct{}

func (n *NoOpEvidenceStore) Store(ctx context.Context, record EvidenceRecord) error {
	return nil
}

// NewGuard creates a new Guard instance
func NewGuard(badgeVerifier *badge.Verifier, evidenceStore EvidenceStore) *Guard {
	if evidenceStore == nil {
		evidenceStore = &NoOpEvidenceStore{}
	}
	return &Guard{
		badgeVerifier: badgeVerifier,
		evidenceStore: evidenceStore,
	}
}

// EvaluateToolAccess evaluates tool access and emits evidence atomically.
// This implements RFC-006 §6.2-6.4.
//
// Key design principle: Single operation returns both decision and evidence
// to avoid partial failures.
func (g *Guard) EvaluateToolAccess(
	ctx context.Context,
	toolName string,
	paramsHash string,
	serverOrigin string,
	credential CallerCredential,
	config *EvaluateConfig,
) (*EvaluateResult, error) {
	if config == nil {
		config = &EvaluateConfig{}
	}

	timestamp := time.Now().UTC()
	evidenceID := uuid.New().String()

	// Initialize result
	result := &EvaluateResult{
		Decision:   DecisionAllow,
		AuthLevel:  credential.GetAuthLevel(),
		Timestamp:  timestamp,
		EvidenceID: evidenceID,
	}

	// 1. Derive identity from credential
	agentDID, badgeJTI, trustLevel, err := g.deriveIdentity(ctx, credential, config)
	if err != nil {
		result.Decision = DecisionDeny
		result.DenyReason = ErrorToDenyReason(err)
		result.DenyDetail = err.Error()
	} else {
		result.AgentDID = agentDID
		result.BadgeJTI = badgeJTI
		result.TrustLevel = trustLevel
	}

	// 2. Check trust level against minimum
	if result.Decision == DecisionAllow && trustLevel < config.MinTrustLevel {
		result.Decision = DecisionDeny
		result.DenyReason = DenyReasonTrustInsufficient
		result.DenyDetail = fmt.Sprintf("trust level %d below minimum %d", trustLevel, config.MinTrustLevel)
	}

	// 3. Check tool against allowed list (if configured)
	if result.Decision == DecisionAllow && len(config.AllowedTools) > 0 {
		if !g.isToolAllowed(toolName, config.AllowedTools) {
			result.Decision = DecisionDeny
			result.DenyReason = DenyReasonToolNotAllowed
			result.DenyDetail = fmt.Sprintf("tool %q not in allowed list", toolName)
		}
	}

	// 4. Emit evidence (ALWAYS - both allow and deny)
	evidenceRecord := EvidenceRecord{
		EventName:     "capiscio.tool_invocation",
		AgentDID:      result.AgentDID,
		BadgeJTI:      result.BadgeJTI,
		AuthLevel:     result.AuthLevel.String(),
		Target:        toolName,
		PolicyVersion: config.PolicyVersion,
		Decision:      result.Decision.String(),
		ParamsHash:    paramsHash,
		// Non-RFC fields
		ID:           evidenceID,
		Timestamp:    timestamp,
		TrustLevel:   result.TrustLevel,
		ServerOrigin: serverOrigin,
	}

	if result.Decision == DecisionDeny {
		evidenceRecord.DenyReason = result.DenyReason.String()
	}

	// Store evidence (best effort - don't fail evaluation on evidence failure)
	_ = g.evidenceStore.Store(ctx, evidenceRecord)

	// Serialize evidence to JSON
	evidenceJSON, err := json.Marshal(evidenceRecord)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize evidence: %w", err)
	}
	result.EvidenceJSON = string(evidenceJSON)

	return result, nil
}

// deriveIdentity extracts identity information from the credential
func (g *Guard) deriveIdentity(
	ctx context.Context,
	credential CallerCredential,
	config *EvaluateConfig,
) (agentDID, badgeJTI string, trustLevel int, err error) {
	switch {
	case credential.BadgeJWS != "":
		// Badge authentication - verify and extract claims
		return g.verifyBadgeCredential(ctx, credential.BadgeJWS, config)

	case credential.APIKey != "":
		// API key authentication - lookup agent info
		// For now, API keys provide minimal identity
		return "", "", 0, nil

	default:
		// Anonymous - no identity
		if config.MinTrustLevel > 0 && !config.AcceptLevelZero {
			return "", "", 0, ErrBadgeMissing
		}
		return "", "", 0, nil
	}
}

// verifyBadgeCredential verifies a badge and extracts identity
func (g *Guard) verifyBadgeCredential(
	ctx context.Context,
	badgeJWS string,
	config *EvaluateConfig,
) (agentDID, badgeJTI string, trustLevel int, err error) {
	if g.badgeVerifier == nil {
		// RFC-006 §6.4: When badge verification is not available,
		// return BADGE_INVALID error to indicate verification failure
		return "", "", 0, fmt.Errorf("%w: badge verification not available", ErrBadgeInvalid)
	}

	// Build verification options
	opts := badge.VerifyOptions{
		TrustedIssuers:   config.TrustedIssuers,
		AcceptSelfSigned: config.AcceptLevelZero,
	}

	// Verify badge
	result, err := g.badgeVerifier.VerifyWithOptions(ctx, badgeJWS, opts)
	if err != nil {
		// Map verification errors to deny reasons
		return "", "", 0, fmt.Errorf("%w: %v", ErrBadgeInvalid, err)
	}

	// Extract trust level from claims
	trustLevelStr := result.Claims.TrustLevel()
	trustLevel = 0
	if trustLevelStr != "" {
		fmt.Sscanf(trustLevelStr, "%d", &trustLevel)
	}

	return result.Claims.Subject, result.Claims.JTI, trustLevel, nil
}

// isToolAllowed checks if a tool matches the allowed patterns
func (g *Guard) isToolAllowed(toolName string, allowedTools []string) bool {
	for _, pattern := range allowedTools {
		matched, err := path.Match(pattern, toolName)
		if err == nil && matched {
			return true
		}
	}
	return false
}
