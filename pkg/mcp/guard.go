package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path"
	"time"

	"github.com/google/uuid"

	"github.com/capiscio/capiscio-core/v2/pkg/badge"
	"github.com/capiscio/capiscio-core/v2/pkg/pip"
)

// Guard implements RFC-006 tool access evaluation with atomic evidence emission.
type Guard struct {
	badgeVerifier *badge.Verifier
	evidenceStore EvidenceStore
	pdpClient     pip.PDPClient
	emMode        pip.EnforcementMode
	obligationReg *pip.ObligationRegistry
	logger        *slog.Logger
}

// GuardOption configures optional Guard behavior.
type GuardOption func(*Guard)

// WithPDPClient enables PDP-based policy evaluation (RFC-005).
// When set, the PDP replaces inline policy evaluation (trust level + allowed tools).
func WithPDPClient(client pip.PDPClient) GuardOption {
	return func(g *Guard) { g.pdpClient = client }
}

// WithEnforcementMode sets the enforcement mode.
func WithEnforcementMode(mode pip.EnforcementMode) GuardOption {
	return func(g *Guard) { g.emMode = mode }
}

// WithObligationRegistry sets the obligation registry for PDP obligations.
func WithObligationRegistry(reg *pip.ObligationRegistry) GuardOption {
	return func(g *Guard) { g.obligationReg = reg }
}

// WithGuardLogger sets the logger for the guard.
// A nil logger is treated as slog.Default().
func WithGuardLogger(logger *slog.Logger) GuardOption {
	return func(g *Guard) {
		if logger == nil {
			g.logger = slog.Default()
			return
		}
		g.logger = logger
	}
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

// NewGuard creates a new Guard instance.
// Use GuardOption functions to configure PDP integration (RFC-005).
func NewGuard(badgeVerifier *badge.Verifier, evidenceStore EvidenceStore, opts ...GuardOption) *Guard {
	if evidenceStore == nil {
		evidenceStore = &NoOpEvidenceStore{}
	}
	g := &Guard{
		badgeVerifier: badgeVerifier,
		evidenceStore: evidenceStore,
		emMode:        pip.EMObserve,
		logger:        slog.Default(),
	}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

// EvaluateToolAccess evaluates tool access and emits evidence atomically.
// This implements RFC-006 §6.2-6.4.
//
// When a PDPClient is configured (via WithPDPClient), the PDP is the authoritative
// decision source — inline policy (trust level + allowed tools) is skipped.
// When no PDPClient is configured, the inline policy is evaluated as before.
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

	// 1. Derive identity from credential (always — PDP doesn't replace authentication)
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

	// 2. Authorization path: PDP or inline policy
	if result.Decision == DecisionAllow && g.pdpClient != nil {
		g.evaluateWithPDP(ctx, result, toolName, agentDID, badgeJTI, trustLevel, config)
	} else if result.Decision == DecisionAllow {
		g.evaluateInlinePolicy(result, toolName, trustLevel, config)
	}

	// 3. Emit evidence (ALWAYS - both allow and deny)
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

// evaluateWithPDP queries the external PDP for an authorization decision.
// PDP replaces inline policy — it is the authoritative decision source.
func (g *Guard) evaluateWithPDP(
	ctx context.Context,
	result *EvaluateResult,
	toolName, agentDID, badgeJTI string,
	trustLevel int,
	config *EvaluateConfig,
) {
	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)
	var txnID string
	if u, err := uuid.NewV7(); err != nil {
		g.logger.ErrorContext(ctx, "failed to generate UUID v7 for txn_id", slog.String("error", err.Error()))
		txnID = uuid.New().String()
	} else {
		txnID = u.String()
	}

	pipReq := &pip.DecisionRequest{
		PIPVersion: pip.PIPVersion,
		Subject: pip.SubjectAttributes{
			DID:        agentDID,
			BadgeJTI:   badgeJTI,
			TrustLevel: fmt.Sprintf("%d", trustLevel),
		},
		Action: pip.ActionAttributes{
			Operation: toolName,
		},
		Resource: pip.ResourceAttributes{
			Identifier: toolName,
		},
		Context: pip.ContextAttributes{
			TxnID:           txnID,
			EnforcementMode: g.emMode.String(),
		},
		Environment: pip.EnvironmentAttrs{
			Time: &nowStr,
		},
	}

	resp, err := g.pdpClient.Evaluate(ctx, pipReq)

	if err != nil {
		// PDP unavailable — handle per enforcement mode (RFC-005 §7.4)
		g.logger.ErrorContext(ctx, "PDP unavailable in MCP guard",
			slog.String(pip.TelemetryErrorCode, pip.ErrorCodePDPUnavailable),
			slog.String("error", err.Error()),
			slog.String("enforcement_mode", g.emMode.String()))

		if g.emMode == pip.EMObserve {
			// Shadow mode: allow through, log ALLOW_OBSERVE
			result.PolicyDecision = pip.DecisionObserve
			result.PolicyDecisionID = "pdp-unavailable"
			return
		}
		// All other modes: fail-closed
		result.Decision = DecisionDeny
		result.DenyReason = DenyReasonPolicyDenied
		result.DenyDetail = "policy service unavailable"
		result.PolicyDecision = pip.DecisionDeny
		result.PolicyDecisionID = "pdp-unavailable"
		return
	}

	// Validate PDP response: Decision must be ALLOW or DENY, DecisionID must be non-empty.
	if !pip.ValidDecision(resp.Decision) || resp.DecisionID == "" {
		g.logger.ErrorContext(ctx, "PDP returned non-compliant response",
			slog.String("decision", resp.Decision),
			slog.String("decision_id", resp.DecisionID))

		if g.emMode == pip.EMObserve {
			result.PolicyDecision = pip.DecisionObserve
			result.PolicyDecisionID = "pdp-invalid-response"
			return
		}
		result.Decision = DecisionDeny
		result.DenyReason = DenyReasonPolicyDenied
		result.DenyDetail = "policy service returned non-compliant response"
		result.PolicyDecision = pip.DecisionDeny
		result.PolicyDecisionID = "pdp-invalid-response"
		return
	}

	result.PolicyDecisionID = resp.DecisionID
	result.PolicyDecision = resp.Decision

	if resp.Decision == pip.DecisionDeny {
		switch g.emMode {
		case pip.EMObserve:
			// Log but allow
			g.logger.InfoContext(ctx, "PDP DENY in EM-OBSERVE (allowing)",
				slog.String(pip.TelemetryDecisionID, resp.DecisionID))
			result.PolicyDecision = pip.DecisionObserve
		default:
			result.Decision = DecisionDeny
			result.DenyReason = DenyReasonPolicyDenied
			result.DenyDetail = resp.Reason
		}
		return
	}

	// ALLOW — handle obligations
	if g.obligationReg != nil && len(resp.Obligations) > 0 {
		oblResult := g.obligationReg.Enforce(ctx, g.emMode, resp.Obligations)
		if !oblResult.Proceed {
			result.Decision = DecisionDeny
			result.DenyReason = DenyReasonPolicyDenied
			result.DenyDetail = "obligation enforcement failed"
			result.PolicyDecision = pip.DecisionDeny
		}
	}
}

// evaluateInlinePolicy runs the traditional trust level + tool glob checks.
func (g *Guard) evaluateInlinePolicy(
	result *EvaluateResult,
	toolName string,
	trustLevel int,
	config *EvaluateConfig,
) {
	// Check trust level against minimum
	if trustLevel < config.MinTrustLevel {
		result.Decision = DecisionDeny
		result.DenyReason = DenyReasonTrustInsufficient
		result.DenyDetail = fmt.Sprintf("trust level %d below minimum %d", trustLevel, config.MinTrustLevel)
		return
	}

	// Check tool against allowed list (if configured)
	if len(config.AllowedTools) > 0 {
		if !g.isToolAllowed(toolName, config.AllowedTools) {
			result.Decision = DecisionDeny
			result.DenyReason = DenyReasonToolNotAllowed
			result.DenyDetail = fmt.Sprintf("tool %q not in allowed list", toolName)
		}
	}
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
		_, _ = fmt.Sscanf(trustLevelStr, "%d", &trustLevel)
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
