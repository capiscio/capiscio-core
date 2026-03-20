// Package rpc provides the gRPC server implementation for CapiscIO SDK integration.
package rpc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/capiscio/capiscio-core/v2/pkg/pip"
	pb "github.com/capiscio/capiscio-core/v2/pkg/rpc/gen/capiscio/v1"
)

// EvaluatePolicyDecision implements RFC-005 centralized policy decision.
//
// Protocol boundary:
//   - Go core owns: PDP query, decision cache, break-glass, enforcement mode, telemetry
//   - SDK caller owns: obligation execution, response propagation, surface error handling
//
// This RPC NEVER returns a gRPC error for PDP unreachability. All outcomes
// are encoded in the response so SDKs don't need to distinguish transport
// errors from policy outcomes.
func (s *MCPService) EvaluatePolicyDecision(
	ctx context.Context,
	req *pb.PolicyDecisionRequest,
) (*pb.PolicyDecisionResponse, error) {
	cfg := req.GetConfig()
	if cfg == nil {
		cfg = &pb.PolicyConfig{}
	}

	// Badge-only mode: no PDP configured, pass through.
	if cfg.PdpEndpoint == "" {
		return &pb.PolicyDecisionResponse{
			Decision:        pip.DecisionAllow,
			DecisionId:      "no-pdp-configured",
			EnforcementMode: enforcementModeOrDefault(cfg.EnforcementMode),
			TxnId:           generateTxnID(),
		}, nil
	}

	// Parse enforcement mode
	em, err := pip.ParseEnforcementMode(enforcementModeOrDefault(cfg.EnforcementMode))
	if err != nil {
		// Invalid enforcement mode is a config error, not a policy outcome
		return nil, fmt.Errorf("invalid enforcement_mode %q: %w", cfg.EnforcementMode, err)
	}

	txnID := generateTxnID()
	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)

	// Build PIP request from proto fields
	subject := req.GetSubject()
	action := req.GetAction()
	resource := req.GetResource()

	pipReq := &pip.DecisionRequest{
		PIPVersion: pip.PIPVersion,
		Subject: pip.SubjectAttributes{
			DID:        subject.GetDid(),
			BadgeJTI:   subject.GetBadgeJti(),
			IAL:        subject.GetIal(),
			TrustLevel: subject.GetTrustLevel(),
		},
		Action: pip.ActionAttributes{
			Operation: action.GetOperation(),
		},
		Resource: pip.ResourceAttributes{
			Identifier: resource.GetIdentifier(),
		},
		Context: pip.ContextAttributes{
			TxnID:           txnID,
			EnforcementMode: em.String(),
		},
		Environment: pip.EnvironmentAttrs{
			Time: &nowStr,
		},
	}

	// Set optional fields
	if action.GetCapabilityClass() != "" {
		cc := action.GetCapabilityClass()
		pipReq.Action.CapabilityClass = &cc
	}
	if cfg.PepId != "" {
		pipReq.Environment.PEPID = &cfg.PepId
	}
	if cfg.Workspace != "" {
		pipReq.Environment.Workspace = &cfg.Workspace
	}

	// Check break-glass override
	if req.BreakglassToken != "" {
		bgResp := s.handleBreakGlass(req.BreakglassToken, cfg, action.GetOperation(), pipReq, txnID, em)
		if bgResp != nil {
			return bgResp, nil
		}
		// If nil, break-glass validation failed — proceed with normal PDP path
	}

	// Check decision cache
	cacheKey := pip.CacheKeyComponents(
		subject.GetDid(),
		subject.GetBadgeJti(),
		action.GetOperation(),
		resource.GetIdentifier(),
	)
	if s.decisionCache != nil {
		if cached, ok := s.decisionCache.Get(cacheKey); ok {
			return s.buildCachedResponse(cached, em, txnID), nil
		}
	}

	// Query PDP
	pdpTimeout := time.Duration(cfg.PdpTimeoutMs) * time.Millisecond
	if pdpTimeout <= 0 {
		pdpTimeout = pip.DefaultPDPTimeout
	}
	client := pip.NewHTTPPDPClient(cfg.PdpEndpoint, pdpTimeout, pip.WithPEPID(cfg.PepId))

	start := time.Now()
	resp, pdpErr := client.Evaluate(ctx, pipReq)
	latencyMs := time.Since(start).Milliseconds()

	if pdpErr != nil {
		return s.handlePDPUnavailable(pdpErr, em, txnID, latencyMs), nil
	}

	// Validate PDP response
	if !pip.ValidDecision(resp.Decision) || resp.DecisionID == "" {
		return s.handlePDPUnavailable(
			fmt.Errorf("non-compliant PDP response: decision=%q decision_id=%q", resp.Decision, resp.DecisionID),
			em, txnID, latencyMs,
		), nil
	}

	// Cache the decision (cache handles DENY skip and TTL bounding)
	if s.decisionCache != nil {
		maxTTL := badgeExpTTL(subject.GetBadgeExp())
		s.decisionCache.Put(cacheKey, resp, maxTTL)
	}

	// Build response based on decision and enforcement mode
	return s.buildLiveResponse(resp, em, txnID, latencyMs), nil
}

// handleBreakGlass validates a break-glass token and returns a response if valid.
// Returns nil if validation fails (caller should proceed with normal PDP path).
func (s *MCPService) handleBreakGlass(
	token string,
	cfg *pb.PolicyConfig,
	operation string,
	pipReq *pip.DecisionRequest,
	txnID string,
	em pip.EnforcementMode,
) *pb.PolicyDecisionResponse {
	if cfg.BreakglassPublicKeyPath == "" {
		slog.Warn("break-glass token provided but no public key configured")
		return nil
	}

	pubKey, err := parseBreakGlassKey(cfg.BreakglassPublicKeyPath)
	if err != nil {
		slog.Error("failed to load break-glass public key", slog.String("error", err.Error()))
		return nil
	}

	bgToken, err := pip.ParseBreakGlassJWS(token, pubKey)
	if err != nil {
		slog.Warn("break-glass token signature invalid", slog.String("error", err.Error()))
		return nil
	}

	validator := pip.NewBreakGlassValidator(pubKey)
	if err := validator.ValidateToken(bgToken); err != nil {
		slog.Warn("break-glass token claims invalid", slog.String("error", err.Error()))
		return nil
	}

	// Check scope — use "*" for method since gRPC doesn't have HTTP methods
	if !validator.MatchesScope(bgToken, "*", operation) {
		slog.Warn("break-glass token scope does not cover operation",
			slog.String("operation", operation),
		)
		return nil
	}

	return &pb.PolicyDecisionResponse{
		Decision:          pip.DecisionAllow,
		DecisionId:        fmt.Sprintf("breakglass:%s", bgToken.JTI),
		Reason:            bgToken.Reason,
		EnforcementMode:   em.String(),
		BreakglassOverride: true,
		BreakglassJti:     bgToken.JTI,
		TxnId:             txnID,
	}
}

// handlePDPUnavailable returns a response when the PDP cannot be reached.
// In EM-OBSERVE: ALLOW_OBSERVE with error_code (not an RPC error).
// All other modes: DENY with error_code.
func (s *MCPService) handlePDPUnavailable(
	pdpErr error,
	em pip.EnforcementMode,
	txnID string,
	latencyMs int64,
) *pb.PolicyDecisionResponse {
	errMsg := pdpErr.Error()
	if em == pip.EMObserve {
		return &pb.PolicyDecisionResponse{
			Decision:        pip.DecisionObserve,
			DecisionId:      "pdp-unavailable",
			Reason:          errMsg,
			EnforcementMode: em.String(),
			ErrorCode:       "pdp_unavailable",
			PdpLatencyMs:    latencyMs,
			TxnId:           txnID,
		}
	}

	return &pb.PolicyDecisionResponse{
		Decision:        pip.DecisionDeny,
		DecisionId:      "pdp-unavailable",
		Reason:          fmt.Sprintf("policy service unavailable: %s", errMsg),
		EnforcementMode: em.String(),
		ErrorCode:       "pdp_unavailable",
		PdpLatencyMs:    latencyMs,
		TxnId:           txnID,
	}
}

// buildCachedResponse converts a cached DecisionResponse to a proto response.
func (s *MCPService) buildCachedResponse(
	cached *pip.DecisionResponse,
	em pip.EnforcementMode,
	txnID string,
) *pb.PolicyDecisionResponse {
	resp := &pb.PolicyDecisionResponse{
		Decision:        cached.Decision,
		DecisionId:      cached.DecisionID,
		Reason:          cached.Reason,
		EnforcementMode: em.String(),
		CacheHit:        true,
		TxnId:           txnID,
	}

	// For cached DENY in EM-OBSERVE: override to ALLOW_OBSERVE
	if cached.Decision == pip.DecisionDeny && em == pip.EMObserve {
		resp.Decision = pip.DecisionObserve
	}

	// Return obligations from cached response
	resp.Obligations = obligationsToProto(cached.Obligations)

	if cached.TTL != nil {
		resp.Ttl = int32(*cached.TTL)
	}

	return resp
}

// buildLiveResponse converts a live PDP DecisionResponse to a proto response,
// applying enforcement mode logic.
func (s *MCPService) buildLiveResponse(
	pdpResp *pip.DecisionResponse,
	em pip.EnforcementMode,
	txnID string,
	latencyMs int64,
) *pb.PolicyDecisionResponse {
	resp := &pb.PolicyDecisionResponse{
		DecisionId:      pdpResp.DecisionID,
		Reason:          pdpResp.Reason,
		EnforcementMode: em.String(),
		PdpLatencyMs:    latencyMs,
		TxnId:           txnID,
		Obligations:     obligationsToProto(pdpResp.Obligations),
	}

	if pdpResp.TTL != nil {
		resp.Ttl = int32(*pdpResp.TTL)
	}

	if pdpResp.Decision == pip.DecisionDeny {
		if em == pip.EMObserve {
			// PDP said DENY but we're in observe mode — pass through as ALLOW_OBSERVE
			resp.Decision = pip.DecisionObserve
		} else {
			resp.Decision = pip.DecisionDeny
		}
		return resp
	}

	// ALLOW — run obligation enforcement through the registry
	resp.Decision = pip.DecisionAllow

	if s.obligationReg != nil && len(pdpResp.Obligations) > 0 {
		oblResult := s.obligationReg.Enforce(ctx_background(), em, pdpResp.Obligations)
		if !oblResult.Proceed {
			// Obligation enforcement failed — decision flips to DENY
			resp.Decision = pip.DecisionDeny
			if len(oblResult.Errors) > 0 {
				resp.Reason = fmt.Sprintf("obligation enforcement failed: %s", oblResult.Errors[0].Message)
			}
		}
	}

	return resp
}

// obligationsToProto converts pip.Obligation slice to proto MCPObligation slice.
func obligationsToProto(obligations []pip.Obligation) []*pb.MCPObligation {
	if len(obligations) == 0 {
		return nil
	}
	result := make([]*pb.MCPObligation, len(obligations))
	for i, ob := range obligations {
		result[i] = &pb.MCPObligation{
			Type:       ob.Type,
			ParamsJson: string(ob.Params),
		}
	}
	return result
}

// parseBreakGlassKey reads a raw Ed25519 public key from a file.
func parseBreakGlassKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read break-glass key: %w", err)
	}
	data = bytes.TrimSpace(data)
	if len(data) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("break-glass key must be %d bytes, got %d", ed25519.PublicKeySize, len(data))
	}
	return ed25519.PublicKey(data), nil
}

// enforcementModeOrDefault returns the enforcement mode string or "EM-OBSERVE" if empty.
func enforcementModeOrDefault(s string) string {
	if s == "" {
		return "EM-OBSERVE"
	}
	return s
}

// generateTxnID creates a UUID v7 transaction ID, falling back to v4.
func generateTxnID() string {
	if id, err := uuid.NewV7(); err == nil {
		return id.String()
	}
	return uuid.New().String()
}

// badgeExpTTL computes a cache TTL bounded by the badge expiration.
func badgeExpTTL(badgeExp int64) time.Duration {
	if badgeExp <= 0 {
		return 5 * time.Minute // reasonable default if no badge exp provided
	}
	remaining := time.Until(time.Unix(badgeExp, 0))
	if remaining <= 0 {
		return 0
	}
	return remaining
}

// ctx_background returns a background context for internal operations
// like obligation enforcement where the original request context is appropriate
// but we alias it for clarity.
func ctx_background() context.Context {
	return context.Background()
}
