// Package rpc provides the gRPC server implementation for CapiscIO SDK integration.
package rpc

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
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

	// Validate enforcement mode upfront so badge-only mode gets the same
	// config error behaviour as the PDP path.
	modeStr := enforcementModeOrDefault(cfg.EnforcementMode)
	em, err := pip.ParseEnforcementMode(modeStr)
	if err != nil {
		return nil, fmt.Errorf("invalid enforcement_mode %q: %w", cfg.EnforcementMode, err)
	}

	// Badge-only mode: no PDP configured, pass through.
	if cfg.PdpEndpoint == "" {
		return &pb.PolicyDecisionResponse{
			Decision:        pip.DecisionAllow,
			DecisionId:      "no-pdp-configured",
			EnforcementMode: modeStr,
			TxnId:           generateTxnID(),
		}, nil
	}

	txnID := generateTxnID()

	pipReq := buildPIPRequest(req, txnID, em)

	action := req.GetAction()
	subject := req.GetSubject()

	// Check break-glass override
	if req.BreakglassToken != "" {
		bgResp := s.handleBreakGlass(req.BreakglassToken, cfg, action.GetOperation(), txnID, em)
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
		req.GetResource().GetIdentifier(),
		em.String(),
	)
	if s.decisionCache != nil {
		if cached, ok := s.decisionCache.Get(cacheKey); ok {
			return s.buildCachedResponse(cached, em, txnID), nil
		}
	}

	// Query PDP
	resp, latencyMs, pdpErr := s.queryPDP(ctx, cfg, pipReq)
	if pdpErr != nil {
		// Client-initiated cancellation should propagate as an RPC error,
		// not a synthetic policy response.
		if errors.Is(pdpErr, context.Canceled) {
			return nil, pdpErr
		}
		return s.handlePDPUnavailable(pdpErr, em, txnID, latencyMs), nil
	}

	// Cache the decision
	if s.decisionCache != nil {
		maxTTL := badgeExpTTL(subject.GetBadgeExp())
		s.decisionCache.Put(cacheKey, resp, maxTTL)
	}

	// Build response based on decision and enforcement mode
	return s.buildLiveResponse(resp, em, txnID, latencyMs), nil
}

// queryPDP creates an HTTP PDP client, queries it, and validates the response.
// Returns the validated response and latency on success; returns an error on
// any failure (client cancellation, PDP unreachable, or non-compliant response).
func (s *MCPService) queryPDP(
	ctx context.Context,
	cfg *pb.PolicyConfig,
	pipReq *pip.DecisionRequest,
) (*pip.DecisionResponse, int64, error) {
	pdpTimeout := time.Duration(cfg.PdpTimeoutMs) * time.Millisecond
	if pdpTimeout <= 0 {
		pdpTimeout = pip.DefaultPDPTimeout
	}
	client := pip.NewHTTPPDPClient(cfg.PdpEndpoint, pdpTimeout, pip.WithPEPID(cfg.PepId))

	if ctx.Err() != nil {
		return nil, 0, ctx.Err()
	}

	start := time.Now()
	resp, err := client.Evaluate(ctx, pipReq)
	latencyMs := time.Since(start).Milliseconds()

	if err != nil {
		return nil, latencyMs, err
	}
	if !pip.ValidDecision(resp.Decision) || resp.DecisionID == "" {
		return nil, latencyMs, &invalidPDPResponseError{decision: resp.Decision, decisionID: resp.DecisionID}
	}
	return resp, latencyMs, nil
}

// handleBreakGlass validates a break-glass token and returns a response if valid.
// Returns nil if validation fails (caller should proceed with normal PDP path).
func (s *MCPService) handleBreakGlass(
	token string,
	cfg *pb.PolicyConfig,
	operation string,
	txnID string,
	em pip.EnforcementMode,
) *pb.PolicyDecisionResponse {
	if len(cfg.BreakglassPublicKey) == 0 {
		slog.Warn("break-glass token provided but no public key configured")
		return nil
	}

	if len(cfg.BreakglassPublicKey) != ed25519.PublicKeySize {
		slog.Error("break-glass public key has wrong size",
			slog.Int("expected", ed25519.PublicKeySize),
			slog.Int("got", len(cfg.BreakglassPublicKey)),
		)
		return nil
	}
	pubKey := ed25519.PublicKey(cfg.BreakglassPublicKey)

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
	// Log the raw error server-side for debugging; expose only the error_code
	// and a stable reason to callers so internal network details don't leak.
	slog.Warn("PDP query failed",
		slog.String("txn_id", txnID),
		slog.String("error", pdpErr.Error()),
	)

	errCode := classifyPDPError(pdpErr)

	if em == pip.EMObserve {
		return &pb.PolicyDecisionResponse{
			Decision:        pip.DecisionObserve,
			DecisionId:      "pdp-unavailable",
			Reason:          "policy service unavailable",
			EnforcementMode: em.String(),
			ErrorCode:       errCode,
			PdpLatencyMs:    latencyMs,
			TxnId:           txnID,
		}
	}

	return &pb.PolicyDecisionResponse{
		Decision:        pip.DecisionDeny,
		DecisionId:      "pdp-unavailable",
		Reason:          "policy service unavailable",
		EnforcementMode: em.String(),
		ErrorCode:       errCode,
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

	// ALLOW — obligations are returned to the caller for enforcement.
	// Obligation execution is context-dependent (rate limiting needs the
	// SDK's HTTP layer, logging needs the SDK's logger) so the Go core
	// only returns them; the SDK decides how to handle each type per the
	// enforcement mode it already knows.
	resp.Decision = pip.DecisionAllow

	return resp
}

// buildPIPRequest constructs a PIP DecisionRequest from the proto request fields.
func buildPIPRequest(req *pb.PolicyDecisionRequest, txnID string, em pip.EnforcementMode) *pip.DecisionRequest {
	cfg := req.GetConfig()
	subject := req.GetSubject()
	action := req.GetAction()
	resource := req.GetResource()

	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)

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

	if action.GetCapabilityClass() != "" {
		cc := action.GetCapabilityClass()
		pipReq.Action.CapabilityClass = &cc
	}
	if cfg.GetPepId() != "" {
		pepID := cfg.GetPepId()
		pipReq.Environment.PEPID = &pepID
	}
	if cfg.GetWorkspace() != "" {
		ws := cfg.GetWorkspace()
		pipReq.Environment.Workspace = &ws
	}

	return pipReq
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

// invalidPDPResponseError indicates the PDP returned a non-compliant response.
type invalidPDPResponseError struct {
	decision   string
	decisionID string
}

func (e *invalidPDPResponseError) Error() string {
	return fmt.Sprintf("non-compliant PDP response: decision=%q decision_id=%q", e.decision, e.decisionID)
}

// classifyPDPError maps a PDP error to a specific error_code string.
func classifyPDPError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "pdp_timeout"
	}
	// net/http timeout errors (Client.Timeout) expose a Timeout() method
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Timeout() {
		return "pdp_timeout"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "pdp_timeout"
	}
	// Errors from our handler or from the PDP client about non-compliant responses
	var invResp *invalidPDPResponseError
	if errors.As(err, &invResp) {
		return "pdp_invalid_response"
	}
	// The HTTPPDPClient validates decision/decision_id — those errors
	// contain specific substrings we can match for classification.
	errMsg := err.Error()
	if strings.Contains(errMsg, "invalid decision") || strings.Contains(errMsg, "empty decision_id") || strings.Contains(errMsg, "unmarshal") {
		return "pdp_invalid_response"
	}
	return "pdp_unavailable"
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
// Returns 0 when badge_exp is missing/invalid — caller should skip caching
// because RFC-005 requires cache lifetime to be bounded by badge expiry.
func badgeExpTTL(badgeExp int64) time.Duration {
	if badgeExp <= 0 {
		return 0
	}
	remaining := time.Until(time.Unix(badgeExp, 0))
	if remaining <= 0 {
		return 0
	}
	return remaining
}
