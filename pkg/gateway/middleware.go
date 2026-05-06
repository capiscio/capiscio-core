// Package gateway provides the HTTP middleware for the CapiscIO Security Sidecar.
package gateway

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/capiscio/capiscio-core/v2/pkg/badge"
	"github.com/capiscio/capiscio-core/v2/pkg/envelope"
	"github.com/capiscio/capiscio-core/v2/pkg/pip"
)

// NewAuthMiddleware creates a middleware that enforces Badge validity.
// Deprecated: Use NewPolicyMiddleware for RFC-005 PDP integration.
func NewAuthMiddleware(verifier *badge.Verifier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract Badge
		token := ExtractBadge(r)
		if token == "" {
			http.Error(w, "Missing Trust Badge", http.StatusUnauthorized)
			return
		}

		// Verify
		claims, err := verifier.Verify(r.Context(), token)
		if err != nil {
			log.Printf("Verification failed: %v", err)
			http.Error(w, "Invalid Trust Badge", http.StatusUnauthorized)
			return
		}

		// Forward verified identity to upstream
		r.Header.Set("X-Capiscio-Subject", claims.Subject)
		r.Header.Set("X-Capiscio-Issuer", claims.Issuer)

		next.ServeHTTP(w, r)
	})
}

// PEPConfig configures the Policy Enforcement Point middleware (RFC-005).
type PEPConfig struct {
	PDPClient       pip.PDPClient            // nil = badge-only mode (skip PDP)
	EnforcementMode pip.EnforcementMode      // default EMObserve
	ObligationReg   *pip.ObligationRegistry  // nil = no obligation handling
	DecisionCache   pip.DecisionCache        // nil = no caching
	BreakGlassKey   crypto.PublicKey          // nil = break-glass disabled
	PEPID           string                   // PEP instance identifier
	Workspace       string                   // workspace/tenant identifier
	Logger          *slog.Logger             // nil = slog.Default()

	// EnvelopeVerifier verifies Authority Envelopes and chains (RFC-008).
	// nil = envelope verification disabled (badge-only mode).
	EnvelopeVerifier *envelope.Verifier

	// MaxChainDepth is the maximum delegation chain length accepted by this PEP.
	// 0 = use default (10, per RFC-008 §9.5 RECOMMENDED).
	MaxChainDepth int

	// OrgTrustBoundary is the DID prefix that identifies this PEP's organization.
	// DIDs outside this prefix are considered foreign-org for cache purposes (§15.4).
	// Example: "did:web:acme.example"
	OrgTrustBoundary string
}

// defaultMaxChainDepth is the maximum chain depth per RFC-008 §9.5 RECOMMENDED.
const defaultMaxChainDepth = 10

// PolicyEvent captures telemetry for a policy enforcement decision.
type PolicyEvent struct {
	Decision     string
	DecisionID   string
	Override     bool
	OverrideJTI  string
	CacheHit     bool
	PDPLatencyMs int64
	Obligations  []string
	ErrorCode    string
}

// PolicyEventCallback is invoked synchronously after each policy enforcement with the event data.
// Implementations MUST return quickly and avoid long-running or blocking operations.
type PolicyEventCallback func(event PolicyEvent, req *pip.DecisionRequest)

// pep is the internal Policy Enforcement Point handler.
type pep struct {
	verifier    *badge.Verifier
	config      PEPConfig
	logger      *slog.Logger
	bgValidator *pip.BreakGlassValidator
	callbacks   []PolicyEventCallback
	next        http.Handler
}

// NewPolicyMiddleware creates a full PEP middleware (RFC-005).
// When PEPConfig.PDPClient is nil, operates in badge-only mode (identical to NewAuthMiddleware).
func NewPolicyMiddleware(verifier *badge.Verifier, config PEPConfig, next http.Handler, callbacks ...PolicyEventCallback) http.Handler {
	p := &pep{
		verifier:  verifier,
		config:    config,
		next:      next,
		callbacks: callbacks,
		logger:    config.Logger,
	}
	if p.logger == nil {
		p.logger = slog.Default()
	}
	if config.BreakGlassKey != nil {
		p.bgValidator = pip.NewBreakGlassValidator(config.BreakGlassKey)
	}
	return http.HandlerFunc(p.serveHTTP)
}

// serveHTTP implements the PEP request flow: authenticate → break-glass → cache → PDP → enforce.
func (p *pep) serveHTTP(w http.ResponseWriter, r *http.Request) {
	// --- 1. Extract and verify badge (authentication) ---
	token := ExtractBadge(r)
	if token == "" {
		http.Error(w, "Missing Trust Badge", http.StatusUnauthorized)
		return
	}

	claims, err := p.verifier.Verify(r.Context(), token)
	if err != nil {
		p.logger.WarnContext(r.Context(), "badge verification failed", slog.String("error", err.Error()))
		http.Error(w, "Invalid Trust Badge", http.StatusUnauthorized)
		return
	}

	// Forward verified identity to upstream
	r.Header.Set("X-Capiscio-Subject", claims.Subject)
	r.Header.Set("X-Capiscio-Issuer", claims.Issuer)

	// --- 2-8. Verify authority chain (RFC-008 §9.2 steps 2–8) ---
	var chainResult *envelope.ChainVerifyResult
	if p.config.EnvelopeVerifier != nil {
		var err error
		chainResult, err = p.verifyAuthorityChain(r, token)
		if err != nil {
			p.handleChainError(w, r, err)
			return
		}
	}

	// If no PDP configured, operate in badge-only mode
	if p.config.PDPClient == nil {
		p.next.ServeHTTP(w, r)
		return
	}

	// --- 9. Build PIP request with verified chain data ---
	pipReq := p.buildPIPRequest(r, claims, chainResult)

	// --- 4. Check break-glass override ---
	if p.handleBreakGlass(w, r, pipReq) {
		return
	}

	// --- 5-9. Cache → PDP → enforce → obligations ---
	p.evaluatePolicy(w, r, claims, pipReq)
}

// buildPIPRequest constructs the PIP decision request from the HTTP request, badge claims,
// and optional verified chain result (nil for badge-only requests).
func (p *pep) buildPIPRequest(r *http.Request, claims *badge.Claims, chain *envelope.ChainVerifyResult) *pip.DecisionRequest {
	txnID := r.Header.Get(pip.TxnIDHeader)
	if txnID == "" {
		if u, err := uuid.NewV7(); err != nil {
			p.logger.ErrorContext(r.Context(), "failed to generate UUID v7 for txn_id", slog.String("error", err.Error()))
			txnID = uuid.New().String()
		} else {
			txnID = u.String()
		}
	}
	r.Header.Set(pip.TxnIDHeader, txnID)

	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)
	req := &pip.DecisionRequest{
		PIPVersion: pip.PIPVersion,
		Subject: pip.SubjectAttributes{
			DID:        claims.Subject,
			BadgeJTI:   claims.JTI,
			IAL:        claims.IAL,
			TrustLevel: claims.TrustLevel(),
		},
		Action: pip.ActionAttributes{
			Operation:       r.Method + " " + r.URL.Path,
			CapabilityClass: strPtrFromHeader(r, "X-Capiscio-Capability-Class"),
		},
		Resource: pip.ResourceAttributes{
			Identifier: r.URL.Path,
		},
		Context: pip.ContextAttributes{
			TxnID:           txnID,
			EnforcementMode: p.config.EnforcementMode.String(),
			EnvelopeID:      strPtrFromHeader(r, "X-Capiscio-Envelope-ID"),
		},
		Environment: pip.EnvironmentAttrs{
			PEPID:     strPtr(p.config.PEPID),
			Workspace: strPtr(p.config.Workspace),
			Time:      &nowStr,
		},
	}

	// When a verified chain is present, override raw header values with
	// cryptographically verified data from VerifyChain() output.
	// This prevents capability class spoofing via header injection.
	if chain != nil {
		req.Action.CapabilityClass = strPtr(chain.LeafCapability)

		leaf := chain.Links[len(chain.Links)-1]
		req.Context.EnvelopeID = strPtr(leaf.Payload.EnvelopeID)
		depth := chain.TotalDepth
		req.Context.DelegationDepth = &depth
		if leaf.Payload.Constraints != nil {
			constraintsJSON, _ := json.Marshal(leaf.Payload.Constraints)
			req.Context.Constraints = constraintsJSON
		}
		if len(chain.Links) > 1 {
			parent := chain.Links[len(chain.Links)-2]
			if parent.Payload.Constraints != nil {
				parentJSON, _ := json.Marshal(parent.Payload.Constraints)
				req.Context.ParentConstraints = parentJSON
			}
		}

		// Use the most restrictive enforcement mode from the chain (D7).
		// envelope.EnforcementMode and pip.EnforcementMode share iota order
		// and string representations; convert via the string form.
		strictest := p.config.EnforcementMode
		for _, link := range chain.Links {
			linkMode, err := pip.ParseEnforcementMode(link.EffectiveMode.String())
			if err != nil {
				continue // skip unparseable modes
			}
			if linkMode > strictest {
				strictest = linkMode
			}
		}
		if strictest > p.config.EnforcementMode {
			req.Context.EnforcementMode = strictest.String()
		}
	}

	return req
}

// maxChainDepth returns the configured maximum chain depth, defaulting to 10.
func (p *pep) maxChainDepth() int {
	if p.config.MaxChainDepth > 0 {
		return p.config.MaxChainDepth
	}
	return defaultMaxChainDepth
}

// verifyAuthorityChain extracts and verifies RFC-008 §15 chain transport headers.
// Returns nil, nil if no chain headers are present (badge-only request).
// The callerBadgeJWS is the already-verified badge from the X-Capiscio-Badge header.
func (p *pep) verifyAuthorityChain(r *http.Request, callerBadgeJWS string) (*envelope.ChainVerifyResult, error) {
	leafJWS := ExtractLeafAuthority(r)
	if leafJWS == "" {
		return nil, nil // No envelope — badge-only mode
	}

	chain, err := ExtractAuthorityChain(r)
	if err != nil {
		return nil, err
	}

	// Validate leaf consistency (Appendix A): chain[-1] must match leaf header.
	if chain != nil {
		if err := ValidateChainLeafConsistency(leafJWS, chain); err != nil {
			return nil, err
		}
	}

	// If no chain, verify the single leaf envelope.
	if chain == nil {
		chain = []string{leafJWS}
	}

	// Check max chain depth before expensive verification.
	if len(chain) > p.maxChainDepth() {
		return nil, envelope.NewError(envelope.ErrCodeChainTooDeep,
			fmt.Sprintf("chain length %d exceeds maximum %d", len(chain), p.maxChainDepth()))
	}

	// Extract the badge map for cross-org chains.
	badgeMap, err := ExtractBadgeMap(r)
	if err != nil {
		return nil, err
	}

	// Build verify options.
	opts := envelope.VerifyOptions{
		Now: func() time.Time { return time.Now() },
	}

	result, err := p.config.EnvelopeVerifier.VerifyChain(r.Context(), chain, badgeMap, opts)
	if err != nil {
		return nil, err
	}

	p.logger.InfoContext(r.Context(), "authority chain verified",
		slog.Int("chain_depth", result.TotalDepth),
		slog.String("root_capability", result.RootCapability),
		slog.String("leaf_capability", result.LeafCapability),
	)

	return result, nil
}

// handleChainError maps envelope verification errors to HTTP responses.
// Errors from chain verification are pre-PDP (RFC-008 §9.2 steps 2–8).
func (p *pep) handleChainError(w http.ResponseWriter, r *http.Request, err error) {
	var envErr *envelope.Error
	if errors.As(err, &envErr) {
		status := ChainErrorHTTPStatus(envErr.Code)
		p.logger.WarnContext(r.Context(), "authority chain verification failed",
			slog.String("error_code", envErr.Code),
			slog.String("error", envErr.Message),
			slog.Int("status", status),
			slog.String("enforcement_mode", p.config.EnforcementMode.String()),
		)

		// In EM-OBSERVE, log but allow the request through (RFC-005 §6.3)
		if p.config.EnforcementMode == pip.EMObserve {
			p.logger.InfoContext(r.Context(), "chain error in EM-OBSERVE (allowing)",
				slog.String("error_code", envErr.Code))
			p.next.ServeHTTP(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		resp := map[string]string{
			"error":      envErr.Code,
			"error_desc": envErr.Message,
		}
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	// Non-envelope error (e.g., network failure in key resolution)
	if p.config.EnforcementMode == pip.EMObserve {
		p.logger.WarnContext(r.Context(), "chain verification error in EM-OBSERVE (allowing)",
			slog.String("error", err.Error()))
		p.next.ServeHTTP(w, r)
		return
	}
	p.logger.ErrorContext(r.Context(), "authority chain verification error",
		slog.String("error", err.Error()),
	)
	http.Error(w, "internal chain verification error", http.StatusInternalServerError)
}

// ChainErrorHTTPStatus maps RFC-008 error codes to HTTP status codes.
func ChainErrorHTTPStatus(code string) int {
	switch code {
	case envelope.ErrCodeMalformed, envelope.ErrCodeCapabilityInvalid, envelope.ErrCodePayloadTooLarge:
		return http.StatusBadRequest // 400
	case envelope.ErrCodeExpired, envelope.ErrCodeNotYetValid:
		return http.StatusUnauthorized // 401
	case envelope.ErrCodeSignatureInvalid, envelope.ErrCodeBadgeBindingFailed,
		envelope.ErrCodeChainBroken, envelope.ErrCodeNarrowingViolation,
		envelope.ErrCodeDepthExceeded, envelope.ErrCodeChainTooDeep,
		envelope.ErrCodeKeyNotBound, envelope.ErrCodeScopeInsufficient:
		return http.StatusForbidden // 403
	case envelope.ErrCodeAlgorithmForbidden:
		return http.StatusForbidden // 403
	default:
		return http.StatusForbidden // 403
	}
}

// handleBreakGlass checks for a valid break-glass override token.
// Returns true if the request was handled (break-glass token was valid).
func (p *pep) handleBreakGlass(w http.ResponseWriter, r *http.Request, pipReq *pip.DecisionRequest) bool {
	if p.bgValidator == nil {
		return false
	}

	bgToken := extractBreakGlass(r, p.bgValidator)
	if bgToken == nil {
		return false
	}

	p.logger.WarnContext(r.Context(), "break-glass override active",
		slog.String(pip.TelemetryOverrideJTI, bgToken.JTI),
		slog.String("operator", bgToken.SUB),
		slog.String("reason", bgToken.Reason))

	emitPolicyEvent(p.callbacks, PolicyEvent{
		Decision:    pip.DecisionAllow,
		DecisionID:  "breakglass:" + bgToken.JTI,
		Override:    true,
		OverrideJTI: bgToken.JTI,
	}, pipReq)
	p.next.ServeHTTP(w, r)
	return true
}

// evaluatePolicy handles cache lookup, PDP query, decision enforcement, and obligations.
func (p *pep) evaluatePolicy(w http.ResponseWriter, r *http.Request, claims *badge.Claims, pipReq *pip.DecisionRequest) {
	cacheKey := pip.CacheKeyComponents(claims.Subject, claims.JTI, pipReq.Action.Operation, pipReq.Resource.Identifier)
	event := PolicyEvent{}

	// --- 5. Check cache ---
	if p.handleCachedDecision(w, r, cacheKey, &event, pipReq) {
		return
	}

	// --- 6. Query PDP ---
	start := time.Now()
	resp, pdpErr := p.config.PDPClient.Evaluate(r.Context(), pipReq)
	event.PDPLatencyMs = time.Since(start).Milliseconds()

	if pdpErr != nil {
		p.logger.ErrorContext(r.Context(), "PDP unavailable",
			slog.String(pip.TelemetryErrorCode, pip.ErrorCodePDPUnavailable),
			slog.String("error", pdpErr.Error()),
			slog.String("enforcement_mode", p.config.EnforcementMode.String()))
		p.handlePDPUnavailable(w, r, &event, pipReq)
		return
	}

	// Validate PDP response: Decision must be ALLOW or DENY, DecisionID must be non-empty.
	// A non-compliant response is treated as PDP unavailability (fail-closed except EM-OBSERVE).
	if !pip.ValidDecision(resp.Decision) || resp.DecisionID == "" {
		p.logger.ErrorContext(r.Context(), "PDP returned non-compliant response",
			slog.String("decision", resp.Decision),
			slog.String("decision_id", resp.DecisionID))
		p.handlePDPUnavailable(w, r, &event, pipReq)
		return
	}

	event.Decision = resp.Decision
	event.DecisionID = resp.DecisionID
	event.Obligations = obligationTypes(resp.Obligations)

	// --- 7. Cache the response ---
	if p.config.DecisionCache != nil {
		maxTTL := time.Until(time.Unix(claims.Expiry, 0))
		if maxTTL > 0 {
			p.config.DecisionCache.Put(cacheKey, resp, maxTTL)
		}
	}

	// --- 8. Enforce decision ---
	if resp.Decision == pip.DecisionDeny {
		p.handlePDPDeny(w, r, resp, &event, pipReq)
		return
	}

	// --- 9. Handle obligations ---
	if p.enforceObligations(w, r, resp.Obligations, &event, pipReq) {
		return
	}

	emitPolicyEvent(p.callbacks, event, pipReq)
	p.next.ServeHTTP(w, r)
}

// handleCachedDecision serves a cached PDP decision if available.
// Returns true if the request was handled from cache.
func (p *pep) handleCachedDecision(w http.ResponseWriter, r *http.Request, cacheKey string, event *PolicyEvent, pipReq *pip.DecisionRequest) bool {
	if p.config.DecisionCache == nil {
		return false
	}

	cached, ok := p.config.DecisionCache.Get(cacheKey)
	if !ok {
		return false
	}

	event.Decision = cached.Decision
	event.DecisionID = cached.DecisionID
	event.CacheHit = true
	event.Obligations = obligationTypes(cached.Obligations)

	if cached.Decision == pip.DecisionDeny {
		if p.config.EnforcementMode == pip.EMObserve {
			p.logger.InfoContext(r.Context(), "cached PDP DENY in EM-OBSERVE (allowing)",
				slog.String(pip.TelemetryDecisionID, cached.DecisionID))
			event.Decision = pip.DecisionObserve
			emitPolicyEvent(p.callbacks, *event, pipReq)
			p.next.ServeHTTP(w, r)
			return true
		}
		reason := cached.Reason
		if reason == "" {
			reason = "Access denied by policy"
		}
		emitPolicyEvent(p.callbacks, *event, pipReq)
		http.Error(w, reason, http.StatusForbidden)
		return true
	}

	if p.config.ObligationReg != nil && len(cached.Obligations) > 0 {
		oblResult := p.config.ObligationReg.Enforce(r.Context(), p.config.EnforcementMode, cached.Obligations)
		if !oblResult.Proceed {
			event.Decision = pip.DecisionDeny
			emitPolicyEvent(p.callbacks, *event, pipReq)
			http.Error(w, "Access denied: obligation enforcement failed", http.StatusForbidden)
			return true
		}
	}

	emitPolicyEvent(p.callbacks, *event, pipReq)
	p.next.ServeHTTP(w, r)
	return true
}

// handlePDPUnavailable handles PDP unreachability per enforcement mode (RFC-005 §7.4).
func (p *pep) handlePDPUnavailable(w http.ResponseWriter, r *http.Request, event *PolicyEvent, pipReq *pip.DecisionRequest) {
	event.ErrorCode = pip.ErrorCodePDPUnavailable

	if p.config.EnforcementMode == pip.EMObserve {
		event.Decision = pip.DecisionObserve
		event.DecisionID = "pdp-unavailable"
		emitPolicyEvent(p.callbacks, *event, pipReq)
		p.next.ServeHTTP(w, r)
		return
	}

	// EM-GUARD, EM-DELEGATE, EM-STRICT: fail-closed
	event.Decision = pip.DecisionDeny
	event.DecisionID = "pdp-unavailable"
	emitPolicyEvent(p.callbacks, *event, pipReq)
	http.Error(w, "Access denied: policy service unavailable", http.StatusForbidden)
}

// handlePDPDeny handles a DENY decision from the PDP per enforcement mode.
func (p *pep) handlePDPDeny(w http.ResponseWriter, r *http.Request, resp *pip.DecisionResponse, event *PolicyEvent, pipReq *pip.DecisionRequest) {
	switch p.config.EnforcementMode {
	case pip.EMObserve:
		p.logger.InfoContext(r.Context(), "PDP DENY in EM-OBSERVE (allowing)",
			slog.String(pip.TelemetryDecisionID, resp.DecisionID))
		event.Decision = pip.DecisionObserve
		emitPolicyEvent(p.callbacks, *event, pipReq)
		p.next.ServeHTTP(w, r)
	default:
		emitPolicyEvent(p.callbacks, *event, pipReq)

		// RFC-008: SCOPE_INSUFFICIENT returns structured JSON 403
		if resp.ErrorCode == pip.ErrorCodeScopeInsufficient {
			var presentedCap, envelopeID string
			if pipReq.Action.CapabilityClass != nil {
				presentedCap = *pipReq.Action.CapabilityClass
			}
			if pipReq.Context.EnvelopeID != nil {
				envelopeID = *pipReq.Context.EnvelopeID
			}
			body := envelope.NewScopeInsufficientRejection(
				resp.RequestedCapability,
				presentedCap,
				envelopeID,
				pipReq.Context.TxnID,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(body)
			return
		}

		reason := "Access denied by policy"
		if resp.Reason != "" {
			reason = resp.Reason
		}
		http.Error(w, reason, http.StatusForbidden)
	}
}

// enforceObligations attempts to enforce obligations from the PDP response.
// Returns true if the request was denied due to obligation failure.
func (p *pep) enforceObligations(w http.ResponseWriter, r *http.Request, obligations []pip.Obligation, event *PolicyEvent, pipReq *pip.DecisionRequest) bool {
	if p.config.ObligationReg == nil || len(obligations) == 0 {
		return false
	}

	oblResult := p.config.ObligationReg.Enforce(r.Context(), p.config.EnforcementMode, obligations)
	if !oblResult.Proceed {
		event.Decision = pip.DecisionDeny
		emitPolicyEvent(p.callbacks, *event, pipReq)
		http.Error(w, "Access denied: obligation enforcement failed", http.StatusForbidden)
		return true
	}

	return false
}

// ExtractBadge retrieves the badge from headers.
func ExtractBadge(r *http.Request) string {
	// 1. X-Capiscio-Badge
	if token := r.Header.Get("X-Capiscio-Badge"); token != "" {
		return token
	}

	// 2. Authorization: Bearer
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}

	return ""
}

// extractBreakGlass checks for a break-glass token in the request, validates it,
// and returns the token if valid and scope-matched. Returns nil otherwise.
func extractBreakGlass(r *http.Request, v *pip.BreakGlassValidator) *pip.BreakGlassToken {
	raw := r.Header.Get("X-Capiscio-Breakglass")
	if raw == "" {
		return nil
	}

	token, err := pip.ParseBreakGlassJWS(raw, v.PublicKey())
	if err != nil {
		return nil
	}

	if err := v.ValidateToken(token); err != nil {
		return nil
	}

	if !v.MatchesScope(token, r.Method, r.URL.Path) {
		return nil
	}

	return token
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func strPtrFromHeader(r *http.Request, header string) *string {
	v := r.Header.Get(header)
	if v == "" {
		return nil
	}
	return &v
}

func obligationTypes(obs []pip.Obligation) []string {
	if len(obs) == 0 {
		return nil
	}
	types := make([]string, len(obs))
	for i, o := range obs {
		types[i] = o.Type
	}
	return types
}

func emitPolicyEvent(callbacks []PolicyEventCallback, event PolicyEvent, req *pip.DecisionRequest) {
	for _, cb := range callbacks {
		cb := cb
		func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("policy event callback panicked", "panic", r)
				}
			}()
			cb(event, req)
		}()
	}
}
