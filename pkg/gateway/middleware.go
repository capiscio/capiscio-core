// Package gateway provides the HTTP middleware for the CapiscIO Security Sidecar.
package gateway

import (
	"crypto"
	"log"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/capiscio/capiscio-core/v2/pkg/badge"
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
}

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

// PolicyEventCallback is invoked after each policy enforcement with the event data.
// Implementations should be non-blocking.
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

	// If no PDP configured, operate in badge-only mode
	if p.config.PDPClient == nil {
		p.next.ServeHTTP(w, r)
		return
	}

	// --- 2-3. Build PIP request ---
	pipReq := p.buildPIPRequest(r, claims)

	// --- 4. Check break-glass override ---
	if p.handleBreakGlass(w, r, pipReq) {
		return
	}

	// --- 5-9. Cache → PDP → enforce → obligations ---
	p.evaluatePolicy(w, r, claims, pipReq)
}

// buildPIPRequest constructs the PIP decision request from the HTTP request and badge claims.
func (p *pep) buildPIPRequest(r *http.Request, claims *badge.Claims) *pip.DecisionRequest {
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
	return &pip.DecisionRequest{
		PIPVersion: pip.PIPVersion,
		Subject: pip.SubjectAttributes{
			DID:        claims.Subject,
			BadgeJTI:   claims.JTI,
			IAL:        claims.IAL,
			TrustLevel: claims.TrustLevel(),
		},
		Action: pip.ActionAttributes{
			Operation: r.Method + " " + r.URL.Path,
		},
		Resource: pip.ResourceAttributes{
			Identifier: r.URL.Path,
		},
		Context: pip.ContextAttributes{
			TxnID:           txnID,
			EnforcementMode: p.config.EnforcementMode.String(),
		},
		Environment: pip.EnvironmentAttrs{
			PEPID:     strPtr(p.config.PEPID),
			Workspace: strPtr(p.config.Workspace),
			Time:      &nowStr,
		},
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
		emitPolicyEvent(p.callbacks, *event, pipReq)
		http.Error(w, "Access denied by policy", http.StatusForbidden)
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
		reason := "Access denied by policy"
		if resp.Reason != "" {
			reason = resp.Reason
		}
		emitPolicyEvent(p.callbacks, *event, pipReq)
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
