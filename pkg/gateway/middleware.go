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

// NewPolicyMiddleware creates a full PEP middleware (RFC-005).
// When PEPConfig.PDPClient is nil, operates in badge-only mode (identical to NewAuthMiddleware).
func NewPolicyMiddleware(verifier *badge.Verifier, config PEPConfig, next http.Handler, callbacks ...PolicyEventCallback) http.Handler {
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}

	var bgValidator *pip.BreakGlassValidator
	if config.BreakGlassKey != nil {
		bgValidator = pip.NewBreakGlassValidator(config.BreakGlassKey)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// --- 1. Extract and verify badge (authentication) ---
		token := ExtractBadge(r)
		if token == "" {
			http.Error(w, "Missing Trust Badge", http.StatusUnauthorized)
			return
		}

		claims, err := verifier.Verify(r.Context(), token)
		if err != nil {
			logger.WarnContext(r.Context(), "badge verification failed", slog.String("error", err.Error()))
			http.Error(w, "Invalid Trust Badge", http.StatusUnauthorized)
			return
		}

		// Forward verified identity to upstream
		r.Header.Set("X-Capiscio-Subject", claims.Subject)
		r.Header.Set("X-Capiscio-Issuer", claims.Issuer)

		// If no PDP configured, operate in badge-only mode
		if config.PDPClient == nil {
			next.ServeHTTP(w, r)
			return
		}

		// --- 2. Resolve txn_id (RFC-004 header or generate UUID v7) ---
		txnID := r.Header.Get(pip.TxnIDHeader)
		if txnID == "" {
			txnID = uuid.Must(uuid.NewV7()).String()
		}
		r.Header.Set(pip.TxnIDHeader, txnID)

		// --- 3. Build PIP request ---
		now := time.Now().UTC()
		nowStr := now.Format(time.RFC3339)
		pipReq := &pip.DecisionRequest{
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
				EnforcementMode: config.EnforcementMode.String(),
			},
			Environment: pip.EnvironmentAttrs{
				PEPID:     strPtr(config.PEPID),
				Workspace: strPtr(config.Workspace),
				Time:      &nowStr,
			},
		}

		event := PolicyEvent{}

		// --- 4. Check break-glass override ---
		if bgValidator != nil {
			if bgToken := extractBreakGlass(r, bgValidator); bgToken != nil {
				logger.WarnContext(r.Context(), "break-glass override active",
					slog.String(pip.TelemetryOverrideJTI, bgToken.JTI),
					slog.String("operator", bgToken.SUB),
					slog.String("reason", bgToken.Reason))

				event.Decision = pip.DecisionAllow
				event.DecisionID = "breakglass:" + bgToken.JTI
				event.Override = true
				event.OverrideJTI = bgToken.JTI
				emitPolicyEvent(callbacks, event, pipReq)
				next.ServeHTTP(w, r)
				return
			}
		}

		// --- 5. Check cache ---
		cacheKey := pip.CacheKeyComponents(claims.Subject, claims.JTI, pipReq.Action.Operation, pipReq.Resource.Identifier)
		if config.DecisionCache != nil {
			if cached, ok := config.DecisionCache.Get(cacheKey); ok {
				event.Decision = cached.Decision
				event.DecisionID = cached.DecisionID
				event.CacheHit = true
				event.Obligations = obligationTypes(cached.Obligations)

				if cached.Decision == pip.DecisionDeny {
					emitPolicyEvent(callbacks, event, pipReq)
					http.Error(w, "Access denied by policy", http.StatusForbidden)
					return
				}

				// Handle obligations from cached response
				if config.ObligationReg != nil && len(cached.Obligations) > 0 {
					oblResult := config.ObligationReg.Enforce(r.Context(), config.EnforcementMode, cached.Obligations)
					if !oblResult.Proceed {
						event.Decision = pip.DecisionDeny
						emitPolicyEvent(callbacks, event, pipReq)
						http.Error(w, "Access denied: obligation enforcement failed", http.StatusForbidden)
						return
					}
				}

				emitPolicyEvent(callbacks, event, pipReq)
				next.ServeHTTP(w, r)
				return
			}
		}

		// --- 6. Query PDP ---
		start := time.Now()
		resp, pdpErr := config.PDPClient.Evaluate(r.Context(), pipReq)
		event.PDPLatencyMs = time.Since(start).Milliseconds()

		if pdpErr != nil {
			// PDP unavailable — handle per enforcement mode (RFC-005 §7.4)
			event.ErrorCode = pip.ErrorCodePDPUnavailable
			logger.ErrorContext(r.Context(), "PDP unavailable",
				slog.String(pip.TelemetryErrorCode, pip.ErrorCodePDPUnavailable),
				slog.String("error", pdpErr.Error()),
				slog.String("enforcement_mode", config.EnforcementMode.String()))

			if config.EnforcementMode == pip.EMObserve {
				event.Decision = pip.DecisionObserve
				event.DecisionID = "pdp-unavailable"
				emitPolicyEvent(callbacks, event, pipReq)
				next.ServeHTTP(w, r)
				return
			}
			// EM-GUARD, EM-DELEGATE, EM-STRICT: fail-closed
			event.Decision = pip.DecisionDeny
			event.DecisionID = "pdp-unavailable"
			emitPolicyEvent(callbacks, event, pipReq)
			http.Error(w, "Access denied: policy service unavailable", http.StatusForbidden)
			return
		}

		event.Decision = resp.Decision
		event.DecisionID = resp.DecisionID
		event.Obligations = obligationTypes(resp.Obligations)

		// --- 7. Cache the response ---
		if config.DecisionCache != nil {
			maxTTL := time.Until(time.Unix(claims.Expiry, 0))
			if maxTTL > 0 {
				config.DecisionCache.Put(cacheKey, resp, maxTTL)
			}
		}

		// --- 8. Enforce decision ---
		if resp.Decision == pip.DecisionDeny {
			switch config.EnforcementMode {
			case pip.EMObserve:
				// Log only, allow through
				logger.InfoContext(r.Context(), "PDP DENY in EM-OBSERVE (allowing)",
					slog.String(pip.TelemetryDecisionID, resp.DecisionID))
				event.Decision = pip.DecisionObserve
				emitPolicyEvent(callbacks, event, pipReq)
				next.ServeHTTP(w, r)
				return
			default:
				// EM-GUARD, EM-DELEGATE, EM-STRICT: block
				reason := "Access denied by policy"
				if resp.Reason != "" {
					reason = resp.Reason
				}
				emitPolicyEvent(callbacks, event, pipReq)
				http.Error(w, reason, http.StatusForbidden)
				return
			}
		}

		// --- 9. Handle obligations ---
		if config.ObligationReg != nil && len(resp.Obligations) > 0 {
			oblResult := config.ObligationReg.Enforce(r.Context(), config.EnforcementMode, resp.Obligations)
			if !oblResult.Proceed {
				event.Decision = pip.DecisionDeny
				emitPolicyEvent(callbacks, event, pipReq)
				http.Error(w, "Access denied: obligation enforcement failed", http.StatusForbidden)
				return
			}
		}

		// --- 10. Emit telemetry and forward ---
		emitPolicyEvent(callbacks, event, pipReq)
		next.ServeHTTP(w, r)
	})
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
		cb(event, req)
	}
}
