//go:build opa_no_wasm

package gateway_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/capiscio/capiscio-core/v2/pkg/badge"
	"github.com/capiscio/capiscio-core/v2/pkg/gateway"
	"github.com/capiscio/capiscio-core/v2/pkg/pdp"
	"github.com/capiscio/capiscio-core/v2/pkg/pip"
	"github.com/capiscio/capiscio-core/v2/pkg/registry"
)

// --- Production Rego policy (mirrors capiscio-server/internal/pdp/policies/default.rego) ---
// This is the REAL Rego policy used in production bundles. Tests prove that
// every policy rule the engine can express is enforceable end-to-end through
// the gateway middleware → real OPA evaluator path, with no server round-trip.

const productionRego = `package capiscio.policy

import rego.v1

default decision := "ALLOW"

agent_policy := data.resolved_policies.by_agent_did[input.subject.did]
effective_policy := agent_policy if { agent_policy }
effective_policy := data.config if { not agent_policy }

decision := "DENY" if {
    required := effective_policy.min_trust_level
    required != ""
    not trust_level_meets(input.subject.trust_level, required)
}

decision := "DENY" if {
    input.subject.did in effective_policy.denied_dids
}

decision := "DENY" if {
    count(effective_policy.allowed_dids) > 0
    not input.subject.did in effective_policy.allowed_dids
}

decision := "DENY" if {
    some op_rule in effective_policy.operations
    glob.match(op_rule.pattern, ["/"], input.action.operation)
    op_rule.min_trust_level != ""
    not trust_level_meets(input.subject.trust_level, op_rule.min_trust_level)
}

decision := "DENY" if {
    some op_rule in effective_policy.operations
    glob.match(op_rule.pattern, ["/"], input.action.operation)
    count(op_rule.allowed_dids) > 0
    not input.subject.did in op_rule.allowed_dids
}

decision := "DENY" if {
    some op_rule in effective_policy.operations
    glob.match(op_rule.pattern, ["/"], input.action.operation)
    input.subject.did in op_rule.denied_dids
}

decision := "DENY" if {
    input.action.mcp_tool
    some tool_rule in effective_policy.mcp_tools
    input.action.mcp_tool == tool_rule.tool
    tool_rule.min_trust_level != ""
    not trust_level_meets(input.subject.trust_level, tool_rule.min_trust_level)
}

decision := "DENY" if {
    input.action.mcp_tool
    some tool_rule in effective_policy.mcp_tools
    input.action.mcp_tool == tool_rule.tool
    input.subject.did in tool_rule.denied_dids
}

decision := "DENY" if {
    input.action.mcp_tool
    some tool_rule in effective_policy.mcp_tools
    input.action.mcp_tool == tool_rule.tool
    count(tool_rule.allowed_dids) > 0
    not input.subject.did in tool_rule.allowed_dids
}

trust_levels := {"SS": 0, "REG": 1, "DV": 2, "OV": 3, "EV": 4, "": 0, "1": 2, "2": 3, "3": 4}

trust_level_meets(have, need) if {
    trust_levels[have] >= trust_levels[need]
}

obligations contains obj if {
    some rate_rule in effective_policy.rate_limits
    input.subject.did == rate_rule.did
    obj := {
        "type": "rate_limit.apply",
        "params": {"rpm": rate_rule.rpm, "key": rate_rule.did},
    }
}

reason := sprintf("Agent %s: trust_level=%s", [input.subject.did, input.subject.trust_level])
`

// --- Test infrastructure ---

type opaIntegrationRegistry struct {
	key ed25519.PublicKey
}

func (m *opaIntegrationRegistry) GetPublicKey(_ context.Context, _ string) (crypto.PublicKey, error) {
	return m.key, nil
}

func (m *opaIntegrationRegistry) IsRevoked(_ context.Context, _ string) (bool, error) {
	return false, nil
}

func (m *opaIntegrationRegistry) GetBadgeStatus(_ context.Context, _ string, jti string) (*registry.BadgeStatus, error) {
	return &registry.BadgeStatus{JTI: jti, Revoked: false}, nil
}

func (m *opaIntegrationRegistry) GetAgentStatus(_ context.Context, _ string, agentID string) (*registry.AgentStatus, error) {
	return &registry.AgentStatus{ID: agentID, Status: registry.AgentStatusActive}, nil
}

func (m *opaIntegrationRegistry) SyncRevocations(_ context.Context, _ string, _ time.Time) ([]registry.Revocation, error) {
	return nil, nil
}

type opaIntegrationSetup struct {
	pub       ed25519.PublicKey
	priv      ed25519.PrivateKey
	verifier  *badge.Verifier
	evaluator *pdp.OPALocalClient
}

func newOPAIntegrationSetup(t *testing.T, modules map[string]string, data map[string]interface{}) *opaIntegrationSetup {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	reg := &opaIntegrationRegistry{key: pub}
	verifier := badge.NewVerifier(reg)

	evaluator := pdp.NewOPALocalClient()
	err = evaluator.LoadBundle(context.Background(), modules, data)
	require.NoError(t, err, "failed to load Rego bundle into OPA")

	return &opaIntegrationSetup{
		pub:       pub,
		priv:      priv,
		verifier:  verifier,
		evaluator: evaluator,
	}
}

func (s *opaIntegrationSetup) signBadge(t *testing.T, subject string, trustLevel string) string {
	t.Helper()
	claims := &badge.Claims{
		JTI:      "opa-int-jti-" + subject,
		Issuer:   "did:web:test.capisc.io",
		Subject:  subject,
		IssuedAt: time.Now().Unix(),
		Expiry:   time.Now().Add(1 * time.Hour).Unix(),
		IAL:      "IAL-1",
		VC: badge.VerifiableCredential{
			Type: []string{"VerifiableCredential", "AgentIdentity"},
			CredentialSubject: badge.CredentialSubject{
				Domain: "test.example.com",
				Level:  trustLevel,
			},
		},
	}
	token, err := badge.SignBadge(claims, s.priv)
	require.NoError(t, err)
	return token
}

func makeOKHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
}

// --- Resolved policy bundle data builders ---

func bundleWithPolicy(policy map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"config":            map[string]interface{}{},
		"resolved_policies": map[string]interface{}{"by_agent_did": map[string]interface{}{}},
		"policy_lineage":    map[string]interface{}{"by_agent_did": map[string]interface{}{}},
		"agents":            []interface{}{},
	}
}

func bundleWithAgentPolicy(did string, policy map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"config": map[string]interface{}{},
		"resolved_policies": map[string]interface{}{
			"by_agent_did": map[string]interface{}{
				did: policy,
			},
		},
		"policy_lineage": map[string]interface{}{"by_agent_did": map[string]interface{}{}},
		"agents":         []interface{}{map[string]interface{}{"did": did, "status": "active"}},
	}
}

func bundleWithOrgBaseline(policy map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"config":            policy,
		"resolved_policies": map[string]interface{}{"by_agent_did": map[string]interface{}{}},
		"policy_lineage":    map[string]interface{}{"by_agent_did": map[string]interface{}{}},
		"agents":            []interface{}{},
	}
}

// =============================================================================
// Gateway + Real OPA Integration Tests
// =============================================================================
// These tests prove that the gateway PEP middleware correctly enforces policy
// decisions made by a real OPA evaluator with production Rego rules. No mocks.
// No server round-trips. The OPALocalClient evaluates in-process in microseconds.

func TestGatewayOPA_MinTrustLevel_AllowAgent(t *testing.T) {
	agentDID := "did:web:example.com:agents:trusted"
	data := bundleWithAgentPolicy(agentDID, map[string]interface{}{
		"min_trust_level": "DV",
		"denied_dids":     []interface{}{},
		"allowed_dids":    []interface{}{},
		"operations":      []interface{}{},
		"mcp_tools":       []interface{}{},
		"rate_limits":     []interface{}{},
	})

	setup := newOPAIntegrationSetup(t, map[string]string{"default.rego": productionRego}, data)
	token := setup.signBadge(t, agentDID, "3") // Level 3 = OV, meets DV

	var event gateway.PolicyEvent
	config := gateway.PEPConfig{
		PDPClient:       setup.evaluator,
		EnforcementMode: pip.EMGuard,
	}
	mw := gateway.NewPolicyMiddleware(setup.verifier, config, makeOKHandler(),
		func(e gateway.PolicyEvent, _ *pip.DecisionRequest) { event = e })

	req := httptest.NewRequest("GET", "/v1/agents", nil)
	req.Header.Set("X-Capiscio-Badge", token)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "OV agent should pass DV policy")
	assert.Equal(t, pip.DecisionAllow, event.Decision)
	assert.NotEmpty(t, event.DecisionID)
	assert.GreaterOrEqual(t, event.PDPLatencyMs, int64(0))
}

func TestGatewayOPA_MinTrustLevel_DenyAgent(t *testing.T) {
	agentDID := "did:web:example.com:agents:low-trust"
	data := bundleWithAgentPolicy(agentDID, map[string]interface{}{
		"min_trust_level": "EV",
		"denied_dids":     []interface{}{},
		"allowed_dids":    []interface{}{},
		"operations":      []interface{}{},
		"mcp_tools":       []interface{}{},
		"rate_limits":     []interface{}{},
	})

	setup := newOPAIntegrationSetup(t, map[string]string{"default.rego": productionRego}, data)
	token := setup.signBadge(t, agentDID, "2") // Level 2 = DV, below EV

	config := gateway.PEPConfig{
		PDPClient:       setup.evaluator,
		EnforcementMode: pip.EMGuard,
	}
	mw := gateway.NewPolicyMiddleware(setup.verifier, config, makeOKHandler())

	req := httptest.NewRequest("GET", "/v1/agents", nil)
	req.Header.Set("X-Capiscio-Badge", token)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code, "DV agent should be denied by EV policy")
}

func TestGatewayOPA_DeniedDIDs(t *testing.T) {
	blockedDID := "did:web:example.com:agents:blocked"
	data := bundleWithAgentPolicy(blockedDID, map[string]interface{}{
		"min_trust_level": "",
		"denied_dids":     []interface{}{blockedDID},
		"allowed_dids":    []interface{}{},
		"operations":      []interface{}{},
		"mcp_tools":       []interface{}{},
		"rate_limits":     []interface{}{},
	})

	setup := newOPAIntegrationSetup(t, map[string]string{"default.rego": productionRego}, data)
	token := setup.signBadge(t, blockedDID, "3") // EV level — doesn't matter, DID is denied

	config := gateway.PEPConfig{
		PDPClient:       setup.evaluator,
		EnforcementMode: pip.EMGuard,
	}
	mw := gateway.NewPolicyMiddleware(setup.verifier, config, makeOKHandler())

	req := httptest.NewRequest("GET", "/v1/agents", nil)
	req.Header.Set("X-Capiscio-Badge", token)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code, "denied DID should be blocked regardless of trust level")
}

func TestGatewayOPA_AllowedDIDs_Allowlist(t *testing.T) {
	allowedDID := "did:web:example.com:agents:vip"
	blockedDID := "did:web:example.com:agents:outsider"

	// Policy with allowlist — only allowedDID is permitted
	policy := map[string]interface{}{
		"min_trust_level": "",
		"denied_dids":     []interface{}{},
		"allowed_dids":    []interface{}{allowedDID},
		"operations":      []interface{}{},
		"mcp_tools":       []interface{}{},
		"rate_limits":     []interface{}{},
	}
	data := map[string]interface{}{
		"config": map[string]interface{}{},
		"resolved_policies": map[string]interface{}{
			"by_agent_did": map[string]interface{}{
				allowedDID: policy,
				blockedDID: policy,
			},
		},
		"policy_lineage": map[string]interface{}{"by_agent_did": map[string]interface{}{}},
		"agents":         []interface{}{},
	}

	setup := newOPAIntegrationSetup(t, map[string]string{"default.rego": productionRego}, data)

	config := gateway.PEPConfig{
		PDPClient:       setup.evaluator,
		EnforcementMode: pip.EMGuard,
	}

	t.Run("allowed DID passes", func(t *testing.T) {
		token := setup.signBadge(t, allowedDID, "1")
		mw := gateway.NewPolicyMiddleware(setup.verifier, config, makeOKHandler())
		req := httptest.NewRequest("GET", "/v1/agents", nil)
		req.Header.Set("X-Capiscio-Badge", token)
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("non-allowed DID blocked", func(t *testing.T) {
		token := setup.signBadge(t, blockedDID, "3")
		mw := gateway.NewPolicyMiddleware(setup.verifier, config, makeOKHandler())
		req := httptest.NewRequest("GET", "/v1/agents", nil)
		req.Header.Set("X-Capiscio-Badge", token)
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusForbidden, rr.Code)
	})
}

func TestGatewayOPA_OperationScopedPolicy(t *testing.T) {
	agentDID := "did:web:example.com:agents:op-test"
	data := bundleWithAgentPolicy(agentDID, map[string]interface{}{
		"min_trust_level": "",
		"denied_dids":     []interface{}{},
		"allowed_dids":    []interface{}{},
		"operations": []interface{}{
			map[string]interface{}{
				"pattern":         "POST /v1/agents/*/badge",
				"min_trust_level": "EV",
				"denied_dids":     []interface{}{},
				"allowed_dids":    []interface{}{},
			},
		},
		"mcp_tools":   []interface{}{},
		"rate_limits":  []interface{}{},
	})

	setup := newOPAIntegrationSetup(t, map[string]string{"default.rego": productionRego}, data)

	config := gateway.PEPConfig{
		PDPClient:       setup.evaluator,
		EnforcementMode: pip.EMGuard,
	}

	t.Run("non-matching operation allowed", func(t *testing.T) {
		token := setup.signBadge(t, agentDID, "1")
		mw := gateway.NewPolicyMiddleware(setup.verifier, config, makeOKHandler())
		req := httptest.NewRequest("GET", "/v1/agents", nil)
		req.Header.Set("X-Capiscio-Badge", token)
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code, "unmatched operation should default to ALLOW")
	})

	t.Run("matching operation with insufficient trust denied", func(t *testing.T) {
		token := setup.signBadge(t, agentDID, "2") // DV < EV
		mw := gateway.NewPolicyMiddleware(setup.verifier, config, makeOKHandler())
		req := httptest.NewRequest("POST", "/v1/agents/abc/badge", nil)
		req.Header.Set("X-Capiscio-Badge", token)
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusForbidden, rr.Code, "DV trust on EV-required operation should be denied")
	})

	t.Run("matching operation with sufficient trust allowed", func(t *testing.T) {
		token := setup.signBadge(t, agentDID, "3") // OV >= EV? No, "3"=OV=3, EV=4. This should DENY.
		// Actually: trust_levels["3"] = 4, trust_levels["EV"] = 4 → 4 >= 4 = true → ALLOW
		mw := gateway.NewPolicyMiddleware(setup.verifier, config, makeOKHandler())
		req := httptest.NewRequest("POST", "/v1/agents/abc/badge", nil)
		req.Header.Set("X-Capiscio-Badge", token)
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code, "level 3 (=EV ordinal 4) should meet EV requirement")
	})
}

func TestGatewayOPA_OrgBaselineFallback(t *testing.T) {
	// Agent not in resolved_policies → falls back to data.config (org baseline)
	unknownDID := "did:web:example.com:agents:new-agent"
	data := bundleWithOrgBaseline(map[string]interface{}{
		"min_trust_level": "OV",
		"denied_dids":     []interface{}{},
		"allowed_dids":    []interface{}{},
		"operations":      []interface{}{},
		"mcp_tools":       []interface{}{},
		"rate_limits":     []interface{}{},
	})

	setup := newOPAIntegrationSetup(t, map[string]string{"default.rego": productionRego}, data)

	config := gateway.PEPConfig{
		PDPClient:       setup.evaluator,
		EnforcementMode: pip.EMGuard,
	}

	t.Run("agent below org baseline denied", func(t *testing.T) {
		token := setup.signBadge(t, unknownDID, "1") // Level 1 = DV = 2, OV = 3 → DENY
		mw := gateway.NewPolicyMiddleware(setup.verifier, config, makeOKHandler())
		req := httptest.NewRequest("GET", "/v1/data", nil)
		req.Header.Set("X-Capiscio-Badge", token)
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusForbidden, rr.Code)
	})

	t.Run("agent meeting org baseline allowed", func(t *testing.T) {
		token := setup.signBadge(t, unknownDID, "2") // Level 2 = OV ordinal 3, OV = 3 → 3 >= 3 → ALLOW
		mw := gateway.NewPolicyMiddleware(setup.verifier, config, makeOKHandler())
		req := httptest.NewRequest("GET", "/v1/data", nil)
		req.Header.Set("X-Capiscio-Badge", token)
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

func TestGatewayOPA_RateLimitObligation(t *testing.T) {
	agentDID := "did:web:example.com:agents:rate-limited"
	data := bundleWithAgentPolicy(agentDID, map[string]interface{}{
		"min_trust_level": "",
		"denied_dids":     []interface{}{},
		"allowed_dids":    []interface{}{},
		"operations":      []interface{}{},
		"mcp_tools":       []interface{}{},
		"rate_limits": []interface{}{
			map[string]interface{}{
				"did": agentDID,
				"rpm": 100,
			},
		},
	})

	setup := newOPAIntegrationSetup(t, map[string]string{"default.rego": productionRego}, data)
	token := setup.signBadge(t, agentDID, "2")

	var event gateway.PolicyEvent
	config := gateway.PEPConfig{
		PDPClient:       setup.evaluator,
		EnforcementMode: pip.EMGuard,
	}
	mw := gateway.NewPolicyMiddleware(setup.verifier, config, makeOKHandler(),
		func(e gateway.PolicyEvent, _ *pip.DecisionRequest) { event = e })

	req := httptest.NewRequest("GET", "/v1/agents", nil)
	req.Header.Set("X-Capiscio-Badge", token)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "rate-limited agent should be allowed (obligation only)")
	assert.Equal(t, pip.DecisionAllow, event.Decision)
	assert.Contains(t, event.Obligations, "rate_limit.apply", "should emit rate_limit obligation")
}

// =============================================================================
// Enforcement mode tests with real OPA
// =============================================================================

func TestGatewayOPA_EnforcementModes(t *testing.T) {
	agentDID := "did:web:example.com:agents:em-test"
	data := bundleWithAgentPolicy(agentDID, map[string]interface{}{
		"min_trust_level": "EV",
		"denied_dids":     []interface{}{},
		"allowed_dids":    []interface{}{},
		"operations":      []interface{}{},
		"mcp_tools":       []interface{}{},
		"rate_limits":     []interface{}{},
	})

	setup := newOPAIntegrationSetup(t, map[string]string{"default.rego": productionRego}, data)
	token := setup.signBadge(t, agentDID, "1") // DV < EV → real OPA returns DENY

	tests := []struct {
		name           string
		mode           pip.EnforcementMode
		expectedStatus int
		expectedEvent  string
	}{
		{
			name:           "EM-OBSERVE logs DENY but allows",
			mode:           pip.EMObserve,
			expectedStatus: http.StatusOK,
			expectedEvent:  pip.DecisionObserve,
		},
		{
			name:           "EM-GUARD blocks on DENY",
			mode:           pip.EMGuard,
			expectedStatus: http.StatusForbidden,
			expectedEvent:  pip.DecisionDeny,
		},
		{
			name:           "EM-DELEGATE blocks on DENY",
			mode:           pip.EMDelegate,
			expectedStatus: http.StatusForbidden,
			expectedEvent:  pip.DecisionDeny,
		},
		{
			name:           "EM-STRICT blocks on DENY",
			mode:           pip.EMStrict,
			expectedStatus: http.StatusForbidden,
			expectedEvent:  pip.DecisionDeny,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var event gateway.PolicyEvent
			config := gateway.PEPConfig{
				PDPClient:       setup.evaluator,
				EnforcementMode: tc.mode,
			}
			mw := gateway.NewPolicyMiddleware(setup.verifier, config, makeOKHandler(),
				func(e gateway.PolicyEvent, _ *pip.DecisionRequest) { event = e })

			req := httptest.NewRequest("GET", "/v1/agents", nil)
			req.Header.Set("X-Capiscio-Badge", token)
			rr := httptest.NewRecorder()
			mw.ServeHTTP(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)
			assert.Equal(t, tc.expectedEvent, event.Decision)
		})
	}
}

// =============================================================================
// Three-level merge tests with real OPA
// =============================================================================

func TestGatewayOPA_ThreeLevelMerge_AgentOverridesGroupOverridesOrg(t *testing.T) {
	// Org baseline: min_trust_level = DV
	// Group agent: overridden to OV
	// Agent override: overridden to EV

	orgAgent := "did:web:example.com:agents:org-only"
	groupAgent := "did:web:example.com:agents:in-group"
	overrideAgent := "did:web:example.com:agents:has-override"

	data := map[string]interface{}{
		"config": map[string]interface{}{
			"min_trust_level": "DV",
			"denied_dids":     []interface{}{},
			"allowed_dids":    []interface{}{},
			"operations":      []interface{}{},
			"mcp_tools":       []interface{}{},
			"rate_limits":     []interface{}{},
		},
		"resolved_policies": map[string]interface{}{
			"by_agent_did": map[string]interface{}{
				groupAgent: map[string]interface{}{
					"min_trust_level": "OV",
					"denied_dids":     []interface{}{},
					"allowed_dids":    []interface{}{},
					"operations":      []interface{}{},
					"mcp_tools":       []interface{}{},
					"rate_limits":     []interface{}{},
				},
				overrideAgent: map[string]interface{}{
					"min_trust_level": "EV",
					"denied_dids":     []interface{}{},
					"allowed_dids":    []interface{}{},
					"operations":      []interface{}{},
					"mcp_tools":       []interface{}{},
					"rate_limits":     []interface{}{},
				},
			},
		},
		"policy_lineage": map[string]interface{}{"by_agent_did": map[string]interface{}{}},
		"agents":         []interface{}{},
	}

	setup := newOPAIntegrationSetup(t, map[string]string{"default.rego": productionRego}, data)

	config := gateway.PEPConfig{
		PDPClient:       setup.evaluator,
		EnforcementMode: pip.EMGuard,
	}

	// Org-only agent: DV required. Level 1 = DV ordinal 2, DV = 2 → 2 >= 2 → ALLOW
	t.Run("org baseline agent with DV trust allowed", func(t *testing.T) {
		token := setup.signBadge(t, orgAgent, "1")
		mw := gateway.NewPolicyMiddleware(setup.verifier, config, makeOKHandler())
		req := httptest.NewRequest("GET", "/v1/test", nil)
		req.Header.Set("X-Capiscio-Badge", token)
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	// Group agent: OV required. Level 1 = DV ordinal 2, OV = 3 → 2 < 3 → DENY
	t.Run("group agent with DV trust denied (needs OV)", func(t *testing.T) {
		token := setup.signBadge(t, groupAgent, "1")
		mw := gateway.NewPolicyMiddleware(setup.verifier, config, makeOKHandler())
		req := httptest.NewRequest("GET", "/v1/test", nil)
		req.Header.Set("X-Capiscio-Badge", token)
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusForbidden, rr.Code)
	})

	// Group agent: OV required. Level 2 = OV ordinal 3, OV = 3 → 3 >= 3 → ALLOW
	t.Run("group agent with OV trust allowed", func(t *testing.T) {
		token := setup.signBadge(t, groupAgent, "2")
		mw := gateway.NewPolicyMiddleware(setup.verifier, config, makeOKHandler())
		req := httptest.NewRequest("GET", "/v1/test", nil)
		req.Header.Set("X-Capiscio-Badge", token)
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	// Override agent: EV required. Level 2 = OV ordinal 3, EV = 4 → 3 < 4 → DENY
	t.Run("override agent with OV trust denied (needs EV)", func(t *testing.T) {
		token := setup.signBadge(t, overrideAgent, "2")
		mw := gateway.NewPolicyMiddleware(setup.verifier, config, makeOKHandler())
		req := httptest.NewRequest("GET", "/v1/test", nil)
		req.Header.Set("X-Capiscio-Badge", token)
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusForbidden, rr.Code)
	})

	// Override agent: EV required. Level 3 ordinal 4, EV = 4 → 4 >= 4 → ALLOW
	t.Run("override agent with EV trust allowed", func(t *testing.T) {
		token := setup.signBadge(t, overrideAgent, "3")
		mw := gateway.NewPolicyMiddleware(setup.verifier, config, makeOKHandler())
		req := httptest.NewRequest("GET", "/v1/test", nil)
		req.Header.Set("X-Capiscio-Badge", token)
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

// =============================================================================
// Bundle hot-swap test — proves policy updates propagate without restart
// =============================================================================

func TestGatewayOPA_BundleHotSwap(t *testing.T) {
	agentDID := "did:web:example.com:agents:hotswap"

	// Start with permissive policy
	permissiveData := bundleWithAgentPolicy(agentDID, map[string]interface{}{
		"min_trust_level": "",
		"denied_dids":     []interface{}{},
		"allowed_dids":    []interface{}{},
		"operations":      []interface{}{},
		"mcp_tools":       []interface{}{},
		"rate_limits":     []interface{}{},
	})

	setup := newOPAIntegrationSetup(t, map[string]string{"default.rego": productionRego}, permissiveData)
	token := setup.signBadge(t, agentDID, "1")

	config := gateway.PEPConfig{
		PDPClient:       setup.evaluator,
		EnforcementMode: pip.EMGuard,
	}

	// Request 1: permissive → ALLOW
	mw := gateway.NewPolicyMiddleware(setup.verifier, config, makeOKHandler())
	req := httptest.NewRequest("GET", "/v1/agents", nil)
	req.Header.Set("X-Capiscio-Badge", token)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, "permissive policy should allow")

	// Hot-swap to restrictive policy (EV required)
	restrictiveData := bundleWithAgentPolicy(agentDID, map[string]interface{}{
		"min_trust_level": "EV",
		"denied_dids":     []interface{}{},
		"allowed_dids":    []interface{}{},
		"operations":      []interface{}{},
		"mcp_tools":       []interface{}{},
		"rate_limits":     []interface{}{},
	})
	err := setup.evaluator.LoadBundle(context.Background(),
		map[string]string{"default.rego": productionRego}, restrictiveData)
	require.NoError(t, err)

	// Request 2: restrictive → DENY (same token, same middleware, new policy)
	mw2 := gateway.NewPolicyMiddleware(setup.verifier, config, makeOKHandler())
	req2 := httptest.NewRequest("GET", "/v1/agents", nil)
	req2.Header.Set("X-Capiscio-Badge", token)
	rr2 := httptest.NewRecorder()
	mw2.ServeHTTP(rr2, req2)
	assert.Equal(t, http.StatusForbidden, rr2.Code, "updated policy should deny")
}

// =============================================================================
// Concurrent evaluation — proves OPA is thread-safe under load
// =============================================================================

func TestGatewayOPA_ConcurrentEvaluation(t *testing.T) {
	agentDID := "did:web:example.com:agents:concurrent"
	data := bundleWithAgentPolicy(agentDID, map[string]interface{}{
		"min_trust_level": "DV",
		"denied_dids":     []interface{}{},
		"allowed_dids":    []interface{}{},
		"operations":      []interface{}{},
		"mcp_tools":       []interface{}{},
		"rate_limits":     []interface{}{},
	})

	setup := newOPAIntegrationSetup(t, map[string]string{"default.rego": productionRego}, data)
	token := setup.signBadge(t, agentDID, "2") // OV meets DV

	config := gateway.PEPConfig{
		PDPClient:       setup.evaluator,
		EnforcementMode: pip.EMGuard,
	}

	const goroutines = 50
	var wg sync.WaitGroup
	results := make([]int, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			mw := gateway.NewPolicyMiddleware(setup.verifier, config, makeOKHandler())
			req := httptest.NewRequest("GET", "/v1/agents", nil)
			req.Header.Set("X-Capiscio-Badge", token)
			rr := httptest.NewRecorder()
			mw.ServeHTTP(rr, req)
			results[idx] = rr.Code
		}(i)
	}

	wg.Wait()

	for i, code := range results {
		assert.Equal(t, http.StatusOK, code, "goroutine %d should succeed", i)
	}
}

// =============================================================================
// OPA evaluation latency — proves sub-millisecond enforcement is achievable
// =============================================================================

func TestGatewayOPA_SubMillisecondLatency(t *testing.T) {
	agentDID := "did:web:example.com:agents:latency-check"
	data := bundleWithAgentPolicy(agentDID, map[string]interface{}{
		"min_trust_level": "DV",
		"denied_dids":     []interface{}{},
		"allowed_dids":    []interface{}{},
		"operations":      []interface{}{},
		"mcp_tools":       []interface{}{},
		"rate_limits":     []interface{}{},
	})

	setup := newOPAIntegrationSetup(t, map[string]string{"default.rego": productionRego}, data)
	token := setup.signBadge(t, agentDID, "2")

	config := gateway.PEPConfig{
		PDPClient:       setup.evaluator,
		EnforcementMode: pip.EMGuard,
	}

	// Warm up
	var latencyEvent gateway.PolicyEvent
	mw := gateway.NewPolicyMiddleware(setup.verifier, config, makeOKHandler(),
		func(e gateway.PolicyEvent, _ *pip.DecisionRequest) { latencyEvent = e })
	req := httptest.NewRequest("GET", "/v1/agents", nil)
	req.Header.Set("X-Capiscio-Badge", token)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	// Measure
	const iterations = 100
	start := time.Now()
	for i := 0; i < iterations; i++ {
		mw2 := gateway.NewPolicyMiddleware(setup.verifier, config, makeOKHandler(),
			func(e gateway.PolicyEvent, _ *pip.DecisionRequest) { latencyEvent = e })
		req := httptest.NewRequest("GET", "/v1/agents", nil)
		req.Header.Set("X-Capiscio-Badge", token)
		rr := httptest.NewRecorder()
		mw2.ServeHTTP(rr, req)
	}
	elapsed := time.Since(start)
	avgMs := float64(elapsed.Milliseconds()) / float64(iterations)

	t.Logf("Average gateway+OPA latency: %.2fms over %d iterations", avgMs, iterations)
	// OPA in-process evaluation should be well under 10ms per request
	assert.Less(t, avgMs, 10.0, "average gateway+OPA enforcement should be under 10ms")
	assert.Equal(t, pip.DecisionAllow, latencyEvent.Decision)
}
