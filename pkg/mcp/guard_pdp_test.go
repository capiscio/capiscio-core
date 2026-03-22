package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"testing"

	"github.com/capiscio/capiscio-core/v2/pkg/pip"
)

// --- Mock PDP for Guard tests ---

type guardMockPDP struct {
	resp *pip.DecisionResponse
	err  error
	mu   sync.Mutex
	reqs []*pip.DecisionRequest
}

func (m *guardMockPDP) Evaluate(_ context.Context, req *pip.DecisionRequest) (*pip.DecisionResponse, error) {
	m.mu.Lock()
	m.reqs = append(m.reqs, req)
	m.mu.Unlock()
	return m.resp, m.err
}

func (m *guardMockPDP) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.reqs)
}

func (m *guardMockPDP) lastRequest() *pip.DecisionRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.reqs) == 0 {
		return nil
	}
	return m.reqs[len(m.reqs)-1]
}

type guardMockOblHandler struct {
	supported string
	err       error
}

func (h *guardMockOblHandler) Handle(_ context.Context, _ pip.Obligation) error {
	return h.err
}

func (h *guardMockOblHandler) Supports(t string) bool {
	return t == h.supported
}

// --- PDP Integration Tests ---

func TestGuard_WithPDP_Allow(t *testing.T) {
	pdp := &guardMockPDP{
		resp: &pip.DecisionResponse{
			Decision:   pip.DecisionAllow,
			DecisionID: "pdp-allow-001",
		},
	}

	guard := NewGuard(nil, nil,
		WithPDPClient(pdp),
		WithEnforcementMode(pip.EMDelegate),
	)

	result, err := guard.EvaluateToolAccess(
		context.Background(),
		"read_file",
		"sha256:abc123",
		"https://example.com",
		NewAnonymousCredential(),
		&EvaluateConfig{},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != DecisionAllow {
		t.Errorf("Decision = %v, want ALLOW", result.Decision)
	}
	if result.PolicyDecisionID != "pdp-allow-001" {
		t.Errorf("PolicyDecisionID = %q, want %q", result.PolicyDecisionID, "pdp-allow-001")
	}
	if result.PolicyDecision != pip.DecisionAllow {
		t.Errorf("PolicyDecision = %q, want %q", result.PolicyDecision, pip.DecisionAllow)
	}
	if pdp.callCount() != 1 {
		t.Errorf("PDP call count = %d, want 1", pdp.callCount())
	}

	// Verify PIP request structure
	pipReq := pdp.lastRequest()
	if pipReq.PIPVersion != pip.PIPVersion {
		t.Errorf("PIPVersion = %q, want %q", pipReq.PIPVersion, pip.PIPVersion)
	}
	if pipReq.Action.Operation != "read_file" {
		t.Errorf("Action.Operation = %q, want %q", pipReq.Action.Operation, "read_file")
	}
	if pipReq.Action.MCPTool == nil || *pipReq.Action.MCPTool != "read_file" {
		t.Errorf("Action.MCPTool = %v, want %q", pipReq.Action.MCPTool, "read_file")
	}
	if pipReq.Context.EnforcementMode != pip.EMDelegate.String() {
		t.Errorf("EM = %q, want %q", pipReq.Context.EnforcementMode, pip.EMDelegate.String())
	}
	if pipReq.Context.TxnID == "" {
		t.Error("TxnID should be generated")
	}
}

func TestGuard_WithPDP_Deny(t *testing.T) {
	pdp := &guardMockPDP{
		resp: &pip.DecisionResponse{
			Decision:   pip.DecisionDeny,
			DecisionID: "pdp-deny-001",
			Reason:     "tool not permitted by policy",
		},
	}

	tests := []struct {
		name           string
		mode           pip.EnforcementMode
		wantDecision   Decision
		wantPolicy     string
	}{
		{"EM-OBSERVE allows through", pip.EMObserve, DecisionAllow, pip.DecisionObserve},
		{"EM-GUARD blocks", pip.EMGuard, DecisionDeny, pip.DecisionDeny},
		{"EM-DELEGATE blocks", pip.EMDelegate, DecisionDeny, pip.DecisionDeny},
		{"EM-STRICT blocks", pip.EMStrict, DecisionDeny, pip.DecisionDeny},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			guard := NewGuard(nil, nil,
				WithPDPClient(pdp),
				WithEnforcementMode(tc.mode),
			)

			result, err := guard.EvaluateToolAccess(
				context.Background(),
				"dangerous_tool",
				"sha256:xyz",
				"https://example.com",
				NewAnonymousCredential(),
				&EvaluateConfig{},
			)

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Decision != tc.wantDecision {
				t.Errorf("Decision = %v, want %v", result.Decision, tc.wantDecision)
			}
			if result.PolicyDecision != tc.wantPolicy {
				t.Errorf("PolicyDecision = %q, want %q", result.PolicyDecision, tc.wantPolicy)
			}
		})
	}
}

func TestGuard_WithPDP_Unavailable(t *testing.T) {
	pdp := &guardMockPDP{
		err: fmt.Errorf("connection refused"),
	}

	tests := []struct {
		name         string
		mode         pip.EnforcementMode
		wantDecision Decision
		wantPolicy   string
	}{
		{"EM-OBSERVE allows on PDP unavailable", pip.EMObserve, DecisionAllow, pip.DecisionObserve},
		{"EM-GUARD fails closed", pip.EMGuard, DecisionDeny, pip.DecisionDeny},
		{"EM-DELEGATE fails closed", pip.EMDelegate, DecisionDeny, pip.DecisionDeny},
		{"EM-STRICT fails closed", pip.EMStrict, DecisionDeny, pip.DecisionDeny},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			guard := NewGuard(nil, nil,
				WithPDPClient(pdp),
				WithEnforcementMode(tc.mode),
			)

			result, err := guard.EvaluateToolAccess(
				context.Background(),
				"read_file",
				"sha256:abc",
				"https://example.com",
				NewAnonymousCredential(),
				&EvaluateConfig{},
			)

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Decision != tc.wantDecision {
				t.Errorf("Decision = %v, want %v", result.Decision, tc.wantDecision)
			}
			if result.PolicyDecision != tc.wantPolicy {
				t.Errorf("PolicyDecision = %q, want %q", result.PolicyDecision, tc.wantPolicy)
			}
			if result.PolicyDecisionID != "pdp-unavailable" {
				t.Errorf("PolicyDecisionID = %q, want %q", result.PolicyDecisionID, "pdp-unavailable")
			}
		})
	}
}

func TestGuard_WithPDP_SkipsInlinePolicy(t *testing.T) {
	// When PDP is configured, inline policy (trust level + allowed tools) is skipped.
	// Even if inline policy would DENY, PDP's ALLOW is authoritative.
	// NOTE: Authentication (badge required) still runs before PDP — only
	// the authorization checks (trust level comparison, tool allowlist) are replaced.
	pdp := &guardMockPDP{
		resp: &pip.DecisionResponse{
			Decision:   pip.DecisionAllow,
			DecisionID: "pdp-override-inline",
		},
	}

	guard := NewGuard(nil, nil,
		WithPDPClient(pdp),
		WithEnforcementMode(pip.EMDelegate),
	)

	result, err := guard.EvaluateToolAccess(
		context.Background(),
		"forbidden_tool", // would be denied by inline AllowedTools
		"sha256:xyz",
		"https://example.com",
		NewAnonymousCredential(),
		&EvaluateConfig{
			AcceptLevelZero: true,                   // let anonymous pass authentication
			MinTrustLevel:   3,                      // inline would deny (trust 0 < 3)
			AllowedTools:    []string{"safe_tool_*"}, // forbidden_tool not in allowed list
		},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != DecisionAllow {
		t.Errorf("Decision = %v, want ALLOW (PDP should override inline policy)", result.Decision)
	}
	if pdp.callCount() != 1 {
		t.Errorf("PDP should have been called once, got %d", pdp.callCount())
	}
}

func TestGuard_WithPDP_AuthStillRequired(t *testing.T) {
	// Even with PDP, authentication failures (badge required but missing)
	// are enforced BEFORE the PDP is consulted.
	pdp := &guardMockPDP{
		resp: &pip.DecisionResponse{
			Decision:   pip.DecisionAllow,
			DecisionID: "should-not-be-called",
		},
	}

	guard := NewGuard(nil, nil,
		WithPDPClient(pdp),
		WithEnforcementMode(pip.EMDelegate),
	)

	result, err := guard.EvaluateToolAccess(
		context.Background(),
		"any_tool",
		"sha256:xyz",
		"https://example.com",
		NewAnonymousCredential(),
		&EvaluateConfig{
			MinTrustLevel:   1,     // requires badge
			AcceptLevelZero: false, // anonymous NOT accepted
		},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != DecisionDeny {
		t.Errorf("Decision = %v, want DENY (auth should block before PDP)", result.Decision)
	}
	if result.DenyReason != DenyReasonBadgeMissing {
		t.Errorf("DenyReason = %v, want BADGE_MISSING", result.DenyReason)
	}
	if pdp.callCount() != 0 {
		t.Errorf("PDP should NOT have been called, got %d", pdp.callCount())
	}
}

func TestGuard_WithPDP_ObligationsSucceed(t *testing.T) {
	pdp := &guardMockPDP{
		resp: &pip.DecisionResponse{
			Decision:    pip.DecisionAllow,
			DecisionID:  "obl-ok-001",
			Obligations: []pip.Obligation{{Type: "rate_limit", Params: json.RawMessage(`{}`)}},
		},
	}

	reg := pip.NewObligationRegistry(slog.Default())
	reg.Register(&guardMockOblHandler{supported: "rate_limit"})

	guard := NewGuard(nil, nil,
		WithPDPClient(pdp),
		WithEnforcementMode(pip.EMStrict),
		WithObligationRegistry(reg),
	)

	result, err := guard.EvaluateToolAccess(
		context.Background(),
		"tool_with_obligations",
		"sha256:abc",
		"https://example.com",
		NewAnonymousCredential(),
		&EvaluateConfig{},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != DecisionAllow {
		t.Errorf("Decision = %v, want ALLOW", result.Decision)
	}
}

func TestGuard_WithPDP_ObligationFailureInStrict(t *testing.T) {
	pdp := &guardMockPDP{
		resp: &pip.DecisionResponse{
			Decision:    pip.DecisionAllow,
			DecisionID:  "obl-fail-001",
			Obligations: []pip.Obligation{{Type: "rate_limit", Params: json.RawMessage(`{}`)}},
		},
	}

	reg := pip.NewObligationRegistry(slog.Default())
	reg.Register(&guardMockOblHandler{supported: "rate_limit", err: fmt.Errorf("rate exceeded")})

	guard := NewGuard(nil, nil,
		WithPDPClient(pdp),
		WithEnforcementMode(pip.EMStrict),
		WithObligationRegistry(reg),
	)

	result, err := guard.EvaluateToolAccess(
		context.Background(),
		"tool_with_obligations",
		"sha256:abc",
		"https://example.com",
		NewAnonymousCredential(),
		&EvaluateConfig{},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != DecisionDeny {
		t.Errorf("Decision = %v, want DENY (obligation failure in EM-STRICT)", result.Decision)
	}
	if result.DenyReason != DenyReasonPolicyDenied {
		t.Errorf("DenyReason = %v, want POLICY_DENIED", result.DenyReason)
	}
}

func TestGuard_WithPDP_UnknownObligationInStrict(t *testing.T) {
	pdp := &guardMockPDP{
		resp: &pip.DecisionResponse{
			Decision:    pip.DecisionAllow,
			DecisionID:  "obl-unknown-001",
			Obligations: []pip.Obligation{{Type: "unknown_type", Params: json.RawMessage(`{}`)}},
		},
	}

	reg := pip.NewObligationRegistry(slog.Default())
	// No handler registered for "unknown_type"

	guard := NewGuard(nil, nil,
		WithPDPClient(pdp),
		WithEnforcementMode(pip.EMStrict),
		WithObligationRegistry(reg),
	)

	result, err := guard.EvaluateToolAccess(
		context.Background(),
		"tool_unknown_obl",
		"sha256:abc",
		"https://example.com",
		NewAnonymousCredential(),
		&EvaluateConfig{},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != DecisionDeny {
		t.Errorf("Decision = %v, want DENY (unknown obligation in EM-STRICT)", result.Decision)
	}
}

func TestGuard_NoPDP_InlinePolicyStillWorks(t *testing.T) {
	// When no PDP is configured, inline policy should function as before
	guard := NewGuard(nil, nil) // no PDP, no options

	t.Run("trust level check", func(t *testing.T) {
		result, err := guard.EvaluateToolAccess(
			context.Background(),
			"read_tool",
			"sha256:abc",
			"https://example.com",
			NewAnonymousCredential(),
			&EvaluateConfig{
				MinTrustLevel:   2,
				AcceptLevelZero: true,
			},
		)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Decision != DecisionDeny {
			t.Errorf("Decision = %v, want DENY (trust level 0 < min 2)", result.Decision)
		}
		if result.DenyReason != DenyReasonTrustInsufficient {
			t.Errorf("DenyReason = %v, want TRUST_INSUFFICIENT", result.DenyReason)
		}
	})

	t.Run("allowed tools check", func(t *testing.T) {
		result, err := guard.EvaluateToolAccess(
			context.Background(),
			"forbidden_tool",
			"sha256:abc",
			"https://example.com",
			NewAnonymousCredential(),
			&EvaluateConfig{
				AllowedTools: []string{"safe_*"},
			},
		)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Decision != DecisionDeny {
			t.Errorf("Decision = %v, want DENY", result.Decision)
		}
		if result.DenyReason != DenyReasonToolNotAllowed {
			t.Errorf("DenyReason = %v, want TOOL_NOT_ALLOWED", result.DenyReason)
		}
	})

	t.Run("allowed tool pattern matches", func(t *testing.T) {
		result, err := guard.EvaluateToolAccess(
			context.Background(),
			"safe_read",
			"sha256:abc",
			"https://example.com",
			NewAnonymousCredential(),
			&EvaluateConfig{
				AllowedTools: []string{"safe_*"},
			},
		)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Decision != DecisionAllow {
			t.Errorf("Decision = %v, want ALLOW", result.Decision)
		}
	})
}

func TestGuard_WithPDP_EvidenceAlwaysEmitted(t *testing.T) {
	// Evidence should be emitted for both ALLOW and DENY via PDP
	pdp := &guardMockPDP{
		resp: &pip.DecisionResponse{
			Decision:   pip.DecisionDeny,
			DecisionID: "evidence-deny-001",
			Reason:     "denied by policy",
		},
	}

	guard := NewGuard(nil, nil,
		WithPDPClient(pdp),
		WithEnforcementMode(pip.EMStrict),
	)

	result, err := guard.EvaluateToolAccess(
		context.Background(),
		"risky_tool",
		"sha256:abc",
		"https://example.com",
		NewAnonymousCredential(),
		&EvaluateConfig{},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != DecisionDeny {
		t.Errorf("Decision = %v, want DENY", result.Decision)
	}
	if result.EvidenceJSON == "" {
		t.Error("EvidenceJSON should not be empty even for DENY")
	}
	if result.EvidenceID == "" {
		t.Error("EvidenceID should not be empty")
	}
}

func TestGuard_WithGuardLogger(t *testing.T) {
	logger := slog.Default()

	guard := NewGuard(nil, nil, WithGuardLogger(logger))

	result, err := guard.EvaluateToolAccess(
		context.Background(),
		"test_tool",
		"sha256:abc",
		"https://example.com",
		NewAnonymousCredential(),
		&EvaluateConfig{},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != DecisionAllow {
		t.Errorf("Decision = %v, want ALLOW", result.Decision)
	}
}
