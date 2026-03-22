//go:build opa_no_wasm

package pdp

import (
	"context"
	"testing"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/pip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Simple Rego policy that always allows.
const regoAlwaysAllow = `package capiscio.policy

default decision = "ALLOW"

reason = "default allow policy"

obligations = []
`

// Rego policy that denies specific DID.
const regoDenySpecificDID = `package capiscio.policy

default decision = "ALLOW"

decision = "DENY" if {
	input.subject.did == "did:web:blocked-agent"
}

reason = "blocked by policy" if {
	input.subject.did == "did:web:blocked-agent"
}

reason = "allowed" if {
	input.subject.did != "did:web:blocked-agent"
}

obligations = []
`

// Rego policy that checks trust level and returns obligations.
const regoWithObligations = `package capiscio.policy

default decision = "ALLOW"

decision = "DENY" if {
	input.subject.trust_level == "untrusted"
}

reason = "untrusted agent" if {
	input.subject.trust_level == "untrusted"
}

reason = "allowed with logging" if {
	input.subject.trust_level != "untrusted"
}

obligations = [{"type": "log_decision", "params": {"level": "info"}}] if {
	input.subject.trust_level != "untrusted"
}

obligations = [] if {
	input.subject.trust_level == "untrusted"
}
`

// Rego policy that uses data document for DID lookup.
const regoWithDataLookup = `package capiscio.policy

import rego.v1

default decision = "DENY"

decision = "ALLOW" if {
	some agent in data.agents
	agent.did == input.subject.did
}

reason = "agent found in registry" if {
	some agent in data.agents
	agent.did == input.subject.did
}

reason = "agent not in registry" if {
	not agent_registered
}

agent_registered if {
	some agent in data.agents
	agent.did == input.subject.did
}

obligations = []
`

// Rego policy that checks MCP tool name.
const regoMCPToolCheck = `package capiscio.policy

import rego.v1

default decision = "ALLOW"

decision = "DENY" if {
	input.action.mcp_tool == "dangerous_tool"
}

reason = "tool blocked" if {
	input.action.mcp_tool == "dangerous_tool"
}

reason = "tool allowed" if {
	not tool_blocked
}

tool_blocked if {
	input.action.mcp_tool == "dangerous_tool"
}

obligations = []
`

func newTestRequest() *pip.DecisionRequest {
	return &pip.DecisionRequest{
		PIPVersion: pip.PIPVersion,
		Subject: pip.SubjectAttributes{
			DID:        "did:web:test-agent",
			BadgeJTI:   "jti-123",
			IAL:        "ial-2",
			TrustLevel: "verified",
		},
		Action: pip.ActionAttributes{
			Operation: "read",
		},
		Resource: pip.ResourceAttributes{
			Identifier: "resource:test",
		},
		Context: pip.ContextAttributes{
			TxnID:           "txn-001",
			EnforcementMode: "EM-OBSERVE",
		},
	}
}

func TestOPALocalClient_EvaluateAllowPolicy(t *testing.T) {
	client := NewOPALocalClient()

	modules := map[string]string{"policy.rego": regoAlwaysAllow}
	err := client.LoadBundle(context.Background(), modules, nil)
	require.NoError(t, err)

	resp, err := client.Evaluate(context.Background(), newTestRequest())
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionAllow, resp.Decision)
	assert.NotEmpty(t, resp.DecisionID)
	assert.Equal(t, "default allow policy", resp.Reason)
}

func TestOPALocalClient_EvaluateDenyPolicy(t *testing.T) {
	client := NewOPALocalClient()

	modules := map[string]string{"policy.rego": regoDenySpecificDID}
	err := client.LoadBundle(context.Background(), modules, nil)
	require.NoError(t, err)

	req := newTestRequest()
	req.Subject.DID = "did:web:blocked-agent"

	resp, err := client.Evaluate(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionDeny, resp.Decision)
	assert.Equal(t, "blocked by policy", resp.Reason)
}

func TestOPALocalClient_EvaluateAllowedDID(t *testing.T) {
	client := NewOPALocalClient()

	modules := map[string]string{"policy.rego": regoDenySpecificDID}
	err := client.LoadBundle(context.Background(), modules, nil)
	require.NoError(t, err)

	resp, err := client.Evaluate(context.Background(), newTestRequest())
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionAllow, resp.Decision)
	assert.Equal(t, "allowed", resp.Reason)
}

func TestOPALocalClient_EvaluateWithObligations(t *testing.T) {
	client := NewOPALocalClient()

	modules := map[string]string{"policy.rego": regoWithObligations}
	err := client.LoadBundle(context.Background(), modules, nil)
	require.NoError(t, err)

	resp, err := client.Evaluate(context.Background(), newTestRequest())
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionAllow, resp.Decision)
	require.Len(t, resp.Obligations, 1)
	assert.Equal(t, "log_decision", resp.Obligations[0].Type)
}

func TestOPALocalClient_EvaluateWithDataDocument(t *testing.T) {
	client := NewOPALocalClient()

	modules := map[string]string{"policy.rego": regoWithDataLookup}
	data := map[string]interface{}{
		"agents": []interface{}{
			map[string]interface{}{"did": "did:web:test-agent"},
			map[string]interface{}{"did": "did:web:other-agent"},
		},
	}

	err := client.LoadBundle(context.Background(), modules, data)
	require.NoError(t, err)

	// Known agent should be allowed
	resp, err := client.Evaluate(context.Background(), newTestRequest())
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionAllow, resp.Decision)
	assert.Equal(t, "agent found in registry", resp.Reason)

	// Unknown agent should be denied
	req := newTestRequest()
	req.Subject.DID = "did:web:unknown-agent"
	resp, err = client.Evaluate(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionDeny, resp.Decision)
	assert.Equal(t, "agent not in registry", resp.Reason)
}

func TestOPALocalClient_EvaluateMCPToolCheck(t *testing.T) {
	client := NewOPALocalClient()

	modules := map[string]string{"policy.rego": regoMCPToolCheck}
	err := client.LoadBundle(context.Background(), modules, nil)
	require.NoError(t, err)

	// Dangerous tool should be denied
	req := newTestRequest()
	dangerousTool := "dangerous_tool"
	req.Action.MCPTool = &dangerousTool
	resp, err := client.Evaluate(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionDeny, resp.Decision)

	// Safe tool should be allowed
	safeTool := "safe_tool"
	req.Action.MCPTool = &safeTool
	resp, err = client.Evaluate(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionAllow, resp.Decision)
}

func TestOPALocalClient_NoBundleLoaded(t *testing.T) {
	client := NewOPALocalClient()

	_, err := client.Evaluate(context.Background(), newTestRequest())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no policy bundle loaded")
}

func TestOPALocalClient_NilRequest(t *testing.T) {
	client := NewOPALocalClient()

	modules := map[string]string{"policy.rego": regoAlwaysAllow}
	err := client.LoadBundle(context.Background(), modules, nil)
	require.NoError(t, err)

	_, err = client.Evaluate(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil decision request")
}

func TestOPALocalClient_EmptyModules(t *testing.T) {
	client := NewOPALocalClient()

	err := client.LoadBundle(context.Background(), map[string]string{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no rego modules")
}

func TestOPALocalClient_InvalidRego(t *testing.T) {
	client := NewOPALocalClient()

	modules := map[string]string{"bad.rego": "this is not valid rego"}
	err := client.LoadBundle(context.Background(), modules, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "compile policy")
}

func TestOPALocalClient_BundleAge(t *testing.T) {
	client := NewOPALocalClient()

	// No bundle loaded — age is 0
	assert.Equal(t, time.Duration(0), client.BundleAge())
	assert.False(t, client.HasBundle())

	modules := map[string]string{"policy.rego": regoAlwaysAllow}
	err := client.LoadBundle(context.Background(), modules, nil)
	require.NoError(t, err)

	assert.True(t, client.HasBundle())
	assert.Greater(t, client.BundleAge(), time.Duration(0))
}

func TestOPALocalClient_BundleHotSwap(t *testing.T) {
	client := NewOPALocalClient()

	// Load allow-all policy
	modules1 := map[string]string{"policy.rego": regoAlwaysAllow}
	err := client.LoadBundle(context.Background(), modules1, nil)
	require.NoError(t, err)

	req := newTestRequest()
	req.Subject.DID = "did:web:blocked-agent"

	resp, err := client.Evaluate(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionAllow, resp.Decision)

	// Hot-swap to deny policy
	modules2 := map[string]string{"policy.rego": regoDenySpecificDID}
	err = client.LoadBundle(context.Background(), modules2, nil)
	require.NoError(t, err)

	resp, err = client.Evaluate(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionDeny, resp.Decision)
}

func TestOPALocalClient_OptionalInputFields(t *testing.T) {
	client := NewOPALocalClient()

	modules := map[string]string{"policy.rego": regoAlwaysAllow}
	err := client.LoadBundle(context.Background(), modules, nil)
	require.NoError(t, err)

	req := newTestRequest()
	capClass := "compute"
	req.Action.CapabilityClass = &capClass
	hopID := "hop-1"
	req.Context.HopID = &hopID
	envelopeID := "env-1"
	req.Context.EnvelopeID = &envelopeID
	depth := 2
	req.Context.DelegationDepth = &depth
	ws := "ws-1"
	req.Environment.Workspace = &ws
	pepID := "pep-1"
	req.Environment.PEPID = &pepID
	now := time.Now().UTC().Format(time.RFC3339)
	req.Environment.Time = &now

	resp, err := client.Evaluate(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionAllow, resp.Decision)
}

func TestOPALocalClient_ConcurrentEvaluations(t *testing.T) {
	client := NewOPALocalClient()

	modules := map[string]string{"policy.rego": regoAlwaysAllow}
	err := client.LoadBundle(context.Background(), modules, nil)
	require.NoError(t, err)

	const goroutines = 50
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			_, err := client.Evaluate(context.Background(), newTestRequest())
			errs <- err
		}()
	}

	for i := 0; i < goroutines; i++ {
		assert.NoError(t, <-errs)
	}
}

func TestOPALocalClient_ContextCancellation(t *testing.T) {
	client := NewOPALocalClient()

	modules := map[string]string{"policy.rego": regoAlwaysAllow}
	err := client.LoadBundle(context.Background(), modules, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = client.Evaluate(ctx, newTestRequest())
	// Cancelled context may or may not produce an error depending on OPA internals
	// The important thing is it doesn't panic
	_ = err
}

func TestOPALocalClient_ImplementsPDPClient(t *testing.T) {
	// Compile-time check that OPALocalClient implements pip.PDPClient
	var _ pip.PDPClient = (*OPALocalClient)(nil)
}

func TestBuildOPAInput_MinimalRequest(t *testing.T) {
	req := &pip.DecisionRequest{
		PIPVersion: pip.PIPVersion,
		Subject: pip.SubjectAttributes{
			DID:        "did:web:test",
			TrustLevel: "verified",
		},
		Action: pip.ActionAttributes{
			Operation: "read",
		},
		Resource: pip.ResourceAttributes{
			Identifier: "resource:test",
		},
		Context: pip.ContextAttributes{
			TxnID:           "txn-1",
			EnforcementMode: "EM-OBSERVE",
		},
	}

	input := buildOPAInput(req)

	assert.Equal(t, pip.PIPVersion, input["pip_version"], "pip_version must be first-class field")

	subject := input["subject"].(map[string]interface{})
	assert.Equal(t, "did:web:test", subject["did"])

	action := input["action"].(map[string]interface{})
	assert.Equal(t, "read", action["operation"])
	_, hasCapClass := action["capability_class"]
	assert.False(t, hasCapClass, "optional capability_class should not be set")
	_, hasMCPTool := action["mcp_tool"]
	assert.False(t, hasMCPTool, "optional mcp_tool should not be set")
}

func TestBuildOPAInput_AllOptionalFields(t *testing.T) {
	capClass := "compute"
	mcpTool := "my_tool"
	hopID := "hop-1"
	envID := "env-1"
	depth := 3
	ws := "workspace-1"
	pepID := "pep-1"
	now := "2026-03-28T12:00:00Z"

	req := &pip.DecisionRequest{
		PIPVersion: pip.PIPVersion,
		Subject:    pip.SubjectAttributes{DID: "did:web:x"},
		Action: pip.ActionAttributes{
			Operation:       "exec",
			CapabilityClass: &capClass,
			MCPTool:         &mcpTool,
		},
		Resource: pip.ResourceAttributes{Identifier: "res:1"},
		Context: pip.ContextAttributes{
			TxnID:           "txn-1",
			HopID:           &hopID,
			EnvelopeID:      &envID,
			DelegationDepth: &depth,
			EnforcementMode: "EM-GUARD",
		},
		Environment: pip.EnvironmentAttrs{
			Workspace: &ws,
			PEPID:     &pepID,
			Time:      &now,
		},
	}

	input := buildOPAInput(req)

	assert.Equal(t, pip.PIPVersion, input["pip_version"])

	action := input["action"].(map[string]interface{})
	assert.Equal(t, "compute", action["capability_class"])
	assert.Equal(t, "my_tool", action["mcp_tool"])

	ctxMap := input["context"].(map[string]interface{})
	assert.Equal(t, "hop-1", ctxMap["hop_id"])
	assert.Equal(t, "env-1", ctxMap["envelope_id"])
	assert.Equal(t, 3, ctxMap["delegation_depth"])

	env := input["environment"].(map[string]interface{})
	assert.Equal(t, "workspace-1", env["workspace"])
	assert.Equal(t, "pep-1", env["pep_id"])
	assert.Equal(t, "2026-03-28T12:00:00Z", env["time"])
}
