package pip

import (
	"encoding/json"
	"testing"
)

func TestDecisionRequestSerialization(t *testing.T) {
	pepID := "pep-1"
	ts := "2026-03-20T12:00:00Z"

	req := DecisionRequest{
		PIPVersion: PIPVersion,
		Subject: SubjectAttributes{
			DID:        "did:web:registry.capisc.io:agents:test-agent",
			BadgeJTI:   "badge-jti-123",
			IAL:        "1",
			TrustLevel: "2",
		},
		Action: ActionAttributes{
			CapabilityClass: nil, // badge-only
			Operation:       "GET /v1/agents/{agentId}",
		},
		Resource: ResourceAttributes{
			Identifier: "/v1/agents/abc-123",
		},
		Context: ContextAttributes{
			TxnID:             "019471a2-0000-7000-8000-000000000001",
			HopID:             nil,
			EnvelopeID:        nil,
			DelegationDepth:   nil,
			Constraints:       nil, // json.RawMessage nil → JSON null
			ParentConstraints: nil,
			EnforcementMode:   "EM-OBSERVE",
		},
		Environment: EnvironmentAttrs{
			PEPID: &pepID,
			Time:  &ts,
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Verify roundtrip
	var decoded DecisionRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.PIPVersion != PIPVersion {
		t.Errorf("pip_version = %q, want %q", decoded.PIPVersion, PIPVersion)
	}
	if decoded.Subject.DID != req.Subject.DID {
		t.Errorf("subject.did = %q, want %q", decoded.Subject.DID, req.Subject.DID)
	}
	if decoded.Action.CapabilityClass != nil {
		t.Errorf("action.capability_class = %v, want nil", decoded.Action.CapabilityClass)
	}
	if decoded.Context.EnforcementMode != "EM-OBSERVE" {
		t.Errorf("context.enforcement_mode = %q, want %q", decoded.Context.EnforcementMode, "EM-OBSERVE")
	}
}

func TestNullEnvelopeFieldsSerialization(t *testing.T) {
	// Badge-only mode: envelope-sourced fields MUST serialize as JSON null, not be absent.
	ctx := ContextAttributes{
		TxnID:             "txn-123",
		EnforcementMode:   "EM-OBSERVE",
		Constraints:       nil,
		ParentConstraints: nil,
	}

	data, err := json.Marshal(ctx)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Parse as generic map to check key presence
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal to map failed: %v", err)
	}

	// These fields MUST be present with value null (not absent)
	for _, key := range []string{"constraints", "parent_constraints", "envelope_id", "delegation_depth", "hop_id"} {
		val, exists := raw[key]
		if !exists {
			t.Errorf("field %q absent from JSON — MUST be present with null value", key)
			continue
		}
		if string(val) != "null" {
			t.Errorf("field %q = %s, want null", key, string(val))
		}
	}
}

func TestDecisionResponseSerialization(t *testing.T) {
	ttl := 300
	resp := DecisionResponse{
		Decision:   DecisionAllow,
		DecisionID: "decision-abc-123",
		Obligations: []Obligation{
			{
				Type:   "rate_limit",
				Params: json.RawMessage(`{"max_rps": 100}`),
			},
		},
		Reason: "trust level sufficient",
		TTL:    &ttl,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded DecisionResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Decision != DecisionAllow {
		t.Errorf("decision = %q, want %q", decoded.Decision, DecisionAllow)
	}
	if decoded.DecisionID != "decision-abc-123" {
		t.Errorf("decision_id = %q, want %q", decoded.DecisionID, "decision-abc-123")
	}
	if len(decoded.Obligations) != 1 {
		t.Fatalf("obligations count = %d, want 1", len(decoded.Obligations))
	}
	if decoded.Obligations[0].Type != "rate_limit" {
		t.Errorf("obligations[0].type = %q, want %q", decoded.Obligations[0].Type, "rate_limit")
	}
	if decoded.TTL == nil || *decoded.TTL != 300 {
		t.Errorf("ttl = %v, want 300", decoded.TTL)
	}
}

func TestDecisionResponseEmptyObligations(t *testing.T) {
	resp := DecisionResponse{
		Decision:    DecisionDeny,
		DecisionID:  "deny-123",
		Obligations: []Obligation{},
		Reason:      "policy denied",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded DecisionResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Obligations == nil {
		t.Error("obligations is nil after decode, want empty slice")
	}
	if len(decoded.Obligations) != 0 {
		t.Errorf("obligations count = %d, want 0", len(decoded.Obligations))
	}
}

func TestValidDecision(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{DecisionAllow, true},
		{DecisionDeny, true},
		{DecisionObserve, false}, // ALLOW_OBSERVE is PEP-only, not a valid PDP response
		{"allow", false},         // case-sensitive
		{"DENY ", false},         // trailing space
		{"", false},
	}

	for _, tt := range tests {
		got := ValidDecision(tt.input)
		if got != tt.valid {
			t.Errorf("ValidDecision(%q) = %v, want %v", tt.input, got, tt.valid)
		}
	}
}

func TestObligationParamsRawMessage(t *testing.T) {
	// Obligation.Params is json.RawMessage — should pass through opaquely
	o := Obligation{
		Type:   "enhanced_logging",
		Params: json.RawMessage(`{"fields": ["request_body", "response_body"], "retention_days": 90}`),
	}

	data, err := json.Marshal(o)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded Obligation
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Type != "enhanced_logging" {
		t.Errorf("type = %q, want %q", decoded.Type, "enhanced_logging")
	}

	// Verify params survived roundtrip
	var params map[string]interface{}
	if err := json.Unmarshal(decoded.Params, &params); err != nil {
		t.Fatalf("Unmarshal params failed: %v", err)
	}
	if params["retention_days"].(float64) != 90 {
		t.Errorf("retention_days = %v, want 90", params["retention_days"])
	}
}

func TestObligationNullParams(t *testing.T) {
	o := Obligation{
		Type:   "simple_log",
		Params: nil,
	}

	data, err := json.Marshal(o)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Params should serialize as null
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal to map failed: %v", err)
	}
	if string(raw["params"]) != "null" {
		t.Errorf("params = %s, want null", string(raw["params"]))
	}
}
