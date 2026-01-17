package mcp

import (
	"context"
	"testing"
)

func TestNewService(t *testing.T) {
	deps := &Dependencies{
		BadgeVerifier: nil,
		EvidenceStore: nil,
	}

	svc := NewService(deps)
	if svc == nil {
		t.Fatal("NewService returned nil")
	}
	if svc.guard == nil {
		t.Error("guard should not be nil")
	}
	if svc.serverVerifier == nil {
		t.Error("serverVerifier should not be nil")
	}
}

func TestService_EvaluateToolAccess_AllowAnonymous(t *testing.T) {
	svc := NewService(&Dependencies{})

	input := &EvaluateToolAccessInput{
		ToolName:   "test_tool",
		ParamsHash: "sha256:abc123",
		Origin:     "https://example.com",
		Credential: NewAnonymousCredential(),
		Config: &EvaluateConfig{
			MinTrustLevel:   0,
			AcceptLevelZero: true,
		},
	}

	result, err := svc.EvaluateToolAccess(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != DecisionAllow {
		t.Errorf("Decision = %v, want ALLOW", result.Decision)
	}
	if result.AuthLevel != AuthLevelAnonymous {
		t.Errorf("AuthLevel = %v, want ANONYMOUS", result.AuthLevel)
	}
	if result.EvidenceID == "" {
		t.Error("EvidenceID should not be empty")
	}
}

func TestService_EvaluateToolAccess_DenyInsufficientTrust(t *testing.T) {
	svc := NewService(&Dependencies{})

	input := &EvaluateToolAccessInput{
		ToolName:   "test_tool",
		ParamsHash: "sha256:abc123",
		Origin:     "https://example.com",
		Credential: NewAnonymousCredential(),
		Config: &EvaluateConfig{
			MinTrustLevel:   2,
			AcceptLevelZero: false,
		},
	}

	result, err := svc.EvaluateToolAccess(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != DecisionDeny {
		t.Errorf("Decision = %v, want DENY", result.Decision)
	}
	if result.DenyReason != DenyReasonBadgeMissing {
		t.Errorf("DenyReason = %v, want BADGE_MISSING", result.DenyReason)
	}
}

func TestService_VerifyServerIdentity_MissingSig(t *testing.T) {
	svc := NewService(&Dependencies{})

	input := &VerifyServerIdentityInput{
		ServerDID:      "did:web:example.com",
		ServerBadgeJWS: "", // Missing
		Origin:         "https://example.com",
	}

	result, err := svc.VerifyServerIdentity(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// RFC-007 §7.2: DID present but no badge → DECLARED_PRINCIPAL
	if result.State != ServerStateDeclaredPrincipal {
		t.Errorf("State = %v, want DECLARED_PRINCIPAL", result.State)
	}
	// No error code for DECLARED_PRINCIPAL - this is a valid state
	if result.ErrorCode != ServerErrorNone {
		t.Errorf("ErrorCode = %v, want NONE", result.ErrorCode)
	}
}

func TestService_ParseServerIdentity_HTTP(t *testing.T) {
	svc := NewService(&Dependencies{})

	// RFC-007 §6.1 compliant header names
	headers := map[string]string{
		"Capiscio-Server-DID":   "did:web:example.com:servers:myserver",
		"Capiscio-Server-Badge": "eyJhbGciOiJFZERTQSJ9.claims.signature",
	}

	result := svc.ParseServerIdentityFromHTTP(headers)
	if result.ServerDID != "did:web:example.com:servers:myserver" {
		t.Errorf("ServerDID = %q, want %q", result.ServerDID, "did:web:example.com:servers:myserver")
	}
	if result.ServerBadgeJWS != "eyJhbGciOiJFZERTQSJ9.claims.signature" {
		t.Errorf("ServerBadgeJWS = %q, want %q", result.ServerBadgeJWS, "eyJhbGciOiJFZERTQSJ9.claims.signature")
	}
}

func TestService_ParseServerIdentity_JSONRPC(t *testing.T) {
	svc := NewService(&Dependencies{})

	// RFC-007 §6.2 compliant field names
	meta := map[string]interface{}{
		"capiscio_server_did":   "did:web:example.com:servers:myserver",
		"capiscio_server_badge": "eyJhbGciOiJFZERTQSJ9.claims.signature",
	}

	result := svc.ParseServerIdentityFromJSONRPC(meta)
	if result.ServerDID != "did:web:example.com:servers:myserver" {
		t.Errorf("ServerDID = %q, want %q", result.ServerDID, "did:web:example.com:servers:myserver")
	}
	if result.ServerBadgeJWS != "eyJhbGciOiJFZERTQSJ9.claims.signature" {
		t.Errorf("ServerBadgeJWS = %q, want %q", result.ServerBadgeJWS, "eyJhbGciOiJFZERTQSJ9.claims.signature")
	}
}

func TestService_Health(t *testing.T) {
	svc := NewService(&Dependencies{})

	input := &HealthInput{
		ClientVersion: "2.5.0",
	}

	result := svc.Health(context.Background(), input)
	if !result.Healthy {
		t.Error("Healthy should be true")
	}
	if result.CoreVersion != CoreVersion {
		t.Errorf("CoreVersion = %q, want %q", result.CoreVersion, CoreVersion)
	}
	if !result.Compatible {
		t.Error("Compatible should be true for 2.5.0")
	}
}

func TestService_Health_IncompatibleVersion(t *testing.T) {
	svc := NewService(&Dependencies{})

	input := &HealthInput{
		ClientVersion: "1.0.0",
	}

	result := svc.Health(context.Background(), input)
	if result.Compatible {
		t.Error("Compatible should be false for 1.0.0")
	}
}
