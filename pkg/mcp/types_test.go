package mcp

import (
	"testing"
)

func TestDecisionString(t *testing.T) {
	tests := []struct {
		decision Decision
		expected string
	}{
		{DecisionUnspecified, "UNSPECIFIED"},
		{DecisionAllow, "ALLOW"},
		{DecisionDeny, "DENY"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.decision.String(); got != tt.expected {
				t.Errorf("Decision.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAuthLevelString(t *testing.T) {
	tests := []struct {
		level    AuthLevel
		expected string
	}{
		{AuthLevelUnspecified, "UNSPECIFIED"},
		{AuthLevelAnonymous, "ANONYMOUS"},
		{AuthLevelAPIKey, "API_KEY"},
		{AuthLevelBadge, "BADGE"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.level.String(); got != tt.expected {
				t.Errorf("AuthLevel.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestServerStateString(t *testing.T) {
	tests := []struct {
		state    ServerState
		expected string
	}{
		{ServerStateUnspecified, "UNSPECIFIED"},
		{ServerStateVerifiedPrincipal, "VERIFIED_PRINCIPAL"},
		{ServerStateDeclaredPrincipal, "DECLARED_PRINCIPAL"},
		{ServerStateUnverifiedOrigin, "UNVERIFIED_ORIGIN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.state.String(); got != tt.expected {
				t.Errorf("ServerState.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNewBadgeCredential(t *testing.T) {
	cred := NewBadgeCredential("eyJhbGc...")
	if cred.BadgeJWS != "eyJhbGc..." {
		t.Errorf("BadgeJWS = %v, want eyJhbGc...", cred.BadgeJWS)
	}
	if cred.APIKey != "" {
		t.Error("APIKey should be empty")
	}
	if cred.IsAnonymous {
		t.Error("IsAnonymous should be false")
	}
}

func TestNewAPIKeyCredential(t *testing.T) {
	cred := NewAPIKeyCredential("api-key-123")
	if cred.APIKey != "api-key-123" {
		t.Errorf("APIKey = %v, want api-key-123", cred.APIKey)
	}
	if cred.BadgeJWS != "" {
		t.Error("BadgeJWS should be empty")
	}
	if cred.IsAnonymous {
		t.Error("IsAnonymous should be false")
	}
}

func TestNewAnonymousCredential(t *testing.T) {
	cred := NewAnonymousCredential()
	if cred.BadgeJWS != "" {
		t.Error("BadgeJWS should be empty")
	}
	if cred.APIKey != "" {
		t.Error("APIKey should be empty")
	}
	if !cred.IsAnonymous {
		t.Error("IsAnonymous should be true")
	}
}

func TestCallerCredential_GetAuthLevel(t *testing.T) {
	tests := []struct {
		name     string
		cred     CallerCredential
		expected AuthLevel
	}{
		{
			name:     "badge credential",
			cred:     NewBadgeCredential("eyJhbGc..."),
			expected: AuthLevelBadge,
		},
		{
			name:     "api key credential",
			cred:     NewAPIKeyCredential("api-key-123"),
			expected: AuthLevelAPIKey,
		},
		{
			name:     "anonymous credential",
			cred:     NewAnonymousCredential(),
			expected: AuthLevelAnonymous,
		},
		{
			name:     "empty credential",
			cred:     CallerCredential{},
			expected: AuthLevelAnonymous,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cred.GetAuthLevel(); got != tt.expected {
				t.Errorf("GetAuthLevel() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEvaluateConfig_Defaults(t *testing.T) {
	config := EvaluateConfig{}

	if config.MinTrustLevel != 0 {
		t.Errorf("MinTrustLevel = %v, want 0", config.MinTrustLevel)
	}
	if config.AcceptLevelZero {
		t.Error("AcceptLevelZero should be false by default")
	}
	if config.TrustedIssuers != nil {
		t.Error("TrustedIssuers should be nil by default")
	}
	if config.AllowedTools != nil {
		t.Error("AllowedTools should be nil by default")
	}
}

func TestVerifyConfig_DefaultsFunction(t *testing.T) {
	config := DefaultVerifyConfig()

	if config.RequireOriginBinding != true {
		t.Error("RequireOriginBinding should be true by default")
	}
	if len(config.AllowedDIDMethods) != 2 {
		t.Errorf("AllowedDIDMethods = %v, want [web, key]", config.AllowedDIDMethods)
	}
}

func TestEvaluateResult_Allow(t *testing.T) {
	result := EvaluateResult{
		Decision:   DecisionAllow,
		AgentDID:   "did:web:example.com:agents:test",
		TrustLevel: 2,
		AuthLevel:  AuthLevelBadge,
	}

	if result.Decision != DecisionAllow {
		t.Errorf("Decision = %v, want ALLOW", result.Decision)
	}
	if result.DenyReason != DenyReasonUnspecified {
		t.Error("DenyReason should be unspecified for allow")
	}
}

func TestEvaluateResult_Deny(t *testing.T) {
	result := EvaluateResult{
		Decision:   DecisionDeny,
		DenyReason: DenyReasonTrustInsufficient,
		DenyDetail: "trust level 1 below minimum 2",
	}

	if result.Decision != DecisionDeny {
		t.Errorf("Decision = %v, want DENY", result.Decision)
	}
	if result.DenyReason != DenyReasonTrustInsufficient {
		t.Errorf("DenyReason = %v, want TRUST_INSUFFICIENT", result.DenyReason)
	}
}

func TestVerifyResult_Verified(t *testing.T) {
	result := VerifyResult{
		State:    ServerStateVerifiedPrincipal,
		ServerID: "did:web:mcp.example.com:servers:fs",
	}

	if result.State != ServerStateVerifiedPrincipal {
		t.Errorf("State = %v, want VERIFIED_PRINCIPAL", result.State)
	}
	if !result.IsVerified() {
		t.Error("IsVerified() should return true")
	}
	if result.ServerID != "did:web:mcp.example.com:servers:fs" {
		t.Errorf("ServerID = %v, want did:web:mcp.example.com:servers:fs", result.ServerID)
	}
}

func TestVerifyResult_Unverified(t *testing.T) {
	result := VerifyResult{
		State:       ServerStateUnverifiedOrigin,
		ErrorCode:   ServerErrorCodeBadgeInvalid,
		ErrorDetail: "badge verification failed",
	}

	if result.State != ServerStateUnverifiedOrigin {
		t.Errorf("State = %v, want UNVERIFIED_ORIGIN", result.State)
	}
	if result.IsVerified() {
		t.Error("IsVerified() should return false")
	}
}

func TestParsedIdentity(t *testing.T) {
	tests := []struct {
		name            string
		identity        ParsedIdentity
		expectServerDID string
		expectBadge     string
	}{
		{
			name: "with DID and badge",
			identity: ParsedIdentity{
				ServerDID:      "did:web:example.com:servers:myserver",
				ServerBadgeJWS: "eyJhbGciOiJFZERTQSJ9.claims.signature",
			},
			expectServerDID: "did:web:example.com:servers:myserver",
			expectBadge:     "eyJhbGciOiJFZERTQSJ9.claims.signature",
		},
		{
			name:            "empty identity",
			identity:        ParsedIdentity{},
			expectServerDID: "",
			expectBadge:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.identity.ServerDID != tt.expectServerDID {
				t.Errorf("ServerDID = %v, want %v", tt.identity.ServerDID, tt.expectServerDID)
			}
			if tt.identity.ServerBadgeJWS != tt.expectBadge {
				t.Errorf("ServerBadgeJWS = %v, want %v", tt.identity.ServerBadgeJWS, tt.expectBadge)
			}
		})
	}
}
