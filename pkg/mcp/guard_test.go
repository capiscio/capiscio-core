package mcp

import (
	"context"
	"testing"
)

func TestGuard_EvaluateToolAccess_AllowAnonymous(t *testing.T) {
	guard := NewGuard(nil, nil)

	result, err := guard.EvaluateToolAccess(
		context.Background(),
		"test_tool",
		"sha256:abc123",
		"https://example.com",
		NewAnonymousCredential(),
		&EvaluateConfig{
			MinTrustLevel:   0, // Allow anonymous
			AcceptLevelZero: true,
		},
	)

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
	if result.EvidenceJSON == "" {
		t.Error("EvidenceJSON should not be empty")
	}
}

func TestGuard_EvaluateToolAccess_DenyAnonymousWhenBadgeRequired(t *testing.T) {
	guard := NewGuard(nil, nil)

	result, err := guard.EvaluateToolAccess(
		context.Background(),
		"test_tool",
		"sha256:abc123",
		"https://example.com",
		NewAnonymousCredential(),
		&EvaluateConfig{
			MinTrustLevel:   1, // Require trust level 1
			AcceptLevelZero: false,
		},
	)

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

func TestGuard_EvaluateToolAccess_DenyInsufficientTrust(t *testing.T) {
	guard := NewGuard(nil, nil)

	result, err := guard.EvaluateToolAccess(
		context.Background(),
		"test_tool",
		"sha256:abc123",
		"https://example.com",
		NewAnonymousCredential(),
		&EvaluateConfig{
			MinTrustLevel:   2, // Require trust level 2
			AcceptLevelZero: true,
		},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != DecisionDeny {
		t.Errorf("Decision = %v, want DENY", result.Decision)
	}
	if result.DenyReason != DenyReasonTrustInsufficient {
		t.Errorf("DenyReason = %v, want TRUST_INSUFFICIENT", result.DenyReason)
	}
}

func TestGuard_EvaluateToolAccess_ToolNotAllowed(t *testing.T) {
	guard := NewGuard(nil, nil)

	result, err := guard.EvaluateToolAccess(
		context.Background(),
		"dangerous_tool",
		"sha256:abc123",
		"https://example.com",
		NewAnonymousCredential(),
		&EvaluateConfig{
			MinTrustLevel:   0,
			AcceptLevelZero: true,
			AllowedTools:    []string{"safe_*", "read_*"}, // Only allow safe_ and read_ tools
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
}

func TestGuard_EvaluateToolAccess_ToolAllowed(t *testing.T) {
	guard := NewGuard(nil, nil)

	result, err := guard.EvaluateToolAccess(
		context.Background(),
		"read_file",
		"sha256:abc123",
		"https://example.com",
		NewAnonymousCredential(),
		&EvaluateConfig{
			MinTrustLevel:   0,
			AcceptLevelZero: true,
			AllowedTools:    []string{"safe_*", "read_*"},
		},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != DecisionAllow {
		t.Errorf("Decision = %v, want ALLOW", result.Decision)
	}
}

func TestGuard_EvaluateToolAccess_EvidenceAlwaysEmitted(t *testing.T) {
	guard := NewGuard(nil, nil)

	// Test ALLOW case
	allowResult, _ := guard.EvaluateToolAccess(
		context.Background(),
		"test_tool",
		"sha256:abc123",
		"https://example.com",
		NewAnonymousCredential(),
		&EvaluateConfig{AcceptLevelZero: true},
	)
	if allowResult.EvidenceJSON == "" {
		t.Error("Evidence should be emitted on ALLOW")
	}

	// Test DENY case
	denyResult, _ := guard.EvaluateToolAccess(
		context.Background(),
		"test_tool",
		"sha256:abc123",
		"https://example.com",
		NewAnonymousCredential(),
		&EvaluateConfig{MinTrustLevel: 2}, // Will deny
	)
	if denyResult.EvidenceJSON == "" {
		t.Error("Evidence should be emitted on DENY")
	}
}

func TestGuard_isToolAllowed(t *testing.T) {
	guard := NewGuard(nil, nil)

	tests := []struct {
		toolName     string
		allowedTools []string
		expected     bool
	}{
		// Exact match
		{"read_file", []string{"read_file"}, true},
		{"write_file", []string{"read_file"}, false},

		// Wildcard patterns
		{"read_file", []string{"read_*"}, true},
		{"read_database", []string{"read_*"}, true},
		{"write_file", []string{"read_*"}, false},

		// Multiple patterns
		{"read_file", []string{"write_*", "read_*"}, true},
		{"delete_all", []string{"write_*", "read_*"}, false},

		// Exact pattern
		{"test", []string{"*"}, true},

		// Empty allowed list
		{"anything", []string{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.toolName, func(t *testing.T) {
			if got := guard.isToolAllowed(tt.toolName, tt.allowedTools); got != tt.expected {
				t.Errorf("isToolAllowed(%q, %v) = %v, want %v",
					tt.toolName, tt.allowedTools, got, tt.expected)
			}
		})
	}
}

func TestGuard_DefaultConfig(t *testing.T) {
	guard := NewGuard(nil, nil)

	// nil config should use defaults
	result, err := guard.EvaluateToolAccess(
		context.Background(),
		"test_tool",
		"sha256:abc123",
		"https://example.com",
		NewAnonymousCredential(),
		nil,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Default config allows anonymous (MinTrustLevel = 0)
	if result.Decision != DecisionAllow {
		t.Errorf("Decision = %v, want ALLOW with default config", result.Decision)
	}
}
