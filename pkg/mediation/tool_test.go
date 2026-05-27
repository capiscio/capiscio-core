// Copyright (c) CapiscIO, Inc.
// Licensed under the MIT License.

package mediation

import (
	"context"
	"testing"

	"github.com/capiscio/capiscio-core/v2/pkg/badge"
	"github.com/capiscio/capiscio-core/v2/pkg/trust"
)

// newMockMaterialManager creates a MaterialManager that appears bootstrapped for testing.
func newMockMaterialManager() *trust.MaterialManager {
	// Use BootstrapFromBundle which properly sets the bootstrapped flag
	bundle := &trust.TrustMaterial{
		JWKS: map[string]*trust.IssuerKeys{
			"https://registry.capiscio.com": {
				IssuerDID: "https://registry.capiscio.com",
			},
		},
	}
	manager, _ := trust.BootstrapFromBundle(bundle, trust.FreshnessPolicy{})
	return manager
}

func TestToolHook_Mediate(t *testing.T) {
	// Create a mock material manager that reports bootstrapped
	manager := newMockMaterialManager()

	tests := []struct {
		name         string
		config       ToolHookConfig
		mctx         *Context
		request      *ToolRequest
		wantDecision Decision
		wantReason   string
	}{
		{
			name:   "unauthenticated request denied",
			config: ToolHookConfig{},
			mctx: &Context{
				TrustMaterial: manager,
			},
			request: &ToolRequest{
				ToolName: "mcp:github/search",
			},
			wantDecision: DecisionDeny,
			wantReason:   "no valid badge presented",
		},
		{
			name: "insufficient trust level denied",
			config: ToolHookConfig{
				MinTrustLevel: 2,
			},
			mctx: &Context{
				TrustMaterial: manager,
				Badge: &badge.Claims{
					Subject: "did:web:agent.example.com",
					Issuer:  "https://registry.capiscio.com",
					IAL:     "1",
				},
				SubjectDID: "did:web:agent.example.com",
				TrustLevel: 1,
			},
			request: &ToolRequest{
				ToolName: "mcp:github/search",
			},
			wantDecision: DecisionDeny,
			wantReason:   "trust level 1 < required 2",
		},
		{
			name: "tool on denied list",
			config: ToolHookConfig{
				DeniedTools: []string{"mcp:dangerous/*"},
			},
			mctx: &Context{
				TrustMaterial: manager,
				Badge: &badge.Claims{
					Subject: "did:web:agent.example.com",
					IAL:     "2",
				},
				TrustLevel: 2,
			},
			request: &ToolRequest{
				ToolName: "mcp:dangerous/delete_all",
			},
			wantDecision: DecisionDeny,
			wantReason:   `tool "mcp:dangerous/delete_all" is on the denied list`,
		},
		{
			name: "tool on allowed list",
			config: ToolHookConfig{
				AllowedTools: []string{"mcp:safe/*"},
				DefaultDeny:  true, // Even with default deny, allowed list wins
			},
			mctx: &Context{
				TrustMaterial: manager,
				Badge: &badge.Claims{
					Subject: "did:web:agent.example.com",
					IAL:     "1",
				},
				TrustLevel: 1,
			},
			request: &ToolRequest{
				ToolName: "mcp:safe/read",
			},
			wantDecision: DecisionAllow,
			wantReason:   `tool "mcp:safe/read" is on the allowed list`,
		},
		{
			name:   "default allow with valid badge",
			config: ToolHookConfig{}, // DefaultDeny: false
			mctx: &Context{
				TrustMaterial: manager,
				Badge: &badge.Claims{
					Subject: "did:web:agent.example.com",
					IAL:     "2",
				},
				TrustLevel: 2,
			},
			request: &ToolRequest{
				ToolName: "mcp:github/search",
			},
			wantDecision: DecisionAllow,
			wantReason:   `authenticated caller may invoke tool "mcp:github/search"`,
		},
		{
			name: "default deny without capability",
			config: ToolHookConfig{
				DefaultDeny: true,
			},
			mctx: &Context{
				TrustMaterial: manager,
				Badge: &badge.Claims{
					Subject: "did:web:agent.example.com",
					IAL:     "2",
				},
				TrustLevel: 2,
			},
			request: &ToolRequest{
				ToolName: "mcp:github/search",
			},
			wantDecision: DecisionDeny,
			wantReason:   `no explicit grant for tool "mcp:github/search"`,
		},
		{
			name: "envelope required but missing",
			config: ToolHookConfig{
				RequireEnvelope: true,
			},
			mctx: &Context{
				TrustMaterial: manager,
				Badge: &badge.Claims{
					Subject: "did:web:agent.example.com",
					IAL:     "3",
				},
				TrustLevel: 3,
				// No Envelope
			},
			request: &ToolRequest{
				ToolName: "mcp:sensitive/operation",
			},
			wantDecision: DecisionDeny,
			wantReason:   "authority envelope required for tool access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hook := NewToolHook(tt.config)
			result, err := hook.Mediate(context.Background(), tt.mctx, tt.request)
			if err != nil {
				t.Fatalf("Mediate() error = %v", err)
			}

			if result.Decision != tt.wantDecision {
				t.Errorf("Decision = %v, want %v", result.Decision, tt.wantDecision)
			}

			if result.Reason != tt.wantReason {
				t.Errorf("Reason = %q, want %q", result.Reason, tt.wantReason)
			}
		})
	}
}

func TestToolHook_PatternMatching(t *testing.T) {
	hook := NewToolHook(ToolHookConfig{})

	tests := []struct {
		toolName string
		pattern  string
		want     bool
	}{
		// Exact match
		{"mcp:github/search", "mcp:github/search", true},
		{"mcp:github/search", "mcp:github/list", false},

		// Wildcard suffix
		{"mcp:github/search", "mcp:github/*", true},
		{"mcp:github/list", "mcp:github/*", true},
		{"mcp:slack/post", "mcp:github/*", false},

		// Prefix wildcard
		{"mcp:github/search", "mcp:*", true},
		{"function:calculate", "mcp:*", false},

		// Full wildcard
		{"anything", "*", true},
	}

	for _, tt := range tests {
		t.Run(tt.toolName+"_vs_"+tt.pattern, func(t *testing.T) {
			got := hook.matchPattern(tt.toolName, tt.pattern)
			if got != tt.want {
				t.Errorf("matchPattern(%q, %q) = %v, want %v",
					tt.toolName, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestDecisionHelpers(t *testing.T) {
	t.Run("AllowResult", func(t *testing.T) {
		r := AllowResult("policy:test", "allowed by test")
		if !r.IsAllowed() {
			t.Error("AllowResult should return IsAllowed() == true")
		}
		if r.IsDenied() {
			t.Error("AllowResult should return IsDenied() == false")
		}
		if r.Timestamp.IsZero() {
			t.Error("AllowResult should set Timestamp")
		}
	})

	t.Run("DenyResult", func(t *testing.T) {
		r := DenyResult("policy:test", "denied by test")
		if !r.IsDenied() {
			t.Error("DenyResult should return IsDenied() == true")
		}
		if r.IsAllowed() {
			t.Error("DenyResult should return IsAllowed() == false")
		}
	})

	t.Run("DelegateResult", func(t *testing.T) {
		r := DelegateResult("policy:test", "did:web:other.example", "delegating")
		if !r.IsDelegate() {
			t.Error("DelegateResult should return IsDelegate() == true")
		}
		if r.DelegateTarget != "did:web:other.example" {
			t.Errorf("DelegateTarget = %q, want %q",
				r.DelegateTarget, "did:web:other.example")
		}
	})

	t.Run("WithObligation", func(t *testing.T) {
		r := AllowResult("policy:test", "allowed").
			WithObligation("audit:log").
			WithObligation("notify:owner")
		if len(r.Obligations) != 2 {
			t.Errorf("Obligations length = %d, want 2", len(r.Obligations))
		}
	})

	t.Run("WithMetadata", func(t *testing.T) {
		r := AllowResult("policy:test", "allowed").
			WithMetadata("key1", "value1").
			WithMetadata("key2", "value2")
		if len(r.Metadata) != 2 {
			t.Errorf("Metadata length = %d, want 2", len(r.Metadata))
		}
		if r.Metadata["key1"] != "value1" {
			t.Errorf("Metadata[key1] = %q, want %q", r.Metadata["key1"], "value1")
		}
	})
}

func TestContext_Helpers(t *testing.T) {
	t.Run("NewContext", func(t *testing.T) {
		claims := &badge.Claims{
			Subject: "did:web:agent.example.com",
			Issuer:  "https://registry.capiscio.com",
			IAL:     "2",
		}
		ctx := NewContext(nil, claims, nil)

		if ctx.SubjectDID != "did:web:agent.example.com" {
			t.Errorf("SubjectDID = %q, want %q",
				ctx.SubjectDID, "did:web:agent.example.com")
		}
		if ctx.TrustLevel != 2 {
			t.Errorf("TrustLevel = %d, want 2", ctx.TrustLevel)
		}
	})

	t.Run("WithTracing", func(t *testing.T) {
		ctx := NewContext(nil, nil, nil).
			WithTracing("trace-123", "txn-456", "hop-1")

		if ctx.TraceID != "trace-123" {
			t.Errorf("TraceID = %q, want %q", ctx.TraceID, "trace-123")
		}
		if ctx.TxnID != "txn-456" {
			t.Errorf("TxnID = %q, want %q", ctx.TxnID, "txn-456")
		}
		if ctx.HopID != "hop-1" {
			t.Errorf("HopID = %q, want %q", ctx.HopID, "hop-1")
		}
	})

	t.Run("HasBadge", func(t *testing.T) {
		ctx := NewContext(nil, nil, nil)
		if ctx.HasBadge() {
			t.Error("HasBadge() should return false when no badge")
		}

		ctx.Badge = &badge.Claims{}
		if !ctx.HasBadge() {
			t.Error("HasBadge() should return true when badge present")
		}
	})
}
