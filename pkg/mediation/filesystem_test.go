// Copyright (c) CapiscIO, Inc.
// Licensed under the MIT License.

package mediation

import (
	"context"
	"testing"

	"github.com/capiscio/capiscio-core/v2/pkg/badge"
)

func TestFilesystemHook_Mediate(t *testing.T) {
	// Create a bootstrapped material manager for tests.
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
		config       FilesystemHookConfig
		path         string
		operation    FileOperation
		useBadge     bool // whether to use mctxWithBadge (true) or bare context (false)
		wantDecision Decision
		wantDeny     bool
	}{
		{
			name: "allowed path - explicit",
			config: FilesystemHookConfig{
				AllowedPaths: []string{"/tmp/*"},
				DefaultDeny:  true,
			},
			path:         "/tmp/test.txt",
			operation:    FileOpRead,
			useBadge:     true,
			wantDecision: DecisionAllow,
			wantDeny:     false,
		},
		{
			name: "denied path - sensitive",
			config: FilesystemHookConfig{
				AllowedPaths: []string{"*"}, // allow all
			},
			path:         "/etc/shadow",
			operation:    FileOpRead,
			useBadge:     true,
			wantDecision: DecisionDeny,
			wantDeny:     true,
		},
		{
			name: "denied path - ssh keys with tilde",
			config: FilesystemHookConfig{
				AllowedPaths: []string{"*"},
			},
			path:         "~/.ssh/id_rsa",
			operation:    FileOpRead,
			useBadge:     true,
			wantDecision: DecisionDeny,
			wantDeny:     true,
		},
		{
			name: "denied path - aws credentials with tilde",
			config: FilesystemHookConfig{
				AllowedPaths: []string{"*"},
			},
			path:         "~/.aws/credentials",
			operation:    FileOpRead,
			useBadge:     true,
			wantDecision: DecisionDeny,
			wantDeny:     true,
		},
		{
			name: "default deny - no match",
			config: FilesystemHookConfig{
				AllowedPaths: []string{"/tmp/*"},
				DefaultDeny:  true,
			},
			path:         "/var/log/app.log",
			operation:    FileOpRead,
			useBadge:     true,
			wantDecision: DecisionDeny,
			wantDeny:     true,
		},
		{
			name: "explicit deny path",
			config: FilesystemHookConfig{
				AllowedPaths: []string{"*"},
				DeniedPaths:  []string{"/var/secret/*"},
			},
			path:         "/var/secret/key.pem",
			operation:    FileOpRead,
			useBadge:     true,
			wantDecision: DecisionDeny,
			wantDeny:     true,
		},
		{
			name: "working directory relative path",
			config: FilesystemHookConfig{
				AllowedPaths:     []string{"/app/*"},
				WorkingDirectory: "/app",
				DefaultDeny:      true,
			},
			path:         "data/file.txt", // relative to /app
			operation:    FileOpRead,
			useBadge:     true,
			wantDecision: DecisionAllow,
			wantDeny:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hook := NewFilesystemHook(tt.config)

			var mctx *Context
			if tt.useBadge {
				mctx = mctxWithBadge
			} else {
				mctx = NewContext(manager, nil, nil)
			}

			req := &FileRequest{
				Path:      tt.path,
				Operation: tt.operation,
			}

			result, err := hook.Mediate(context.Background(), mctx, req)
			if err != nil {
				t.Fatalf("Mediate() error = %v", err)
			}

			if result.Decision != tt.wantDecision {
				t.Errorf("Mediate() decision = %v, want %v", result.Decision, tt.wantDecision)
			}

			if tt.wantDeny && result.Decision != DecisionDeny {
				t.Errorf("Expected deny, got %v (reason: %s)", result.Decision, result.Reason)
			}
		})
	}
}

func TestFilesystemHook_PathCanonicalization(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		workingDir string
		want       string
	}{
		{
			name:       "absolute path unchanged",
			input:      "/tmp/test.txt",
			workingDir: "",
			want:       "/tmp/test.txt",
		},
		{
			name:       "relative with working directory",
			input:      "data/file.txt",
			workingDir: "/app",
			want:       "/app/data/file.txt",
		},
		{
			name:       "dot-dot traversal blocked",
			input:      "/app/../etc/passwd",
			workingDir: "",
			want:       "/etc/passwd",
		},
		{
			name:       "double slashes normalized",
			input:      "/tmp//test///file.txt",
			workingDir: "",
			want:       "/tmp/test/file.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hook := &FilesystemHook{
				config: FilesystemHookConfig{
					WorkingDirectory: tt.workingDir,
				},
			}
			got := hook.canonicalizePath(tt.input)
			if got != tt.want {
				t.Errorf("canonicalizePath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestFilesystemHook_NoTrustMaterial(t *testing.T) {
	hook := NewFilesystemHook(FilesystemHookConfig{
		AllowedPaths: []string{"/tmp/*"},
	})

	// Create context WITHOUT trust material
	mctx := NewContext(nil, nil, nil)

	req := &FileRequest{
		Path:      "/tmp/test.txt",
		Operation: "read",
	}

	result, err := hook.Mediate(context.Background(), mctx, req)
	if err != nil {
		t.Fatalf("Mediate() error = %v", err)
	}

	// Should deny due to no trust material
	if result.Decision != DecisionDeny {
		t.Errorf("Expected deny for no trust material, got %v", result.Decision)
	}
	if result.PolicyRef != "builtin:no_trust_material" {
		t.Errorf("Expected policy ref 'builtin:no_trust_material', got %q", result.PolicyRef)
	}
}
