// Copyright (c) CapiscIO, Inc.
// Licensed under the MIT License.

package mediation

import (
	"context"
	"testing"

	"github.com/capiscio/capiscio-core/v2/pkg/badge"
)

func TestNetworkHook_Mediate(t *testing.T) {
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
		config       NetworkHookConfig
		url          string
		method       string
		useBadge     bool
		wantDecision Decision
	}{
		{
			name: "allowed host",
			config: NetworkHookConfig{
				AllowedHosts: []string{"api.example.com"},
			},
			url:          "https://api.example.com/v1/data",
			method:       "GET",
			useBadge:     true,
			wantDecision: DecisionAllow,
		},
		{
			name: "denied host - explicit",
			config: NetworkHookConfig{
				AllowedHosts: []string{"*"},
				DeniedHosts:  []string{"malicious.com"},
			},
			url:          "https://malicious.com/steal",
			method:       "GET",
			useBadge:     true,
			wantDecision: DecisionDeny,
		},
		{
			name: "denied - private network",
			config: NetworkHookConfig{
				AllowedHosts:         []string{"*"},
				BlockPrivateNetworks: true,
			},
			url:          "http://192.168.1.1/admin",
			method:       "GET",
			useBadge:     true,
			wantDecision: DecisionDeny,
		},
		{
			name: "denied - localhost",
			config: NetworkHookConfig{
				AllowedHosts:         []string{"*"},
				BlockPrivateNetworks: true,
			},
			url:          "http://localhost:8080/internal",
			method:       "GET",
			useBadge:     true,
			wantDecision: DecisionDeny,
		},
		{
			name: "denied - 10.x.x.x range",
			config: NetworkHookConfig{
				AllowedHosts:         []string{"*"},
				BlockPrivateNetworks: true,
			},
			url:          "http://10.0.0.1/internal",
			method:       "GET",
			useBadge:     true,
			wantDecision: DecisionDeny,
		},
		{
			name: "denied - disallowed protocol",
			config: NetworkHookConfig{
				AllowedHosts:     []string{"example.com"},
				AllowedProtocols: []string{"https"},
			},
			url:          "http://example.com/insecure",
			method:       "GET",
			useBadge:     true,
			wantDecision: DecisionDeny,
		},
		{
			name: "wildcard host match",
			config: NetworkHookConfig{
				AllowedHosts: []string{"*.example.com"},
			},
			url:          "https://api.example.com/v1/data",
			method:       "GET",
			useBadge:     true,
			wantDecision: DecisionAllow,
		},
		{
			name: "default deny - no match",
			config: NetworkHookConfig{
				AllowedHosts: []string{"allowed.com"},
				DefaultDeny:  true,
			},
			url:          "https://other.com/data",
			method:       "GET",
			useBadge:     true,
			wantDecision: DecisionDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hook := NewNetworkHook(tt.config)

			var mctx *Context
			if tt.useBadge {
				mctx = mctxWithBadge
			} else {
				mctx = NewContext(manager, nil, nil)
			}

			req := &NetworkRequest{
				URL:    tt.url,
				Method: tt.method,
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

func TestNetworkHook_PrivateNetworkDetection(t *testing.T) {
	tests := []struct {
		name      string
		host      string
		isPrivate bool
	}{
		{"localhost", "localhost", true},
		{"127.0.0.1", "127.0.0.1", true},
		{"10.0.0.1", "10.0.0.1", true},
		{"10.255.255.255", "10.255.255.255", true},
		{"172.16.0.1", "172.16.0.1", true},
		{"172.31.255.255", "172.31.255.255", true},
		{"192.168.0.1", "192.168.0.1", true},
		{"192.168.255.255", "192.168.255.255", true},
		{"169.254.1.1", "169.254.1.1", true}, // link-local
		{"public IP", "8.8.8.8", false},
		{"public domain", "api.example.com", false},
	}

	hook := &NetworkHook{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hook.isPrivateNetwork(tt.host)
			if got != tt.isPrivate {
				t.Errorf("isPrivateNetwork(%q) = %v, want %v", tt.host, got, tt.isPrivate)
			}
		})
	}
}

func TestNetworkHook_NoTrustMaterial(t *testing.T) {
	hook := NewNetworkHook(NetworkHookConfig{
		AllowedHosts: []string{"*"},
	})

	// Create context WITHOUT trust material
	mctx := NewContext(nil, nil, nil)

	req := &NetworkRequest{
		URL:    "https://api.example.com/data",
		Method: "GET",
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
