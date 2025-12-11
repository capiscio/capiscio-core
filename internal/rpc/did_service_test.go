package rpc

import (
	"context"
	"testing"

	pb "github.com/capiscio/capiscio-core/pkg/rpc/gen/capiscio/v1"
)

func TestNewDIDService(t *testing.T) {
	svc := NewDIDService()
	if svc == nil {
		t.Fatal("NewDIDService returned nil")
	}
}

func TestDIDService_Parse(t *testing.T) {
	svc := NewDIDService()
	ctx := context.Background()

	tests := []struct {
		name       string
		did        string
		wantErr    bool
		wantDomain string
	}{
		{
			name:    "empty did",
			did:     "",
			wantErr: true,
		},
		{
			name:    "invalid did",
			did:     "not-a-did",
			wantErr: true,
		},
		{
			name:       "valid did:web",
			did:        "did:web:example.com",
			wantDomain: "example.com",
		},
		{
			name:       "did:web with path",
			did:        "did:web:example.com:agents:agent-1",
			wantDomain: "example.com",
		},
		{
			name:       "did:key",
			did:        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			wantDomain: "", // did:key has no domain
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.Parse(ctx, &pb.ParseDIDRequest{Did: tt.did})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr {
				if resp.ErrorMessage == "" {
					t.Error("expected error message")
				}
				return
			}
			if resp.ErrorMessage != "" {
				t.Errorf("unexpected error: %s", resp.ErrorMessage)
			}
			if resp.Did == nil {
				t.Fatal("expected DID response")
			}
			if resp.Did.Domain != tt.wantDomain {
				t.Errorf("domain = %v, want %v", resp.Did.Domain, tt.wantDomain)
			}
		})
	}
}

func TestDIDService_NewAgentDID(t *testing.T) {
	svc := NewDIDService()
	ctx := context.Background()

	tests := []struct {
		name    string
		domain  string
		agentID string
		wantErr bool
		wantDID string
	}{
		{
			name:    "missing domain",
			domain:  "",
			agentID: "agent-1",
			wantErr: true,
		},
		{
			name:    "missing agent_id",
			domain:  "example.com",
			agentID: "",
			wantErr: true,
		},
		{
			name:    "valid",
			domain:  "example.com",
			agentID: "agent-1",
			wantDID: "did:web:example.com:agents:agent-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.NewAgentDID(ctx, &pb.NewAgentDIDRequest{Domain: tt.domain, AgentId: tt.agentID})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr {
				if resp.ErrorMessage == "" {
					t.Error("expected error message")
				}
				return
			}
			if resp.Did != tt.wantDID {
				t.Errorf("did = %v, want %v", resp.Did, tt.wantDID)
			}
		})
	}
}

func TestDIDService_NewCapiscIOAgentDID(t *testing.T) {
	svc := NewDIDService()
	ctx := context.Background()

	tests := []struct {
		name    string
		agentID string
		wantErr bool
	}{
		{
			name:    "missing agent_id",
			agentID: "",
			wantErr: true,
		},
		{
			name:    "valid",
			agentID: "agent-1",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.NewCapiscIOAgentDID(ctx, &pb.NewCapiscIOAgentDIDRequest{AgentId: tt.agentID})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr {
				if resp.ErrorMessage == "" {
					t.Error("expected error message")
				}
				return
			}
			if resp.Did == "" {
				t.Error("expected DID")
			}
		})
	}
}

func TestDIDService_DocumentURL(t *testing.T) {
	svc := NewDIDService()
	ctx := context.Background()

	tests := []struct {
		name    string
		did     string
		wantErr bool
		wantURL string
	}{
		{
			name:    "empty did",
			did:     "",
			wantErr: true,
		},
		{
			name:    "invalid did",
			did:     "not-a-did",
			wantErr: true,
		},
		{
			name:    "valid did:web",
			did:     "did:web:example.com",
			wantURL: "https://example.com/did.json",
		},
		{
			name:    "did:web with path",
			did:     "did:web:example.com:agents:agent-1",
			wantURL: "https://example.com/agents/agent-1/did.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.DocumentURL(ctx, &pb.DocumentURLRequest{Did: tt.did})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr {
				if resp.ErrorMessage == "" {
					t.Error("expected error message")
				}
				return
			}
			if resp.Url != tt.wantURL {
				t.Errorf("url = %v, want %v", resp.Url, tt.wantURL)
			}
		})
	}
}

func TestDIDService_IsAgentDID(t *testing.T) {
	svc := NewDIDService()
	ctx := context.Background()

	tests := []struct {
		name        string
		did         string
		wantIsAgent bool
		wantAgentID string
	}{
		{
			name:        "empty did",
			did:         "",
			wantIsAgent: false,
		},
		{
			name:        "invalid did",
			did:         "not-a-did",
			wantIsAgent: false,
		},
		{
			name:        "root did:web",
			did:         "did:web:example.com",
			wantIsAgent: false,
		},
		{
			name:        "agent did:web",
			did:         "did:web:example.com:agents:agent-1",
			wantIsAgent: true,
			wantAgentID: "agent-1",
		},
		{
			name:        "did:key",
			did:         "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			wantIsAgent: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.IsAgentDID(ctx, &pb.IsAgentDIDRequest{Did: tt.did})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.IsAgentDid != tt.wantIsAgent {
				t.Errorf("isAgentDid = %v, want %v", resp.IsAgentDid, tt.wantIsAgent)
			}
			if tt.wantAgentID != "" && resp.AgentId != tt.wantAgentID {
				t.Errorf("agentId = %v, want %v", resp.AgentId, tt.wantAgentID)
			}
		})
	}
}
