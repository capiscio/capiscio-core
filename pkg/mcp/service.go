package mcp

import (
	"context"

	"github.com/capiscio/capiscio-core/v2/pkg/badge"
)

// Service implements the MCP service logic
// Note: gRPC integration requires running `make proto` first to generate
// pkg/rpc/gen/capiscio/v1/mcp.pb.go and mcp_grpc.pb.go
type Service struct {
	guard          *Guard
	serverVerifier *ServerIdentityVerifier
}

// Dependencies holds the dependencies for the MCP service
type Dependencies struct {
	BadgeVerifier *badge.Verifier
	EvidenceStore EvidenceStore
}

// NewService creates a new MCP service instance
func NewService(deps *Dependencies) *Service {
	if deps == nil {
		deps = &Dependencies{}
	}
	return &Service{
		guard:          NewGuard(deps.BadgeVerifier, deps.EvidenceStore),
		serverVerifier: NewServerIdentityVerifier(deps.BadgeVerifier),
	}
}

// EvaluateToolAccessInput represents the input for tool access evaluation
type EvaluateToolAccessInput struct {
	ToolName   string
	ParamsHash string
	Origin     string
	Credential CallerCredential
	Config     *EvaluateConfig
}

// EvaluateToolAccess evaluates tool access using RFC-006 §6.2-6.4
func (s *Service) EvaluateToolAccess(
	ctx context.Context,
	input *EvaluateToolAccessInput,
) (*EvaluateResult, error) {
	return s.guard.EvaluateToolAccess(
		ctx,
		input.ToolName,
		input.ParamsHash,
		input.Origin,
		input.Credential,
		input.Config,
	)
}

// VerifyServerIdentityInput represents the input for server identity verification
type VerifyServerIdentityInput struct {
	ServerDID      string
	ServerBadgeJWS string
	Origin         string
	Config         *VerifyConfig
}

// VerifyServerIdentity verifies server identity using RFC-007 §7.2
func (s *Service) VerifyServerIdentity(
	ctx context.Context,
	input *VerifyServerIdentityInput,
) (*VerifyResult, error) {
	return s.serverVerifier.VerifyServerIdentity(
		ctx,
		input.ServerDID,
		input.ServerBadgeJWS,
		input.Origin,
		input.Config,
	)
}

// ParseServerIdentityFromHTTP parses server identity from HTTP headers
func (s *Service) ParseServerIdentityFromHTTP(headers map[string]string) *ParsedIdentity {
	return ParseHTTPHeaders(headers)
}

// ParseServerIdentityFromJSONRPC parses server identity from JSON-RPC _meta
func (s *Service) ParseServerIdentityFromJSONRPC(meta map[string]interface{}) *ParsedIdentity {
	return ParseJSONRPCMeta(meta)
}

// HealthInput represents the input for health checks
type HealthInput struct {
	ClientVersion string
}

// Health performs a health check
func (s *Service) Health(ctx context.Context, input *HealthInput) *HealthStatus {
	compat, _ := CheckVersionCompatibility(input.ClientVersion)
	status := CheckHealth()
	status.Compatible = compat
	return status
}
