// Package rpc provides the gRPC server implementation for CapiscIO SDK integration.
package rpc

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/capiscio/capiscio-core/v2/pkg/badge"
	"github.com/capiscio/capiscio-core/v2/pkg/mcp"
	"github.com/capiscio/capiscio-core/v2/pkg/registry"
	pb "github.com/capiscio/capiscio-core/v2/pkg/rpc/gen/capiscio/v1"
)

// MCPService implements the MCPServiceServer interface for RFC-006 and RFC-007.
type MCPService struct {
	pb.UnimplementedMCPServiceServer
	service *mcp.Service
}

// MCPServiceConfig configures the MCP service
type MCPServiceConfig struct {
	// TrustStoreKeyPath is the path to the trusted CA public key (JWK format)
	// If empty, badge verification is disabled
	TrustStoreKeyPath string

	// EvidenceMode determines evidence storage mode (local, registry, hybrid)
	EvidenceMode mcp.EvidenceStoreMode

	// EvidenceDir is the local evidence directory (for local/hybrid modes)
	EvidenceDir string

	// RegistryEndpoint is the registry events endpoint (for registry/hybrid modes)
	RegistryEndpoint string

	// RegistryAPIKey is the API key for registry authentication
	RegistryAPIKey string
}

// NewMCPService creates a new MCPService instance with default configuration.
// For production use, prefer NewMCPServiceWithConfig.
func NewMCPService() *MCPService {
	// Try to load config from environment
	cfg := MCPServiceConfig{
		TrustStoreKeyPath: os.Getenv("CAPISCIO_TRUST_STORE_KEY"),
		EvidenceMode:      mcp.EvidenceStoreMode(os.Getenv("CAPISCIO_EVIDENCE_MODE")),
		EvidenceDir:       os.Getenv("CAPISCIO_EVIDENCE_DIR"),
		RegistryEndpoint:  os.Getenv("CAPISCIO_REGISTRY_ENDPOINT"),
		RegistryAPIKey:    os.Getenv("CAPISCIO_REGISTRY_API_KEY"),
	}

	// Default to local evidence storage
	if cfg.EvidenceMode == "" {
		cfg.EvidenceMode = mcp.EvidenceStoreModeLocal
	}

	svc, _ := NewMCPServiceWithConfig(cfg)
	return svc
}

// NewMCPServiceWithConfig creates a new MCPService with explicit configuration.
func NewMCPServiceWithConfig(cfg MCPServiceConfig) (*MCPService, error) {
	deps := &mcp.Dependencies{}

	// Initialize badge verifier if trust store key is provided
	if cfg.TrustStoreKeyPath != "" {
		reg := registry.NewLocalRegistry(cfg.TrustStoreKeyPath)
		deps.BadgeVerifier = badge.NewVerifier(reg)
	}

	// Initialize evidence store based on mode
	switch cfg.EvidenceMode {
	case mcp.EvidenceStoreModeLocal:
		store, err := mcp.NewLocalEvidenceStore(cfg.EvidenceDir)
		if err != nil {
			// Fall back to no-op if local fails
			deps.EvidenceStore = &mcp.NoOpEvidenceStore{}
		} else {
			deps.EvidenceStore = store
		}

	case mcp.EvidenceStoreModeRegistry:
		if cfg.RegistryEndpoint != "" {
			deps.EvidenceStore = mcp.NewRegistryEvidenceStore(mcp.RegistryEvidenceStoreConfig{
				Endpoint: cfg.RegistryEndpoint,
				APIKey:   cfg.RegistryAPIKey,
			})
		} else {
			deps.EvidenceStore = &mcp.NoOpEvidenceStore{}
		}

	case mcp.EvidenceStoreModeHybrid:
		if cfg.RegistryEndpoint != "" {
			store, err := mcp.NewHybridEvidenceStore(cfg.EvidenceDir, mcp.RegistryEvidenceStoreConfig{
				Endpoint: cfg.RegistryEndpoint,
				APIKey:   cfg.RegistryAPIKey,
			})
			if err != nil {
				deps.EvidenceStore = &mcp.NoOpEvidenceStore{}
			} else {
				deps.EvidenceStore = store
			}
		} else {
			// Fall back to local only
			store, _ := mcp.NewLocalEvidenceStore(cfg.EvidenceDir)
			deps.EvidenceStore = store
		}

	default:
		deps.EvidenceStore = &mcp.NoOpEvidenceStore{}
	}

	return &MCPService{
		service: mcp.NewService(deps),
	}, nil
}

// EvaluateToolAccess implements RFC-006 tool access evaluation.
func (s *MCPService) EvaluateToolAccess(
	ctx context.Context,
	req *pb.EvaluateToolAccessRequest,
) (*pb.EvaluateToolAccessResponse, error) {
	// Build caller credential from request
	var cred mcp.CallerCredential
	switch c := req.CallerCredential.(type) {
	case *pb.EvaluateToolAccessRequest_BadgeJws:
		cred = mcp.NewBadgeCredential(c.BadgeJws)
	case *pb.EvaluateToolAccessRequest_ApiKey:
		cred = mcp.NewAPIKeyCredential(c.ApiKey)
	default:
		cred = mcp.NewAnonymousCredential()
	}

	// Build config from request
	var config *mcp.EvaluateConfig
	if req.Config != nil {
		config = &mcp.EvaluateConfig{
			TrustedIssuers:  req.Config.TrustedIssuers,
			MinTrustLevel:   int(req.Config.MinTrustLevel),
			AcceptLevelZero: req.Config.AcceptLevelZero,
			AllowedTools:    req.Config.AllowedTools,
		}
	}

	// Evaluate tool access
	result, err := s.service.EvaluateToolAccess(ctx, &mcp.EvaluateToolAccessInput{
		ToolName:   req.ToolName,
		ParamsHash: req.ParamsHash,
		Origin:     req.ServerOrigin,
		Credential: cred,
		Config:     config,
	})
	if err != nil {
		return nil, err
	}

	// Convert result to proto response
	resp := &pb.EvaluateToolAccessResponse{
		AgentDid:   result.AgentDID,
		BadgeJti:   result.BadgeJTI,
		TrustLevel: int32(result.TrustLevel),
		EvidenceId: result.EvidenceID,
		Timestamp:  timestamppb.New(time.Now()),
	}

	// Set decision
	switch result.Decision {
	case mcp.DecisionAllow:
		resp.Decision = pb.MCPDecision_MCP_DECISION_ALLOW
	case mcp.DecisionDeny:
		resp.Decision = pb.MCPDecision_MCP_DECISION_DENY
	}

	// Set auth level
	switch result.AuthLevel {
	case mcp.AuthLevelAnonymous:
		resp.AuthLevel = pb.MCPAuthLevel_MCP_AUTH_LEVEL_ANONYMOUS
	case mcp.AuthLevelAPIKey:
		resp.AuthLevel = pb.MCPAuthLevel_MCP_AUTH_LEVEL_API_KEY
	case mcp.AuthLevelBadge:
		resp.AuthLevel = pb.MCPAuthLevel_MCP_AUTH_LEVEL_BADGE
	}

	// Set deny reason if applicable
	if result.Decision == mcp.DecisionDeny {
		resp.DenyReason = convertDenyReason(result.DenyReason)
		resp.DenyDetail = result.DenyDetail
	}

	// Use pre-serialized evidence JSON
	resp.EvidenceJson = result.EvidenceJSON

	return resp, nil
}

// VerifyServerIdentity implements RFC-007 server identity verification.
func (s *MCPService) VerifyServerIdentity(
	ctx context.Context,
	req *pb.VerifyServerIdentityRequest,
) (*pb.VerifyServerIdentityResponse, error) {
	// Build config from request (map proto config to internal config)
	var config *mcp.VerifyConfig
	if req.Config != nil {
		config = &mcp.VerifyConfig{
			// Map proto fields to internal fields
			RequireOriginBinding: !req.Config.SkipOriginBinding,
		}
	}

	// Verify server identity
	result, err := s.service.VerifyServerIdentity(ctx, &mcp.VerifyServerIdentityInput{
		ServerDID:      req.ServerDid,
		ServerBadgeJWS: req.ServerBadge,
		Origin:         req.TransportOrigin,
		Config:         config,
	})
	if err != nil {
		return nil, err
	}

	// Convert result to proto response
	resp := &pb.VerifyServerIdentityResponse{
		ServerDid:  result.ServerID,
		BadgeJti:   result.BadgeJTI,
		TrustLevel: int32(result.TrustLevel()),
	}

	// Set state
	switch result.State {
	case mcp.ServerStateVerifiedPrincipal:
		resp.State = pb.MCPServerState_MCP_SERVER_STATE_VERIFIED_PRINCIPAL
	case mcp.ServerStateDeclaredPrincipal:
		resp.State = pb.MCPServerState_MCP_SERVER_STATE_DECLARED_PRINCIPAL
	case mcp.ServerStateUnverifiedOrigin:
		resp.State = pb.MCPServerState_MCP_SERVER_STATE_UNVERIFIED_ORIGIN
	}

	// Set error if present
	if result.ErrorCode != mcp.ServerErrorNone {
		resp.ErrorCode = convertServerErrorCode(result.ErrorCode)
		resp.ErrorDetail = result.ErrorDetail
	}

	return resp, nil
}

// ParseServerIdentity extracts server identity from headers or JSON-RPC meta.
func (s *MCPService) ParseServerIdentity(
	ctx context.Context,
	req *pb.ParseServerIdentityRequest,
) (*pb.ParseServerIdentityResponse, error) {
	var parsed *mcp.ParsedIdentity

	switch source := req.Source.(type) {
	case *pb.ParseServerIdentityRequest_HttpHeaders:
		headers := map[string]string{
			"Capiscio-Server-DID":   source.HttpHeaders.CapiscioServerDid,
			"Capiscio-Server-Badge": source.HttpHeaders.CapiscioServerBadge,
		}
		parsed = s.service.ParseServerIdentityFromHTTP(headers)
	case *pb.ParseServerIdentityRequest_JsonrpcMeta:
		var meta map[string]interface{}
		if err := json.Unmarshal([]byte(source.JsonrpcMeta.MetaJson), &meta); err != nil {
			return &pb.ParseServerIdentityResponse{IdentityPresent: false}, nil
		}
		parsed = s.service.ParseServerIdentityFromJSONRPC(meta)
	default:
		return &pb.ParseServerIdentityResponse{IdentityPresent: false}, nil
	}

	return &pb.ParseServerIdentityResponse{
		ServerDid:       parsed.ServerDID,
		ServerBadge:     parsed.ServerBadgeJWS,
		IdentityPresent: parsed.ServerDID != "" || parsed.ServerBadgeJWS != "",
	}, nil
}

// Health implements the health check for client supervision.
func (s *MCPService) Health(
	ctx context.Context,
	req *pb.MCPHealthRequest,
) (*pb.MCPHealthResponse, error) {
	status := s.service.Health(ctx, &mcp.HealthInput{
		ClientVersion: req.ClientVersion,
	})

	return &pb.MCPHealthResponse{
		Healthy:           status.Healthy,
		CoreVersion:       status.CoreVersion,
		ProtoVersion:      status.ProtoVersion,
		VersionCompatible: status.Compatible,
	}, nil
}

// convertDenyReason converts internal deny reason to proto enum.
func convertDenyReason(reason mcp.DenyReason) pb.MCPDenyReason {
	switch reason {
	case mcp.DenyReasonBadgeMissing:
		return pb.MCPDenyReason_MCP_DENY_REASON_BADGE_MISSING
	case mcp.DenyReasonBadgeInvalid:
		return pb.MCPDenyReason_MCP_DENY_REASON_BADGE_INVALID
	case mcp.DenyReasonBadgeExpired:
		return pb.MCPDenyReason_MCP_DENY_REASON_BADGE_EXPIRED
	case mcp.DenyReasonBadgeRevoked:
		return pb.MCPDenyReason_MCP_DENY_REASON_BADGE_REVOKED
	case mcp.DenyReasonTrustInsufficient:
		return pb.MCPDenyReason_MCP_DENY_REASON_TRUST_INSUFFICIENT
	case mcp.DenyReasonToolNotAllowed:
		return pb.MCPDenyReason_MCP_DENY_REASON_TOOL_NOT_ALLOWED
	case mcp.DenyReasonIssuerUntrusted:
		return pb.MCPDenyReason_MCP_DENY_REASON_ISSUER_UNTRUSTED
	case mcp.DenyReasonPolicyDenied:
		return pb.MCPDenyReason_MCP_DENY_REASON_POLICY_DENIED
	default:
		return pb.MCPDenyReason_MCP_DENY_REASON_UNSPECIFIED
	}
}

// convertServerErrorCode converts internal error code to proto enum.
func convertServerErrorCode(code mcp.ServerErrorCode) pb.MCPServerErrorCode {
	switch code {
	case mcp.ServerErrorCodeDIDResolutionFailed:
		return pb.MCPServerErrorCode_MCP_SERVER_ERROR_DID_INVALID
	case mcp.ServerErrorCodeBadgeInvalid:
		return pb.MCPServerErrorCode_MCP_SERVER_ERROR_BADGE_INVALID
	case mcp.ServerErrorCodeBadgeRevoked:
		return pb.MCPServerErrorCode_MCP_SERVER_ERROR_BADGE_REVOKED
	case mcp.ServerErrorCodeTrustInsufficient:
		return pb.MCPServerErrorCode_MCP_SERVER_ERROR_TRUST_INSUFFICIENT
	case mcp.ServerErrorCodeOriginMismatch:
		return pb.MCPServerErrorCode_MCP_SERVER_ERROR_ORIGIN_MISMATCH
	case mcp.ServerErrorCodePathMismatch:
		return pb.MCPServerErrorCode_MCP_SERVER_ERROR_PATH_MISMATCH
	case mcp.ServerErrorCodeIssuerUntrusted:
		return pb.MCPServerErrorCode_MCP_SERVER_ERROR_ISSUER_UNTRUSTED
	default:
		return pb.MCPServerErrorCode_MCP_SERVER_ERROR_NONE
	}
}
