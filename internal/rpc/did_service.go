package rpc

import (
	"context"

	"github.com/capiscio/capiscio-core/pkg/did"

	pb "github.com/capiscio/capiscio-core/pkg/rpc/gen/capiscio/v1"
)

// DIDService implements the gRPC DIDService.
type DIDService struct {
	pb.UnimplementedDIDServiceServer
}

// NewDIDService creates a new DIDService instance.
func NewDIDService() *DIDService {
	return &DIDService{}
}

// Parse parses a did:web identifier.
func (s *DIDService) Parse(ctx context.Context, req *pb.ParseDIDRequest) (*pb.ParseDIDResponse, error) {
	if req.Did == "" {
		return &pb.ParseDIDResponse{
			ErrorMessage: "did is required",
		}, nil
	}

	parsed, err := did.Parse(req.Did)
	if err != nil {
		return &pb.ParseDIDResponse{
			ErrorMessage: err.Error(),
		}, nil
	}

	return &pb.ParseDIDResponse{
		Did: &pb.DID{
			Raw:    parsed.Raw,
			Method: parsed.Method,
			Domain: parsed.Domain,
			Path:   parsed.PathSegments,
		},
	}, nil
}

// NewAgentDID constructs a new agent DID.
func (s *DIDService) NewAgentDID(ctx context.Context, req *pb.NewAgentDIDRequest) (*pb.NewAgentDIDResponse, error) {
	if req.Domain == "" {
		return &pb.NewAgentDIDResponse{
			ErrorMessage: "domain is required",
		}, nil
	}
	if req.AgentId == "" {
		return &pb.NewAgentDIDResponse{
			ErrorMessage: "agent_id is required",
		}, nil
	}

	didStr := did.NewAgentDID(req.Domain, req.AgentId)
	return &pb.NewAgentDIDResponse{
		Did: didStr,
	}, nil
}

// NewCapiscIOAgentDID constructs a Capiscio registry DID.
func (s *DIDService) NewCapiscIOAgentDID(ctx context.Context, req *pb.NewCapiscIOAgentDIDRequest) (*pb.NewAgentDIDResponse, error) {
	if req.AgentId == "" {
		return &pb.NewAgentDIDResponse{
			ErrorMessage: "agent_id is required",
		}, nil
	}

	didStr := did.NewCapiscIOAgentDID(req.AgentId)
	return &pb.NewAgentDIDResponse{
		Did: didStr,
	}, nil
}

// DocumentURL gets the document URL for a DID.
func (s *DIDService) DocumentURL(ctx context.Context, req *pb.DocumentURLRequest) (*pb.DocumentURLResponse, error) {
	if req.Did == "" {
		return &pb.DocumentURLResponse{
			ErrorMessage: "did is required",
		}, nil
	}

	parsed, err := did.Parse(req.Did)
	if err != nil {
		return &pb.DocumentURLResponse{
			ErrorMessage: err.Error(),
		}, nil
	}

	return &pb.DocumentURLResponse{
		Url: parsed.DocumentURL(),
	}, nil
}

// IsAgentDID checks if a DID is an agent DID.
func (s *DIDService) IsAgentDID(ctx context.Context, req *pb.IsAgentDIDRequest) (*pb.IsAgentDIDResponse, error) {
	if req.Did == "" {
		return &pb.IsAgentDIDResponse{
			IsAgentDid: false,
		}, nil
	}

	parsed, err := did.Parse(req.Did)
	if err != nil {
		return &pb.IsAgentDIDResponse{
			IsAgentDid: false,
		}, nil
	}

	return &pb.IsAgentDIDResponse{
		IsAgentDid: parsed.IsAgentDID(),
		AgentId:    parsed.AgentID,
	}, nil
}
