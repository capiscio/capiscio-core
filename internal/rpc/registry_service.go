package rpc

import (
	"context"
	"time"

	pb "github.com/capiscio/capiscio-core/v2/pkg/rpc/gen/capiscio/v1"
)

// RegistryService implements the gRPC RegistryService.
type RegistryService struct {
	pb.UnimplementedRegistryServiceServer
}

// NewRegistryService creates a new RegistryService instance.
func NewRegistryService() *RegistryService {
	return &RegistryService{}
}

// GetAgent gets an agent card by DID.
func (s *RegistryService) GetAgent(_ context.Context, _ *pb.GetAgentRequest) (*pb.GetAgentResponse, error) {
	// TODO: Implement with registry.Registry
	return &pb.GetAgentResponse{
		ErrorMessage: "not yet implemented",
	}, nil
}

// SearchAgents searches for agents.
func (s *RegistryService) SearchAgents(_ context.Context, _ *pb.SearchAgentsRequest) (*pb.SearchAgentsResponse, error) {
	// TODO: Implement with registry.Registry
	return &pb.SearchAgentsResponse{}, nil
}

// RegisterAgent registers a new agent.
func (s *RegistryService) RegisterAgent(_ context.Context, _ *pb.RegisterAgentRequest) (*pb.RegisterAgentResponse, error) {
	// TODO: Implement with registry.Registry
	return &pb.RegisterAgentResponse{
		ErrorMessage: "not yet implemented",
	}, nil
}

// UpdateAgent updates an existing agent.
func (s *RegistryService) UpdateAgent(_ context.Context, _ *pb.UpdateAgentRequest) (*pb.UpdateAgentResponse, error) {
	// TODO: Implement with registry.Registry
	return &pb.UpdateAgentResponse{
		ErrorMessage: "not yet implemented",
	}, nil
}

// DeregisterAgent deregisters an agent.
func (s *RegistryService) DeregisterAgent(_ context.Context, _ *pb.DeregisterAgentRequest) (*pb.DeregisterAgentResponse, error) {
	// TODO: Implement with registry.Registry
	return &pb.DeregisterAgentResponse{
		ErrorMessage: "not yet implemented",
	}, nil
}

// VerifyRegistration verifies agent registration.
func (s *RegistryService) VerifyRegistration(_ context.Context, _ *pb.VerifyRegistrationRequest) (*pb.VerifyRegistrationResponse, error) {
	// TODO: Implement with registry.Registry
	return &pb.VerifyRegistrationResponse{
		ErrorMessage: "not yet implemented",
	}, nil
}

// ListAgents lists agents (with pagination).
func (s *RegistryService) ListAgents(_ context.Context, _ *pb.ListAgentsRequest) (*pb.ListAgentsResponse, error) {
	// TODO: Implement with registry.Registry
	return &pb.ListAgentsResponse{}, nil
}

// GetStats gets registry statistics.
func (s *RegistryService) GetStats(_ context.Context, _ *pb.GetStatsRequest) (*pb.GetStatsResponse, error) {
	// TODO: Implement with registry.Registry
	return &pb.GetStatsResponse{}, nil
}

// Ping pings registry health.
func (s *RegistryService) Ping(_ context.Context, _ *pb.PingRequest) (*pb.PingResponse, error) {
	return &pb.PingResponse{
		Status:  "ok",
		Version: "1.0.0",
		ServerTime: &pb.Timestamp{
			Value: time.Now().Format(time.RFC3339),
		},
	}, nil
}
