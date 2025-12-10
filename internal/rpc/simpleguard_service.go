package rpc

import (
	"context"

	pb "github.com/capiscio/capiscio-core/pkg/rpc/gen/capiscio/v1"
)

// SimpleGuardService implements the gRPC SimpleGuardService.
type SimpleGuardService struct {
	pb.UnimplementedSimpleGuardServiceServer
}

// NewSimpleGuardService creates a new SimpleGuardService instance.
func NewSimpleGuardService() *SimpleGuardService {
	return &SimpleGuardService{}
}

// Sign signs a message.
func (s *SimpleGuardService) Sign(ctx context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
	// TODO: Implement with simpleguard.SimpleGuard
	return &pb.SignResponse{
		ErrorMessage: "not yet implemented",
	}, nil
}

// Verify verifies a signed message.
func (s *SimpleGuardService) Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	// TODO: Implement with simpleguard.SimpleGuard
	return &pb.VerifyResponse{
		Valid:        false,
		ErrorMessage: "not yet implemented",
	}, nil
}

// SignAttached signs with attached payload (creates JWS).
func (s *SimpleGuardService) SignAttached(ctx context.Context, req *pb.SignAttachedRequest) (*pb.SignAttachedResponse, error) {
	// TODO: Implement with simpleguard.SimpleGuard
	return &pb.SignAttachedResponse{
		ErrorMessage: "not yet implemented",
	}, nil
}

// VerifyAttached verifies with attached payload.
func (s *SimpleGuardService) VerifyAttached(ctx context.Context, req *pb.VerifyAttachedRequest) (*pb.VerifyAttachedResponse, error) {
	// TODO: Implement with simpleguard.SimpleGuard
	return &pb.VerifyAttachedResponse{
		Valid:        false,
		ErrorMessage: "not yet implemented",
	}, nil
}

// GenerateKeyPair generates a new key pair.
func (s *SimpleGuardService) GenerateKeyPair(ctx context.Context, req *pb.GenerateKeyPairRequest) (*pb.GenerateKeyPairResponse, error) {
	// TODO: Implement with crypto package
	return &pb.GenerateKeyPairResponse{
		ErrorMessage: "not yet implemented",
	}, nil
}

// LoadKey loads key from file.
func (s *SimpleGuardService) LoadKey(ctx context.Context, req *pb.LoadKeyRequest) (*pb.LoadKeyResponse, error) {
	// TODO: Implement
	return &pb.LoadKeyResponse{
		ErrorMessage: "not yet implemented",
	}, nil
}

// ExportKey exports key to file.
func (s *SimpleGuardService) ExportKey(ctx context.Context, req *pb.ExportKeyRequest) (*pb.ExportKeyResponse, error) {
	// TODO: Implement
	return &pb.ExportKeyResponse{
		ErrorMessage: "not yet implemented",
	}, nil
}

// GetKeyInfo gets key info.
func (s *SimpleGuardService) GetKeyInfo(ctx context.Context, req *pb.GetKeyInfoRequest) (*pb.GetKeyInfoResponse, error) {
	// TODO: Implement
	return &pb.GetKeyInfoResponse{
		ErrorMessage: "not yet implemented",
	}, nil
}
