package rpc

import (
	"context"

	pb "github.com/capiscio/capiscio-core/pkg/rpc/gen/capiscio/v1"
)

// TrustStoreService implements the gRPC TrustStoreService.
type TrustStoreService struct {
	pb.UnimplementedTrustStoreServiceServer
}

// NewTrustStoreService creates a new TrustStoreService instance.
func NewTrustStoreService() *TrustStoreService {
	return &TrustStoreService{}
}

// AddKey adds a trusted public key.
func (s *TrustStoreService) AddKey(ctx context.Context, req *pb.AddKeyRequest) (*pb.AddKeyResponse, error) {
	// TODO: Implement with trust.FileStore
	return &pb.AddKeyResponse{
		ErrorMessage: "not yet implemented",
	}, nil
}

// RemoveKey removes a trusted key.
func (s *TrustStoreService) RemoveKey(ctx context.Context, req *pb.RemoveKeyRequest) (*pb.RemoveKeyResponse, error) {
	// TODO: Implement with trust.FileStore
	return &pb.RemoveKeyResponse{
		ErrorMessage: "not yet implemented",
	}, nil
}

// GetKey gets a key by DID.
func (s *TrustStoreService) GetKey(ctx context.Context, req *pb.GetKeyRequest) (*pb.GetKeyResponse, error) {
	// TODO: Implement with trust.FileStore
	return &pb.GetKeyResponse{
		ErrorMessage: "not yet implemented",
	}, nil
}

// ListKeys lists all trusted keys.
func (s *TrustStoreService) ListKeys(ctx context.Context, req *pb.ListKeysRequest) (*pb.ListKeysResponse, error) {
	// TODO: Implement with trust.FileStore
	return &pb.ListKeysResponse{}, nil
}

// IsTrusted checks if a key is trusted.
func (s *TrustStoreService) IsTrusted(ctx context.Context, req *pb.IsTrustedRequest) (*pb.IsTrustedResponse, error) {
	// TODO: Implement with trust.FileStore
	return &pb.IsTrustedResponse{
		IsTrusted: false,
	}, nil
}

// ImportFromDirectory imports keys from a directory.
func (s *TrustStoreService) ImportFromDirectory(ctx context.Context, req *pb.ImportFromDirectoryRequest) (*pb.ImportFromDirectoryResponse, error) {
	// TODO: Implement with trust.FileStore
	return &pb.ImportFromDirectoryResponse{
		Errors: []string{"not yet implemented"},
	}, nil
}

// ExportToDirectory exports keys to a directory.
func (s *TrustStoreService) ExportToDirectory(ctx context.Context, req *pb.ExportToDirectoryRequest) (*pb.ExportToDirectoryResponse, error) {
	// TODO: Implement with trust.FileStore
	return &pb.ExportToDirectoryResponse{
		ErrorMessage: "not yet implemented",
	}, nil
}

// Clear clears all keys.
func (s *TrustStoreService) Clear(ctx context.Context, req *pb.ClearKeysRequest) (*pb.ClearKeysResponse, error) {
	// TODO: Implement with trust.FileStore
	return &pb.ClearKeysResponse{}, nil
}
