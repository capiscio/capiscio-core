package rpc

import (
	"context"

	pb "github.com/capiscio/capiscio-core/pkg/rpc/gen/capiscio/v1"
)

// RevocationService implements the gRPC RevocationService.
type RevocationService struct {
	pb.UnimplementedRevocationServiceServer
}

// NewRevocationService creates a new RevocationService instance.
func NewRevocationService() *RevocationService {
	return &RevocationService{}
}

// IsRevoked checks if a key is revoked.
func (s *RevocationService) IsRevoked(ctx context.Context, req *pb.IsRevokedRequest) (*pb.IsRevokedResponse, error) {
	// TODO: Implement with revocation.Cache
	return &pb.IsRevokedResponse{
		IsRevoked: false,
	}, nil
}

// Revoke adds a revocation entry.
func (s *RevocationService) Revoke(ctx context.Context, req *pb.RevokeRequest) (*pb.RevokeResponse, error) {
	// TODO: Implement with revocation.Cache
	return &pb.RevokeResponse{
		ErrorMessage: "not yet implemented",
	}, nil
}

// Unrevoke removes a revocation entry.
func (s *RevocationService) Unrevoke(ctx context.Context, req *pb.UnrevokeRequest) (*pb.UnrevokeResponse, error) {
	// TODO: Implement with revocation.Cache
	return &pb.UnrevokeResponse{
		ErrorMessage: "not yet implemented",
	}, nil
}

// ListRevocations lists revoked entries.
func (s *RevocationService) ListRevocations(ctx context.Context, req *pb.ListRevocationsRequest) (*pb.ListRevocationsResponse, error) {
	// TODO: Implement with revocation.Cache
	return &pb.ListRevocationsResponse{}, nil
}

// FetchRevocationList fetches revocation list from URL.
func (s *RevocationService) FetchRevocationList(ctx context.Context, req *pb.FetchRevocationListRequest) (*pb.FetchRevocationListResponse, error) {
	// TODO: Implement with revocation.Cache
	return &pb.FetchRevocationListResponse{
		ErrorMessage: "not yet implemented",
	}, nil
}

// ClearCache clears the revocation cache.
func (s *RevocationService) ClearCache(ctx context.Context, req *pb.ClearCacheRequest) (*pb.ClearCacheResponse, error) {
	// TODO: Implement with revocation.Cache
	return &pb.ClearCacheResponse{}, nil
}

// GetCacheStats gets cache statistics.
func (s *RevocationService) GetCacheStats(ctx context.Context, req *pb.GetCacheStatsRequest) (*pb.GetCacheStatsResponse, error) {
	// TODO: Implement with revocation.Cache
	return &pb.GetCacheStatsResponse{}, nil
}
