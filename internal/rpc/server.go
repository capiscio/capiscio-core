// Package rpc provides the gRPC server implementation for CapiscIO SDK integration.
package rpc

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	pb "github.com/capiscio/capiscio-core/pkg/rpc/gen/capiscio/v1"
)

// RegisterServices registers all CapiscIO gRPC services with the server.
func RegisterServices(server *grpc.Server) {
	// Register reflection for grpcurl/debugging
	reflection.Register(server)

	// Register health check service
	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(server, healthServer)
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

	// Register CapiscIO services
	pb.RegisterBadgeServiceServer(server, NewBadgeService())
	pb.RegisterDIDServiceServer(server, NewDIDService())
	pb.RegisterTrustStoreServiceServer(server, NewTrustStoreService())
	pb.RegisterRevocationServiceServer(server, NewRevocationService())
	pb.RegisterScoringServiceServer(server, NewScoringService())
	pb.RegisterSimpleGuardServiceServer(server, NewSimpleGuardService())
	pb.RegisterRegistryServiceServer(server, NewRegistryService())
}
