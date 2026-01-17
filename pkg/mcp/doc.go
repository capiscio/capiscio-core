// Package mcp implements MCP security services for tool authority (RFC-006)
// and server identity verification (RFC-007).
//
// This package provides:
//   - Tool access evaluation with trust badge verification
//   - Evidence emission for audit trails
//   - Server identity verification with did:web origin binding
//
// Usage as library:
//
//	import "github.com/capiscio/capiscio-core/pkg/mcp"
//
//	service := mcp.NewService(mcp.Dependencies{...})
//	result, err := service.EvaluateToolAccess(ctx, req)
//
// The package also provides gRPC service handlers that can be registered
// with a gRPC server:
//
//	pb.RegisterMCPServiceServer(grpcServer, service)
package mcp
