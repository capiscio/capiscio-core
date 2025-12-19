// Package main provides the rpc command for starting the gRPC server.
package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/capiscio/capiscio-core/v2/internal/rpc"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

var (
	rpcSocket  string
	rpcAddress string
)

var rpcCmd = &cobra.Command{
	Use:   "rpc",
	Short: "Start the gRPC server",
	Long: `Start the gRPC server for SDK integration.

The server can listen on either a Unix socket (default) or TCP address.
SDKs connect to this server to access CapiscIO core functionality.`,
	RunE: runRPCServer,
}

func init() {
	rpcCmd.Flags().StringVar(&rpcSocket, "socket", "", "Unix socket path (default: ~/.capiscio/rpc.sock)")
	rpcCmd.Flags().StringVar(&rpcAddress, "address", "", "TCP address to listen on (e.g., localhost:50051)")
	rootCmd.AddCommand(rpcCmd)
}

func runRPCServer(_ *cobra.Command, _ []string) error {
	var listener net.Listener
	var err error

	// Determine listener type
	if rpcAddress != "" {
		// TCP mode
		listener, err = net.Listen("tcp", rpcAddress)
		if err != nil {
			return fmt.Errorf("failed to listen on %s: %w", rpcAddress, err)
		}
		fmt.Printf("gRPC server listening on tcp://%s\n", rpcAddress)
	} else {
		// Unix socket mode (default)
		socketPath := rpcSocket
		if socketPath == "" {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("failed to get home directory: %w", err)
			}
			socketDir := homeDir + "/.capiscio"
			if err := os.MkdirAll(socketDir, 0700); err != nil {
				return fmt.Errorf("failed to create socket directory: %w", err)
			}
			socketPath = socketDir + "/rpc.sock"
		}

		// Remove existing socket file
		if err := os.RemoveAll(socketPath); err != nil {
			return fmt.Errorf("failed to remove existing socket: %w", err)
		}

		listener, err = net.Listen("unix", socketPath)
		if err != nil {
			return fmt.Errorf("failed to listen on %s: %w", socketPath, err)
		}
		fmt.Printf("gRPC server listening on unix://%s\n", socketPath)

		// Ensure socket is cleaned up on exit
		defer func() { _ = os.RemoveAll(socketPath) }()
	}

	// Create gRPC server with services
	server := grpc.NewServer()
	rpc.RegisterServices(server)

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nShutting down gRPC server...")
		server.GracefulStop()
	}()

	// Start serving
	if err := server.Serve(listener); err != nil {
		return fmt.Errorf("failed to serve: %w", err)
	}

	return nil
}
