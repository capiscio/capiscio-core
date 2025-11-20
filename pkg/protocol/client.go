// Package protocol defines the interfaces and implementations for communicating with A2A agents.
package protocol

import (
	"context"
	"time"
)

// Client defines the interface for an A2A protocol client.
type Client interface {
	// Ping checks if the agent is reachable and responsive.
	// Returns the latency and any error encountered.
	Ping(ctx context.Context) (time.Duration, error)

	// Close cleans up any resources used by the client.
	Close() error
}
