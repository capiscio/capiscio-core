// Package scoring implements the validation and scoring logic for Agent Cards.
package scoring

import (
	"context"
	"time"

	"github.com/capiscio/capiscio-core/pkg/agentcard"
	"github.com/capiscio/capiscio-core/pkg/protocol"
	"github.com/capiscio/capiscio-core/pkg/report"
)

// AvailabilityScorer evaluates the operational status of the agent.
type AvailabilityScorer struct {
	timeout time.Duration
}

// NewAvailabilityScorer creates a new AvailabilityScorer.
func NewAvailabilityScorer(timeout time.Duration) *AvailabilityScorer {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	return &AvailabilityScorer{
		timeout: timeout,
	}
}

// Score checks the agent's endpoint and calculates an availability score.
func (s *AvailabilityScorer) Score(ctx context.Context, card *agentcard.AgentCard) report.AvailabilityResult {
	res := report.AvailabilityResult{
		Tested:      true,
		EndpointURL: card.URL,
	}

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	var client protocol.Client

	// Determine transport
	switch card.PreferredTransport {
	case agentcard.TransportJSONRPC:
		client = protocol.NewJSONRPCClient(card.URL)
	case agentcard.TransportHTTPJSON:
		client = protocol.NewHTTPClient(card.URL)
	case agentcard.TransportGRPC:
		// TODO: Implement GRPC client
		res.Error = "GRPC transport not yet supported in core engine"
		res.Score = 0
		return res
	default:
		// Default to JSONRPC if unspecified, as it's the most common A2A transport
		if card.PreferredTransport == "" {
			client = protocol.NewJSONRPCClient(card.URL)
		} else {
			res.Error = "Unsupported transport: " + string(card.PreferredTransport)
			res.Score = 0
			return res
		}
	}
	defer func() { _ = client.Close() }()

	latency, err := client.Ping(ctx)
	if err != nil {
		res.Error = err.Error()
		res.Score = 0
		return res
	}

	res.LatencyMS = latency.Milliseconds()

	// Scoring logic based on latency
	if latency < 200*time.Millisecond {
		res.Score = 100
	} else if latency < 500*time.Millisecond {
		res.Score = 90
	} else if latency < 1000*time.Millisecond {
		res.Score = 70
	} else {
		res.Score = 50
	}

	return res
}
