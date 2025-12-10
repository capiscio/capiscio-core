package rpc

import (
	"context"

	pb "github.com/capiscio/capiscio-core/pkg/rpc/gen/capiscio/v1"
)

// ScoringService implements the gRPC ScoringService.
type ScoringService struct {
	pb.UnimplementedScoringServiceServer
}

// NewScoringService creates a new ScoringService instance.
func NewScoringService() *ScoringService {
	return &ScoringService{}
}

// ScoreAgentCard validates an agent card and generates a score.
func (s *ScoringService) ScoreAgentCard(ctx context.Context, req *pb.ScoreAgentCardRequest) (*pb.ScoreAgentCardResponse, error) {
	// TODO: Implement with scoring.Engine
	return &pb.ScoreAgentCardResponse{
		ErrorMessage: "not yet implemented",
	}, nil
}

// ValidateRule validates a single rule.
func (s *ScoringService) ValidateRule(ctx context.Context, req *pb.ValidateRuleRequest) (*pb.ValidateRuleResponse, error) {
	// TODO: Implement with scoring.Engine
	return &pb.ValidateRuleResponse{
		ErrorMessage: "not yet implemented",
	}, nil
}

// ListRuleSets gets available rule sets.
func (s *ScoringService) ListRuleSets(ctx context.Context, req *pb.ListRuleSetsRequest) (*pb.ListRuleSetsResponse, error) {
	// TODO: Implement with scoring.Engine
	return &pb.ListRuleSetsResponse{}, nil
}

// GetRuleSet gets rule set details.
func (s *ScoringService) GetRuleSet(ctx context.Context, req *pb.GetRuleSetRequest) (*pb.GetRuleSetResponse, error) {
	// TODO: Implement with scoring.Engine
	return &pb.GetRuleSetResponse{
		ErrorMessage: "not yet implemented",
	}, nil
}

// AggregateScores calculates aggregate score from multiple validations.
func (s *ScoringService) AggregateScores(ctx context.Context, req *pb.AggregateScoresRequest) (*pb.AggregateScoresResponse, error) {
	// TODO: Implement with scoring.Engine
	return &pb.AggregateScoresResponse{}, nil
}
