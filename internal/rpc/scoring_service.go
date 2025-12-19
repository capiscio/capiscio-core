package rpc

import (
	"context"
	"encoding/json"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/agentcard"
	"github.com/capiscio/capiscio-core/v2/pkg/report"
	pb "github.com/capiscio/capiscio-core/v2/pkg/rpc/gen/capiscio/v1"
	"github.com/capiscio/capiscio-core/v2/pkg/scoring"
)

// ScoringService implements the gRPC ScoringService.
type ScoringService struct {
	pb.UnimplementedScoringServiceServer
	engine *scoring.Engine
}

// NewScoringService creates a new ScoringService instance.
func NewScoringService() *ScoringService {
	return &ScoringService{
		engine: scoring.NewEngine(scoring.DefaultEngineConfig()),
	}
}

// NewScoringServiceWithConfig creates a ScoringService with custom configuration.
func NewScoringServiceWithConfig(config *scoring.EngineConfig) *ScoringService {
	return &ScoringService{
		engine: scoring.NewEngine(config),
	}
}

// ScoreAgentCard validates an agent card and generates a score.
func (s *ScoringService) ScoreAgentCard(ctx context.Context, req *pb.ScoreAgentCardRequest) (*pb.ScoreAgentCardResponse, error) {
	if req.AgentCardJson == "" {
		return &pb.ScoreAgentCardResponse{
			ErrorMessage: "agent_card_json is required",
		}, nil
	}

	// Parse the agent card JSON
	var card agentcard.AgentCard
	if err := json.Unmarshal([]byte(req.AgentCardJson), &card); err != nil {
		return &pb.ScoreAgentCardResponse{
			ErrorMessage: "invalid agent card JSON: " + err.Error(),
		}, nil
	}

	// Run validation through the engine
	// checkAvailability=false for RPC calls (can be expensive)
	result, err := s.engine.Validate(ctx, &card, false)
	if err != nil {
		return &pb.ScoreAgentCardResponse{
			ErrorMessage: "validation error: " + err.Error(),
		}, nil
	}

	// Convert result to protobuf format
	pbResult := s.convertToProtoResult(result)

	return &pb.ScoreAgentCardResponse{
		Result: pbResult,
	}, nil
}

// convertToProtoResult converts internal ValidationResult to protobuf ScoringResult.
func (s *ScoringService) convertToProtoResult(result *report.ValidationResult) *pb.ScoringResult {
	// Calculate overall score (weighted average of compliance and trust)
	// Compliance is weighted higher as it's the base requirement
	overallScore := (result.ComplianceScore*0.6 + result.TrustScore*0.4) / 100.0

	// Determine rating based on overall score
	rating := s.scoreToRating(overallScore)

	// Build category scores
	categories := []*pb.CategoryScore{
		{
			Category: pb.ScoreCategory_SCORE_CATEGORY_COMPLIANCE,
			Score:    result.ComplianceScore / 100.0,
		},
		{
			Category: pb.ScoreCategory_SCORE_CATEGORY_SECURITY,
			Score:    result.TrustScore / 100.0,
		},
	}

	// Add availability if tested
	if result.Availability.Tested {
		categories = append(categories, &pb.CategoryScore{
			Category: pb.ScoreCategory_SCORE_CATEGORY_CAPABILITIES,
			Score:    result.Availability.Score / 100.0,
		})
	}

	// Convert validation issues to rule results
	ruleResults := make([]*pb.RuleResult, 0, len(result.Issues))
	for _, issue := range result.Issues {
		ruleResults = append(ruleResults, &pb.RuleResult{
			RuleId:  issue.Code,
			Passed:  issue.Severity != "error",
			Message: issue.Message,
			Details: map[string]string{
				"field":    issue.Field,
				"severity": issue.Severity,
			},
		})
	}

	// Build validation result for proto
	pbValidation := &pb.ValidationResult{
		Valid: result.Success,
	}
	for _, issue := range result.Issues {
		pbValidation.Issues = append(pbValidation.Issues, &pb.ValidationIssue{
			Code:     issue.Code,
			Message:  issue.Message,
			Severity: s.severityToProto(issue.Severity),
			Field:    issue.Field,
		})
	}

	return &pb.ScoringResult{
		OverallScore: overallScore,
		Rating:       rating,
		Categories:   categories,
		RuleResults:  ruleResults,
		Validation:   pbValidation,
		ScoredAt: &pb.Timestamp{
			Value: time.Now().UTC().Format(time.RFC3339),
		},
		RuleSetId:      "default",
		RuleSetVersion: "1.0.0",
	}
}

// scoreToRating converts a 0.0-1.0 score to a Rating enum.
func (s *ScoringService) scoreToRating(score float64) pb.Rating {
	switch {
	case score >= 0.9:
		return pb.Rating_RATING_EXCELLENT
	case score >= 0.75:
		return pb.Rating_RATING_GOOD
	case score >= 0.5:
		return pb.Rating_RATING_FAIR
	case score >= 0.25:
		return pb.Rating_RATING_POOR
	default:
		return pb.Rating_RATING_CRITICAL
	}
}

// severityToProto converts severity string to protobuf enum.
func (s *ScoringService) severityToProto(severity string) pb.ValidationSeverity {
	switch severity {
	case "error":
		return pb.ValidationSeverity_VALIDATION_SEVERITY_ERROR
	case "warning":
		return pb.ValidationSeverity_VALIDATION_SEVERITY_WARNING
	case "info":
		return pb.ValidationSeverity_VALIDATION_SEVERITY_INFO
	default:
		return pb.ValidationSeverity_VALIDATION_SEVERITY_UNSPECIFIED
	}
}

// ValidateRule validates a single rule against an agent card.
func (s *ScoringService) ValidateRule(ctx context.Context, req *pb.ValidateRuleRequest) (*pb.ValidateRuleResponse, error) {
	if req.RuleId == "" {
		return &pb.ValidateRuleResponse{
			ErrorMessage: "rule_id is required",
		}, nil
	}
	if req.AgentCardJson == "" {
		return &pb.ValidateRuleResponse{
			ErrorMessage: "agent_card_json is required",
		}, nil
	}

	// Parse the agent card
	var card agentcard.AgentCard
	if err := json.Unmarshal([]byte(req.AgentCardJson), &card); err != nil {
		return &pb.ValidateRuleResponse{
			ErrorMessage: "invalid agent card JSON: " + err.Error(),
		}, nil
	}

	// Run full validation and find the specific rule
	result, err := s.engine.Validate(ctx, &card, false)
	if err != nil {
		return &pb.ValidateRuleResponse{
			ErrorMessage: "validation error: " + err.Error(),
		}, nil
	}

	// Look for the specific rule result
	for _, issue := range result.Issues {
		if issue.Code == req.RuleId {
			return &pb.ValidateRuleResponse{
				Result: &pb.RuleResult{
					RuleId:  issue.Code,
					Passed:  issue.Severity != "error",
					Message: issue.Message,
					Details: map[string]string{
						"field":    issue.Field,
						"severity": issue.Severity,
					},
				},
			}, nil
		}
	}

	// Rule passed (not found in issues)
	return &pb.ValidateRuleResponse{
		Result: &pb.RuleResult{
			RuleId:  req.RuleId,
			Passed:  true,
			Message: "Rule passed",
		},
	}, nil
}

// ListRuleSets returns available rule sets.
func (s *ScoringService) ListRuleSets(_ context.Context, _ *pb.ListRuleSetsRequest) (*pb.ListRuleSetsResponse, error) {
	// For now, return a single default rule set
	// This can be extended to support custom rule sets
	defaultRuleSet := &pb.RuleSet{
		Id:          "default",
		Name:        "Default A2A Compliance Rules",
		Version:     "1.0.0",
		Description: "Standard compliance, trust, and availability rules for A2A Agent Cards",
		Rules:       s.getDefaultRules(),
	}

	return &pb.ListRuleSetsResponse{
		RuleSets: []*pb.RuleSet{defaultRuleSet},
	}, nil
}

// GetRuleSet returns details for a specific rule set.
func (s *ScoringService) GetRuleSet(_ context.Context, req *pb.GetRuleSetRequest) (*pb.GetRuleSetResponse, error) {
	if req.Id == "" {
		return &pb.GetRuleSetResponse{
			ErrorMessage: "id is required",
		}, nil
	}

	// Currently only support the default rule set
	if req.Id != "default" {
		return &pb.GetRuleSetResponse{
			ErrorMessage: "rule set not found: " + req.Id,
		}, nil
	}

	return &pb.GetRuleSetResponse{
		RuleSet: &pb.RuleSet{
			Id:          "default",
			Name:        "Default A2A Compliance Rules",
			Version:     "1.0.0",
			Description: "Standard compliance, trust, and availability rules for A2A Agent Cards",
			Rules:       s.getDefaultRules(),
		},
	}, nil
}

// getDefaultRules returns the built-in validation rules.
func (s *ScoringService) getDefaultRules() []*pb.Rule {
	return []*pb.Rule{
		{
			Id:          "MISSING_PROTOCOL_VERSION",
			Name:        "Protocol Version Required",
			Description: "Agent card must specify a protocol version",
			Category:    pb.ScoreCategory_SCORE_CATEGORY_COMPLIANCE,
			Severity:    pb.RuleSeverity_RULE_SEVERITY_ERROR,
			Weight:      20,
		},
		{
			Id:          "INVALID_PROTOCOL_VERSION",
			Name:        "Valid SemVer Protocol Version",
			Description: "Protocol version must be a valid semantic version string",
			Category:    pb.ScoreCategory_SCORE_CATEGORY_COMPLIANCE,
			Severity:    pb.RuleSeverity_RULE_SEVERITY_ERROR,
			Weight:      10,
		},
		{
			Id:          "MISSING_NAME",
			Name:        "Agent Name Required",
			Description: "Agent card must have a name",
			Category:    pb.ScoreCategory_SCORE_CATEGORY_IDENTITY,
			Severity:    pb.RuleSeverity_RULE_SEVERITY_ERROR,
			Weight:      10,
		},
		{
			Id:          "MISSING_VERSION",
			Name:        "Agent Version Required",
			Description: "Agent card must specify its version",
			Category:    pb.ScoreCategory_SCORE_CATEGORY_COMPLIANCE,
			Severity:    pb.RuleSeverity_RULE_SEVERITY_ERROR,
			Weight:      10,
		},
		{
			Id:          "MISSING_URL",
			Name:        "Agent URL Required",
			Description: "Agent card must have a URL endpoint",
			Category:    pb.ScoreCategory_SCORE_CATEGORY_COMPLIANCE,
			Severity:    pb.RuleSeverity_RULE_SEVERITY_ERROR,
			Weight:      20,
		},
		{
			Id:          "NO_SKILLS",
			Name:        "Skills Recommended",
			Description: "Agent card should define at least one skill",
			Category:    pb.ScoreCategory_SCORE_CATEGORY_CAPABILITIES,
			Severity:    pb.RuleSeverity_RULE_SEVERITY_WARNING,
			Weight:      15,
		},
		{
			Id:          "MISSING_PROVIDER",
			Name:        "Provider Recommended",
			Description: "Agent card should include provider information",
			Category:    pb.ScoreCategory_SCORE_CATEGORY_TRANSPARENCY,
			Severity:    pb.RuleSeverity_RULE_SEVERITY_WARNING,
			Weight:      5,
		},
		{
			Id:          "INVALID_TRANSPORT",
			Name:        "Valid Transport Protocol",
			Description: "Transport must be JSONRPC, GRPC, or HTTP+JSON",
			Category:    pb.ScoreCategory_SCORE_CATEGORY_COMPLIANCE,
			Severity:    pb.RuleSeverity_RULE_SEVERITY_ERROR,
			Weight:      10,
		},
	}
}

// AggregateScores calculates aggregate score from multiple validations.
func (s *ScoringService) AggregateScores(_ context.Context, req *pb.AggregateScoresRequest) (*pb.AggregateScoresResponse, error) {
	if len(req.Results) == 0 {
		return &pb.AggregateScoresResponse{
			AggregateScore:  0,
			AggregateRating: pb.Rating_RATING_UNSPECIFIED,
		}, nil
	}

	// Calculate aggregate score based on method
	var aggregateScore float64
	categoryTotals := make(map[string]float64)
	categoryCounts := make(map[string]int)

	for _, result := range req.Results {
		aggregateScore += result.OverallScore

		for _, cat := range result.Categories {
			catName := cat.Category.String()
			categoryTotals[catName] += cat.Score
			categoryCounts[catName]++
		}
	}

	// Default to average
	count := float64(len(req.Results))
	switch req.AggregationMethod {
	case "min":
		minScore := req.Results[0].OverallScore
		for _, r := range req.Results[1:] {
			if r.OverallScore < minScore {
				minScore = r.OverallScore
			}
		}
		aggregateScore = minScore
	case "max":
		maxScore := req.Results[0].OverallScore
		for _, r := range req.Results[1:] {
			if r.OverallScore > maxScore {
				maxScore = r.OverallScore
			}
		}
		aggregateScore = maxScore
	default: // "average" or empty
		aggregateScore = aggregateScore / count
	}

	// Calculate category averages
	categoryAggregates := make(map[string]float64)
	for cat, total := range categoryTotals {
		categoryAggregates[cat] = total / float64(categoryCounts[cat])
	}

	return &pb.AggregateScoresResponse{
		AggregateScore:     aggregateScore,
		AggregateRating:    s.scoreToRating(aggregateScore),
		CategoryAggregates: categoryAggregates,
	}, nil
}
