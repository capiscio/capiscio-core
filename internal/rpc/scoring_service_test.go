package rpc

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	pb "github.com/capiscio/capiscio-core/v2/pkg/rpc/gen/capiscio/v1"
	"github.com/capiscio/capiscio-core/v2/pkg/scoring"
)

func TestScoreAgentCard_ValidCard(t *testing.T) {
	svc := NewScoringService()
	ctx := context.Background()

	cardJSON := `{
		"protocolVersion": "1.0.0",
		"name": "Test Agent",
		"description": "A test agent",
		"url": "https://example.com/agent",
		"version": "1.0.0",
		"preferredTransport": "JSONRPC",
		"capabilities": {
			"streaming": true,
			"pushNotifications": false
		},
		"provider": {
			"organization": "Test Org",
			"url": "https://example.com"
		},
		"skills": [
			{
				"id": "skill-1",
				"name": "Test Skill",
				"description": "A test skill",
				"tags": ["test"]
			}
		],
		"defaultInputModes": ["text"],
		"defaultOutputModes": ["text"]
	}`

	resp, err := svc.ScoreAgentCard(ctx, &pb.ScoreAgentCardRequest{
		AgentCardJson: cardJSON,
	})

	if err != nil {
		t.Fatalf("ScoreAgentCard failed: %v", err)
	}
	if resp.ErrorMessage != "" {
		t.Fatalf("Unexpected error: %s", resp.ErrorMessage)
	}
	if resp.Result == nil {
		t.Fatal("Expected result, got nil")
	}

	// Valid card should have good compliance score
	// Note: Trust score is 0 when no signatures (no signature verification)
	// So overall = (compliance*0.6 + trust*0.4) where trust=0
	// A fully compliant card gets ~100 compliance, so overall ~ 0.6
	if resp.Result.OverallScore < 0.5 {
		t.Errorf("Expected reasonable score for valid card, got %.2f", resp.Result.OverallScore)
	}
	
	// Check that compliance category is high
	for _, cat := range resp.Result.Categories {
		if cat.Category == pb.ScoreCategory_SCORE_CATEGORY_COMPLIANCE {
			if cat.Score < 0.8 {
				t.Errorf("Expected high compliance score, got %.2f", cat.Score)
			}
		}
	}
}

func TestScoreAgentCard_InvalidCard(t *testing.T) {
	svc := NewScoringService()
	ctx := context.Background()

	// Minimal invalid card - missing required fields
	cardJSON := `{
		"name": "Incomplete Agent"
	}`

	resp, err := svc.ScoreAgentCard(ctx, &pb.ScoreAgentCardRequest{
		AgentCardJson: cardJSON,
	})

	if err != nil {
		t.Fatalf("ScoreAgentCard failed: %v", err)
	}
	if resp.ErrorMessage != "" {
		t.Fatalf("Unexpected error: %s", resp.ErrorMessage)
	}
	if resp.Result == nil {
		t.Fatal("Expected result, got nil")
	}

	// Invalid card should have low score
	if resp.Result.OverallScore > 0.5 {
		t.Errorf("Expected low score for invalid card, got %.2f", resp.Result.OverallScore)
	}

	// Should have validation issues
	if resp.Result.Validation == nil || len(resp.Result.Validation.Issues) == 0 {
		t.Error("Expected validation issues for incomplete card")
	}
}

func TestScoreAgentCard_EmptyJSON(t *testing.T) {
	svc := NewScoringService()
	ctx := context.Background()

	resp, err := svc.ScoreAgentCard(ctx, &pb.ScoreAgentCardRequest{
		AgentCardJson: "",
	})

	if err != nil {
		t.Fatalf("ScoreAgentCard failed: %v", err)
	}
	if resp.ErrorMessage == "" {
		t.Error("Expected error message for empty JSON")
	}
}

func TestScoreAgentCard_InvalidJSON(t *testing.T) {
	svc := NewScoringService()
	ctx := context.Background()

	resp, err := svc.ScoreAgentCard(ctx, &pb.ScoreAgentCardRequest{
		AgentCardJson: "not valid json",
	})

	if err != nil {
		t.Fatalf("ScoreAgentCard failed: %v", err)
	}
	if resp.ErrorMessage == "" {
		t.Error("Expected error message for invalid JSON")
	}
}

func TestValidateRule_Exists(t *testing.T) {
	svc := NewScoringService()
	ctx := context.Background()

	// Card missing protocol version
	cardJSON := `{
		"name": "Test Agent",
		"version": "1.0.0",
		"url": "https://example.com"
	}`

	resp, err := svc.ValidateRule(ctx, &pb.ValidateRuleRequest{
		RuleId:        "MISSING_PROTOCOL_VERSION",
		AgentCardJson: cardJSON,
	})

	if err != nil {
		t.Fatalf("ValidateRule failed: %v", err)
	}
	if resp.ErrorMessage != "" {
		t.Fatalf("Unexpected error: %s", resp.ErrorMessage)
	}
	if resp.Result == nil {
		t.Fatal("Expected result, got nil")
	}

	if resp.Result.RuleId != "MISSING_PROTOCOL_VERSION" {
		t.Errorf("Expected rule ID 'MISSING_PROTOCOL_VERSION', got '%s'", resp.Result.RuleId)
	}
	if resp.Result.Passed {
		t.Error("Expected rule to fail (missing protocol version)")
	}
}

func TestValidateRule_Passes(t *testing.T) {
	svc := NewScoringService()
	ctx := context.Background()

	// Card with protocol version
	cardJSON := `{
		"protocolVersion": "1.0.0",
		"name": "Test Agent",
		"version": "1.0.0",
		"url": "https://example.com"
	}`

	resp, err := svc.ValidateRule(ctx, &pb.ValidateRuleRequest{
		RuleId:        "MISSING_PROTOCOL_VERSION",
		AgentCardJson: cardJSON,
	})

	if err != nil {
		t.Fatalf("ValidateRule failed: %v", err)
	}
	if resp.ErrorMessage != "" {
		t.Fatalf("Unexpected error: %s", resp.ErrorMessage)
	}
	if resp.Result == nil {
		t.Fatal("Expected result, got nil")
	}

	if !resp.Result.Passed {
		t.Error("Expected rule to pass (protocol version present)")
	}
}

func TestListRuleSets(t *testing.T) {
	svc := NewScoringService()
	ctx := context.Background()

	resp, err := svc.ListRuleSets(ctx, &pb.ListRuleSetsRequest{})

	if err != nil {
		t.Fatalf("ListRuleSets failed: %v", err)
	}
	if len(resp.RuleSets) == 0 {
		t.Error("Expected at least one rule set")
	}

	// Should have the default rule set
	found := false
	for _, rs := range resp.RuleSets {
		if rs.Id == "default" {
			found = true
			if len(rs.Rules) == 0 {
				t.Error("Default rule set should have rules")
			}
			break
		}
	}
	if !found {
		t.Error("Expected to find 'default' rule set")
	}
}

func TestGetRuleSet_Default(t *testing.T) {
	svc := NewScoringService()
	ctx := context.Background()

	resp, err := svc.GetRuleSet(ctx, &pb.GetRuleSetRequest{
		Id: "default",
	})

	if err != nil {
		t.Fatalf("GetRuleSet failed: %v", err)
	}
	if resp.ErrorMessage != "" {
		t.Fatalf("Unexpected error: %s", resp.ErrorMessage)
	}
	if resp.RuleSet == nil {
		t.Fatal("Expected rule set, got nil")
	}
	if resp.RuleSet.Id != "default" {
		t.Errorf("Expected 'default' ID, got '%s'", resp.RuleSet.Id)
	}
}

func TestGetRuleSet_NotFound(t *testing.T) {
	svc := NewScoringService()
	ctx := context.Background()

	resp, err := svc.GetRuleSet(ctx, &pb.GetRuleSetRequest{
		Id: "nonexistent",
	})

	if err != nil {
		t.Fatalf("GetRuleSet failed: %v", err)
	}
	if resp.ErrorMessage == "" {
		t.Error("Expected error message for nonexistent rule set")
	}
}

func TestAggregateScores_Average(t *testing.T) {
	svc := NewScoringService()
	ctx := context.Background()

	results := []*pb.ScoringResult{
		{OverallScore: 0.8},
		{OverallScore: 0.6},
		{OverallScore: 1.0},
	}

	resp, err := svc.AggregateScores(ctx, &pb.AggregateScoresRequest{
		Results:           results,
		AggregationMethod: "average",
	})

	if err != nil {
		t.Fatalf("AggregateScores failed: %v", err)
	}

	expected := 0.8 // (0.8 + 0.6 + 1.0) / 3
	tolerance := 0.001
	diff := resp.AggregateScore - expected
	if diff < -tolerance || diff > tolerance {
		t.Errorf("Expected aggregate score ~%.2f, got %.2f", expected, resp.AggregateScore)
	}
}

func TestAggregateScores_Min(t *testing.T) {
	svc := NewScoringService()
	ctx := context.Background()

	results := []*pb.ScoringResult{
		{OverallScore: 0.8},
		{OverallScore: 0.6},
		{OverallScore: 1.0},
	}

	resp, err := svc.AggregateScores(ctx, &pb.AggregateScoresRequest{
		Results:           results,
		AggregationMethod: "min",
	})

	if err != nil {
		t.Fatalf("AggregateScores failed: %v", err)
	}

	if resp.AggregateScore != 0.6 {
		t.Errorf("Expected min score 0.6, got %.2f", resp.AggregateScore)
	}
}

func TestAggregateScores_Max(t *testing.T) {
	svc := NewScoringService()
	ctx := context.Background()

	results := []*pb.ScoringResult{
		{OverallScore: 0.8},
		{OverallScore: 0.6},
		{OverallScore: 1.0},
	}

	resp, err := svc.AggregateScores(ctx, &pb.AggregateScoresRequest{
		Results:           results,
		AggregationMethod: "max",
	})

	if err != nil {
		t.Fatalf("AggregateScores failed: %v", err)
	}

	if resp.AggregateScore != 1.0 {
		t.Errorf("Expected max score 1.0, got %.2f", resp.AggregateScore)
	}
}

func TestAggregateScores_Empty(t *testing.T) {
	svc := NewScoringService()
	ctx := context.Background()

	resp, err := svc.AggregateScores(ctx, &pb.AggregateScoresRequest{
		Results: []*pb.ScoringResult{},
	})

	if err != nil {
		t.Fatalf("AggregateScores failed: %v", err)
	}

	if resp.AggregateScore != 0 {
		t.Errorf("Expected 0 for empty input, got %.2f", resp.AggregateScore)
	}
	if resp.AggregateRating != pb.Rating_RATING_UNSPECIFIED {
		t.Errorf("Expected UNSPECIFIED rating for empty input, got %v", resp.AggregateRating)
	}
}

// Integration test: verify JSON output can be properly marshalled
func TestScoreAgentCard_JSONOutput(t *testing.T) {
	svc := NewScoringService()
	ctx := context.Background()

	cardJSON := `{
		"protocolVersion": "1.0.0",
		"name": "Test Agent",
		"version": "1.0.0",
		"url": "https://example.com/agent"
	}`

	resp, err := svc.ScoreAgentCard(ctx, &pb.ScoreAgentCardRequest{
		AgentCardJson: cardJSON,
	})

	if err != nil {
		t.Fatalf("ScoreAgentCard failed: %v", err)
	}

	// Verify result can be marshalled to JSON
	_, err = json.Marshal(resp.Result)
	if err != nil {
		t.Fatalf("Failed to marshal result to JSON: %v", err)
	}
}

// Additional tests for improved coverage

func TestNewScoringServiceWithConfig(t *testing.T) {
	config := &scoring.EngineConfig{
		HTTPTimeout: 5 * time.Second,
		SchemaOnly:  true,
	}

	svc := NewScoringServiceWithConfig(config)
	if svc == nil {
		t.Fatal("Expected non-nil service")
	}
	if svc.engine == nil {
		t.Fatal("Expected non-nil engine")
	}
}

func TestValidateRule_InvalidJSON(t *testing.T) {
	svc := NewScoringService()
	ctx := context.Background()

	resp, err := svc.ValidateRule(ctx, &pb.ValidateRuleRequest{
		RuleId:        "MISSING_NAME",
		AgentCardJson: "not valid json",
	})

	if err != nil {
		t.Fatalf("ValidateRule failed: %v", err)
	}
	if resp.ErrorMessage == "" {
		t.Error("Expected error message for invalid JSON")
	}
}

func TestValidateRule_EmptyJSON(t *testing.T) {
	svc := NewScoringService()
	ctx := context.Background()

	resp, err := svc.ValidateRule(ctx, &pb.ValidateRuleRequest{
		RuleId:        "MISSING_NAME",
		AgentCardJson: "",
	})

	if err != nil {
		t.Fatalf("ValidateRule failed: %v", err)
	}
	if resp.ErrorMessage == "" {
		t.Error("Expected error message for empty JSON")
	}
}

func TestAggregateScores_Weighted(t *testing.T) {
	svc := NewScoringService()
	ctx := context.Background()

	results := []*pb.ScoringResult{
		{OverallScore: 0.8},
		{OverallScore: 0.6},
	}

	// Weighted method without explicit weights falls back to average
	resp, err := svc.AggregateScores(ctx, &pb.AggregateScoresRequest{
		Results:           results,
		AggregationMethod: "weighted",
	})

	if err != nil {
		t.Fatalf("AggregateScores failed: %v", err)
	}

	// Without weights, should use average
	expected := 0.7
	tolerance := 0.001
	diff := resp.AggregateScore - expected
	if diff < -tolerance || diff > tolerance {
		t.Errorf("Expected score ~%.2f, got %.2f", expected, resp.AggregateScore)
	}
}

func TestAggregateScores_UnknownMethod(t *testing.T) {
	svc := NewScoringService()
	ctx := context.Background()

	results := []*pb.ScoringResult{
		{OverallScore: 0.8},
		{OverallScore: 0.6},
	}

	// Unknown method should default to average
	resp, err := svc.AggregateScores(ctx, &pb.AggregateScoresRequest{
		Results:           results,
		AggregationMethod: "unknown_method",
	})

	if err != nil {
		t.Fatalf("AggregateScores failed: %v", err)
	}

	// Should use average as default
	expected := 0.7
	tolerance := 0.001
	diff := resp.AggregateScore - expected
	if diff < -tolerance || diff > tolerance {
		t.Errorf("Expected average score ~%.2f, got %.2f", expected, resp.AggregateScore)
	}
}

func TestScoreAgentCard_RatingLevels(t *testing.T) {
	svc := NewScoringService()
	ctx := context.Background()

	testCases := []struct {
		name             string
		cardJSON         string
		expectHighRating bool
	}{
		{
			name: "Excellent card",
			cardJSON: `{
				"protocolVersion": "1.0.0",
				"name": "Excellent Agent",
				"description": "A fully compliant agent card with all fields",
				"url": "https://example.com/agent",
				"version": "1.0.0",
				"preferredTransport": "JSONRPC",
				"capabilities": {"streaming": true, "pushNotifications": true},
				"provider": {"organization": "Test Org", "url": "https://example.com"},
				"skills": [
					{
						"id": "skill-1",
						"name": "Test Skill",
						"description": "A test skill with tags and examples",
						"tags": ["ai", "automation"],
						"examples": ["example 1", "example 2"]
					}
				],
				"defaultInputModes": ["text/plain", "application/json"],
				"defaultOutputModes": ["text/plain", "application/json"]
			}`,
			expectHighRating: true,
		},
		{
			name: "Minimal card",
			cardJSON: `{
				"name": "Minimal Agent"
			}`,
			expectHighRating: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := svc.ScoreAgentCard(ctx, &pb.ScoreAgentCardRequest{
				AgentCardJson: tc.cardJSON,
			})

			if err != nil {
				t.Fatalf("ScoreAgentCard failed: %v", err)
			}

			if tc.expectHighRating {
				if resp.Result.Rating == pb.Rating_RATING_POOR || resp.Result.Rating == pb.Rating_RATING_UNSPECIFIED {
					t.Errorf("Expected high rating, got %v", resp.Result.Rating)
				}
			}
		})
	}
}

func TestScoreAgentCard_ValidationIssues(t *testing.T) {
	svc := NewScoringService()
	ctx := context.Background()

	// Card with multiple issues
	cardJSON := `{
		"name": "Bad Agent",
		"url": "not-a-url",
		"version": "invalid-version"
	}`

	resp, err := svc.ScoreAgentCard(ctx, &pb.ScoreAgentCardRequest{
		AgentCardJson: cardJSON,
	})

	if err != nil {
		t.Fatalf("ScoreAgentCard failed: %v", err)
	}
	if resp.Result == nil {
		t.Fatal("Expected result, got nil")
	}

	// Should have multiple validation issues
	if resp.Result.Validation == nil {
		t.Fatal("Expected validation result")
	}

	// Check that issues have proper severity levels
	for _, issue := range resp.Result.Validation.Issues {
		if issue.Severity == pb.ValidationSeverity_VALIDATION_SEVERITY_UNSPECIFIED {
			t.Error("Issue has unspecified severity")
		}
	}
}
