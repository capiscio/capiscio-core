package scoring

import (
	"context"
	"testing"

	"github.com/capiscio/capiscio-core/v2/pkg/agentcard"
	"github.com/stretchr/testify/assert"
)

func TestEngine_Validate_Integration(t *testing.T) {
	engine := NewEngine(nil)

	// Minimal valid card for compliance
	card := &agentcard.AgentCard{
		ProtocolVersion: "0.3.0",
		Name:            "Test Agent",
		Version:         "1.0.0",
		URL:             "https://example.com",
		Skills: []agentcard.AgentSkill{
			{ID: "s1", Tags: []string{"t1"}},
		},
		Provider: &agentcard.AgentProvider{Organization: "Org", URL: "url"},
	}

	// Run validation (no live check)
	result, err := engine.Validate(context.Background(), card, false)

	assert.NoError(t, err)
	assert.True(t, result.Success) // Should be true because warnings don't fail it
	assert.Equal(t, 100.0, result.ComplianceScore)
	assert.Equal(t, 20.0, result.TrustScore) // No signatures = 20

	// Check issues
	assert.Len(t, result.Issues, 1)
	assert.Equal(t, "NO_SIGNATURES", result.Issues[0].Code)
}

func TestEngine_Validate_Failure(t *testing.T) {
	engine := NewEngine(nil)

	// Invalid card
	card := &agentcard.AgentCard{
		Name: "Bad Agent",
	}

	result, err := engine.Validate(context.Background(), card, false)

	assert.NoError(t, err)
	assert.False(t, result.Success)
	assert.Less(t, result.ComplianceScore, 50.0)

	// Should have errors
	hasError := false
	for _, issue := range result.Issues {
		if issue.Severity == "error" {
			hasError = true
			break
		}
	}
	assert.True(t, hasError)
}
