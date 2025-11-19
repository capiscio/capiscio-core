package scoring

import (
	"testing"

	"github.com/capiscio/capiscio-core/pkg/agentcard"
	"github.com/stretchr/testify/assert"
)

func TestComplianceScorer_Score_PerfectCard(t *testing.T) {
	scorer := NewComplianceScorer()
	card := &agentcard.AgentCard{
		ProtocolVersion: "0.3.0",
		Name:            "Perfect Agent",
		Version:         "1.0.0",
		URL:             "https://example.com/agent",
		Skills: []agentcard.AgentSkill{
			{ID: "skill-1", Name: "Skill 1", Description: "Desc", Tags: []string{"tag1"}},
		},
		Provider: &agentcard.AgentProvider{
			Organization: "Acme Corp",
			URL:          "https://acme.com",
		},
	}

	score, issues := scorer.Score(card)
	assert.Equal(t, 100.0, score)
	assert.Empty(t, issues)
}

func TestComplianceScorer_Score_MissingRequiredFields(t *testing.T) {
	scorer := NewComplianceScorer()
	card := &agentcard.AgentCard{
		// Missing ProtocolVersion, Name, Version, URL
	}

	score, issues := scorer.Score(card)

	// Expected penalties:
	// -20 ProtocolVersion
	// -10 Name
	// -10 Version
	// -20 URL
	// -15 No Skills
	// -5 Missing Provider
	// Total: -80 -> Score 20

	assert.Equal(t, 20.0, score)
	assert.Len(t, issues, 6)

	codes := make([]string, len(issues))
	for i, issue := range issues {
		codes[i] = issue.Code
	}

	assert.Contains(t, codes, "MISSING_PROTOCOL_VERSION")
	assert.Contains(t, codes, "MISSING_NAME")
	assert.Contains(t, codes, "MISSING_VERSION")
	assert.Contains(t, codes, "MISSING_URL")
	assert.Contains(t, codes, "NO_SKILLS")
	assert.Contains(t, codes, "MISSING_PROVIDER")
}

func TestComplianceScorer_Score_InvalidURL(t *testing.T) {
	scorer := NewComplianceScorer()
	card := &agentcard.AgentCard{
		ProtocolVersion: "0.3.0",
		Name:            "Agent",
		Version:         "1.0.0",
		URL:             "ftp://example.com", // Invalid scheme
		Skills: []agentcard.AgentSkill{
			{ID: "s1", Tags: []string{"t1"}},
		},
		Provider: &agentcard.AgentProvider{Organization: "Org", URL: "url"},
	}

	score, issues := scorer.Score(card)
	// -10 for invalid URL scheme
	assert.Equal(t, 90.0, score)
	assert.Contains(t, issues[0].Code, "INVALID_URL_SCHEME")
}

func TestComplianceScorer_Score_SkillIssues(t *testing.T) {
	scorer := NewComplianceScorer()
	card := &agentcard.AgentCard{
		ProtocolVersion: "0.3.0",
		Name:            "Agent",
		Version:         "1.0.0",
		URL:             "https://example.com",
		Skills: []agentcard.AgentSkill{
			{ID: "", Tags: []string{"t1"}}, // Missing ID (-5)
			{ID: "s2", Tags: []string{}},   // Missing Tags (-2)
		},
		Provider: &agentcard.AgentProvider{Organization: "Org", URL: "url"},
	}

	score, issues := scorer.Score(card)
	// -5 missing ID
	// -2 missing tags
	assert.Equal(t, 93.0, score)
	assert.Len(t, issues, 2)
}
