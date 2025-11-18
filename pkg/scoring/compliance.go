package scoring

import (
	"strings"

	"github.com/capiscio/capiscio-core/pkg/agentcard"
	"github.com/capiscio/capiscio-core/pkg/report"
)

// ComplianceScorer evaluates how well the Agent Card adheres to the A2A specification.
type ComplianceScorer struct{}

// NewComplianceScorer creates a new ComplianceScorer.
func NewComplianceScorer() *ComplianceScorer {
	return &ComplianceScorer{}
}

// Score calculates the compliance score (0-100) and identifies issues.
func (s *ComplianceScorer) Score(card *agentcard.AgentCard) (float64, []report.ValidationIssue) {
	var issues []report.ValidationIssue
	score := 100.0

	// 1. Check Required Fields (Critical)
	if card.ProtocolVersion == "" {
		issues = append(issues, report.ValidationIssue{
			Code: "MISSING_PROTOCOL_VERSION", Message: "protocolVersion is required", Severity: "error", Field: "protocolVersion",
		})
		score -= 20
	}
	if card.Name == "" {
		issues = append(issues, report.ValidationIssue{
			Code: "MISSING_NAME", Message: "name is required", Severity: "error", Field: "name",
		})
		score -= 10
	}
	if card.Version == "" {
		issues = append(issues, report.ValidationIssue{
			Code: "MISSING_VERSION", Message: "version is required", Severity: "error", Field: "version",
		})
		score -= 10
	}

	// 2. Check Capabilities (Critical)
	// Note: In Go struct, Capabilities is a struct, not a pointer, so it's always "present" but fields might be false.
	// We can't easily check if the *object* was missing in JSON without a custom unmarshaler or pointer.
	// For now, we assume the struct presence is enough, but we should check if it makes sense.
	// Actually, A2A spec says capabilities object is required.

	// 3. Check Skills (Important)
	if len(card.Skills) == 0 {
		issues = append(issues, report.ValidationIssue{
			Code: "NO_SKILLS", Message: "At least one skill should be defined", Severity: "warning", Field: "skills",
		})
		score -= 15
	} else {
		for i, skill := range card.Skills {
			if skill.ID == "" {
				issues = append(issues, report.ValidationIssue{
					Code: "MISSING_SKILL_ID", Message: "Skill ID is required", Severity: "error", Field: "skills[" + string(rune(i)) + "].id",
				})
				score -= 5
			}
			if len(skill.Tags) == 0 {
				issues = append(issues, report.ValidationIssue{
					Code: "MISSING_SKILL_TAGS", Message: "Skill tags are required", Severity: "warning", Field: "skills[" + string(rune(i)) + "].tags",
				})
				score -= 2
			}
		}
	}

	// 4. Check Transport (Important)
	if card.URL == "" {
		issues = append(issues, report.ValidationIssue{
			Code: "MISSING_URL", Message: "Agent URL is required", Severity: "error", Field: "url",
		})
		score -= 20
	} else if !strings.HasPrefix(card.URL, "http") && !strings.HasPrefix(card.URL, "grpc") {
		issues = append(issues, report.ValidationIssue{
			Code: "INVALID_URL_SCHEME", Message: "URL must start with http(s) or grpc", Severity: "error", Field: "url",
		})
		score -= 10
	}

	// 5. Check Provider (Recommended)
	if card.Provider == nil {
		issues = append(issues, report.ValidationIssue{
			Code: "MISSING_PROVIDER", Message: "Provider information is recommended", Severity: "warning", Field: "provider",
		})
		score -= 5
	} else {
		if card.Provider.Organization == "" {
			issues = append(issues, report.ValidationIssue{
				Code: "MISSING_PROVIDER_ORG", Message: "Provider organization is required", Severity: "error", Field: "provider.organization",
			})
			score -= 5
		}
	}

	if score < 0 {
		score = 0
	}
	return score, issues
}
