package scoring

import (
	"fmt"
	"regexp"

	"github.com/capiscio/capiscio-core/pkg/agentcard"
	"github.com/capiscio/capiscio-core/pkg/report"
)

// ComplianceScorer evaluates how well the Agent Card adheres to the A2A specification.
type ComplianceScorer struct {
	config *ComplianceConfig
}

// ComplianceConfig holds configuration for the ComplianceScorer.
type ComplianceConfig struct {
	AllowPrivateIPs bool
}

// NewComplianceScorer creates a new ComplianceScorer.
func NewComplianceScorer(config *ComplianceConfig) *ComplianceScorer {
	if config == nil {
		config = &ComplianceConfig{
			AllowPrivateIPs: false,
		}
	}
	return &ComplianceScorer{
		config: config,
	}
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
	} else {
		// Validate SemVer
		if !isValidSemVer(card.ProtocolVersion) {
			issues = append(issues, report.ValidationIssue{
				Code: "INVALID_PROTOCOL_VERSION", Message: "protocolVersion must be a valid SemVer string", Severity: "error", Field: "protocolVersion",
			})
			score -= 10
		}
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
					Code: "MISSING_SKILL_ID", Message: "Skill ID is required", Severity: "error", Field: fmt.Sprintf("skills[%d].id", i),
				})
				score -= 5
			}
			if len(skill.Tags) == 0 {
				issues = append(issues, report.ValidationIssue{
					Code: "MISSING_SKILL_TAGS", Message: "Skill tags are required", Severity: "warning", Field: fmt.Sprintf("skills[%d].tags", i),
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
	} else {
		// Use URLValidator
		urlVal := NewURLValidator(s.config.AllowPrivateIPs)
		urlIssues := urlVal.Validate(card.URL, "url")
		issues = append(issues, urlIssues...)
		if len(urlIssues) > 0 {
			score -= 10
		}
	}

	if card.PreferredTransport != "" {
		validTransports := map[string]bool{
			"JSONRPC":   true,
			"GRPC":      true,
			"HTTP+JSON": true,
		}
		if !validTransports[string(card.PreferredTransport)] {
			issues = append(issues, report.ValidationIssue{
				Code: "INVALID_TRANSPORT", Message: "Invalid transport protocol. Valid options: JSONRPC, GRPC, HTTP+JSON", Severity: "error", Field: "preferredTransport",
			})
			score -= 10
		}
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

	// 6. Check Additional Interfaces
	if len(card.AdditionalInterfaces) > 0 {
		urlVal := NewURLValidator(s.config.AllowPrivateIPs)
		for i, iface := range card.AdditionalInterfaces {
			if iface.URL == "" {
				issues = append(issues, report.ValidationIssue{
					Code: "MISSING_INTERFACE_URL", Message: "Interface URL is required", Severity: "error", Field: fmt.Sprintf("additionalInterfaces[%d].url", i),
				})
				score -= 5
			} else {
				urlIssues := urlVal.Validate(iface.URL, fmt.Sprintf("additionalInterfaces[%d].url", i))
				issues = append(issues, urlIssues...)
				if len(urlIssues) > 0 {
					score -= 2
				}
			}
			if iface.Transport == "" {
				issues = append(issues, report.ValidationIssue{
					Code: "MISSING_INTERFACE_TRANSPORT", Message: "Interface transport is required", Severity: "error", Field: fmt.Sprintf("additionalInterfaces[%d].transport", i),
				})
				score -= 5
			}
		}
	}

	if score < 0 {
		score = 0
	}
	return score, issues
}

// isValidSemVer checks if a string is a valid Semantic Version.
// This is a simplified regex for SemVer 2.0.0.
func isValidSemVer(v string) bool {
	// Regex from https://semver.org/
	re := regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)
	return re.MatchString(v)
}
