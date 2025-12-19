package scoring

import (
	"fmt"
	"regexp"

	"github.com/capiscio/capiscio-core/v2/pkg/agentcard"
	"github.com/capiscio/capiscio-core/v2/pkg/report"
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
	reqIssues, reqPenalty := s.checkRequiredFields(card)
	issues = append(issues, reqIssues...)
	score -= reqPenalty

	// 2. Check Skills (Important)
	skillIssues, skillPenalty := s.checkSkills(card)
	issues = append(issues, skillIssues...)
	score -= skillPenalty

	// 3. Check Transport (Important)
	transIssues, transPenalty := s.checkTransport(card)
	issues = append(issues, transIssues...)
	score -= transPenalty

	// 4. Check Provider (Recommended)
	provIssues, provPenalty := s.checkProvider(card)
	issues = append(issues, provIssues...)
	score -= provPenalty

	// 5. Check Additional Interfaces
	ifaceIssues, ifacePenalty := s.checkAdditionalInterfaces(card)
	issues = append(issues, ifaceIssues...)
	score -= ifacePenalty

	if score < 0 {
		score = 0
	}
	return score, issues
}

func (s *ComplianceScorer) checkRequiredFields(card *agentcard.AgentCard) ([]report.ValidationIssue, float64) {
	var issues []report.ValidationIssue
	var penalty float64

	if card.ProtocolVersion == "" {
		issues = append(issues, report.ValidationIssue{
			Code: "MISSING_PROTOCOL_VERSION", Message: "protocolVersion is required", Severity: "error", Field: "protocolVersion",
		})
		penalty += 20
	} else {
		if !isValidSemVer(card.ProtocolVersion) {
			issues = append(issues, report.ValidationIssue{
				Code: "INVALID_PROTOCOL_VERSION", Message: "protocolVersion must be a valid SemVer string", Severity: "error", Field: "protocolVersion",
			})
			penalty += 10
		}
	}

	if card.Name == "" {
		issues = append(issues, report.ValidationIssue{
			Code: "MISSING_NAME", Message: "name is required", Severity: "error", Field: "name",
		})
		penalty += 10
	}
	if card.Version == "" {
		issues = append(issues, report.ValidationIssue{
			Code: "MISSING_VERSION", Message: "version is required", Severity: "error", Field: "version",
		})
		penalty += 10
	}

	return issues, penalty
}

func (s *ComplianceScorer) checkSkills(card *agentcard.AgentCard) ([]report.ValidationIssue, float64) {
	var issues []report.ValidationIssue
	var penalty float64

	if len(card.Skills) == 0 {
		issues = append(issues, report.ValidationIssue{
			Code: "NO_SKILLS", Message: "At least one skill should be defined", Severity: "warning", Field: "skills",
		})
		penalty += 15
	} else {
		for i, skill := range card.Skills {
			if skill.ID == "" {
				issues = append(issues, report.ValidationIssue{
					Code: "MISSING_SKILL_ID", Message: "Skill ID is required", Severity: "error", Field: fmt.Sprintf("skills[%d].id", i),
				})
				penalty += 5
			}
			if len(skill.Tags) == 0 {
				issues = append(issues, report.ValidationIssue{
					Code: "MISSING_SKILL_TAGS", Message: "Skill tags are required", Severity: "warning", Field: fmt.Sprintf("skills[%d].tags", i),
				})
				penalty += 2
			}
		}
	}
	return issues, penalty
}

func (s *ComplianceScorer) checkTransport(card *agentcard.AgentCard) ([]report.ValidationIssue, float64) {
	var issues []report.ValidationIssue
	var penalty float64

	if card.URL == "" {
		issues = append(issues, report.ValidationIssue{
			Code: "MISSING_URL", Message: "Agent URL is required", Severity: "error", Field: "url",
		})
		penalty += 20
	} else {
		urlVal := NewURLValidator(s.config.AllowPrivateIPs)
		urlIssues := urlVal.Validate(card.URL, "url")
		issues = append(issues, urlIssues...)
		for _, issue := range urlIssues {
			switch issue.Severity {
			case "error":
				penalty += 10
			case "warning":
				penalty += 2
			}
		}
	}

	if card.PreferredTransport != "" {
		validTransports := map[agentcard.TransportProtocol]bool{
			"JSONRPC":   true,
			"GRPC":      true,
			"HTTP+JSON": true,
		}
		if !validTransports[card.PreferredTransport] {
			issues = append(issues, report.ValidationIssue{
				Code: "INVALID_TRANSPORT", Message: "Invalid transport protocol. Valid options: JSONRPC, GRPC, HTTP+JSON", Severity: "error", Field: "preferredTransport",
			})
			penalty += 10
		}
	}
	return issues, penalty
}

func (s *ComplianceScorer) checkProvider(card *agentcard.AgentCard) ([]report.ValidationIssue, float64) {
	var issues []report.ValidationIssue
	var penalty float64

	if card.Provider == nil {
		issues = append(issues, report.ValidationIssue{
			Code: "MISSING_PROVIDER", Message: "Provider information is recommended", Severity: "warning", Field: "provider",
		})
		penalty += 5
	} else {
		if card.Provider.Organization == "" {
			issues = append(issues, report.ValidationIssue{
				Code: "MISSING_PROVIDER_ORG", Message: "Provider organization is required", Severity: "error", Field: "provider.organization",
			})
			penalty += 5
		}
	}
	return issues, penalty
}

func (s *ComplianceScorer) checkAdditionalInterfaces(card *agentcard.AgentCard) ([]report.ValidationIssue, float64) {
	var issues []report.ValidationIssue
	var penalty float64

	if len(card.AdditionalInterfaces) > 0 {
		urlVal := NewURLValidator(s.config.AllowPrivateIPs)
		for i, iface := range card.AdditionalInterfaces {
			if iface.URL == "" {
				issues = append(issues, report.ValidationIssue{
					Code: "MISSING_INTERFACE_URL", Message: "Interface URL is required", Severity: "error", Field: fmt.Sprintf("additionalInterfaces[%d].url", i),
				})
				penalty += 5
			} else {
				urlIssues := urlVal.Validate(iface.URL, fmt.Sprintf("additionalInterfaces[%d].url", i))
				issues = append(issues, urlIssues...)
				for _, issue := range urlIssues {
					switch issue.Severity {
					case "error":
						penalty += 2
					case "warning":
						penalty++
					}
				}
			}
			if iface.Transport == "" {
				issues = append(issues, report.ValidationIssue{
					Code: "MISSING_INTERFACE_TRANSPORT", Message: "Interface transport is required", Severity: "error", Field: fmt.Sprintf("additionalInterfaces[%d].transport", i),
				})
				penalty += 5
			}
		}
	}
	return issues, penalty
}

var semVerRegex = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)

// isValidSemVer checks if a string is a valid Semantic Version.
func isValidSemVer(v string) bool {
	return semVerRegex.MatchString(v)
}
