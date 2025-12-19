// Package report defines the structures for validation and scoring reports.
package report

import (
	"github.com/capiscio/capiscio-core/v2/pkg/crypto"
)

// ValidationResult contains the complete results of an Agent Card validation.
type ValidationResult struct {
	Success         bool                                `json:"success"`
	ComplianceScore float64                             `json:"complianceScore"`
	TrustScore      float64                             `json:"trustScore"`
	Availability    AvailabilityResult                  `json:"availability"`
	Issues          []ValidationIssue                   `json:"issues"`
	Signatures      *crypto.SignatureVerificationResult `json:"signatures,omitempty"`
}

// AvailabilityResult contains the results of availability testing.
type AvailabilityResult struct {
	Score       float64 `json:"score"`
	Tested      bool    `json:"tested"`
	EndpointURL string  `json:"endpointUrl,omitempty"`
	LatencyMS   int64   `json:"latencyMs,omitempty"`
	Error       string  `json:"error,omitempty"`
}

// ValidationIssue represents a specific problem found during validation.
type ValidationIssue struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	Severity string `json:"severity"` // "error", "warning", "info"
	Field    string `json:"field,omitempty"`
}

// AddError adds an error issue to the result.
func (r *ValidationResult) AddError(code, message, field string) {
	r.Issues = append(r.Issues, ValidationIssue{
		Code:     code,
		Message:  message,
		Severity: "error",
		Field:    field,
	})
	r.Success = false
}

// AddWarning adds a warning issue to the result.
func (r *ValidationResult) AddWarning(code, message, field string) {
	r.Issues = append(r.Issues, ValidationIssue{
		Code:     code,
		Message:  message,
		Severity: "warning",
		Field:    field,
	})
}
