package scoring

import (
	"github.com/capiscio/capiscio-core/pkg/crypto"
	"github.com/capiscio/capiscio-core/pkg/report"
)

// TrustScorer evaluates the trustworthiness of the Agent Card.
type TrustScorer struct {
	trustedIssuers []string
}

// NewTrustScorer creates a new TrustScorer with optional trusted issuers.
func NewTrustScorer(trustedIssuers []string) *TrustScorer {
	return &TrustScorer{
		trustedIssuers: trustedIssuers,
	}
}

// Score calculates the trust score (0-100) based on signatures and other factors.
func (s *TrustScorer) Score(sigResult *crypto.SignatureVerificationResult) (float64, []report.ValidationIssue) {
	var issues []report.ValidationIssue
	score := 0.0

	// 1. Signature Verification (Primary Factor)
	if sigResult == nil || len(sigResult.Signatures) == 0 {
		issues = append(issues, report.ValidationIssue{
			Code: "NO_SIGNATURES", Message: "Agent Card is unsigned", Severity: "warning",
		})
		// Base score for unsigned cards is low
		score = 20.0
	} else if sigResult.Valid {
		// Valid signatures boost trust significantly

		// Check if signature is from a Trusted Issuer
		isTrusted := false
		if len(s.trustedIssuers) > 0 {
			for _, sig := range sigResult.Signatures {
				if sig.Valid {
					for _, trusted := range s.trustedIssuers {
						if sig.JWKSUri == trusted {
							isTrusted = true
							break
						}
					}
				}
				if isTrusted {
					break
				}
			}

			if isTrusted {
				score = 100.0 // Max trust for trusted issuer
			} else {
				score = 60.0 // Reduced trust for valid but untrusted issuer
				issues = append(issues, report.ValidationIssue{
					Code: "UNTRUSTED_ISSUER", Message: "Signature is valid but issuer is not in trusted list", Severity: "info",
				})
			}
		} else {
			// No trusted issuers configured, so any valid signature is "trusted" enough
			score = 80.0
		}

		// Check for secure algorithms
		for _, sig := range sigResult.Signatures {
			if sig.Algorithm == "RS256" || sig.Algorithm == "ES256" {
				// Standard secure algorithms
			} else {
				// Could penalize weak algos if we supported them, but verifier rejects 'none'
			}
		}

	} else {
		// Signatures present but invalid - this is worse than no signatures
		issues = append(issues, report.ValidationIssue{
			Code: "INVALID_SIGNATURES", Message: "Agent Card has invalid signatures", Severity: "error",
		})
		score = 0.0
		for _, err := range sigResult.Summary.Errors {
			issues = append(issues, report.ValidationIssue{
				Code: "SIGNATURE_ERROR", Message: err, Severity: "error",
			})
		}
	}

	// Future: Domain Verification (DNS-TXT), Registry Reputation, etc.

	return score, issues
}
