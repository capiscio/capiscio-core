package scoring

import (
	"context"
	"time"

	"github.com/capiscio/capiscio-core/pkg/agentcard"
	"github.com/capiscio/capiscio-core/pkg/crypto"
	"github.com/capiscio/capiscio-core/pkg/report"
)

// EngineConfig holds configuration for the scoring Engine.
type EngineConfig struct {
	// TrustedIssuers is a list of trusted JWKS URIs or Issuer IDs.
	// If empty, all valid signatures are considered "trusted" (low security mode).
	TrustedIssuers []string

	// JWKSCacheTTL is the time-to-live for cached JWKS. Default: 1 hour.
	JWKSCacheTTL time.Duration

	// HTTPTimeout is the timeout for availability checks. Default: 5 seconds.
	HTTPTimeout time.Duration
}

// DefaultEngineConfig returns a default configuration.
func DefaultEngineConfig() *EngineConfig {
	return &EngineConfig{
		TrustedIssuers: []string{},
		JWKSCacheTTL:   1 * time.Hour,
		HTTPTimeout:    5 * time.Second,
	}
}

// Engine is the main entry point for scoring and validation.
type Engine struct {
	config       *EngineConfig
	compliance   *ComplianceScorer
	trust        *TrustScorer
	availability *AvailabilityScorer
	verifier     *crypto.Verifier
}

// NewEngine creates a new scoring Engine with the provided configuration.
// If config is nil, default configuration is used.
func NewEngine(config *EngineConfig) *Engine {
	if config == nil {
		config = DefaultEngineConfig()
	}

	// Configure components
	jwksFetcher := crypto.NewDefaultJWKSFetcher()
	if config.JWKSCacheTTL > 0 {
		jwksFetcher.SetTTL(config.JWKSCacheTTL)
	}
	verifier := crypto.NewVerifierWithFetcher(jwksFetcher)

	trustScorer := NewTrustScorer(config.TrustedIssuers)
	availabilityScorer := NewAvailabilityScorer(config.HTTPTimeout)

	return &Engine{
		config:       config,
		compliance:   NewComplianceScorer(),
		trust:        trustScorer,
		availability: availabilityScorer,
		verifier:     verifier,
	}
}

// Validate performs a full validation of the Agent Card.
func (e *Engine) Validate(ctx context.Context, card *agentcard.AgentCard, checkAvailability bool) (*report.ValidationResult, error) {
	result := &report.ValidationResult{
		Success: true,
	}

	// 1. Compliance Scoring
	compScore, compIssues := e.compliance.Score(card)
	result.ComplianceScore = compScore
	result.Issues = append(result.Issues, compIssues...)

	// 2. Signature Verification
	sigResult, err := e.verifier.VerifyAgentCardSignatures(ctx, card)
	if err != nil {
		// System error during verification (e.g. network fail), not necessarily invalid sig
		result.AddError("VERIFICATION_ERROR", "Failed to execute signature verification: "+err.Error(), "")
	}
	result.Signatures = sigResult

	// 3. Trust Scoring
	trustScore, trustIssues := e.trust.Score(sigResult)
	result.TrustScore = trustScore
	result.Issues = append(result.Issues, trustIssues...)

	// 4. Availability Scoring (Optional)
	if checkAvailability {
		availResult := e.availability.Score(ctx, card)
		result.Availability = availResult
		if availResult.Error != "" {
			result.AddWarning("AVAILABILITY_CHECK_FAILED", availResult.Error, "url")
		}
	}

	// 5. Determine overall success
	for _, issue := range result.Issues {
		if issue.Severity == "error" {
			result.Success = false
			break
		}
	}

	return result, nil
}
