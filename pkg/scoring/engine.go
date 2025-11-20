package scoring

import (
	"context"
	"time"

	"github.com/capiscio/capiscio-core/pkg/agentcard"
	"github.com/capiscio/capiscio-core/pkg/crypto"
	"github.com/capiscio/capiscio-core/pkg/report"
)

// ValidationMode determines the strictness of the validation.
type ValidationMode string

const (
	// ModeProgressive is the default mode. Standard checks, allows some warnings.
	ModeProgressive ValidationMode = "progressive"
	// ModeStrict fails on ANY warning or error.
	ModeStrict ValidationMode = "strict"
	// ModeConservative only fails on critical errors, ignores best practices.
	ModeConservative ValidationMode = "conservative"
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

	// Mode determines the validation strictness. Default: ModeProgressive.
	Mode ValidationMode

	// SkipSignatureVerification disables JWS signature verification.
	SkipSignatureVerification bool

	// SchemaOnly skips logic and network checks, validating only the JSON structure.
	SchemaOnly bool

	// RegistryReady enables additional checks required for registry submission.
	RegistryReady bool

	// AllowPrivateIPs allows URLs to resolve to private IP addresses.
	AllowPrivateIPs bool
}

// DefaultEngineConfig returns a default configuration.
func DefaultEngineConfig() *EngineConfig {
	return &EngineConfig{
		TrustedIssuers: []string{},
		JWKSCacheTTL:   1 * time.Hour,
		HTTPTimeout:    5 * time.Second,
		Mode:           ModeProgressive,
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

	complianceConfig := &ComplianceConfig{
		AllowPrivateIPs: config.AllowPrivateIPs,
	}

	return &Engine{
		config:       config,
		compliance:   NewComplianceScorer(complianceConfig),
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

	// Override checkAvailability if SchemaOnly is set
	if e.config.SchemaOnly {
		checkAvailability = false
	}

	// 1. Compliance Scoring
	compScore, compIssues := e.compliance.Score(card)
	result.ComplianceScore = compScore
	result.Issues = append(result.Issues, compIssues...)

	// 2. Signature Verification
	if !e.config.SchemaOnly && !e.config.SkipSignatureVerification {
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
	} else {
		// Ensure fields are initialized when signature verification and trust scoring are skipped
		result.Signatures = nil
		result.TrustScore = 0
	}

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
		if e.config.Mode == ModeStrict && issue.Severity == "warning" {
			result.Success = false
			break
		}
	}

	return result, nil
}
