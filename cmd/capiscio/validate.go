package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/capiscio/capiscio-core/pkg/agentcard"
	"github.com/capiscio/capiscio-core/pkg/report"
	"github.com/capiscio/capiscio-core/pkg/scoring"
	"github.com/spf13/cobra"
)

var (
	flagJSON          bool
	flagLive          bool
	flagTestLive      bool
	flagInsecure      bool
	flagStrict        bool
	flagProgressive   bool
	flagConservative  bool
	flagSkipSignature bool
	flagSchemaOnly    bool
	flagRegistryReady bool
	flagTimeout       time.Duration
	flagErrorsOnly    bool
	flagVerbose       bool
)

func init() {
	validateCmd.Flags().BoolVar(&flagJSON, "json", false, "Output results as JSON")
	validateCmd.Flags().BoolVar(&flagLive, "live", false, "Perform live availability checks (deprecated, use --test-live)")
	validateCmd.Flags().BoolVar(&flagTestLive, "test-live", false, "Test live agent endpoint")
	validateCmd.Flags().BoolVar(&flagInsecure, "insecure", false, "Allow insecure (HTTP) JWKS fetching")
	validateCmd.Flags().BoolVar(&flagStrict, "strict", false, "Enable strict validation mode")
	validateCmd.Flags().BoolVar(&flagProgressive, "progressive", false, "Enable progressive validation mode (default)")
	validateCmd.Flags().BoolVar(&flagConservative, "conservative", false, "Enable conservative validation mode")
	validateCmd.Flags().BoolVar(&flagSkipSignature, "skip-signature", false, "Skip JWS signature verification")
	validateCmd.Flags().BoolVar(&flagSchemaOnly, "schema-only", false, "Validate schema only, skip endpoint testing")
	validateCmd.Flags().BoolVar(&flagRegistryReady, "registry-ready", false, "Check registry deployment readiness")
	validateCmd.Flags().DurationVar(&flagTimeout, "timeout", 10*time.Second, "Request timeout")
	validateCmd.Flags().BoolVar(&flagErrorsOnly, "errors-only", false, "Show only errors and warnings")
	validateCmd.Flags().BoolVar(&flagVerbose, "verbose", false, "Show detailed validation steps")

	rootCmd.AddCommand(validateCmd)
}

var validateCmd = &cobra.Command{
	Use:   "validate [file-or-url]",
	Short: "Validate an Agent Card",
	Long:  `Validate an Agent Card from a local file or URL. Checks compliance, verifies signatures, and optionally tests availability.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		if flagLive {
			fmt.Fprintln(os.Stderr, "Warning: --live is deprecated and will be removed in v1.1.0. Please use --test-live instead.")
		}

		input := args[0]
		var cardData []byte
		var err error

		// 1. Load Data
		if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
			resp, err := http.Get(input)
			if err != nil {
				return fmt.Errorf("failed to fetch URL: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()
			cardData, err = io.ReadAll(resp.Body)
			if err != nil {
				return fmt.Errorf("failed to read response body: %w", err)
			}
		} else {
			cardData, err = os.ReadFile(input)
			if err != nil {
				return fmt.Errorf("failed to read file: %w", err)
			}
		}

		// 2. Parse Agent Card
		var card agentcard.AgentCard
		if err := json.Unmarshal(cardData, &card); err != nil {
			return fmt.Errorf("failed to parse Agent Card JSON: %w", err)
		}

		// 3. Run Validation Engine
		mode := scoring.ModeProgressive
		if flagStrict || flagRegistryReady {
			mode = scoring.ModeStrict
		} else if flagConservative {
			mode = scoring.ModeConservative
		}

		config := &scoring.EngineConfig{
			Mode:                      mode,
			SkipSignatureVerification: flagSkipSignature,
			SchemaOnly:                flagSchemaOnly,
			RegistryReady:             flagRegistryReady,
			HTTPTimeout:               flagTimeout,
			TrustedIssuers:            []string{}, // TODO: Add flag for trusted issuers
			JWKSCacheTTL:              1 * time.Hour,
		}

		engine := scoring.NewEngine(config)
		// TODO: Pass insecure flag to verifier if needed (requires engine update)

		ctx := context.Background()
		checkLive := (flagLive || flagTestLive) && !flagSchemaOnly
		result, err := engine.Validate(ctx, &card, checkLive)
		if err != nil {
			return fmt.Errorf("validation engine error: %w", err)
		}

		// 4. Output Results
		if flagJSON {
			output := adaptToCLIOutput(result, &card)
			encoder := json.NewEncoder(os.Stdout)
			encoder.SetIndent("", "  ")
			err := encoder.Encode(output)
			if err != nil {
				return err
			}
			if !result.Success {
				os.Exit(1)
			}
			return nil
		}

		// Text Output
		if !flagErrorsOnly {
			if result.Success {
				fmt.Println("✅ A2A AGENT VALIDATION PASSED")
			} else {
				fmt.Println("❌ A2A AGENT VALIDATION FAILED")
			}

			fmt.Printf("Score: %.0f/100\n", result.ComplianceScore)
			fmt.Printf("Version: %s\n", card.ProtocolVersion) // Assuming ProtocolVersion is available in card

			if result.Success && len(result.Issues) == 0 {
				fmt.Println("Perfect! Your agent passes all validations")
			} else if result.Success {
				fmt.Println("Agent passed with warnings")
			}
		}

		if len(result.Issues) > 0 {
			if !flagErrorsOnly {
				fmt.Println("\nERRORS FOUND:")
			}
			for _, issue := range result.Issues {
				icon := "⚠️"
				if issue.Severity == "error" {
					icon = "❌"
				}
				fmt.Printf("%s [%s] %s: %s\n", icon, issue.Code, issue.Severity, issue.Message)
			}
		}

		if !result.Success {
			os.Exit(1)
		}

		return nil
	},
}

type CLIOutput struct {
	Success       bool                     `json:"success"`
	Score         float64                  `json:"score"`
	Version       string                   `json:"version"`
	Errors        []report.ValidationIssue `json:"errors"`
	Warnings      []report.ValidationIssue `json:"warnings"`
	ScoringResult *report.ValidationResult `json:"scoringResult"`
	LiveTest      *CLILiveTestResult       `json:"liveTest,omitempty"`
}

type CLILiveTestResult struct {
	Success      bool     `json:"success"`
	Endpoint     string   `json:"endpoint"`
	ResponseTime int64    `json:"responseTime"`
	Errors       []string `json:"errors"`
}

func adaptToCLIOutput(r *report.ValidationResult, card *agentcard.AgentCard) CLIOutput {
	errors := []report.ValidationIssue{}
	warnings := []report.ValidationIssue{}

	for _, issue := range r.Issues {
		switch issue.Severity {
		case "error":
			errors = append(errors, issue)
		case "warning":
			warnings = append(warnings, issue)
		}
	}

	out := CLIOutput{
		Success:       r.Success,
		Score:         r.ComplianceScore, // Use compliance score as main score for now
		Version:       card.ProtocolVersion,
		Errors:        errors,
		Warnings:      warnings,
		ScoringResult: r,
	}

	if r.Availability.Tested {
		out.LiveTest = &CLILiveTestResult{
			Success:      r.Availability.Error == "",
			Endpoint:     r.Availability.EndpointURL,
			ResponseTime: r.Availability.LatencyMS,
			Errors:       []string{},
		}
		if r.Availability.Error != "" {
			out.LiveTest.Errors = []string{r.Availability.Error}
		}
	}

	return out
}
