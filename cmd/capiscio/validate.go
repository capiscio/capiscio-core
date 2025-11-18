package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/capiscio/capiscio-core/pkg/agentcard"
	"github.com/capiscio/capiscio-core/pkg/scoring"
	"github.com/spf13/cobra"
)

var (
	flagJSON     bool
	flagLive     bool
	flagInsecure bool
)

func init() {
	validateCmd.Flags().BoolVar(&flagJSON, "json", false, "Output results as JSON")
	validateCmd.Flags().BoolVar(&flagLive, "live", false, "Perform live availability checks")
	validateCmd.Flags().BoolVar(&flagInsecure, "insecure", false, "Allow insecure (HTTP) JWKS fetching")
	rootCmd.AddCommand(validateCmd)
}

var validateCmd = &cobra.Command{
	Use:   "validate [file-or-url]",
	Short: "Validate an Agent Card",
	Long:  `Validate an Agent Card from a local file or URL. Checks compliance, verifies signatures, and optionally tests availability.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		input := args[0]
		var cardData []byte
		var err error

		// 1. Load Data
		if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
			resp, err := http.Get(input)
			if err != nil {
				return fmt.Errorf("failed to fetch URL: %w", err)
			}
			defer resp.Body.Close()
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
		// Use default config for CLI for now
		engine := scoring.NewEngine(nil)
		// TODO: Pass insecure flag to verifier if needed (requires engine update)
		
		ctx := context.Background()
		result, err := engine.Validate(ctx, &card, flagLive)
		if err != nil {
			return fmt.Errorf("validation engine error: %w", err)
		}

		// 4. Output Results
		if flagJSON {
			encoder := json.NewEncoder(os.Stdout)
			encoder.SetIndent("", "  ")
			return encoder.Encode(result)
		}

		// Text Output
		fmt.Printf("Validation Results for: %s\n", card.Name)
		fmt.Println("----------------------------------------")
		fmt.Printf("Success:          %v\n", result.Success)
		fmt.Printf("Compliance Score: %.1f/100\n", result.ComplianceScore)
		fmt.Printf("Trust Score:      %.1f/100\n", result.TrustScore)
		
		if result.Availability.Tested {
			fmt.Printf("Availability:     %.1f/100 (Latency: %dms)\n", result.Availability.Score, result.Availability.LatencyMS)
		}

		if len(result.Issues) > 0 {
			fmt.Println("\nIssues:")
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
