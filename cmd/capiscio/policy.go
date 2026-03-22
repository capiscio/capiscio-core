package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/policy"
	"github.com/spf13/cobra"
)

var (
	policyFile      string
	policyServerURL string
	policyAPIKey    string
	policyOutput    string
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Policy configuration management",
	Long:  `Manage CapiscIO YAML policy configuration files. Validate configs locally or fetch policy context from the registry.`,
}

var policyValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate a YAML policy config file",
	Long: `Validate a CapiscIO YAML policy configuration file locally.
No network access is required. Checks schema version, trust levels,
DID formats, rate limits, operation patterns, and MCP tool rules.`,
	Example: `  # Validate default config file
  capiscio policy validate

  # Validate a specific file
  capiscio policy validate -f my-policy.yaml

  # Validate and print parsed config (JSON)
  capiscio policy validate -f policy.yaml --json`,
	Args: cobra.NoArgs,
	RunE: runPolicyValidate,
}

var policyContextCmd = &cobra.Command{
	Use:   "context",
	Short: "Fetch policy context from registry",
	Long: `Fetch the aggregate policy context from the CapiscIO registry.
This calls GET /v1/sdk/policy-context and writes the result as JSON.

The API key must have appropriate permissions to access the policy context.
It can be provided via CAPISCIO_API_KEY environment variable or --api-key flag.`,
	Example: `  # Fetch context using env var
  export CAPISCIO_API_KEY=sk_live_...
  capiscio policy context

  # Fetch and write to file
  capiscio policy context -o policy-context.json

  # Custom registry
  capiscio policy context --registry https://my-registry.example.com`,
	Args: cobra.NoArgs,
	RunE: runPolicyContext,
}

var policyValidateJSON bool

func init() {
	// Validate flags
	policyValidateCmd.Flags().StringVarP(&policyFile, "file", "f", "capiscio-policy.yaml",
		"Path to YAML policy config file")
	policyValidateCmd.Flags().BoolVar(&policyValidateJSON, "json", false,
		"Output parsed config as JSON on success")

	// Context flags
	policyContextCmd.Flags().StringVar(&policyServerURL, "registry", defaultServerURL,
		"CapiscIO registry server URL")
	policyContextCmd.Flags().StringVar(&policyAPIKey, "api-key", "",
		"CapiscIO API key (prefer CAPISCIO_API_KEY env var)")
	policyContextCmd.Flags().StringVarP(&policyOutput, "output", "o", "",
		"Output file path (default: stdout)")

	policyCmd.AddCommand(policyValidateCmd)
	policyCmd.AddCommand(policyContextCmd)
	rootCmd.AddCommand(policyCmd)
}

func runPolicyValidate(_ *cobra.Command, _ []string) error {
	data, err := os.ReadFile(policyFile)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", policyFile, err)
	}

	cfg, err := policy.Parse(data)
	if err != nil {
		return fmt.Errorf("❌ Validation failed for %s:\n%s", policyFile, err.Error())
	}

	if policyValidateJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(cfg); err != nil {
			return fmt.Errorf("JSON encode: %w", err)
		}
		return nil
	}

	fmt.Printf("✅ %s is valid (version %s, min_trust_level: %s)\n", policyFile, cfg.Version, cfg.MinTrustLevel)

	// Print summary
	if len(cfg.AllowedDIDs) > 0 {
		fmt.Printf("   allowed_dids: %d\n", len(cfg.AllowedDIDs))
	}
	if len(cfg.DeniedDIDs) > 0 {
		fmt.Printf("   denied_dids: %d\n", len(cfg.DeniedDIDs))
	}
	if len(cfg.RateLimits) > 0 {
		fmt.Printf("   rate_limits: %d rules\n", len(cfg.RateLimits))
	}
	if len(cfg.Operations) > 0 {
		fmt.Printf("   operations: %d rules\n", len(cfg.Operations))
	}
	if len(cfg.MCPTools) > 0 {
		fmt.Printf("   mcp_tools: %d rules\n", len(cfg.MCPTools))
	}

	return nil
}

func runPolicyContext(_ *cobra.Command, _ []string) error {
	apiKey := policyAPIKey
	if apiKey == "" {
		apiKey = os.Getenv("CAPISCIO_API_KEY")
	}
	if apiKey == "" {
		return fmt.Errorf("API key required: set CAPISCIO_API_KEY or use --api-key")
	}

	serverURL := strings.TrimSuffix(policyServerURL, "/")
	url := serverURL + "/v1/sdk/policy-context"

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("X-Capiscio-Registry-Key", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	// Pretty-print JSON
	var parsed interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("invalid JSON response: %w", err)
	}

	var output []byte
	output, err = json.MarshalIndent(parsed, "", "  ")
	if err != nil {
		return fmt.Errorf("format JSON: %w", err)
	}

	if policyOutput != "" {
		if err := os.WriteFile(policyOutput, append(output, '\n'), 0644); err != nil {
			return fmt.Errorf("write output file: %w", err)
		}
		fmt.Printf("✅ Policy context written to %s\n", policyOutput)
		return nil
	}

	fmt.Println(string(output))
	return nil
}
