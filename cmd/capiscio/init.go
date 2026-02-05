package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/did"
	"github.com/go-jose/go-jose/v4"
	"github.com/spf13/cobra"
)

var (
	// Init command flags
	initAPIKey    string
	initAgentID   string
	initAgentName string
	initServerURL string
	initOutputDir string
	initAutoBadge bool
	initForce     bool
)

// Default server URL
const defaultServerURL = "https://registry.capisc.io"

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new agent identity",
	Long: `Initialize a new CapiscIO agent identity with a single command.

This is the "Let's Encrypt" style setup for agents - one command does everything:
  1. Generates Ed25519 keypair
  2. Derives did:key identifier  
  3. Registers DID with the CapiscIO registry
  4. Requests initial Trust Badge (optional)
  5. Creates agent-card.json with x-capiscio extension

The API key can be provided via:
  - Environment variable: CAPISCIO_API_KEY (recommended)
  - Flag: --api-key (visible in process list, use with caution)

Output files are created in ~/.capiscio/keys/{agent-id}/:
  - private.jwk   (0600 permissions - keep secret!)
  - public.jwk
  - did.txt
  - agent-card.json
  - badge.jwt     (if --auto-badge is true)`,
	Example: `  # Initialize using environment variable (recommended)
  export CAPISCIO_API_KEY=sk_live_...
  capiscio init --agent-id my-agent-001

  # Initialize with specific agent ID and name
  capiscio init --agent-id my-agent-001 --name "My Research Agent"

  # Initialize without automatic badge (keys only)
  capiscio init --agent-id my-agent-001 --auto-badge=false

  # Initialize with custom output directory
  capiscio init --agent-id my-agent-001 --output ./my-agent-keys/

  # Re-initialize (overwrite existing keys - use with caution!)
  capiscio init --agent-id my-agent-001 --force`,
	RunE: runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)

	// API key - prefer environment variable
	initCmd.Flags().StringVar(&initAPIKey, "api-key", "",
		"CapiscIO API key (prefer CAPISCIO_API_KEY env var for security)")

	// Agent identification
	initCmd.Flags().StringVar(&initAgentID, "agent-id", "",
		"Agent ID (UUID) - if omitted, will use first agent from registry")
	initCmd.Flags().StringVar(&initAgentName, "name", "",
		"Agent name (for display purposes)")

	// Server configuration
	initCmd.Flags().StringVar(&initServerURL, "server", defaultServerURL,
		"CapiscIO registry server URL")

	// Output configuration
	initCmd.Flags().StringVar(&initOutputDir, "output", "",
		"Output directory (default: ~/.capiscio/keys/{agent-id}/)")

	// Badge configuration
	initCmd.Flags().BoolVar(&initAutoBadge, "auto-badge", false,
		"Automatically request initial Trust Badge (requires PoP, consider using 'badge keep' instead)")

	// Safety flags
	initCmd.Flags().BoolVar(&initForce, "force", false,
		"Overwrite existing keys (use with caution!)")
}

func runInit(cmd *cobra.Command, _ []string) error {
	// 1. Resolve API key
	apiKey, err := resolveAPIKey()
	if err != nil {
		return err
	}

	// 2. Validate server URL
	serverURL := validateServerURL(initServerURL)

	// 3. Resolve agent ID
	agentID, agentName, err := resolveAgentID(serverURL, apiKey)
	if err != nil {
		return err
	}

	// 4. Set up output directory
	outputDir, err := setupOutputDir(agentID)
	if err != nil {
		return err
	}
	fmt.Printf("📁 Output directory: %s\n", outputDir)

	// 5. Generate keys and save
	pub, priv, didKey, pubJwk, err := generateAndSaveKeys(outputDir)
	if err != nil {
		return err
	}

	// 6. Register DID with server
	registerDIDWithWarning(serverURL, apiKey, agentID, didKey, pub)

	// 7. Create and save agent card
	if err := saveAgentCard(outputDir, agentID, agentName, didKey, serverURL, pubJwk); err != nil {
		return err
	}

	// 8. Request initial badge (if auto-badge enabled)
	if initAutoBadge {
		requestBadgeWithWarning(serverURL, apiKey, agentID, didKey, priv, outputDir)
	}

	// 9. Print summary
	printInitSummary(agentID, didKey, outputDir)

	return nil
}

// resolveAPIKey gets API key from environment or flag.
func resolveAPIKey() (string, error) {
	apiKey := os.Getenv("CAPISCIO_API_KEY")
	if apiKey == "" {
		apiKey = initAPIKey
	}
	if apiKey == "" {
		return "", fmt.Errorf("API key required. Set CAPISCIO_API_KEY environment variable or use --api-key flag.\nGet your API key at https://app.capisc.io")
	}
	return apiKey, nil
}

// validateServerURL validates and normalizes the server URL.
func validateServerURL(url string) string {
	serverURL := strings.TrimSuffix(url, "/")
	if !strings.HasPrefix(serverURL, "https://") && serverURL != "http://localhost:8080" {
		fmt.Fprintln(os.Stderr, "⚠️  Warning: Using non-HTTPS server URL. This is insecure for production!")
	}
	return serverURL
}

// resolveAgentID resolves agent ID from flag or fetches from registry.
func resolveAgentID(serverURL, apiKey string) (string, string, error) {
	agentID := initAgentID
	agentName := initAgentName
	if agentID == "" {
		fmt.Println("🔍 No agent ID provided, looking up agents from registry...")
		id, name, err := fetchFirstAgent(serverURL, apiKey)
		if err != nil {
			return "", "", fmt.Errorf("failed to fetch agent: %w\nCreate an agent at https://app.capisc.io or provide --agent-id", err)
		}
		agentID = id
		if agentName == "" {
			agentName = name
		}
		fmt.Printf("📋 Using agent: %s (%s)\n", agentName, agentID)
	}
	return agentID, agentName, nil
}

// setupOutputDir creates and validates the output directory.
func setupOutputDir(agentID string) (string, error) {
	outputDir := initOutputDir
	if outputDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get home directory: %w", err)
		}
		outputDir = filepath.Join(homeDir, ".capiscio", "keys", agentID)
	}

	privateKeyPath := filepath.Join(outputDir, "private.jwk")
	if _, err := os.Stat(privateKeyPath); err == nil && !initForce {
		return "", fmt.Errorf("keys already exist at %s. Use --force to overwrite (this will invalidate existing badges!)", outputDir)
	}

	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create output directory: %w", err)
	}
	return outputDir, nil
}

// generateAndSaveKeys generates Ed25519 keypair and saves to disk.
func generateAndSaveKeys(outputDir string) (ed25519.PublicKey, ed25519.PrivateKey, string, jose.JSONWebKey, error) {
	fmt.Println("🔑 Generating Ed25519 keypair...")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, "", jose.JSONWebKey{}, fmt.Errorf("failed to generate key: %w", err)
	}

	didKey := did.NewKeyDID(pub)
	fmt.Printf("🆔 DID: %s\n", didKey)

	privJwk := jose.JSONWebKey{Key: priv, KeyID: didKey, Algorithm: string(jose.EdDSA), Use: "sig"}
	pubJwk := jose.JSONWebKey{Key: pub, KeyID: didKey, Algorithm: string(jose.EdDSA), Use: "sig"}

	// Save private key
	privBytes, _ := json.MarshalIndent(privJwk, "", "  ")
	privateKeyPath := filepath.Join(outputDir, "private.jwk")
	if err := os.WriteFile(privateKeyPath, privBytes, 0600); err != nil {
		return nil, nil, "", jose.JSONWebKey{}, fmt.Errorf("failed to write private key: %w", err)
	}
	fmt.Printf("✅ Private key saved: %s (0600)\n", privateKeyPath)

	// Save public key
	pubBytes, _ := json.MarshalIndent(pubJwk, "", "  ")
	publicKeyPath := filepath.Join(outputDir, "public.jwk")
	if err := os.WriteFile(publicKeyPath, pubBytes, 0644); err != nil {
		return nil, nil, "", jose.JSONWebKey{}, fmt.Errorf("failed to write public key: %w", err)
	}
	fmt.Printf("✅ Public key saved: %s\n", publicKeyPath)

	// Save DID
	didPath := filepath.Join(outputDir, "did.txt")
	if err := os.WriteFile(didPath, []byte(didKey+"\n"), 0644); err != nil {
		return nil, nil, "", jose.JSONWebKey{}, fmt.Errorf("failed to write DID: %w", err)
	}
	fmt.Printf("✅ DID saved: %s\n", didPath)

	return pub, priv, didKey, pubJwk, nil
}

// registerDIDWithWarning attempts DID registration and prints warning on failure.
func registerDIDWithWarning(serverURL, apiKey, agentID, didKey string, pub ed25519.PublicKey) {
	fmt.Println("📡 Registering DID with registry...")
	if err := registerDID(serverURL, apiKey, agentID, didKey, pub); err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Warning: Failed to register DID: %v\n", err)
		fmt.Fprintln(os.Stderr, "   Keys were saved locally. You can register manually later.")
	} else {
		fmt.Println("✅ DID registered with registry")
	}
}

// saveAgentCard creates and saves the agent card.
func saveAgentCard(outputDir, agentID, agentName, didKey, serverURL string, pubJwk jose.JSONWebKey) error {
	agentCardPath := filepath.Join(outputDir, "agent-card.json")
	agentCard := createAgentCard(agentID, agentName, didKey, serverURL, pubJwk)
	cardBytes, err := json.MarshalIndent(agentCard, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal agent card: %w", err)
	}
	if err := os.WriteFile(agentCardPath, cardBytes, 0644); err != nil {
		return fmt.Errorf("failed to write agent card: %w", err)
	}
	fmt.Printf("✅ Agent card saved: %s\n", agentCardPath)
	return nil
}

// requestBadgeWithWarning attempts badge request and prints warning on failure.
func requestBadgeWithWarning(serverURL, apiKey, agentID, didKey string, priv ed25519.PrivateKey, outputDir string) {
	fmt.Println("🏷️  Requesting initial Trust Badge...")
	badgePath := filepath.Join(outputDir, "badge.jwt")
	if err := requestInitialBadge(serverURL, apiKey, agentID, didKey, priv, badgePath); err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Warning: Failed to request badge: %v\n", err)
		fmt.Fprintln(os.Stderr, "   You can request a badge later with: capiscio badge keep")
	} else {
		fmt.Printf("✅ Badge saved: %s\n", badgePath)
	}
}

// printInitSummary prints the initialization summary.
func printInitSummary(agentID, didKey, outputDir string) {
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println("✅ Agent initialized successfully!")
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Printf("   Agent ID:  %s\n", agentID)
	fmt.Printf("   DID:       %s\n", didKey)
	fmt.Printf("   Keys:      %s\n", outputDir)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Keep your private.jwk secret and backed up")
	fmt.Println("  2. Start the badge keeper for automatic badge renewal:")
	fmt.Printf("     capiscio badge keep --agent-id %s\n", agentID)
	fmt.Println("  3. Use the SDK: agent = CapiscIO.connect(api_key=...)")
	fmt.Println()
}

// fetchFirstAgent fetches the first agent from the registry
func fetchFirstAgent(serverURL, apiKey string) (id string, name string, err error) {
	req, err := http.NewRequest("GET", serverURL+"/v1/agents", nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("X-Capiscio-Registry-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Data []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", fmt.Errorf("failed to decode response: %w", err)
	}

	if len(result.Data) == 0 {
		return "", "", fmt.Errorf("no agents found")
	}

	return result.Data[0].ID, result.Data[0].Name, nil
}

// registerDID registers the DID with the server
func registerDID(serverURL, apiKey, agentID, didKey string, pub ed25519.PublicKey) error {
	// Prepare public key as base64 for registration
	pubJwk := jose.JSONWebKey{
		Key:       pub,
		KeyID:     didKey,
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}
	pubJwkBytes, _ := json.Marshal(pubJwk)

	payload := map[string]interface{}{
		"did":       didKey,
		"publicKey": string(pubJwkBytes),
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest("PUT", serverURL+"/v1/agents/"+agentID, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Capiscio-Registry-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// createAgentCard creates an A2A-compliant agent card
func createAgentCard(agentID, name, didKey, serverURL string, pubJwk jose.JSONWebKey) map[string]interface{} {
	if name == "" {
		name = "Agent-" + agentID[:8]
	}

	return map[string]interface{}{
		"name":            name,
		"version":         "1.0.0",
		"protocolVersion": "0.3.0",
		"url":             "http://localhost:8000",
		"description":     "CapiscIO-enabled A2A agent",
		"capabilities": map[string]bool{
			"streaming":              false,
			"pushNotifications":      false,
			"stateTransitionHistory": false,
		},
		"skills": []interface{}{},
		"x-capiscio": map[string]interface{}{
			"did":      didKey,
			"agentId":  agentID,
			"registry": serverURL,
			"publicKey": map[string]interface{}{
				"kty": "OKP",
				"crv": "Ed25519",
				"kid": pubJwk.KeyID,
				"x":   pubJwk.Key,
			},
		},
	}
}

// requestInitialBadge requests an initial badge from the registry
func requestInitialBadge(serverURL, apiKey, agentID, didKey string, priv ed25519.PrivateKey, outputPath string) error {
	// Request badge via POST /v1/agents/{id}/badge
	// Note: For production use with PoP, use `capiscio badge keep` instead
	
	req, err := http.NewRequest("POST", serverURL+"/v1/agents/"+agentID+"/badge", nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Capiscio-Registry-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Badge string `json:"badge"`
		Data  struct {
			Badge string `json:"badge"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	badge := result.Badge
	if badge == "" {
		badge = result.Data.Badge
	}
	if badge == "" {
		return fmt.Errorf("no badge in response")
	}

	if err := os.WriteFile(outputPath, []byte(badge), 0600); err != nil {
		return fmt.Errorf("failed to write badge: %w", err)
	}

	return nil
}
