package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/trust"
	"github.com/go-jose/go-jose/v4"
	"github.com/spf13/cobra"
)

var (
	trustFromJWKS string
)

var trustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Manage trusted CA keys",
	Long: `Manage the local trust store for offline badge verification.

The trust store contains CA public keys that are trusted for badge
verification. This enables offline and air-gapped deployments.

Location: ~/.capiscio/trust/ (or $CAPISCIO_TRUST_PATH)

See RFC-002 §13.1 for details.`,
}

var trustAddCmd = &cobra.Command{
	Use:   "add [jwk-file]",
	Short: "Add a CA public key to the trust store",
	Long: `Add a CA public key to the trust store.

Examples:
  # Add from a JWK file
  capiscio trust add ca-public.jwk

  # Add from JWKS URL (production CA)
  capiscio trust add --from-jwks https://registry.capisc.io/.well-known/jwks.json

  # Add from stdin (pipe from curl)
  curl -s https://registry.capisc.io/.well-known/jwks.json | capiscio trust add --from-jwks -`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		store, err := trust.NewFileStore("")
		if err != nil {
			return fmt.Errorf("failed to open trust store: %w", err)
		}

		if trustFromJWKS != "" {
			return addFromJWKS(store, trustFromJWKS)
		}

		if len(args) == 0 {
			return fmt.Errorf("provide a JWK file path or use --from-jwks")
		}

		return addFromJWKFile(store, args[0])
	},
}

func addFromJWKFile(store *trust.FileStore, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	var key jose.JSONWebKey
	if err := json.Unmarshal(data, &key); err != nil {
		return fmt.Errorf("failed to parse JWK: %w", err)
	}

	if key.KeyID == "" {
		return fmt.Errorf("JWK must have a key ID (kid)")
	}

	if err := store.Add(key); err != nil {
		return fmt.Errorf("failed to add key: %w", err)
	}

	fmt.Printf("✅ Added key: %s\n", key.KeyID)
	fmt.Printf("   Algorithm: %s\n", key.Algorithm)
	return nil
}

func addFromJWKS(store *trust.FileStore, source string) error {
	var data []byte
	var err error
	var issuerURL string

	if source == "-" {
		// Read from stdin
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read stdin: %w", err)
		}
	} else {
		// Fetch from URL
		issuerURL = source
		// Strip /.well-known/jwks.json to get base issuer URL
		if len(issuerURL) > 22 && issuerURL[len(issuerURL)-22:] == "/.well-known/jwks.json" {
			issuerURL = issuerURL[:len(issuerURL)-22]
		}

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Get(source)
		if err != nil {
			return fmt.Errorf("failed to fetch JWKS: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("failed to fetch JWKS: status %d", resp.StatusCode)
		}

		data, err = io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response: %w", err)
		}
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(data, &jwks); err != nil {
		return fmt.Errorf("failed to parse JWKS: %w", err)
	}

	if len(jwks.Keys) == 0 {
		return fmt.Errorf("JWKS contains no keys")
	}

	if err := store.AddFromJWKS(&jwks, issuerURL); err != nil {
		return fmt.Errorf("failed to add keys: %w", err)
	}

	fmt.Printf("✅ Added %d key(s) from JWKS\n", len(jwks.Keys))
	for _, key := range jwks.Keys {
		fmt.Printf("   - %s (%s)\n", key.KeyID, key.Algorithm)
	}
	if issuerURL != "" {
		fmt.Printf("   Mapped to issuer: %s\n", issuerURL)
	}

	return nil
}

var trustListCmd = &cobra.Command{
	Use:   "list",
	Short: "List trusted CA keys",
	RunE: func(_ *cobra.Command, _ []string) error {
		store, err := trust.NewFileStore("")
		if err != nil {
			return fmt.Errorf("failed to open trust store: %w", err)
		}

		keys, err := store.List()
		if err != nil {
			return fmt.Errorf("failed to list keys: %w", err)
		}

		if len(keys) == 0 {
			fmt.Println("No trusted keys in store.")
			fmt.Println("\nAdd keys with:")
			fmt.Println("  capiscio trust add --from-jwks https://registry.capisc.io/.well-known/jwks.json")
			return nil
		}

		fmt.Printf("🔑 Trusted CA Keys (%d):\n\n", len(keys))
		for _, key := range keys {
			fmt.Printf("  Key ID: %s\n", key.KeyID)
			fmt.Printf("    Algorithm: %s\n", key.Algorithm)
			fmt.Printf("    Use: %s\n", key.Use)
			fmt.Println()
		}

		fmt.Printf("Trust store location: %s\n", trust.DefaultTrustDir())
		return nil
	},
}

var trustRemoveCmd = &cobra.Command{
	Use:   "remove [kid]",
	Short: "Remove a CA key from the trust store",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		kid := args[0]

		store, err := trust.NewFileStore("")
		if err != nil {
			return fmt.Errorf("failed to open trust store: %w", err)
		}

		if err := store.Remove(kid); err != nil {
			if err == trust.ErrKeyNotFound {
				return fmt.Errorf("key not found: %s", kid)
			}
			return fmt.Errorf("failed to remove key: %w", err)
		}

		fmt.Printf("✅ Removed key: %s\n", kid)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(trustCmd)
	trustCmd.AddCommand(trustAddCmd)
	trustCmd.AddCommand(trustListCmd)
	trustCmd.AddCommand(trustRemoveCmd)

	trustAddCmd.Flags().StringVar(&trustFromJWKS, "from-jwks", "", "Fetch from JWKS URL or '-' for stdin")
}
