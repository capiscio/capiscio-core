package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"

	"github.com/capiscio/capiscio-core/v2/pkg/did"
	"github.com/go-jose/go-jose/v4"
	"github.com/spf13/cobra"
)

var (
	keyOutPrivate string
	keyOutPublic  string
	keyOutDID     string
	keyShowDID    bool
)

var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Manage Cryptographic Keys",
}

var keyGenCmd = &cobra.Command{
	Use:   "gen",
	Short: "Generate a new Ed25519 Key Pair",
	Long: `Generate a new Ed25519 key pair for Trust Badge operations.

Outputs:
  - Private key in JWK format (for signing badges)
  - Public key in JWK format (for verification)
  - did:key identifier (for self-signed badges, RFC-002 v1.1)

The did:key identifier encodes the public key using the W3C did:key method
and can be used as both the issuer (iss) and subject (sub) for Level 0
self-signed Trust Badges.`,
	Example: `  # Generate keys with default names
  capiscio key gen

  # Generate keys with custom names and save did:key to file
  capiscio key gen --out-priv agent.key.jwk --out-pub agent.pub.jwk --out-did agent.did

  # Generate keys and only show did:key on stdout
  capiscio key gen --show-did`,
	RunE: func(_ *cobra.Command, _ []string) error {
		// 1. Generate Key Pair
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate key: %w", err)
		}

		// 2. Generate did:key identifier
		didKey := did.NewKeyDID(pub)

		// 3. Create JWKs with did:key as the Key ID
		// Using did:key as kid makes it easy to identify the key
		kid := didKey

		privJwk := jose.JSONWebKey{
			Key:       priv,
			KeyID:     kid,
			Algorithm: string(jose.EdDSA),
			Use:       "sig",
		}

		pubJwk := jose.JSONWebKey{
			Key:       pub,
			KeyID:     kid,
			Algorithm: string(jose.EdDSA),
			Use:       "sig",
		}

		// 4. Save Private Key
		privBytes, err := json.MarshalIndent(privJwk, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(keyOutPrivate, privBytes, 0600); err != nil {
			return fmt.Errorf("failed to write private key: %w", err)
		}
		fmt.Printf("✅ Private Key saved to %s\n", keyOutPrivate)

		// 5. Save Public Key
		pubBytes, err := json.MarshalIndent(pubJwk, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(keyOutPublic, pubBytes, 0644); err != nil {
			return fmt.Errorf("failed to write public key: %w", err)
		}
		fmt.Printf("✅ Public Key saved to %s\n", keyOutPublic)

		// 6. Output did:key identifier
		if keyOutDID != "" {
			if err := os.WriteFile(keyOutDID, []byte(didKey+"\n"), 0644); err != nil {
				return fmt.Errorf("failed to write did:key: %w", err)
			}
			fmt.Printf("✅ did:key saved to %s\n", keyOutDID)
		}

		// Always show did:key if --show-did flag is set, or print it normally
		if keyShowDID {
			fmt.Println(didKey)
		} else {
			fmt.Printf("🔑 did:key: %s\n", didKey)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(keyCmd)
	keyCmd.AddCommand(keyGenCmd)

	keyGenCmd.Flags().StringVar(&keyOutPrivate, "out-priv", "private.jwk", "Output path for private key (JWK format)")
	keyGenCmd.Flags().StringVar(&keyOutPublic, "out-pub", "public.jwk", "Output path for public key (JWK format)")
	keyGenCmd.Flags().StringVar(&keyOutDID, "out-did", "", "Output path for did:key identifier (optional)")
	keyGenCmd.Flags().BoolVar(&keyShowDID, "show-did", false, "Only output did:key to stdout (for scripting)")
}
