package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"

	"github.com/go-jose/go-jose/v4"
	"github.com/spf13/cobra"
)

var (
	keyOutPrivate string
	keyOutPublic  string
)

var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Manage Cryptographic Keys",
}

var keyGenCmd = &cobra.Command{
	Use:   "gen",
	Short: "Generate a new Ed25519 Key Pair",
	RunE: func(cmd *cobra.Command, args []string) error {
		// 1. Generate Key Pair
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate key: %w", err)
		}

		// 2. Create JWKs
		// We use a consistent Key ID (kid) for simplicity in this MVP, 
		// or generate a random one. Let's generate a simple one or use a timestamp.
		// For a real system, this might be a hash of the key.
		kid := fmt.Sprintf("key-%d", 1) 

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

		// 3. Save Private Key
		privBytes, err := json.MarshalIndent(privJwk, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(keyOutPrivate, privBytes, 0600); err != nil {
			return fmt.Errorf("failed to write private key: %w", err)
		}
		fmt.Printf("✅ Private Key saved to %s\n", keyOutPrivate)

		// 4. Save Public Key
		pubBytes, err := json.MarshalIndent(pubJwk, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(keyOutPublic, pubBytes, 0644); err != nil {
			return fmt.Errorf("failed to write public key: %w", err)
		}
		fmt.Printf("✅ Public Key saved to %s\n", keyOutPublic)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(keyCmd)
	keyCmd.AddCommand(keyGenCmd)

	keyGenCmd.Flags().StringVar(&keyOutPrivate, "out-priv", "private.jwk", "Output path for private key")
	keyGenCmd.Flags().StringVar(&keyOutPublic, "out-pub", "public.jwk", "Output path for public key")
}
