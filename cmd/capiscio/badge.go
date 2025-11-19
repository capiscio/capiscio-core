package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/capiscio/capiscio-core/pkg/badge"
	"github.com/go-jose/go-jose/v4"
	"github.com/spf13/cobra"
)

var (
	issueSubject string
	issueIssuer  string
	issueExpiry  time.Duration
	keyFile      string
)

var badgeCmd = &cobra.Command{
	Use:   "badge",
	Short: "Manage Trust Badges",
}

var issueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issue a new Trust Badge",
	RunE: func(cmd *cobra.Command, args []string) error {
		// 1. Get Private Key
		var priv ed25519.PrivateKey
		var pub ed25519.PublicKey
		
		if keyFile != "" {
			// Load from file (TODO: Implement file loading)
			return fmt.Errorf("loading key from file not yet implemented, omit --key to generate ephemeral key")
		} else {
			// Generate ephemeral key
			var err error
			pub, priv, err = ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return fmt.Errorf("failed to generate key: %w", err)
			}
			// Print public key to stderr for use in verification
			jwk := jose.JSONWebKey{Key: pub, KeyID: "ephemeral-key", Algorithm: string(jose.EdDSA)}
			jwkJSON, _ := jwk.MarshalJSON()
			fmt.Fprintf(os.Stderr, "Generated Ephemeral Public Key (save this to verify):\n%s\n\n", string(jwkJSON))
		}

		// 2. Create Claims
		now := time.Now()
		claims := &badge.BadgeClaims{
			Issuer:   issueIssuer,
			Subject:  issueSubject,
			IssuedAt: now.Unix(),
			Expiry:   now.Add(issueExpiry).Unix(),
			VC: badge.VerifiableCredential{
				Type: []string{"VerifiableCredential", "AgentIdentity"},
				CredentialSubject: badge.CredentialSubject{
					Domain: "finance.internal", // Hardcoded for MVP demo
				},
			},
		}

		// 3. Sign
		token, err := badge.SignBadge(claims, priv)
		if err != nil {
			return err
		}

		// 4. Print Token
		fmt.Println(token)
		return nil
	},
}

var verifyCmd = &cobra.Command{
	Use:   "verify [token]",
	Short: "Verify a Trust Badge",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		token := args[0]
		
		if keyFile == "" {
			return fmt.Errorf("public key required via --key (path to JWK file)")
		}
		
		// Read key file
		keyData, err := os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("failed to read key file: %w", err)
		}
		
		var jwk jose.JSONWebKey
		if err := json.Unmarshal(keyData, &jwk); err != nil {
			return fmt.Errorf("failed to parse JWK: %w", err)
		}
		
		// 2. Verify using StaticRegistry
		reg := &StaticRegistry{Key: jwk.Key}
		verifier := badge.NewVerifier(reg)
		
		claims, err := verifier.Verify(cmd.Context(), token)
		if err != nil {
			return fmt.Errorf("verification failed: %w", err)
		}
		
		fmt.Printf("✅ Badge Valid!\nSubject: %s\nIssuer: %s\nExpires: %s\n", 
			claims.Subject, claims.Issuer, time.Unix(claims.Expiry, 0))
		
		return nil
	},
}

// StaticRegistry is a simple registry that returns a single fixed key.
type StaticRegistry struct {
	Key interface{}
}

func (r *StaticRegistry) GetPublicKey(ctx context.Context, issuer string) (crypto.PublicKey, error) {
	return r.Key, nil
}

func (r *StaticRegistry) IsRevoked(ctx context.Context, id string) (bool, error) {
	return false, nil
}

func init() {
	rootCmd.AddCommand(badgeCmd)
	badgeCmd.AddCommand(issueCmd)
	badgeCmd.AddCommand(verifyCmd)

	issueCmd.Flags().StringVar(&issueSubject, "sub", "did:capiscio:agent:test", "Subject DID")
	issueCmd.Flags().StringVar(&issueIssuer, "iss", "https://registry.capisc.io", "Issuer URL")
	issueCmd.Flags().DurationVar(&issueExpiry, "exp", 1*time.Hour, "Expiration duration")
	issueCmd.Flags().StringVar(&keyFile, "key", "", "Path to private key file (optional)")
	
	verifyCmd.Flags().StringVar(&keyFile, "key", "", "Path to public key file (JWK)")
	verifyCmd.MarkFlagRequired("key")
}
