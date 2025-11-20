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
	issueDomain  string
	issueExpiry  time.Duration
	keyFile      string

	// Keep command flags
	keepOutFile       string
	keepRenewBefore   time.Duration
	keepCheckInterval time.Duration
)

var badgeCmd = &cobra.Command{
	Use:   "badge",
	Short: "Manage Trust Badges",
}

// loadPrivateKey loads an Ed25519 private key from a JWK file.
func loadPrivateKey(path string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	var jwk jose.JSONWebKey
	if err := json.Unmarshal(keyData, &jwk); err != nil {
		return nil, nil, fmt.Errorf("failed to parse private JWK: %w", err)
	}

	priv, ok := jwk.Key.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("key in file is not an Ed25519 private key")
	}
	pub := priv.Public().(ed25519.PublicKey)
	return priv, pub, nil
}

var issueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issue a new Trust Badge",
	RunE: func(_ *cobra.Command, _ []string) error {
		// 1. Get Private Key
		var priv ed25519.PrivateKey
		var pub ed25519.PublicKey

		if keyFile != "" {
			var err error
			priv, pub, err = loadPrivateKey(keyFile)
			if err != nil {
				return err
			}
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

		// Create Public Key JWK for embedding
		pubJWK := &jose.JSONWebKey{
			Key:       pub,
			Algorithm: string(jose.EdDSA),
			Use:       "sig",
		}

		claims := &badge.Claims{
			Issuer:   issueIssuer,
			Subject:  issueSubject,
			IssuedAt: now.Unix(),
			Expiry:   now.Add(issueExpiry).Unix(),
			Key:      pubJWK,
			VC: badge.VerifiableCredential{
				Type: []string{"VerifiableCredential", "AgentIdentity"},
				CredentialSubject: badge.CredentialSubject{
					Domain: issueDomain,
					Level:  "1",
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

var keepCmd = &cobra.Command{
	Use:   "keep",
	Short: "Run a daemon to keep a badge renewed",
	RunE: func(cmd *cobra.Command, _ []string) error {
		// 1. Load Private Key
		priv, pub, err := loadPrivateKey(keyFile)
		if err != nil {
			return err
		}

		// 2. Setup Config
		pubJWK := &jose.JSONWebKey{
			Key:       pub,
			Algorithm: string(jose.EdDSA),
			Use:       "sig",
		}

		config := badge.KeeperConfig{
			PrivateKey: priv,
			Claims: badge.Claims{
				Issuer:  issueIssuer,
				Subject: issueSubject,
				Key:     pubJWK,
				VC: badge.VerifiableCredential{
					Type: []string{"VerifiableCredential", "AgentIdentity"},
					CredentialSubject: badge.CredentialSubject{
						Domain: issueDomain,
						Level:  "1",
					},
				},
			},
			OutputFile:    keepOutFile,
			Expiry:        issueExpiry,
			RenewBefore:   keepRenewBefore,
			CheckInterval: keepCheckInterval,
		}

		// 3. Run Keeper
		keeper := badge.NewKeeper(config)
		fmt.Printf("Starting Badge Keeper for %s\nOutput: %s\nRenew Before: %v\n", issueSubject, keepOutFile, keepRenewBefore)
		return keeper.Run(cmd.Context())
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

func (r *StaticRegistry) GetPublicKey(_ context.Context, _ string) (crypto.PublicKey, error) {
	return r.Key, nil
}

func (r *StaticRegistry) IsRevoked(_ context.Context, _ string) (bool, error) {
	return false, nil
}

func init() {
	rootCmd.AddCommand(badgeCmd)
	badgeCmd.AddCommand(issueCmd)
	badgeCmd.AddCommand(verifyCmd)
	badgeCmd.AddCommand(keepCmd)

	// Issue Flags
	issueCmd.Flags().StringVar(&issueSubject, "sub", "did:capiscio:agent:test", "Subject DID")
	issueCmd.Flags().StringVar(&issueIssuer, "iss", "https://registry.capisc.io", "Issuer URL")
	issueCmd.Flags().StringVar(&issueDomain, "domain", "example.com", "Agent Domain")
	issueCmd.Flags().DurationVar(&issueExpiry, "exp", 1*time.Hour, "Expiration duration")
	issueCmd.Flags().StringVar(&keyFile, "key", "", "Path to private key file (optional)")

	// Keep Flags (reuses some issue flags)
	keepCmd.Flags().StringVar(&issueSubject, "sub", "did:capiscio:agent:test", "Subject DID")
	keepCmd.Flags().StringVar(&issueIssuer, "iss", "https://registry.capisc.io", "Issuer URL")
	keepCmd.Flags().StringVar(&issueDomain, "domain", "example.com", "Agent Domain")
	keepCmd.Flags().DurationVar(&issueExpiry, "exp", 1*time.Hour, "Expiration duration")
	keepCmd.Flags().StringVar(&keyFile, "key", "", "Path to private key file (required)")
	_ = keepCmd.MarkFlagRequired("key")

	keepCmd.Flags().StringVar(&keepOutFile, "out", "badge.jwt", "Output file path")
	keepCmd.Flags().DurationVar(&keepRenewBefore, "renew-before", 10*time.Minute, "Time before expiry to renew")
	keepCmd.Flags().DurationVar(&keepCheckInterval, "check-interval", 1*time.Minute, "Interval to check for renewal")

	// Verify Flags
	verifyCmd.Flags().StringVar(&keyFile, "key", "", "Path to public key file (JWK)")
	_ = verifyCmd.MarkFlagRequired("key")
}
