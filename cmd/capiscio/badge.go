package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/capiscio/capiscio-core/pkg/badge"
	"github.com/capiscio/capiscio-core/pkg/did"
	"github.com/capiscio/capiscio-core/pkg/registry"
	"github.com/capiscio/capiscio-core/pkg/revocation"
	"github.com/capiscio/capiscio-core/pkg/trust"
	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

var (
	// Issue command flags
	issueSubject  string
	issueIssuer   string
	issueDomain   string
	issueExpiry   time.Duration
	issueLevel    string
	issueAudience string
	issueSelfSign bool
	keyFile       string

	// Keep command flags
	keepOutFile       string
	keepRenewBefore   time.Duration
	keepCheckInterval time.Duration
	keepCA            string
	keepAPIKey        string
	keepSelfSign      bool

	// Verify command flags
	verifyOffline          bool
	verifyTrustedIssuers   string
	verifyAudience         string
	verifySkipRevocation   bool
	verifySkipAgentStatus  bool
)

var badgeCmd = &cobra.Command{
	Use:   "badge",
	Short: "Manage Trust Badges",
	Long: `Manage Trust Badges for CapiscIO agents.

Trust Badges are signed JWS tokens that provide portable, verifiable
identity for agents. See RFC-002 for the full specification.`,
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
	Long: `Issue a new Trust Badge.

By default, issues a self-signed badge for development use.
In production, use the CA endpoint to request a signed badge.

Examples:
  # Self-signed badge for development
  capiscio badge issue --self-sign --sub did:web:registry.capisc.io:agents:my-agent

  # With specific trust level
  capiscio badge issue --self-sign --level 2 --domain example.com

  # With audience restriction
  capiscio badge issue --self-sign --aud "https://api.example.com,https://backup.example.com"`,
	RunE: func(_ *cobra.Command, _ []string) error {
		// Validate subject is a valid did:web
		if !strings.HasPrefix(issueSubject, "did:web:") {
			fmt.Fprintf(os.Stderr, "⚠️  Warning: Subject should be a did:web identifier (got: %s)\n", issueSubject)
		}

		// Validate trust level
		if issueLevel != "1" && issueLevel != "2" && issueLevel != "3" {
			return fmt.Errorf("invalid trust level: %s (must be 1, 2, or 3)", issueLevel)
		}

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

		// 2. Parse audience
		var audience []string
		if issueAudience != "" {
			audience = strings.Split(issueAudience, ",")
			for i, a := range audience {
				audience[i] = strings.TrimSpace(a)
			}
		}

		// 3. Create Claims
		now := time.Now()

		// Generate JTI (UUID v4)
		jti := uuid.New().String()

		// Create Public Key JWK for embedding
		pubJWK := &jose.JSONWebKey{
			Key:       pub,
			Algorithm: string(jose.EdDSA),
			Use:       "sig",
		}

		claims := &badge.Claims{
			JTI:      jti,
			Issuer:   issueIssuer,
			Subject:  issueSubject,
			Audience: audience,
			IssuedAt: now.Unix(),
			Expiry:   now.Add(issueExpiry).Unix(),
			Key:      pubJWK,
			VC: badge.VerifiableCredential{
				Type: []string{"VerifiableCredential", "AgentIdentity"},
				CredentialSubject: badge.CredentialSubject{
					Domain: issueDomain,
					Level:  issueLevel,
				},
			},
		}

		// 4. Sign
		if issueSelfSign {
			fmt.Fprintf(os.Stderr, "⚠️  Warning: Self-signed badges are for development only. Do not use in production.\n")
		}

		token, err := badge.SignBadge(claims, priv)
		if err != nil {
			return err
		}

		// 5. Print Token
		fmt.Println(token)

		// Print summary to stderr
		fmt.Fprintf(os.Stderr, "\n📛 Badge Issued:\n")
		fmt.Fprintf(os.Stderr, "   JTI: %s\n", jti)
		fmt.Fprintf(os.Stderr, "   Subject: %s\n", issueSubject)
		fmt.Fprintf(os.Stderr, "   Issuer: %s\n", issueIssuer)
		fmt.Fprintf(os.Stderr, "   Trust Level: %s\n", issueLevel)
		fmt.Fprintf(os.Stderr, "   Expires: %s\n", time.Unix(claims.Expiry, 0).Format(time.RFC3339))
		if len(audience) > 0 {
			fmt.Fprintf(os.Stderr, "   Audience: %s\n", strings.Join(audience, ", "))
		}

		return nil
	},
}

var keepCmd = &cobra.Command{
	Use:   "keep",
	Short: "Run a daemon to keep a badge renewed",
	Long: `Run a daemon that automatically renews badges before they expire.

The keeper monitors the badge file and renews it when approaching expiry.
This is essential for agents that need continuous operation.

Examples:
  # Self-signed mode for development
  capiscio badge keep --self-sign --key private.jwk --out badge.jwt

  # With CA (future)
  capiscio badge keep --ca https://registry.capisc.io --api-key $API_KEY`,
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
						Level:  issueLevel,
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
		fmt.Printf("🔄 Starting Badge Keeper\n")
		fmt.Printf("   Subject: %s\n", issueSubject)
		fmt.Printf("   Output: %s\n", keepOutFile)
		fmt.Printf("   Expiry: %v\n", issueExpiry)
		fmt.Printf("   Renew Before: %v\n", keepRenewBefore)
		if keepSelfSign {
			fmt.Printf("   Mode: Self-signed (development only)\n")
		}
		fmt.Println()
		return keeper.Run(cmd.Context())
	},
}

var verifyCmd = &cobra.Command{
	Use:   "verify [token]",
	Short: "Verify a Trust Badge",
	Long: `Verify a Trust Badge and display the claims.

Performs verification per RFC-002 §8.1:
1. Parse and validate JWS structure
2. Verify signature against CA key
3. Validate claims (exp, iat, iss, aud)
4. Check revocation status (online mode)
5. Check agent status (online mode)

Examples:
  # Online verification with local key
  capiscio badge verify $TOKEN --key ca-public.jwk

  # Offline verification
  capiscio badge verify $TOKEN --offline

  # With audience check
  capiscio badge verify $TOKEN --key ca.jwk --audience https://api.example.com

  # With trusted issuers list
  capiscio badge verify $TOKEN --key ca.jwk --trusted-issuers "https://registry.capisc.io"`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		token := args[0]

		// Build verification options
		opts := badge.VerifyOptions{
			Mode:                 badge.VerifyModeOnline,
			SkipRevocationCheck:  verifySkipRevocation,
			SkipAgentStatusCheck: verifySkipAgentStatus,
		}

		if verifyOffline {
			opts.Mode = badge.VerifyModeOffline
		}

		if verifyAudience != "" {
			opts.Audience = verifyAudience
		}

		if verifyTrustedIssuers != "" {
			opts.TrustedIssuers = strings.Split(verifyTrustedIssuers, ",")
			for i, iss := range opts.TrustedIssuers {
				opts.TrustedIssuers[i] = strings.TrimSpace(iss)
			}
		}

		// Setup revocation cache for offline mode
		if verifyOffline {
			cache, err := revocation.NewFileCache("")
			if err == nil {
				opts.RevocationCache = cache
			}
		}

		// Determine key source
		var reg registry.Registry

		if keyFile != "" {
			// Load key from file
			keyData, err := os.ReadFile(keyFile)
			if err != nil {
				return fmt.Errorf("failed to read key file: %w", err)
			}

			var jwk jose.JSONWebKey
			if err := json.Unmarshal(keyData, &jwk); err != nil {
				return fmt.Errorf("failed to parse JWK: %w", err)
			}

			reg = &StaticRegistry{Key: jwk.Key}
		} else if verifyOffline {
			// Use trust store
			store, err := trust.NewFileStore("")
			if err != nil {
				return fmt.Errorf("failed to open trust store: %w", err)
			}
			reg = &TrustStoreRegistry{store: store}
		} else {
			return fmt.Errorf("public key required: use --key (path to JWK file) or --offline (uses trust store)")
		}

		// Verify
		verifier := badge.NewVerifier(reg)
		result, err := verifier.VerifyWithOptions(cmd.Context(), token, opts)
		if err != nil {
			// Check if it's a badge error with a code
			if badgeErr, ok := badge.IsBadgeError(err); ok {
				fmt.Fprintf(os.Stderr, "❌ Verification Failed\n")
				fmt.Fprintf(os.Stderr, "   Error: %s\n", badgeErr.Code)
				fmt.Fprintf(os.Stderr, "   Message: %s\n", badgeErr.Message)
				if badgeErr.Cause != nil {
					fmt.Fprintf(os.Stderr, "   Cause: %v\n", badgeErr.Cause)
				}
				return fmt.Errorf("verification failed: %s", badgeErr.Code)
			}
			return fmt.Errorf("verification failed: %w", err)
		}

		claims := result.Claims

		// Print success
		fmt.Printf("✅ Badge Valid!\n\n")
		fmt.Printf("📛 Badge Details:\n")
		fmt.Printf("   JTI: %s\n", claims.JTI)
		fmt.Printf("   Subject: %s\n", claims.Subject)
		if agentID := claims.AgentID(); agentID != "" {
			fmt.Printf("   Agent ID: %s\n", agentID)
		}
		fmt.Printf("   Issuer: %s\n", claims.Issuer)
		fmt.Printf("   Issued At: %s\n", claims.IssuedAtTime().Format(time.RFC3339))
		fmt.Printf("   Expires: %s\n", claims.ExpiresAt().Format(time.RFC3339))
		if len(claims.Audience) > 0 {
			fmt.Printf("   Audience: %s\n", strings.Join(claims.Audience, ", "))
		}
		fmt.Printf("\n🔐 Verifiable Credential:\n")
		fmt.Printf("   Type: %s\n", strings.Join(claims.VC.Type, ", "))
		fmt.Printf("   Domain: %s\n", claims.Domain())
		fmt.Printf("   Trust Level: %s\n", claims.TrustLevel())

		// Print warnings if any
		if len(result.Warnings) > 0 {
			fmt.Printf("\n⚠️  Warnings:\n")
			for _, w := range result.Warnings {
				fmt.Printf("   - %s\n", w)
			}
		}

		// Print mode
		modeNames := map[badge.VerifyMode]string{
			badge.VerifyModeOnline:  "Online",
			badge.VerifyModeOffline: "Offline",
			badge.VerifyModeHybrid:  "Hybrid",
		}
		fmt.Printf("\n🔍 Verification Mode: %s\n", modeNames[result.Mode])

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

func (r *StaticRegistry) GetBadgeStatus(_ context.Context, _ string, _ string) (*registry.BadgeStatus, error) {
	return &registry.BadgeStatus{Revoked: false}, nil
}

func (r *StaticRegistry) GetAgentStatus(_ context.Context, _ string, _ string) (*registry.AgentStatus, error) {
	return &registry.AgentStatus{Status: registry.AgentStatusActive}, nil
}

func (r *StaticRegistry) SyncRevocations(_ context.Context, _ string, _ time.Time) ([]registry.Revocation, error) {
	return nil, nil
}

// TrustStoreRegistry uses the local trust store for offline verification.
type TrustStoreRegistry struct {
	store *trust.FileStore
}

func (r *TrustStoreRegistry) GetPublicKey(_ context.Context, issuer string) (crypto.PublicKey, error) {
	keys, err := r.store.GetByIssuer(issuer)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no keys found for issuer: %s", issuer)
	}
	// Return the first key (in a real implementation, might check kid in header)
	return keys[0].Key, nil
}

func (r *TrustStoreRegistry) IsRevoked(_ context.Context, _ string) (bool, error) {
	return false, nil
}

func (r *TrustStoreRegistry) GetBadgeStatus(_ context.Context, _ string, _ string) (*registry.BadgeStatus, error) {
	return nil, fmt.Errorf("badge status check not available in offline mode")
}

func (r *TrustStoreRegistry) GetAgentStatus(_ context.Context, _ string, _ string) (*registry.AgentStatus, error) {
	return nil, fmt.Errorf("agent status check not available in offline mode")
}

func (r *TrustStoreRegistry) SyncRevocations(_ context.Context, _ string, _ time.Time) ([]registry.Revocation, error) {
	return nil, fmt.Errorf("revocation sync not available in offline mode")
}

func init() {
	rootCmd.AddCommand(badgeCmd)
	badgeCmd.AddCommand(issueCmd)
	badgeCmd.AddCommand(verifyCmd)
	badgeCmd.AddCommand(keepCmd)

	// Issue Flags
	issueCmd.Flags().StringVar(&issueSubject, "sub", did.NewCapiscIOAgentDID("test"), "Subject DID (did:web format)")
	issueCmd.Flags().StringVar(&issueIssuer, "iss", "https://registry.capisc.io", "Issuer URL")
	issueCmd.Flags().StringVar(&issueDomain, "domain", "example.com", "Agent Domain")
	issueCmd.Flags().DurationVar(&issueExpiry, "exp", 5*time.Minute, "Expiration duration (default 5m per RFC-002)")
	issueCmd.Flags().StringVar(&issueLevel, "level", "1", "Trust level: 1 (DV), 2 (OV), or 3 (EV)")
	issueCmd.Flags().StringVar(&issueAudience, "aud", "", "Audience (comma-separated URLs)")
	issueCmd.Flags().BoolVar(&issueSelfSign, "self-sign", false, "Self-sign for development (explicit)")
	issueCmd.Flags().StringVar(&keyFile, "key", "", "Path to private key file (optional)")

	// Keep Flags
	keepCmd.Flags().StringVar(&issueSubject, "sub", did.NewCapiscIOAgentDID("test"), "Subject DID")
	keepCmd.Flags().StringVar(&issueIssuer, "iss", "https://registry.capisc.io", "Issuer URL")
	keepCmd.Flags().StringVar(&issueDomain, "domain", "example.com", "Agent Domain")
	keepCmd.Flags().DurationVar(&issueExpiry, "exp", 5*time.Minute, "Expiration duration")
	keepCmd.Flags().StringVar(&issueLevel, "level", "1", "Trust level")
	keepCmd.Flags().StringVar(&keyFile, "key", "", "Path to private key file (required for self-sign)")
	keepCmd.Flags().StringVar(&keepOutFile, "out", "badge.jwt", "Output file path")
	keepCmd.Flags().DurationVar(&keepRenewBefore, "renew-before", 1*time.Minute, "Time before expiry to renew")
	keepCmd.Flags().DurationVar(&keepCheckInterval, "check-interval", 30*time.Second, "Interval to check for renewal")
	keepCmd.Flags().StringVar(&keepCA, "ca", "https://registry.capisc.io", "CA URL for badge requests (future)")
	keepCmd.Flags().StringVar(&keepAPIKey, "api-key", "", "API key for CA authentication (future)")
	keepCmd.Flags().BoolVar(&keepSelfSign, "self-sign", false, "Self-sign instead of requesting from CA")

	// Verify Flags
	verifyCmd.Flags().StringVar(&keyFile, "key", "", "Path to public key file (JWK)")
	verifyCmd.Flags().BoolVar(&verifyOffline, "offline", false, "Offline mode (uses trust store)")
	verifyCmd.Flags().StringVar(&verifyTrustedIssuers, "trusted-issuers", "", "Comma-separated list of trusted issuer URLs")
	verifyCmd.Flags().StringVar(&verifyAudience, "audience", "", "Verifier's identity for audience validation")
	verifyCmd.Flags().BoolVar(&verifySkipRevocation, "skip-revocation", false, "Skip revocation check (testing only)")
	verifyCmd.Flags().BoolVar(&verifySkipAgentStatus, "skip-agent-status", false, "Skip agent status check (testing only)")
}
