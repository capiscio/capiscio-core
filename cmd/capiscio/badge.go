package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/badge"
	"github.com/capiscio/capiscio-core/v2/pkg/did"
	"github.com/capiscio/capiscio-core/v2/pkg/registry"
	"github.com/capiscio/capiscio-core/v2/pkg/revocation"
	"github.com/capiscio/capiscio-core/v2/pkg/trust"
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
	keepAgentID       string
	keepSelfSign      bool

	// Verify command flags
	verifyOffline           bool
	verifyTrustedIssuers    string
	verifyAudience          string
	verifySkipRevocation    bool
	verifySkipAgentStatus   bool
	verifyAcceptSelfSigned  bool
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

Trust Levels:
  0 - Self-signed (did:key, iss == sub) - implied by --self-sign
  1 - Domain Validated (DV) - requires registry CA
  2 - Organization Validated (OV) - requires registry CA  
  3 - Extended Validated (EV) - requires registry CA
  4 - Community Vouched (CV) - requires registry CA

Examples:
  # Self-signed badge (level 0 implied)
  capiscio badge issue --self-sign

  # Self-signed with existing key
  capiscio badge issue --self-sign --key private.jwk

  # With audience restriction
  capiscio badge issue --self-sign --aud "https://api.example.com"`,
	RunE: func(_ *cobra.Command, _ []string) error {
		// Self-sign implies level 0 (per RFC-002: self-signed = self-assertion = level 0)
		if issueSelfSign {
			// If level wasn't explicitly set or is default "1", use level 0
			if issueLevel == "1" {
				issueLevel = "0"
			} else if issueLevel != "0" {
				return fmt.Errorf("--self-sign implies level 0; higher levels require registry CA issuance")
			}
		}

		// Validate trust level (0-4 per RFC-002 v1.1)
		validLevels := map[string]bool{"0": true, "1": true, "2": true, "3": true, "4": true}
		if !validLevels[issueLevel] {
			return fmt.Errorf("invalid trust level: %s (must be 0, 1, 2, 3, or 4)", issueLevel)
		}

		// Level 0 requires --self-sign
		if issueLevel == "0" && !issueSelfSign {
			return fmt.Errorf("level 0 badges require --self-sign flag")
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
		}

		// For level 0 self-signed: generate did:key and set iss = sub
		var didKey string
		if issueSelfSign && issueLevel == "0" {
			didKey = did.NewKeyDID(pub)
			issueIssuer = didKey
			issueSubject = didKey
			fmt.Fprintf(os.Stderr, "🔑 Generated did:key: %s\n\n", didKey)
		} else if keyFile == "" {
			// Non-level-0: print ephemeral public key for verification
			jwk := jose.JSONWebKey{Key: pub, KeyID: "ephemeral-key", Algorithm: string(jose.EdDSA)}
			jwkJSON, _ := jwk.MarshalJSON()
			fmt.Fprintf(os.Stderr, "Generated Ephemeral Public Key (save this to verify):\n%s\n\n", string(jwkJSON))
		}

		// Validate subject format for non-level-0 badges
		if issueLevel != "0" && !strings.HasPrefix(issueSubject, "did:web:") {
			fmt.Fprintf(os.Stderr, "⚠️  Warning: Subject should be a did:web identifier (got: %s)\n", issueSubject)
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
		if issueSelfSign && issueLevel != "0" {
			fmt.Fprintf(os.Stderr, "⚠️  Warning: Self-signed badges at level %s are for development only.\n", issueLevel)
		} else if issueSelfSign && issueLevel == "0" {
			fmt.Fprintf(os.Stderr, "📛 Issuing Level 0 self-signed badge (iss == sub == did:key)\n")
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

Modes:
  1. CA Mode (production): Request badges from CapiscIO registry
     Requires: --api-key, --agent-id
     
  2. Self-Sign Mode (development): Generate self-signed badges locally
     Requires: --self-sign, --key

Examples:
  # CA mode - production use
  capiscio badge keep --agent-id <uuid> --api-key $CAPISCIO_API_KEY --out badge.jwt

  # Self-signed mode for development
  capiscio badge keep --self-sign --key private.jwk --out badge.jwt

Environment Variables:
  CAPISCIO_API_KEY    API key (alternative to --api-key flag)
  CAPISCIO_CA_URL     CA URL (alternative to --ca flag)`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		// Check for API key from env if not provided via flag
		if keepAPIKey == "" {
			keepAPIKey = os.Getenv("CAPISCIO_API_KEY")
		}
		
		// Check for CA URL from env if not provided via flag
		if keepCA == "" || keepCA == "https://registry.capisc.io" {
			if envCA := os.Getenv("CAPISCIO_CA_URL"); envCA != "" {
				keepCA = envCA
			}
		}

		// Determine mode
		if keepSelfSign {
			return runSelfSignKeeper(cmd.Context())
		}
		
		// CA mode - validate requirements
		if keepAPIKey == "" {
			return &AuthRequiredError{
				Command: "badge keep",
				Message: "API key required for CA mode",
				Help: `To use the badge keeper with CapiscIO as CA:

  1. Create an account at https://app.capisc.io
  2. Register your agent and get an API key
  3. Run with:
     capiscio badge keep --agent-id <uuid> --api-key <key>
     
     Or set environment variable:
     export CAPISCIO_API_KEY=sk_live_...
     capiscio badge keep --agent-id <uuid>

For local development without a CA, use:
  capiscio badge keep --self-sign --key private.jwk`,
			}
		}
		
		if keepAgentID == "" {
			return &AuthRequiredError{
				Command: "badge keep",
				Message: "Agent ID required for CA mode",
				Help: `Specify the agent ID to request badges for:

  capiscio badge keep --agent-id <uuid> --api-key <key>

Find your agent ID at https://app.capisc.io/agents`,
			}
		}
		
		return runCAKeeper(cmd.Context())
	},
}

// AuthRequiredError is returned when authentication is required but not provided.
type AuthRequiredError struct {
	Command string
	Message string
	Help    string
}

func (e *AuthRequiredError) Error() string {
	return fmt.Sprintf("🔐 Authentication Required\n\n%s\n\n%s", e.Message, e.Help)
}

// runSelfSignKeeper runs the badge keeper in self-sign mode
func runSelfSignKeeper(ctx context.Context) error {
	if keyFile == "" {
		return fmt.Errorf("--key required for self-sign mode: provide path to Ed25519 private key (JWK)")
	}
	
	// Load Private Key
	priv, pub, err := loadPrivateKey(keyFile)
	if err != nil {
		return err
	}

	// For self-sign mode, generate did:key
	didKey := did.NewKeyDID(pub)
	
	// Setup Config
	pubJWK := &jose.JSONWebKey{
		Key:       pub,
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	config := badge.KeeperConfig{
		PrivateKey: priv,
		Claims: badge.Claims{
			Issuer:  didKey,
			Subject: didKey,
			Key:     pubJWK,
			VC: badge.VerifiableCredential{
				Type: []string{"VerifiableCredential", "AgentIdentity"},
				CredentialSubject: badge.CredentialSubject{
					Domain: issueDomain,
					Level:  "0", // Self-sign is always level 0
				},
			},
		},
		OutputFile:    keepOutFile,
		Expiry:        issueExpiry,
		RenewBefore:   keepRenewBefore,
		CheckInterval: keepCheckInterval,
	}

	// Run Keeper
	keeper := badge.NewKeeper(config)
	fmt.Printf("🔄 Starting Badge Keeper (Self-Sign Mode)\n")
	fmt.Printf("   DID: %s\n", didKey)
	fmt.Printf("   Output: %s\n", keepOutFile)
	fmt.Printf("   Expiry: %v\n", issueExpiry)
	fmt.Printf("   Renew Before: %v\n", keepRenewBefore)
	fmt.Printf("   ⚠️  Level 0 badges - development/testing only\n")
	fmt.Println()
	return keeper.Run(ctx)
}

// runCAKeeper runs the badge keeper in CA mode
func runCAKeeper(ctx context.Context) error {
	fmt.Printf("🔄 Starting Badge Keeper (CA Mode)\n")
	fmt.Printf("   CA: %s\n", keepCA)
	fmt.Printf("   Agent ID: %s\n", keepAgentID)
	fmt.Printf("   Output: %s\n", keepOutFile)
	fmt.Printf("   Renew Before: %v\n", keepRenewBefore)
	fmt.Println()

	// Initial badge request
	if err := requestBadgeFromCA(); err != nil {
		return fmt.Errorf("initial badge request failed: %w", err)
	}
	
	// Run keeper loop
	ticker := time.NewTicker(keepCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Println("🛑 Badge Keeper stopped")
			return nil
		case <-ticker.C:
			// Check if badge needs renewal
			needsRenewal, err := checkBadgeNeedsRenewal()
			if err != nil {
				fmt.Fprintf(os.Stderr, "⚠️  Error checking badge: %v\n", err)
				continue
			}
			
			if needsRenewal {
				fmt.Printf("🔄 Renewing badge...\n")
				if err := requestBadgeFromCA(); err != nil {
					fmt.Fprintf(os.Stderr, "❌ Badge renewal failed: %v\n", err)
				}
			}
		}
	}
}

// requestBadgeFromCA requests a new badge from the CA
func requestBadgeFromCA() error {
	// Build request
	reqBody := map[string]interface{}{
		"domain":     issueDomain,
		"trustLevel": issueLevel,
	}
	
	if issueExpiry > 0 {
		reqBody["duration"] = issueExpiry.String()
	}
	
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}
	
	// Build URL
	url := fmt.Sprintf("%s/v1/agents/%s/badge", strings.TrimSuffix(keepCA, "/"), keepAgentID)
	
	// Create request
	req, err := http.NewRequest("POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+keepAPIKey)
	req.Header.Set("User-Agent", "capiscio-cli/1.0")
	
	// Send request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	
	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}
	
	// Check status
	if resp.StatusCode == http.StatusUnauthorized {
		return &AuthRequiredError{
			Command: "badge keep",
			Message: "Invalid or expired API key",
			Help: `Your API key was rejected. Please check:

  1. The API key is correct (starts with sk_live_ or sk_test_)
  2. The API key has not been revoked
  3. You have permission to manage this agent

Get a new API key at https://app.capisc.io/api-keys`,
		}
	}
	
	if resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("agent is disabled or you don't have permission")
	}
	
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("agent not found: %s", keepAgentID)
	}
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("CA returned status %d: %s", resp.StatusCode, string(respBody))
	}
	
	// Parse response
	var caResp struct {
		Success bool `json:"success"`
		Data    struct {
			Token      string    `json:"token"`
			JTI        string    `json:"jti"`
			Subject    string    `json:"subject"`
			TrustLevel string    `json:"trustLevel"`
			ExpiresAt  time.Time `json:"expiresAt"`
		} `json:"data"`
		Error string `json:"error"`
	}
	
	if err := json.Unmarshal(respBody, &caResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	
	if !caResp.Success {
		return fmt.Errorf("CA error: %s", caResp.Error)
	}
	
	// Write badge to file
	if err := os.WriteFile(keepOutFile, []byte(caResp.Data.Token), 0600); err != nil {
		return fmt.Errorf("failed to write badge file: %w", err)
	}
	
	fmt.Printf("✅ Badge issued: %s\n", caResp.Data.JTI)
	fmt.Printf("   Subject: %s\n", caResp.Data.Subject)
	fmt.Printf("   Level: %s\n", caResp.Data.TrustLevel)
	fmt.Printf("   Expires: %s\n", caResp.Data.ExpiresAt.Format(time.RFC3339))
	
	return nil
}

// checkBadgeNeedsRenewal checks if the current badge needs renewal
func checkBadgeNeedsRenewal() (bool, error) {
	// Read current badge
	badgeData, err := os.ReadFile(keepOutFile)
	if err != nil {
		if os.IsNotExist(err) {
			return true, nil // No badge, need one
		}
		return false, err
	}
	
	// Parse badge to get expiry (parse JWS and extract claims)
	token := strings.TrimSpace(string(badgeData))
	jwsObj, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.EdDSA, jose.ES256})
	if err != nil {
		return true, nil // Invalid badge, need new one
	}
	
	// Extract claims without verification (just to check expiry)
	var claims badge.Claims
	if err := json.Unmarshal(jwsObj.UnsafePayloadWithoutVerification(), &claims); err != nil {
		return true, nil // Invalid claims, need new one
	}
	
	// Check if approaching expiry
	expiresAt := claims.ExpiresAt()
	renewAt := expiresAt.Add(-keepRenewBefore)
	
	return time.Now().After(renewAt), nil
}

var verifyCmd = &cobra.Command{
	Use:   "verify [token]",
	Short: "Verify a Trust Badge",
	Long: `Verify a Trust Badge and display the claims.

Performs verification per RFC-002 §8.1:
1. Parse and validate JWS structure
2. Verify signature against issuer key
3. Validate claims (exp, iat, iss, aud)
4. Check revocation status (online mode)
5. Check agent status (online mode)

Self-Signed Badges (Level 0):
  For did:key issuers, use --accept-self-signed to allow verification.
  The public key is extracted directly from the did:key identifier.

Examples:
  # Verify a Level 0 self-signed badge
  capiscio badge verify $TOKEN --accept-self-signed

  # Verify with local key file
  capiscio badge verify $TOKEN --key ca-public.jwk

  # Offline verification
  capiscio badge verify $TOKEN --offline

  # With audience check
  capiscio badge verify $TOKEN --key ca.jwk --audience https://api.example.com

  # With trusted issuers list
  capiscio badge verify $TOKEN --trusted-issuers "did:web:registry.capisc.io"`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		token := args[0]

		// Build verification options
		opts := badge.VerifyOptions{
			Mode:                 badge.VerifyModeOnline,
			SkipRevocationCheck:  verifySkipRevocation,
			SkipAgentStatusCheck: verifySkipAgentStatus,
			AcceptSelfSigned:     verifyAcceptSelfSigned,
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
		} else if verifyAcceptSelfSigned {
			// For self-signed badges, we don't need a registry - the verifier
			// extracts the public key from the did:key issuer
			reg = &SelfSignedRegistry{}
		} else if verifyOffline {
			// Use trust store
			store, err := trust.NewFileStore("")
			if err != nil {
				return fmt.Errorf("failed to open trust store: %w", err)
			}
			reg = &TrustStoreRegistry{store: store}
		} else {
			return fmt.Errorf("public key required: use --key (path to JWK file), --accept-self-signed, or --offline (uses trust store)")
		}

		// Verify
		verifier := badge.NewVerifier(reg)
		result, err := verifier.VerifyWithOptions(cmd.Context(), token, opts)
		if err != nil {
			// Check if it's a badge error with a code
			if badgeErr, ok := badge.AsError(err); ok {
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

// SelfSignedRegistry is a placeholder registry for self-signed badge verification.
// The actual key extraction is handled by the verifier from the did:key issuer.
type SelfSignedRegistry struct{}

func (r *SelfSignedRegistry) GetPublicKey(_ context.Context, issuer string) (crypto.PublicKey, error) {
	// For did:key issuers, extract the public key from the DID
	if strings.HasPrefix(issuer, "did:key:") {
		pub, err := did.PublicKeyFromKeyDID(issuer)
		if err != nil {
			return nil, fmt.Errorf("failed to extract public key from did:key: %w", err)
		}
		return pub, nil
	}
	return nil, fmt.Errorf("self-signed verification only supports did:key issuers (got: %s)", issuer)
}

func (r *SelfSignedRegistry) IsRevoked(_ context.Context, _ string) (bool, error) {
	// Self-signed badges don't support revocation
	return false, nil
}

func (r *SelfSignedRegistry) GetBadgeStatus(_ context.Context, _ string, _ string) (*registry.BadgeStatus, error) {
	return &registry.BadgeStatus{Revoked: false}, nil
}

func (r *SelfSignedRegistry) GetAgentStatus(_ context.Context, _ string, _ string) (*registry.AgentStatus, error) {
	return &registry.AgentStatus{Status: registry.AgentStatusActive}, nil
}

func (r *SelfSignedRegistry) SyncRevocations(_ context.Context, _ string, _ time.Time) ([]registry.Revocation, error) {
	return nil, nil
}

func init() {
	rootCmd.AddCommand(badgeCmd)
	badgeCmd.AddCommand(issueCmd)
	badgeCmd.AddCommand(verifyCmd)
	badgeCmd.AddCommand(keepCmd)

	// Issue Flags
	issueCmd.Flags().StringVar(&issueSubject, "sub", did.NewCapiscIOAgentDID("test"), "Subject DID (did:web format, auto-set for level 0)")
	issueCmd.Flags().StringVar(&issueIssuer, "iss", "did:web:registry.capisc.io", "Issuer DID (auto-set to did:key for level 0)")
	issueCmd.Flags().StringVar(&issueDomain, "domain", "example.com", "Agent Domain")
	issueCmd.Flags().DurationVar(&issueExpiry, "exp", 5*time.Minute, "Expiration duration (default 5m per RFC-002)")
	issueCmd.Flags().StringVar(&issueLevel, "level", "1", "Trust level (0=self-signed, 1=DV, 2=OV, 3=EV, 4=CV)")
	issueCmd.Flags().StringVar(&issueAudience, "aud", "", "Audience (comma-separated URLs)")
	issueCmd.Flags().BoolVar(&issueSelfSign, "self-sign", false, "Issue self-signed badge (implies level 0)")
	issueCmd.Flags().StringVar(&keyFile, "key", "", "Path to private key file (optional, auto-generates if not provided)")

	// Keep Flags
	keepCmd.Flags().StringVar(&keepAgentID, "agent-id", "", "Agent ID (UUID) to request badges for")
	keepCmd.Flags().StringVar(&issueDomain, "domain", "", "Agent domain (optional, uses agent's registered domain)")
	keepCmd.Flags().DurationVar(&issueExpiry, "exp", 5*time.Minute, "Badge expiration duration")
	keepCmd.Flags().StringVar(&issueLevel, "level", "1", "Trust level (1=DV, 2=OV, 3=EV, 4=CV)")
	keepCmd.Flags().StringVar(&keyFile, "key", "", "Path to private key file (required for --self-sign)")
	keepCmd.Flags().StringVar(&keepOutFile, "out", "badge.jwt", "Output file path for badge")
	keepCmd.Flags().DurationVar(&keepRenewBefore, "renew-before", 1*time.Minute, "Time before expiry to renew")
	keepCmd.Flags().DurationVar(&keepCheckInterval, "check-interval", 30*time.Second, "Interval to check for renewal")
	keepCmd.Flags().StringVar(&keepCA, "ca", "https://registry.capisc.io", "CA URL for badge requests")
	keepCmd.Flags().StringVar(&keepAPIKey, "api-key", "", "API key for CA authentication (or use CAPISCIO_API_KEY env)")
	keepCmd.Flags().BoolVar(&keepSelfSign, "self-sign", false, "Self-sign badges locally (development only)")

	// Verify Flags
	verifyCmd.Flags().StringVar(&keyFile, "key", "", "Path to public key file (JWK)")
	verifyCmd.Flags().BoolVar(&verifyOffline, "offline", false, "Offline mode (uses trust store)")
	verifyCmd.Flags().StringVar(&verifyTrustedIssuers, "trusted-issuers", "", "Comma-separated list of trusted issuer DIDs")
	verifyCmd.Flags().StringVar(&verifyAudience, "audience", "", "Verifier's identity for audience validation")
	verifyCmd.Flags().BoolVar(&verifySkipRevocation, "skip-revocation", false, "Skip revocation check (testing only)")
	verifyCmd.Flags().BoolVar(&verifySkipAgentStatus, "skip-agent-status", false, "Skip agent status check (testing only)")
	verifyCmd.Flags().BoolVar(&verifyAcceptSelfSigned, "accept-self-signed", false, "Accept Level 0 self-signed badges (did:key issuers)")
}
