package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/did"
	"github.com/capiscio/capiscio-core/v2/pkg/envelope"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

var (
	// Envelope issue flags
	envIssuerDID   string
	envSubjectDID  string
	envCapability  string
	envDepth       int
	envExpiry      time.Duration
	envKeyFile     string
	envConstraints string
	envMinMode     string
	envTxnID       string
	envBadgeJTI    string

	// Envelope derive flags
	envParentFile     string
	envDeriveKeyFile  string

	// Envelope verify flags
	envSkipBadge            bool
	envVerifyMinMode        string
)

var envelopeCmd = &cobra.Command{
	Use:   "envelope",
	Short: "Manage Authority Envelopes (RFC-008)",
	Long: `Manage Authority Envelopes for delegated capability authorization.

Authority Envelopes are signed JWS tokens that grant capabilities to agents
and can be delegated through chains with monotonically narrowing permissions.
See RFC-008 for the full specification.`,
}

var envIssueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issue a root Authority Envelope",
	Long: `Issue a root Authority Envelope.

A root envelope has no parent and establishes the initial capability grant.

Examples:
  # Issue a root envelope (auto-generates keys)
  capiscio envelope issue --subject did:key:z6Mk... --capability tools.database --depth 5

  # Issue with a specific key file
  capiscio envelope issue --key issuer.jwk --subject did:key:z6Mk... --capability tools.database.read --depth 3`,
	RunE: runEnvIssue,
}

var envDeriveCmd = &cobra.Command{
	Use:   "derive",
	Short: "Derive a child envelope from a parent",
	Long: `Derive a child Authority Envelope from a parent envelope.

The child must have narrower or equal permissions compared to the parent
across all four dimensions: capability scope, temporal bounds, depth, and constraints.

Examples:
  capiscio envelope derive --parent root.env --key child.jwk --subject did:key:z6Mk... --capability tools.database.read --depth 2`,
	RunE: runEnvDerive,
}

var envVerifyCmd = &cobra.Command{
	Use:   "verify [envelope-file]",
	Short: "Verify an Authority Envelope",
	Long: `Verify an Authority Envelope's signature, temporal validity, and structure.

Examples:
  capiscio envelope verify envelope.jws
  capiscio envelope verify --skip-badge envelope.jws`,
	Args: cobra.ExactArgs(1),
	RunE: runEnvVerify,
}

var envChainCmd = &cobra.Command{
	Use:   "chain [envelope-files...]",
	Short: "Verify a chain of Authority Envelopes",
	Long: `Verify a delegation chain of Authority Envelopes (root-to-leaf order).

Validates hash links, DID continuity, narrowing rules, and signatures.

Examples:
  capiscio envelope chain root.env child1.env child2.env`,
	Args: cobra.MinimumNArgs(1),
	RunE: runEnvChain,
}

var envInspectCmd = &cobra.Command{
	Use:   "inspect [envelope-file]",
	Short: "Inspect an Authority Envelope without verification",
	Long: `Parse and display the contents of an Authority Envelope without signature verification.

Examples:
  capiscio envelope inspect envelope.jws`,
	Args: cobra.ExactArgs(1),
	RunE: runEnvInspect,
}

func runEnvIssue(cmd *cobra.Command, args []string) error {
	var priv, pub, err = loadOrGenerateKey(envKeyFile)
	if err != nil {
		return err
	}

	issuerDID := envIssuerDID
	if issuerDID == "" {
		issuerDID = did.NewKeyDID(pub)
	}

	subjectDID := envSubjectDID
	if subjectDID == "" {
		return fmt.Errorf("--subject is required")
	}

	txnID := envTxnID
	if txnID == "" {
		txnID = uuid.New().String()
	}

	badgeJTI := envBadgeJTI
	if badgeJTI == "" {
		badgeJTI = uuid.New().String()
	}

	now := time.Now()
	payload := &envelope.Payload{
		EnvelopeID:               uuid.New().String(),
		IssuerDID:                issuerDID,
		SubjectDID:               subjectDID,
		TxnID:                    txnID,
		CapabilityClass:          envCapability,
		Constraints:              map[string]any{},
		DelegationDepthRemaining: envDepth,
		IssuedAt:                 now.Unix(),
		ExpiresAt:                now.Add(envExpiry).Unix(),
		IssuerBadgeJTI:           badgeJTI,
	}

	if envMinMode != "" {
		payload.EnforcementModeMin = &envMinMode
	}

	if envConstraints != "" {
		var constraints map[string]any
		if err := json.Unmarshal([]byte(envConstraints), &constraints); err != nil {
			return fmt.Errorf("invalid constraints JSON: %w", err)
		}
		payload.Constraints = constraints
	}

	kid := issuerDID + "#key-1"
	token, err := envelope.SignEnvelope(payload, priv, kid)
	if err != nil {
		return fmt.Errorf("failed to sign envelope: %w", err)
	}

	fmt.Println(token)
	return nil
}

func runEnvDerive(cmd *cobra.Command, args []string) error {
	// Load parent envelope
	parentData, err := os.ReadFile(envParentFile)
	if err != nil {
		return fmt.Errorf("failed to read parent envelope: %w", err)
	}
	parentToken, err := envelope.ParseToken(string(parentData))
	if err != nil {
		return fmt.Errorf("failed to parse parent envelope: %w", err)
	}

	priv, pub, err := loadOrGenerateKey(envDeriveKeyFile)
	if err != nil {
		return err
	}

	issuerDID := envIssuerDID
	if issuerDID == "" {
		issuerDID = did.NewKeyDID(pub)
	}

	subjectDID := envSubjectDID
	if subjectDID == "" {
		return fmt.Errorf("--subject is required")
	}

	now := time.Now()
	childPayload := &envelope.Payload{
		EnvelopeID:               uuid.New().String(),
		IssuerDID:                issuerDID,
		SubjectDID:               subjectDID,
		TxnID:                    parentToken.Payload.TxnID,
		CapabilityClass:          envCapability,
		Constraints:              map[string]any{},
		DelegationDepthRemaining: envDepth,
		IssuedAt:                 now.Unix(),
		ExpiresAt:                now.Add(envExpiry).Unix(),
		IssuerBadgeJTI:           envBadgeJTI,
	}

	if envMinMode != "" {
		childPayload.EnforcementModeMin = &envMinMode
	}

	if envConstraints != "" {
		var constraints map[string]any
		if err := json.Unmarshal([]byte(envConstraints), &constraints); err != nil {
			return fmt.Errorf("invalid constraints JSON: %w", err)
		}
		childPayload.Constraints = constraints
	}

	kid := issuerDID + "#key-1"
	token, err := envelope.DeriveEnvelope(parentToken, childPayload, priv, kid)
	if err != nil {
		return fmt.Errorf("failed to derive envelope: %w", err)
	}

	fmt.Println(token)
	return nil
}

func runEnvVerify(cmd *cobra.Command, args []string) error {
	data, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("failed to read envelope file: %w", err)
	}

	v := &envelope.Verifier{
		KeyResolver: envelope.DefaultKeyResolver,
	}

	minMode := envelope.EMObserve
	if envVerifyMinMode != "" {
		minMode, err = envelope.ParseEnforcementMode(envVerifyMinMode)
		if err != nil {
			return err
		}
	}

	result, err := v.VerifyEnvelope(context.Background(), string(data), "", "", envelope.VerifyOptions{
		SkipBadgeVerification: envSkipBadge,
		EnforcementMode:       minMode,
	})
	if err != nil {
		return fmt.Errorf("envelope verification failed: %w", err)
	}

	output := map[string]any{
		"status":          "VALID",
		"envelope_id":     result.Payload.EnvelopeID,
		"issuer_did":      result.Payload.IssuerDID,
		"subject_did":     result.Payload.SubjectDID,
		"capability":      result.Payload.CapabilityClass,
		"depth_remaining": result.Payload.DelegationDepthRemaining,
		"effective_mode":  result.EffectiveMode.String(),
		"is_root":         result.Payload.IsRoot(),
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

func runEnvChain(cmd *cobra.Command, args []string) error {
	envelopes := make([]string, 0, len(args))
	for _, file := range args {
		data, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", file, err)
		}
		envelopes = append(envelopes, string(data))
	}

	v := &envelope.Verifier{
		KeyResolver: envelope.DefaultKeyResolver,
	}

	result, err := v.VerifyChain(context.Background(), envelopes, map[string]string{}, envelope.VerifyOptions{
		SkipBadgeVerification: envSkipBadge,
	})
	if err != nil {
		return fmt.Errorf("chain verification failed: %w", err)
	}

	output := map[string]any{
		"status":          "VALID",
		"total_depth":     result.TotalDepth,
		"root_capability": result.RootCapability,
		"leaf_capability": result.LeafCapability,
		"chain_length":    len(result.Links),
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

func runEnvInspect(cmd *cobra.Command, args []string) error {
	data, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("failed to read envelope file: %w", err)
	}

	token, err := envelope.ParseToken(string(data))
	if err != nil {
		return fmt.Errorf("failed to parse envelope: %w", err)
	}

	output := map[string]any{
		"envelope_id":               token.Payload.EnvelopeID,
		"issuer_did":                token.Payload.IssuerDID,
		"subject_did":               token.Payload.SubjectDID,
		"txn_id":                    token.Payload.TxnID,
		"capability_class":          token.Payload.CapabilityClass,
		"constraints":               token.Payload.Constraints,
		"delegation_depth_remaining": token.Payload.DelegationDepthRemaining,
		"issued_at":                 token.Payload.IssuedAt,
		"expires_at":                token.Payload.ExpiresAt,
		"issuer_badge_jti":          token.Payload.IssuerBadgeJTI,
		"is_root":                   token.Payload.IsRoot(),
	}

	if token.Payload.ParentAuthorityHash != nil {
		output["parent_authority_hash"] = *token.Payload.ParentAuthorityHash
	}
	if token.Payload.SubjectBadgeJTI != nil {
		output["subject_badge_jti"] = *token.Payload.SubjectBadgeJTI
	}
	if token.Payload.EnforcementModeMin != nil {
		output["enforcement_mode_min"] = *token.Payload.EnforcementModeMin
	}

	output["hash"] = envelope.ComputeHash(string(data))

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

// loadOrGenerateKey loads a key from file or generates a new Ed25519 key pair.
func loadOrGenerateKey(keyFilePath string) (any, []byte, error) {
	if keyFilePath != "" {
		priv, pub, err := loadPrivateKey(keyFilePath)
		if err != nil {
			return nil, nil, err
		}
		return priv, pub, nil
	}

	// Auto-generate
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}
	fmt.Fprintln(os.Stderr, "Auto-generated Ed25519 key pair (use --key to provide your own)")
	return priv, pub, nil
}

func init() {
	rootCmd.AddCommand(envelopeCmd)
	envelopeCmd.AddCommand(envIssueCmd)
	envelopeCmd.AddCommand(envDeriveCmd)
	envelopeCmd.AddCommand(envVerifyCmd)
	envelopeCmd.AddCommand(envChainCmd)
	envelopeCmd.AddCommand(envInspectCmd)

	// Issue flags
	envIssueCmd.Flags().StringVar(&envIssuerDID, "issuer", "", "Issuer DID (auto-derived from key if not set)")
	envIssueCmd.Flags().StringVar(&envSubjectDID, "subject", "", "Subject DID (required)")
	envIssueCmd.Flags().StringVar(&envCapability, "capability", "", "Capability class (e.g. tools.database.read)")
	envIssueCmd.Flags().IntVar(&envDepth, "depth", 0, "Maximum delegation depth remaining")
	envIssueCmd.Flags().DurationVar(&envExpiry, "expiry", 1*time.Hour, "Envelope expiry duration")
	envIssueCmd.Flags().StringVar(&envKeyFile, "key", "", "Path to issuer private key file (JWK)")
	envIssueCmd.Flags().StringVar(&envConstraints, "constraints", "", "Constraints as JSON object")
	envIssueCmd.Flags().StringVar(&envMinMode, "min-mode", "", "Minimum enforcement mode (EM-OBSERVE|EM-GUARD|EM-DELEGATE|EM-STRICT)")
	envIssueCmd.Flags().StringVar(&envTxnID, "txn-id", "", "Transaction ID (auto-generated if not set)")
	envIssueCmd.Flags().StringVar(&envBadgeJTI, "badge-jti", "", "Issuer badge JTI (auto-generated if not set)")

	// Derive flags
	envDeriveCmd.Flags().StringVar(&envParentFile, "parent", "", "Path to parent envelope file (required)")
	envDeriveCmd.Flags().StringVar(&envSubjectDID, "subject", "", "Subject DID (required)")
	envDeriveCmd.Flags().StringVar(&envCapability, "capability", "", "Capability class (must be within parent scope)")
	envDeriveCmd.Flags().IntVar(&envDepth, "depth", 0, "Delegation depth remaining (must be less than parent)")
	envDeriveCmd.Flags().DurationVar(&envExpiry, "expiry", 30*time.Minute, "Envelope expiry duration")
	envDeriveCmd.Flags().StringVar(&envDeriveKeyFile, "key", "", "Path to issuer private key file (JWK)")
	envDeriveCmd.Flags().StringVar(&envConstraints, "constraints", "", "Constraints as JSON object")
	envDeriveCmd.Flags().StringVar(&envMinMode, "min-mode", "", "Minimum enforcement mode")
	envDeriveCmd.Flags().StringVar(&envIssuerDID, "issuer", "", "Issuer DID (auto-derived from key if not set)")
	envDeriveCmd.Flags().StringVar(&envBadgeJTI, "badge-jti", "", "Issuer badge JTI")

	// Verify flags
	envVerifyCmd.Flags().BoolVar(&envSkipBadge, "skip-badge", false, "Skip badge verification (testing only)")
	envVerifyCmd.Flags().StringVar(&envVerifyMinMode, "min-mode", "", "Required minimum enforcement mode")

	// Chain flags (uses same verify flags)
	envChainCmd.Flags().BoolVar(&envSkipBadge, "skip-badge", false, "Skip badge verification (testing only)")
}
