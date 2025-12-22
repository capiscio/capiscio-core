// Package badge provides badge client functionality for requesting badges from a CA.
package badge

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
)

// PoPClient is an HTTP client for requesting badges using Proof of Possession (RFC-003).
// This provides IAL-1 badge issuance with cryptographic key binding.
type PoPClient struct {
	CAURL      string
	APIKey     string
	HTTPClient *http.Client
}

// NewPoPClient creates a new PoP badge client with a default HTTP client.
// The default HTTP client uses a 30-second timeout.
func NewPoPClient(caURL, apiKey string) *PoPClient {
	return NewPoPClientWithHTTPClient(caURL, apiKey, nil)
}

// NewPoPClientWithHTTPClient creates a new PoP badge client with a custom HTTP client.
// If httpClient is nil, a default client with 30-second timeout is used.
func NewPoPClientWithHTTPClient(caURL, apiKey string, httpClient *http.Client) *PoPClient {
	if caURL == "" {
		caURL = DefaultCAURL
	}
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
		}
	}
	// Trim trailing slash for consistency with Client in client.go
	caURL = strings.TrimSuffix(caURL, "/")
	return &PoPClient{
		CAURL:      caURL,
		APIKey:     apiKey,
		HTTPClient: httpClient,
	}
}

// RequestPoPBadgeOptions contains options for PoP badge request.
type RequestPoPBadgeOptions struct {
	// AgentDID is the DID of the agent (e.g., did:key:z6Mk... or did:web:...)
	AgentDID string

	// PrivateKey is the agent's private key for signing the PoP proof
	PrivateKey crypto.PrivateKey

	// TTL is the requested badge TTL (optional, default 5 min)
	TTL time.Duration

	// Audience is the optional audience restrictions
	Audience []string
}

// RequestPoPBadgeResult contains the result of a PoP badge request.
type RequestPoPBadgeResult struct {
	Token          string
	JTI            string
	Subject        string
	TrustLevel     string
	AssuranceLevel string // "IAL-1" for PoP badges
	ExpiresAt      time.Time
	CNF            map[string]interface{} // Confirmation claim with key binding
}

// ChallengeResponse represents the server's challenge response.
type ChallengeResponse struct {
	ChallengeID string    `json:"challenge_id"`
	Nonce       string    `json:"nonce"`
	ExpiresAt   time.Time `json:"expires_at"`
	Aud         string    `json:"aud"`
	HTU         string    `json:"htu"`
	HTM         string    `json:"htm"`
}

// PoPProofClaims represents the claims in a PoP proof JWS.
type PoPProofClaims struct {
	CID   string `json:"cid"`   // Challenge ID
	Nonce string `json:"nonce"` // Server nonce
	Sub   string `json:"sub"`   // Subject (DID)
	Aud   string `json:"aud"`   // Audience (registry)
	HTU   string `json:"htu"`   // HTTP Target URI
	HTM   string `json:"htm"`   // HTTP Method
	IAT   int64  `json:"iat"`   // Issued at
	Exp   int64  `json:"exp"`   // Expiration
	JTI   string `json:"jti"`   // Proof JTI (unique)
}

// RequestPoPBadge requests a badge using the PoP protocol (RFC-003 IAL-1).
// This provides cryptographic proof that the requester controls the DID's private key.
func (c *PoPClient) RequestPoPBadge(ctx context.Context, opts RequestPoPBadgeOptions) (*RequestPoPBadgeResult, error) {
	if opts.AgentDID == "" {
		return nil, fmt.Errorf("AgentDID is required")
	}
	if opts.PrivateKey == nil {
		return nil, fmt.Errorf("PrivateKey is required for PoP")
	}

	// Phase 1: Request challenge
	challenge, err := c.requestChallenge(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get challenge: %w", err)
	}

	// Phase 2: Sign challenge and request badge
	return c.submitProof(ctx, opts, challenge)
}

// requestChallenge performs Phase 1: Request a PoP challenge from the CA.
func (c *PoPClient) requestChallenge(ctx context.Context, opts RequestPoPBadgeOptions) (*ChallengeResponse, error) {
	// URL-encode the DID for the path
	encodedDID := url.PathEscape(opts.AgentDID)
	challengeURL := fmt.Sprintf("%s/v1/agents/%s/badge/challenge", c.CAURL, encodedDID)

	// Build request body
	reqBody := map[string]interface{}{}
	if opts.TTL > 0 {
		reqBody["badge_ttl"] = int(opts.TTL.Seconds())
	}
	if len(opts.Audience) > 0 {
		reqBody["badge_aud"] = opts.Audience
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal challenge request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", challengeURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create challenge request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	// RFC-003 §3.1: Phase 1 requires X-Capiscio-Registry-Key
	req.Header.Set("X-Capiscio-Registry-Key", c.APIKey)
	req.Header.Set("User-Agent", "capiscio-core/2.2.0")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("challenge request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read challenge response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseErrorResponse(resp.StatusCode, respBody, "challenge")
	}

	var challenge ChallengeResponse
	if err := json.Unmarshal(respBody, &challenge); err != nil {
		return nil, fmt.Errorf("failed to parse challenge response: %w", err)
	}

	return &challenge, nil
}

// submitProof performs Phase 2: Sign the challenge and submit proof for badge issuance.
func (c *PoPClient) submitProof(ctx context.Context, opts RequestPoPBadgeOptions, challenge *ChallengeResponse) (*RequestPoPBadgeResult, error) {
	// Validate challenge hasn't expired before signing.
	// Add 5-second buffer to account for signing time and network latency.
	now := time.Now()
	const expiryBuffer = 5 * time.Second
	if !challenge.ExpiresAt.IsZero() && now.Add(expiryBuffer).After(challenge.ExpiresAt) {
		return nil, &ClientError{
			Code:    "CHALLENGE_EXPIRED",
			Message: "challenge expired or expiring too soon to safely submit proof",
		}
	}

	// Build proof claims per RFC-003 §6.2
	proofClaims := PoPProofClaims{
		CID:   challenge.ChallengeID,
		Nonce: challenge.Nonce,
		Sub:   opts.AgentDID,
		Aud:   challenge.Aud,
		HTU:   challenge.HTU,
		HTM:   challenge.HTM,
		IAT:   now.Unix(),
		Exp:   now.Add(60 * time.Second).Unix(), // RFC-003: proof exp ≤ iat + 60s
		JTI:   uuid.New().String(),
	}

	// Sign the proof
	proofJWS, err := c.signProof(proofClaims, opts.PrivateKey, opts.AgentDID)
	if err != nil {
		return nil, fmt.Errorf("failed to sign proof: %w", err)
	}

	// Submit to badge/pop endpoint
	// URL-encode the DID for the path
	encodedDID := url.PathEscape(opts.AgentDID)
	popURL := fmt.Sprintf("%s/v1/agents/%s/badge/pop", c.CAURL, encodedDID)

	reqBody := map[string]string{
		"challenge_id": challenge.ChallengeID,
		"proof_jws":    proofJWS,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PoP request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", popURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create PoP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	// RFC-003 §5.2.1: Phase 2 (PoP submission) is self-authenticating via the signed proof;
	// Phase 1 (challenge request) still requires the API key.
	req.Header.Set("User-Agent", "capiscio-core/2.2.0")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("PoP request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read PoP response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseErrorResponse(resp.StatusCode, respBody, "pop")
	}

	return c.parsePoPResponse(respBody)
}

// signProof signs the proof claims with the agent's private key.
func (c *PoPClient) signProof(claims PoPProofClaims, privateKey crypto.PrivateKey, agentDID string) (string, error) {
	// Determine key ID from DID
	// For did:key, the fragment is the multibase identifier (everything after "did:key:")
	// For did:web, the key ID should reference a verification method ID from the DID Document.
	keyID := agentDID
	const didKeyPrefix = "did:key:"
	const didWebPrefix = "did:web:"
	if strings.HasPrefix(agentDID, didKeyPrefix) {
		multibaseID := agentDID[len(didKeyPrefix):]
		if multibaseID != "" {
			keyID = agentDID + "#" + multibaseID
		}
	} else if strings.HasPrefix(agentDID, didWebPrefix) {
		// For did:web DIDs, default to the primary verification method ID ("#key-1").
		// This assumes the DID Document exposes a verification method with this fragment,
		// which is the convention used by CapiscIO's DID documents.
		keyID = agentDID + "#key-1"
	}

	// Create signer based on key type
	var signer jose.Signer

	switch k := privateKey.(type) {
	case ed25519.PrivateKey:
		signerKey := jose.SigningKey{
			Algorithm: jose.EdDSA,
			Key:       k,
		}
		// RFC-003 §6.2: Use capiscio-pop-proof+jwt to distinguish from badge JWTs
		var err error
		signer, err = jose.NewSigner(signerKey, &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				jose.HeaderKey("kid"): keyID,
				jose.HeaderKey("typ"): "capiscio-pop-proof+jwt",
			},
		})
		if err != nil {
			return "", fmt.Errorf("failed to create signer: %w", err)
		}
	default:
		return "", fmt.Errorf("unsupported key type: %T", privateKey)
	}

	// Marshal claims to JSON
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}

	// Sign
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}

	// Serialize to compact format
	return jws.CompactSerialize()
}

// parseErrorResponse parses error responses from the server.
func (c *PoPClient) parseErrorResponse(statusCode int, respBody []byte, phase string) error {
	var errResp struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Message != "" {
		return &ClientError{
			Code:    errResp.Error,
			Message: fmt.Sprintf("%s phase failed: %s", phase, errResp.Message),
		}
	}

	// Sanitize response body to avoid leaking sensitive information in logs
	sanitizedBody := string(respBody)
	const maxBodyLen = 256
	if len(sanitizedBody) > maxBodyLen {
		sanitizedBody = sanitizedBody[:maxBodyLen] + "...(truncated)"
	}

	switch statusCode {
	case http.StatusUnauthorized:
		return &ClientError{Code: "AUTH_INVALID", Message: fmt.Sprintf("%s phase: invalid or expired API key", phase)}
	case http.StatusForbidden:
		return &ClientError{Code: "FORBIDDEN", Message: fmt.Sprintf("%s phase: forbidden - %s", phase, sanitizedBody)}
	case http.StatusNotFound:
		return &ClientError{Code: "NOT_FOUND", Message: fmt.Sprintf("%s phase: resource not found", phase)}
	case http.StatusTooManyRequests:
		return &ClientError{Code: "RATE_LIMITED", Message: fmt.Sprintf("%s phase: rate limit exceeded", phase)}
	default:
		return &ClientError{Code: "CA_ERROR", Message: fmt.Sprintf("%s phase: CA returned status %d: %s", phase, statusCode, sanitizedBody)}
	}
}

// parsePoPResponse parses a successful PoP badge response.
// Note: The server uses snake_case for JSON field names (trust_level, assurance_level)
// as per the RFC-003 API specification. This differs from the IAL-0 endpoint.
func (c *PoPClient) parsePoPResponse(respBody []byte) (*RequestPoPBadgeResult, error) {
	var caResp struct {
		Success bool `json:"success"`
		Data    struct {
			Token          string                 `json:"token"`
			JTI            string                 `json:"jti"`
			Subject        string                 `json:"subject"`
			TrustLevel     string                 `json:"trust_level"`
			AssuranceLevel string                 `json:"assurance_level"`
			ExpiresAt      time.Time              `json:"expires_at"`
			CNF            map[string]interface{} `json:"cnf"`
		} `json:"data"`
		Message string `json:"message"`
		Error   string `json:"error"`
	}

	if err := json.Unmarshal(respBody, &caResp); err != nil {
		return nil, fmt.Errorf("failed to parse PoP response: %w", err)
	}

	if !caResp.Success {
		return nil, &ClientError{Code: "CA_ERROR", Message: caResp.Error}
	}

	return &RequestPoPBadgeResult{
		Token:          caResp.Data.Token,
		JTI:            caResp.Data.JTI,
		Subject:        caResp.Data.Subject,
		TrustLevel:     caResp.Data.TrustLevel,
		AssuranceLevel: caResp.Data.AssuranceLevel,
		ExpiresAt:      caResp.Data.ExpiresAt,
		CNF:            caResp.Data.CNF,
	}, nil
}
