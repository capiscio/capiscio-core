package badge

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// KeeperMode defines the mode of operation for the keeper.
type KeeperMode string

const (
	// KeeperModeSelfSign generates self-signed badges locally.
	KeeperModeSelfSign KeeperMode = "self-sign"
	// KeeperModeCA requests badges from a Certificate Authority (IAL-0, deprecated).
	// Deprecated: Use KeeperModePoP for production - IAL-0 lacks cryptographic key binding.
	KeeperModeCA KeeperMode = "ca"
	// KeeperModePoP requests badges using Proof of Possession (RFC-003 IAL-1).
	// This is the recommended mode for production as it provides cryptographic key binding.
	KeeperModePoP KeeperMode = "pop"
)

// KeeperEventType defines the type of event emitted by the keeper.
type KeeperEventType string

// Keeper event types.
const (
	// KeeperEventStarted indicates the keeper has started.
	KeeperEventStarted KeeperEventType = "started"
	// KeeperEventRenewed indicates a badge was renewed.
	KeeperEventRenewed KeeperEventType = "renewed"
	// KeeperEventError indicates an error occurred.
	KeeperEventError KeeperEventType = "error"
	// KeeperEventStopped indicates the keeper has stopped.
	KeeperEventStopped KeeperEventType = "stopped"
)

// KeeperEvent represents an event emitted by the badge keeper.
type KeeperEvent struct {
	Type       KeeperEventType
	BadgeJTI   string
	Subject    string
	TrustLevel string
	ExpiresAt  time.Time
	Error      string
	ErrorCode  string
	Timestamp  time.Time
	Token      string // The badge token (optional, for renewed events)
}

// KeeperConfig holds configuration for the Badge Keeper.
type KeeperConfig struct {
	// Mode: self-sign, ca (deprecated), or pop (recommended)
	Mode KeeperMode

	// Common settings
	OutputFile    string
	Expiry        time.Duration
	RenewBefore   time.Duration
	CheckInterval time.Duration
	Domain        string
	TrustLevel    string

	// Self-sign mode settings
	PrivateKey crypto.PrivateKey
	Claims     Claims

	// CA mode settings (IAL-0, deprecated)
	CAURL   string
	APIKey  string
	AgentID string

	// PoP mode settings (IAL-1, recommended)
	// AgentDID is the DID of the agent (e.g., did:key:z6Mk...)
	AgentDID string
	// Audience is the optional audience restrictions for the badge
	Audience []string
}

// Keeper manages the lifecycle of a Trust Badge file.
type Keeper struct {
	config    KeeperConfig
	client    *Client    // HTTP client for CA mode (deprecated)
	popClient *PoPClient // HTTP client for PoP mode
}

// NewKeeper creates a new Keeper.
// Returns an error if an unsupported mode is specified.
func NewKeeper(config KeeperConfig) (*Keeper, error) {
	if config.CheckInterval == 0 {
		config.CheckInterval = 30 * time.Second
	}
	if config.RenewBefore == 0 {
		config.RenewBefore = 1 * time.Minute
	}
	if config.Expiry == 0 {
		config.Expiry = 5 * time.Minute
	}
	if config.Mode == "" {
		config.Mode = KeeperModeSelfSign
	}

	k := &Keeper{config: config}

	// Initialize client based on mode
	switch config.Mode {
	case KeeperModeCA:
		k.client = NewClient(config.CAURL, config.APIKey)
	case KeeperModePoP:
		k.popClient = NewPoPClient(config.CAURL, config.APIKey)
	case KeeperModeSelfSign:
		// Self-sign mode doesn't need a client
	default:
		return nil, fmt.Errorf("unsupported keeper mode: %s", config.Mode)
	}

	return k, nil
}

// Run starts the keeper loop.
func (k *Keeper) Run(ctx context.Context) error {
	ticker := time.NewTicker(k.config.CheckInterval)
	defer ticker.Stop()

	// Initial check
	if err := k.CheckAndRenew(); err != nil {
		return fmt.Errorf("initial badge issuance failed: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := k.CheckAndRenew(); err != nil {
				// Log error but keep daemon alive
				log.Printf("badge renewal failed: %v\n", err)
			}
		}
	}
}

// RunWithEvents starts the keeper loop and sends events to the provided channel.
// The channel is closed when the keeper stops.
func (k *Keeper) RunWithEvents(ctx context.Context, events chan<- KeeperEvent) error {
	defer close(events)

	ticker := time.NewTicker(k.config.CheckInterval)
	defer ticker.Stop()

	// Send started event
	events <- KeeperEvent{
		Type:      KeeperEventStarted,
		Timestamp: time.Now(),
	}

	// Initial renewal
	result, err := k.renewAndGetResult()
	if err != nil {
		events <- KeeperEvent{
			Type:      KeeperEventError,
			Error:     err.Error(),
			Timestamp: time.Now(),
		}
		return fmt.Errorf("initial badge issuance failed: %w", err)
	}

	events <- KeeperEvent{
		Type:       KeeperEventRenewed,
		BadgeJTI:   result.JTI,
		Subject:    result.Subject,
		TrustLevel: result.TrustLevel,
		ExpiresAt:  result.ExpiresAt,
		Token:      result.Token,
		Timestamp:  time.Now(),
	}

	for {
		select {
		case <-ctx.Done():
			events <- KeeperEvent{
				Type:      KeeperEventStopped,
				Timestamp: time.Now(),
			}
			return nil
		case <-ticker.C:
			needsRenewal, err := k.checkNeedsRenewal()
			if err != nil {
				events <- KeeperEvent{
					Type:      KeeperEventError,
					Error:     err.Error(),
					Timestamp: time.Now(),
				}
				continue
			}

			if needsRenewal {
				result, err := k.renewAndGetResult()
				if err != nil {
					events <- KeeperEvent{
						Type:      KeeperEventError,
						Error:     err.Error(),
						Timestamp: time.Now(),
					}
					continue
				}

				events <- KeeperEvent{
					Type:       KeeperEventRenewed,
					BadgeJTI:   result.JTI,
					Subject:    result.Subject,
					TrustLevel: result.TrustLevel,
					ExpiresAt:  result.ExpiresAt,
					Token:      result.Token,
					Timestamp:  time.Now(),
				}
			}
		}
	}
}

// RenewalResult contains details about a renewed badge.
type RenewalResult struct {
	JTI        string
	Subject    string
	TrustLevel string
	ExpiresAt  time.Time
	Token      string
}

// renewAndGetResult performs renewal and returns the result.
func (k *Keeper) renewAndGetResult() (*RenewalResult, error) {
	switch k.config.Mode {
	case KeeperModeCA:
		return k.renewFromCA()
	case KeeperModePoP:
		return k.renewFromPoP()
	case KeeperModeSelfSign:
		return k.renewSelfSign()
	default:
		return nil, fmt.Errorf("unsupported keeper mode: %s", k.config.Mode)
	}
}

// renewFromCA requests a new badge from the CA (IAL-0, deprecated).
// Deprecated: Use renewFromPoP for production - IAL-0 lacks cryptographic key binding.
func (k *Keeper) renewFromCA() (*RenewalResult, error) {
	result, err := k.client.RequestBadge(context.Background(), RequestBadgeOptions{
		AgentID:    k.config.AgentID,
		Domain:     k.config.Domain,
		TTL:        k.config.Expiry,
		TrustLevel: k.config.TrustLevel,
	})
	if err != nil {
		return nil, err
	}

	// Write to file
	if k.config.OutputFile != "" {
		if err := os.WriteFile(k.config.OutputFile, []byte(result.Token), 0600); err != nil {
			return nil, fmt.Errorf("failed to write badge file: %w", err)
		}
	}

	return &RenewalResult{
		JTI:        result.JTI,
		Subject:    result.Subject,
		TrustLevel: result.TrustLevel,
		ExpiresAt:  result.ExpiresAt,
		Token:      result.Token,
	}, nil
}

// renewSelfSign generates a new self-signed badge.
func (k *Keeper) renewSelfSign() (*RenewalResult, error) {
	now := time.Now()
	newClaims := k.config.Claims
	newClaims.IssuedAt = now.Unix()
	newClaims.Expiry = now.Add(k.config.Expiry).Unix()

	token, err := SignBadge(&newClaims, k.config.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign badge: %w", err)
	}

	// Write to file
	if k.config.OutputFile != "" {
		if err := os.WriteFile(k.config.OutputFile, []byte(token), 0644); err != nil {
			return nil, fmt.Errorf("failed to write badge file: %w", err)
		}
	}

	return &RenewalResult{
		JTI:        newClaims.JTI,
		Subject:    newClaims.Subject,
		TrustLevel: newClaims.TrustLevel(),
		ExpiresAt:  time.Unix(newClaims.Expiry, 0),
		Token:      token,
	}, nil
}

// renewFromPoP requests a new badge using Proof of Possession (RFC-003 IAL-1).
// This is the recommended mode for production as it provides cryptographic key binding.
func (k *Keeper) renewFromPoP() (*RenewalResult, error) {
	if k.popClient == nil {
		return nil, fmt.Errorf("PoP client is not initialized; ensure Keeper was created with KeeperModePoP")
	}
	if k.config.PrivateKey == nil {
		return nil, fmt.Errorf("PrivateKey is required for PoP mode")
	}
	if k.config.AgentDID == "" {
		return nil, fmt.Errorf("AgentDID is required for PoP mode")
	}

	result, err := k.popClient.RequestPoPBadge(context.Background(), RequestPoPBadgeOptions{
		AgentDID:   k.config.AgentDID,
		PrivateKey: k.config.PrivateKey,
		TTL:        k.config.Expiry,
		Audience:   k.config.Audience,
	})
	if err != nil {
		return nil, err
	}

	// Write to file
	if k.config.OutputFile != "" {
		if err := os.WriteFile(k.config.OutputFile, []byte(result.Token), 0600); err != nil {
			return nil, fmt.Errorf("failed to write badge file: %w", err)
		}
	}

	return &RenewalResult{
		JTI:        result.JTI,
		Subject:    result.Subject,
		TrustLevel: result.TrustLevel,
		ExpiresAt:  result.ExpiresAt,
		Token:      result.Token,
	}, nil
}

// checkNeedsRenewal checks if the current badge needs renewal.
func (k *Keeper) checkNeedsRenewal() (bool, error) {
	if k.config.OutputFile == "" {
		return true, nil
	}

	data, err := os.ReadFile(k.config.OutputFile)
	if os.IsNotExist(err) {
		return true, nil
	} else if err != nil {
		return false, fmt.Errorf("failed to read badge file: %w", err)
	}

	jwsObj, err := jose.ParseSigned(string(data), []jose.SignatureAlgorithm{jose.EdDSA, jose.ES256})
	if err != nil {
		return true, nil
	}

	payload := jwsObj.UnsafePayloadWithoutVerification()
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return true, nil
	}

	expiry := time.Unix(claims.Expiry, 0)
	remaining := time.Until(expiry)
	return remaining < k.config.RenewBefore, nil
}

// CheckAndRenew checks if the badge needs renewal and renews it if necessary.
// This is the legacy method for backward compatibility.
func (k *Keeper) CheckAndRenew() error {
	needsRenewal, err := k.checkNeedsRenewal()
	if err != nil {
		return err
	}

	if needsRenewal {
		return k.Renew()
	}

	return nil
}

// Renew generates a new badge and writes it to disk.
// This is the legacy method for backward compatibility.
func (k *Keeper) Renew() error {
	_, err := k.renewAndGetResult()
	return err
}
