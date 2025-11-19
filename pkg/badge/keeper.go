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

// KeeperConfig holds configuration for the Badge Keeper.
type KeeperConfig struct {
	PrivateKey    crypto.PrivateKey
	Claims        Claims
	OutputFile    string
	Expiry        time.Duration
	RenewBefore   time.Duration
	CheckInterval time.Duration
}

// Keeper manages the lifecycle of a Trust Badge file.
type Keeper struct {
	config KeeperConfig
}

// NewKeeper creates a new Keeper.
func NewKeeper(config KeeperConfig) *Keeper {
	if config.CheckInterval == 0 {
		config.CheckInterval = 1 * time.Minute
	}
	if config.RenewBefore == 0 {
		config.RenewBefore = 5 * time.Minute
	}
	return &Keeper{config: config}
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

// CheckAndRenew checks if the badge needs renewal and renews it if necessary.
func (k *Keeper) CheckAndRenew() error {
	needsRenewal := false

	// 1. Read existing file
	data, err := os.ReadFile(k.config.OutputFile)
	if os.IsNotExist(err) {
		needsRenewal = true
	} else if err != nil {
		return fmt.Errorf("failed to read badge file: %w", err)
	} else {
		// 2. Parse and check expiry
		jwsObj, err := jose.ParseSigned(string(data), []jose.SignatureAlgorithm{jose.EdDSA})
		if err != nil {
			needsRenewal = true
		} else {
			payload := jwsObj.UnsafePayloadWithoutVerification()
			var claims Claims
			if err := json.Unmarshal(payload, &claims); err != nil {
				needsRenewal = true
			} else {
				// Check if expiring soon
				expiry := time.Unix(claims.Expiry, 0)
				remaining := time.Until(expiry)
				// fmt.Printf("DEBUG: Expiry: %v, Remaining: %v, Threshold: %v\n", expiry, remaining, k.config.RenewBefore)
				if remaining < k.config.RenewBefore {
					needsRenewal = true
				}
			}
		}
	}

	if needsRenewal {
		return k.Renew()
	}

	return nil
}

// Renew generates a new badge and writes it to disk.
func (k *Keeper) Renew() error {
	// Update timestamps
	now := time.Now()
	newClaims := k.config.Claims
	newClaims.IssuedAt = now.Unix()
	newClaims.Expiry = now.Add(k.config.Expiry).Unix()

	// Sign
	token, err := SignBadge(&newClaims, k.config.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to sign badge: %w", err)
	}

	// Write to file
	if err := os.WriteFile(k.config.OutputFile, []byte(token), 0644); err != nil {
		return fmt.Errorf("failed to write badge file: %w", err)
	}

	return nil
}
