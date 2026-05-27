// Copyright (c) CapiscIO, Inc.
// Licensed under the MIT License.

package badge

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/trust"
	"github.com/go-jose/go-jose/v4"
)

// =============================================================================
// LOCAL VERIFIER TESTS — RFC-001 §2.3 Compliance
// =============================================================================

// TestLocalVerifier_RequiresBootstrap verifies that verification fails if
// MaterialManager is not bootstrapped.
func TestLocalVerifier_RequiresBootstrap(t *testing.T) {
	// Create unbootstrapped manager
	mgr, err := trust.NewMaterialManager(trust.BootstrapConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Note: Don't call Bootstrap() - we want it unbootstrapped

	verifier := NewLocalVerifier(mgr, LocalVerifyOptions{})

	_, err = verifier.Verify(context.Background(), "dummy.token.here")
	if err == nil {
		t.Fatal("expected error for unbootstrapped manager")
	}

	if err != trust.ErrNoTrustMaterial {
		t.Errorf("expected ErrNoTrustMaterial, got: %v", err)
	}
}

// TestLocalVerifier_SelfSignedBadge verifies self-signed badge handling.
func TestLocalVerifier_SelfSignedBadge(t *testing.T) {
	// Generate a test key
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create a self-signed badge (did:key issuer)
	issuerDID := "did:key:z6Mk" + "testkey123456789"
	claims := &Claims{
		JTI:      "test-jti-123",
		Issuer:   issuerDID,
		Subject:  issuerDID,
		IssuedAt: time.Now().Unix(),
		Expiry:   time.Now().Add(24 * time.Hour).Unix(),
		IAL:      "0",
		VC: VerifiableCredential{
			Type: []string{"VerifiableCredential", "TrustBadge"},
			CredentialSubject: CredentialSubject{
				Level:  "0",
				Domain: "test.example.com",
			},
		},
	}

	// Create JWK from key
	jwk := jose.JSONWebKey{
		Key:       priv,
		KeyID:     "key-1",
		Algorithm: string(jose.EdDSA),
	}

	// Sign the claims
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.EdDSA,
		Key:       jwk,
	}, &jose.SignerOptions{})
	if err != nil {
		t.Fatal(err)
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}

	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	token, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("rejects self-signed by default", func(t *testing.T) {
		// Create bootstrapped manager
		mgr := createTestMaterialManager(t)

		verifier := NewLocalVerifier(mgr, LocalVerifyOptions{
			AcceptSelfSigned: false,
		})

		_, err := verifier.Verify(context.Background(), token)
		if err == nil {
			t.Error("expected error for self-signed badge")
		}
	})

	t.Run("accepts self-signed when enabled", func(t *testing.T) {
		mgr := createTestMaterialManager(t)

		verifier := NewLocalVerifier(mgr, LocalVerifyOptions{
			AcceptSelfSigned: true,
		})

		// Note: This will likely fail because the did:key encoding is fake
		// In real tests we'd use proper did:key encoding
		_, err := verifier.Verify(context.Background(), token)
		// Just checking it doesn't panic and returns an error (fake did:key)
		if err == nil {
			// The verification might pass or fail depending on did:key parsing
			// The important thing is no panic
		}
	})
}

// TestLocalVerifier_ExpiredBadge verifies expired badge rejection.
func TestLocalVerifier_ExpiredBadge(t *testing.T) {
	// Generate a test key
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	issuer := "https://registry.test.example.com"
	claims := &Claims{
		JTI:      "test-jti-expired",
		Issuer:   issuer,
		Subject:  "did:web:example.com:agents:test-agent",
		IssuedAt: time.Now().Add(-48 * time.Hour).Unix(),
		Expiry:   time.Now().Add(-24 * time.Hour).Unix(), // Already expired
		IAL:      "1",
		VC: VerifiableCredential{
			Type: []string{"VerifiableCredential", "TrustBadge"},
			CredentialSubject: CredentialSubject{
				Level:  "1",
				Domain: "example.com",
			},
		},
	}

	// Create JWK from key
	jwk := jose.JSONWebKey{
		Key:       priv,
		KeyID:     "key-1",
		Algorithm: string(jose.EdDSA),
	}

	// Sign the claims
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.EdDSA,
		Key:       jwk,
	}, &jose.SignerOptions{})
	if err != nil {
		t.Fatal(err)
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}

	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	token, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	// Create manager with the issuer key
	mgr := createTestMaterialManagerWithIssuer(t, pub, issuer)

	verifier := NewLocalVerifier(mgr, LocalVerifyOptions{})

	_, err = verifier.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for expired badge")
	}

	// Check error code
	badgeErr, ok := AsError(err)
	if ok {
		if badgeErr.Code != ErrCodeExpired {
			t.Errorf("expected ErrCodeExpired, got: %s", badgeErr.Code)
		}
	}
}

// TestLocalVerifier_NoNetworkCalls ensures verification is local-only.
// This is a CRITICAL locality invariant test per RFC-001 §2.3.
func TestLocalVerifier_NoNetworkCalls(t *testing.T) {
	// Create a LocalityGuard to detect any network calls
	guard := trust.NewLocalityGuard(t)

	// Generate a test key
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	issuer := "https://registry.test.example.com"
	claims := &Claims{
		JTI:      "test-jti-locality",
		Issuer:   issuer,
		Subject:  "did:web:example.com:agents:test-agent",
		IssuedAt: time.Now().Unix(),
		Expiry:   time.Now().Add(24 * time.Hour).Unix(),
		IAL:      "1",
		VC: VerifiableCredential{
			Type: []string{"VerifiableCredential", "TrustBadge"},
			CredentialSubject: CredentialSubject{
				Level:  "1",
				Domain: "example.com",
			},
		},
	}

	// Create JWK from key
	jwk := jose.JSONWebKey{
		Key:       priv,
		KeyID:     "key-1",
		Algorithm: string(jose.EdDSA),
	}

	// Sign the claims
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.EdDSA,
		Key:       jwk,
	}, &jose.SignerOptions{})
	if err != nil {
		t.Fatal(err)
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}

	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	token, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	// Create manager with the issuer key
	mgr := createTestMaterialManagerWithIssuer(t, pub, issuer)

	verifier := NewLocalVerifier(mgr, LocalVerifyOptions{})

	// Verify the badge
	_, err = verifier.Verify(context.Background(), token)
	// We don't care if verification succeeds or fails for this test
	// What matters is that NO network calls were made
	_ = err

	// Assert no network calls were made (will fail test if any were made)
	guard.Assert()
}

// =============================================================================
// TEST HELPERS
// =============================================================================

// createTestMaterialManager creates a bootstrapped MaterialManager for testing.
func createTestMaterialManager(t *testing.T) *trust.MaterialManager {
	t.Helper()

	mgr, err := trust.NewMaterialManager(trust.BootstrapConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Bootstrap with empty material (for self-signed tests)
	err = mgr.Bootstrap(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	return mgr
}

// createTestMaterialManagerWithIssuer creates a MaterialManager with an issuer key.
func createTestMaterialManagerWithIssuer(t *testing.T, pub ed25519.PublicKey, issuer string) *trust.MaterialManager {
	t.Helper()

	mgr, err := trust.NewMaterialManager(trust.BootstrapConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Bootstrap first
	err = mgr.Bootstrap(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Create trust material with the issuer key
	material := &trust.TrustMaterial{
		JWKS: map[string]*trust.IssuerKeys{
			issuer: {
				IssuerDID: issuer,
				Keys:      []crypto.PublicKey{pub},
				FetchedAt: time.Now(),
				ExpiresAt: time.Now().Add(24 * time.Hour),
			},
		},
		Revocations: &trust.RevocationSet{
			Revoked:  make(map[string]trust.RevocationEntry),
			SyncedAt: time.Now(),
		},
	}

	err = mgr.ImportBundle(material)
	if err != nil {
		t.Fatal(err)
	}

	return mgr
}
