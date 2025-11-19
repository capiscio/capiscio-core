package badge_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/capiscio/capiscio-core/pkg/badge"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeeper(t *testing.T) {
	// 1. Setup
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	badgeFile := filepath.Join(tmpDir, "badge.jwt")

	claims := badge.BadgeClaims{
		Subject: "did:test",
		Issuer:  "iss:test",
	}

	config := badge.KeeperConfig{
		PrivateKey:    priv,
		Claims:        claims,
		OutputFile:    badgeFile,
		Expiry:        1 * time.Hour,
		RenewBefore:   30 * time.Minute,
		CheckInterval: 100 * time.Millisecond,
	}

	keeper := badge.NewKeeper(config)

	// 2. Test Initial Creation
	err = keeper.CheckAndRenew()
	require.NoError(t, err)
	assert.FileExists(t, badgeFile)

	// Read file and check expiry
	data, _ := os.ReadFile(badgeFile)
	token1 := string(data)
	assert.NotEmpty(t, token1)

	// 3. Test No Renewal Needed
	// Modify file mtime to simulate time passing? No, logic checks claims.Expiry.
	// Since we just created it with 1h expiry, and RenewBefore is 30m, it should NOT renew.
	err = keeper.CheckAndRenew()
	require.NoError(t, err)

	data2, _ := os.ReadFile(badgeFile)
	token2 := string(data2)
	assert.Equal(t, token1, token2, "Should not have renewed")

	// 4. Test Renewal Needed
	// Sleep to ensure timestamp changes (so new token is different)
	time.Sleep(1100 * time.Millisecond)

	// The existing token has ~1h remaining.
	// We set RenewBefore to 2h, so 1h < 2h triggers renewal.
	forceConfig := config
	forceConfig.RenewBefore = 2 * time.Hour

	keeper2 := badge.NewKeeper(forceConfig)
	err = keeper2.CheckAndRenew() // Should overwrite
	require.NoError(t, err)

	data3, _ := os.ReadFile(badgeFile)
	token3 := string(data3)
	assert.NotEqual(t, token1, token3, "Should have renewed")
}
