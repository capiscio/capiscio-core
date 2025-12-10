package trust_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/capiscio/capiscio-core/pkg/trust"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileStore(t *testing.T) {
	// Create temp directory
	dir := t.TempDir()

	store, err := trust.NewFileStore(dir)
	require.NoError(t, err)

	// Create a test key
	testKey := jose.JSONWebKey{
		KeyID:     "test-key-2025-01",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
		Key:       []byte("test-public-key-bytes"), // Simplified for test
	}

	t.Run("Add and Get", func(t *testing.T) {
		err := store.Add(testKey)
		require.NoError(t, err)

		// Verify file was created
		keyPath := filepath.Join(dir, "test-key-2025-01.jwk")
		_, err = os.Stat(keyPath)
		require.NoError(t, err)

		// Get the key back
		got, err := store.Get("test-key-2025-01")
		require.NoError(t, err)
		assert.Equal(t, testKey.KeyID, got.KeyID)
		assert.Equal(t, testKey.Algorithm, got.Algorithm)
	})

	t.Run("Get non-existent key", func(t *testing.T) {
		_, err := store.Get("non-existent")
		assert.ErrorIs(t, err, trust.ErrKeyNotFound)
	})

	t.Run("List", func(t *testing.T) {
		keys, err := store.List()
		require.NoError(t, err)
		assert.Len(t, keys, 1)
		assert.Equal(t, "test-key-2025-01", keys[0].KeyID)
	})

	t.Run("Issuer mapping", func(t *testing.T) {
		issuerURL := "https://registry.capisc.io"
		err := store.AddIssuerMapping(issuerURL, "test-key-2025-01")
		require.NoError(t, err)

		keys, err := store.GetByIssuer(issuerURL)
		require.NoError(t, err)
		assert.Len(t, keys, 1)
		assert.Equal(t, "test-key-2025-01", keys[0].KeyID)
	})

	t.Run("GetByIssuer non-existent", func(t *testing.T) {
		_, err := store.GetByIssuer("https://unknown.com")
		assert.ErrorIs(t, err, trust.ErrIssuerNotFound)
	})

	t.Run("Remove", func(t *testing.T) {
		err := store.Remove("test-key-2025-01")
		require.NoError(t, err)

		_, err = store.Get("test-key-2025-01")
		assert.ErrorIs(t, err, trust.ErrKeyNotFound)
	})

	t.Run("Remove non-existent", func(t *testing.T) {
		err := store.Remove("non-existent")
		assert.ErrorIs(t, err, trust.ErrKeyNotFound)
	})
}

func TestFileStore_AddWithoutKid(t *testing.T) {
	dir := t.TempDir()
	store, err := trust.NewFileStore(dir)
	require.NoError(t, err)

	keyWithoutKid := jose.JSONWebKey{
		Algorithm: string(jose.EdDSA),
		Key:       []byte("test"),
	}

	err = store.Add(keyWithoutKid)
	assert.ErrorIs(t, err, trust.ErrInvalidKey)
}

func TestFileStore_SanitizeFilename(t *testing.T) {
	dir := t.TempDir()
	store, err := trust.NewFileStore(dir)
	require.NoError(t, err)

	// Key ID with special characters
	testKey := jose.JSONWebKey{
		KeyID:     "key/with:special*chars",
		Algorithm: string(jose.EdDSA),
		Key:       []byte("test"),
	}

	err = store.Add(testKey)
	require.NoError(t, err)

	// Should be able to get it back
	got, err := store.Get("key/with:special*chars")
	require.NoError(t, err)
	assert.Equal(t, testKey.KeyID, got.KeyID)
}

func TestDefaultTrustDir(t *testing.T) {
	// Test with env var
	t.Setenv("CAPISCIO_TRUST_PATH", "/custom/path")
	assert.Equal(t, "/custom/path", trust.DefaultTrustDir())

	// Test without env var (should return home-based path)
	t.Setenv("CAPISCIO_TRUST_PATH", "")
	dir := trust.DefaultTrustDir()
	assert.Contains(t, dir, ".capiscio/trust")
}
