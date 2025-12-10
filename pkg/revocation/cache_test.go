package revocation_test

import (
	"testing"
	"time"

	"github.com/capiscio/capiscio-core/pkg/revocation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileCache(t *testing.T) {
	dir := t.TempDir()
	cachePath := dir + "/revocations.json"

	cache, err := revocation.NewFileCache(cachePath)
	require.NoError(t, err)

	t.Run("Initial state", func(t *testing.T) {
		assert.False(t, cache.IsRevoked("some-jti"))
		assert.True(t, cache.IsStale(revocation.DefaultStaleThreshold))
		assert.Equal(t, 0, cache.Count())
	})

	t.Run("Add and check", func(t *testing.T) {
		jti := "550e8400-e29b-41d4-a716-446655440000"
		err := cache.Add(jti, time.Now())
		require.NoError(t, err)

		assert.True(t, cache.IsRevoked(jti))
		assert.False(t, cache.IsRevoked("other-jti"))
		assert.Equal(t, 1, cache.Count())
	})

	t.Run("Sync", func(t *testing.T) {
		revocations := []revocation.Revocation{
			{JTI: "jti-1", RevokedAt: time.Now()},
			{JTI: "jti-2", RevokedAt: time.Now()},
		}
		err := cache.Sync(revocations)
		require.NoError(t, err)

		assert.True(t, cache.IsRevoked("jti-1"))
		assert.True(t, cache.IsRevoked("jti-2"))
		assert.Equal(t, 3, cache.Count()) // 1 from Add + 2 from Sync
	})

	t.Run("LastSynced and IsStale", func(t *testing.T) {
		lastSynced := cache.LastSynced()
		assert.False(t, lastSynced.IsZero())
		assert.False(t, cache.IsStale(1*time.Hour))
		assert.True(t, cache.IsStale(0)) // 0 threshold means always stale
	})

	t.Run("Persistence", func(t *testing.T) {
		// Create new cache instance pointing to same file
		cache2, err := revocation.NewFileCache(cachePath)
		require.NoError(t, err)

		// Should have same data
		assert.True(t, cache2.IsRevoked("jti-1"))
		assert.True(t, cache2.IsRevoked("jti-2"))
		assert.Equal(t, 3, cache2.Count())
	})

	t.Run("Clear", func(t *testing.T) {
		err := cache.Clear()
		require.NoError(t, err)

		assert.False(t, cache.IsRevoked("jti-1"))
		assert.Equal(t, 0, cache.Count())
		assert.True(t, cache.IsStale(revocation.DefaultStaleThreshold))
	})
}

func TestMemoryCache(t *testing.T) {
	cache := revocation.NewMemoryCache()

	t.Run("Initial state", func(t *testing.T) {
		assert.False(t, cache.IsRevoked("some-jti"))
		assert.True(t, cache.IsStale(revocation.DefaultStaleThreshold))
	})

	t.Run("Add and check", func(t *testing.T) {
		jti := "test-jti"
		err := cache.Add(jti, time.Now())
		require.NoError(t, err)

		assert.True(t, cache.IsRevoked(jti))
	})

	t.Run("Sync", func(t *testing.T) {
		revocations := []revocation.Revocation{
			{JTI: "sync-1", RevokedAt: time.Now()},
			{JTI: "sync-2", RevokedAt: time.Now()},
		}
		err := cache.Sync(revocations)
		require.NoError(t, err)

		assert.True(t, cache.IsRevoked("sync-1"))
		assert.True(t, cache.IsRevoked("sync-2"))
	})

	t.Run("Clear", func(t *testing.T) {
		err := cache.Clear()
		require.NoError(t, err)

		assert.False(t, cache.IsRevoked("sync-1"))
	})
}

func TestDefaultCacheDir(t *testing.T) {
	// Test with env var
	t.Setenv("CAPISCIO_CACHE_PATH", "/custom/cache")
	assert.Equal(t, "/custom/cache", revocation.DefaultCacheDir())

	// Test without env var
	t.Setenv("CAPISCIO_CACHE_PATH", "")
	dir := revocation.DefaultCacheDir()
	assert.Contains(t, dir, ".capiscio/cache")
}
