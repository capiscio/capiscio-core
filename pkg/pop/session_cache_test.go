package pop

import (
	"testing"
	"time"
)

func TestNewSessionCache(t *testing.T) {
	cache := NewSessionCache(nil) // Uses defaults
	if cache == nil {
		t.Fatal("NewSessionCache returned nil")
	}
	if cache.Size() != 0 {
		t.Errorf("Size() = %d, want 0", cache.Size())
	}
}

func TestSessionCache_StoreAndGet(t *testing.T) {
	cache := NewSessionCache(&CacheConfig{
		DefaultTTL:      time.Minute,
		CleanupInterval: 0, // No background cleanup for tests
	})

	entry := &CacheEntry{
		SubjectDID:     "did:web:example.com:servers:myserver",
		TrustLevelStr:  "2",
		BadgeJTI:       "jti-123",
		BadgeExpiresAt: time.Now().Add(time.Hour),
		VerifiedAt:     time.Now(),
	}

	cache.Store("key1", entry)

	retrieved := cache.Get("key1")
	if retrieved == nil {
		t.Fatal("Get() returned nil")
	}
	if retrieved.SubjectDID != entry.SubjectDID {
		t.Errorf("SubjectDID = %q, want %q", retrieved.SubjectDID, entry.SubjectDID)
	}
	if retrieved.TrustLevelStr != entry.TrustLevelStr {
		t.Errorf("TrustLevelStr = %q, want %q", retrieved.TrustLevelStr, entry.TrustLevelStr)
	}
}

func TestSessionCache_Get_NotFound(t *testing.T) {
	cache := NewSessionCache(&CacheConfig{
		CleanupInterval: 0,
	})

	retrieved := cache.Get("nonexistent")
	if retrieved != nil {
		t.Error("Get() should return nil for nonexistent key")
	}
}

func TestSessionCache_Get_Expired(t *testing.T) {
	cache := NewSessionCache(&CacheConfig{
		CleanupInterval: 0,
	})

	entry := &CacheEntry{
		SubjectDID:     "did:web:example.com",
		TrustLevelStr:  "1",
		BadgeExpiresAt: time.Now().Add(-time.Minute), // Already expired
		VerifiedAt:     time.Now().Add(-time.Hour),
		ExpiresAt:      time.Now().Add(-time.Minute),
	}

	cache.Store("expired-key", entry)

	retrieved := cache.Get("expired-key")
	if retrieved != nil {
		t.Error("Get() should return nil for expired entry")
	}
}

func TestSessionCache_Delete(t *testing.T) {
	cache := NewSessionCache(&CacheConfig{
		DefaultTTL:      time.Hour,
		CleanupInterval: 0,
	})

	entry := &CacheEntry{
		SubjectDID:    "did:web:example.com",
		TrustLevelStr: "1",
		ExpiresAt:     time.Now().Add(time.Hour),
	}

	cache.Store("to-delete", entry)
	if cache.Get("to-delete") == nil {
		t.Fatal("entry should exist before delete")
	}

	cache.Delete("to-delete")
	if cache.Get("to-delete") != nil {
		t.Error("entry should not exist after delete")
	}
}

func TestSessionCache_InvalidateBySession(t *testing.T) {
	cache := NewSessionCache(&CacheConfig{
		DefaultTTL:      time.Hour,
		CleanupInterval: 0,
	})

	cache.Store("key1", &CacheEntry{SubjectDID: "did1", SessionID: "session-A", ExpiresAt: time.Now().Add(time.Hour)})
	cache.Store("key2", &CacheEntry{SubjectDID: "did2", SessionID: "session-A", ExpiresAt: time.Now().Add(time.Hour)})
	cache.Store("key3", &CacheEntry{SubjectDID: "did3", SessionID: "session-B", ExpiresAt: time.Now().Add(time.Hour)})

	cache.InvalidateBySession("session-A")

	if cache.Get("key1") != nil {
		t.Error("key1 should be invalidated")
	}
	if cache.Get("key2") != nil {
		t.Error("key2 should be invalidated")
	}
	if cache.Get("key3") == nil {
		t.Error("key3 should still exist")
	}
}

func TestSessionCache_InvalidateByTrustLevel(t *testing.T) {
	cache := NewSessionCache(&CacheConfig{
		DefaultTTL:      time.Hour,
		CleanupInterval: 0,
	})

	cache.Store("low", &CacheEntry{SubjectDID: "did1", TrustLevelStr: "1", ExpiresAt: time.Now().Add(time.Hour)})
	cache.Store("mid", &CacheEntry{SubjectDID: "did2", TrustLevelStr: "2", ExpiresAt: time.Now().Add(time.Hour)})
	cache.Store("high", &CacheEntry{SubjectDID: "did3", TrustLevelStr: "3", ExpiresAt: time.Now().Add(time.Hour)})

	cache.InvalidateByTrustLevel("2")

	if cache.Get("low") != nil {
		t.Error("low trust entry should be invalidated")
	}
	if cache.Get("mid") == nil {
		t.Error("mid trust entry should still exist")
	}
	if cache.Get("high") == nil {
		t.Error("high trust entry should still exist")
	}
}

func TestSessionCache_Clear(t *testing.T) {
	cache := NewSessionCache(&CacheConfig{
		CleanupInterval: 0,
	})

	cache.Store("key1", &CacheEntry{SubjectDID: "did1"})
	cache.Store("key2", &CacheEntry{SubjectDID: "did2"})

	if cache.Size() != 2 {
		t.Errorf("Size() = %d, want 2", cache.Size())
	}

	cache.Clear()

	if cache.Size() != 0 {
		t.Errorf("Size() after Clear() = %d, want 0", cache.Size())
	}
}

func TestSessionCache_ExpirySync(t *testing.T) {
	cache := NewSessionCache(&CacheConfig{
		DefaultTTL:      time.Hour, // Long default TTL
		CleanupInterval: 0,
	})

	// Badge expires in 1 minute - should use badge expiry
	shortBadgeExpiry := time.Now().Add(time.Minute)
	entry := &CacheEntry{
		SubjectDID:     "did:web:example.com",
		TrustLevelStr:  "2",
		BadgeExpiresAt: shortBadgeExpiry,
	}

	cache.Store("key", entry)

	// ExpiresAt should be set to badge expiry (sooner than default TTL)
	retrieved := cache.Get("key")
	if retrieved == nil {
		t.Fatal("entry should exist")
	}
	
	// Entry expiry should be close to badge expiry
	if retrieved.ExpiresAt.After(shortBadgeExpiry.Add(time.Second)) {
		t.Error("entry expiry should be <= badge expiry")
	}
}

func TestDefaultCacheConfig(t *testing.T) {
	config := DefaultCacheConfig()
	if config == nil {
		t.Fatal("DefaultCacheConfig returned nil")
	}
	if config.DefaultTTL == 0 {
		t.Error("DefaultTTL should not be zero")
	}
	if config.MaxEntries == 0 {
		t.Error("MaxEntries should not be zero")
	}
}
