package pip

import (
	"testing"
	"time"
)

func TestCacheKeyComponents(t *testing.T) {
	key1 := CacheKeyComponents("did:web:a", "jti-1", "GET /v1/test", "/v1/test/123")
	key2 := CacheKeyComponents("did:web:a", "jti-1", "GET /v1/test", "/v1/test/123")
	key3 := CacheKeyComponents("did:web:b", "jti-1", "GET /v1/test", "/v1/test/123")

	if key1 != key2 {
		t.Error("same inputs should produce same key")
	}
	if key1 == key3 {
		t.Error("different DID should produce different key")
	}
	if key1 == "" {
		t.Error("key should not be empty")
	}
}

func TestInMemoryCache_HitAndMiss(t *testing.T) {
	cache := NewInMemoryCache()
	resp := &DecisionResponse{Decision: DecisionAllow, DecisionID: "d1"}

	// Miss
	if _, ok := cache.Get("key1"); ok {
		t.Error("expected cache miss on empty cache")
	}

	// Put + Hit
	cache.Put("key1", resp, 5*time.Second)
	got, ok := cache.Get("key1")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got.DecisionID != "d1" {
		t.Errorf("decision_id = %q, want %q", got.DecisionID, "d1")
	}

	// Different key = miss
	if _, ok := cache.Get("key2"); ok {
		t.Error("expected cache miss for different key")
	}
}

func TestInMemoryCache_TTLExpiry(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	cache := NewInMemoryCache(withNowFunc(clock))

	resp := &DecisionResponse{Decision: DecisionAllow, DecisionID: "d1"}
	cache.Put("key1", resp, 10*time.Second)

	// Should hit at t+5s
	now = now.Add(5 * time.Second)
	if _, ok := cache.Get("key1"); !ok {
		t.Error("expected cache hit at t+5s (TTL=10s)")
	}

	// Should miss at t+11s
	now = now.Add(6 * time.Second)
	if _, ok := cache.Get("key1"); ok {
		t.Error("expected cache miss at t+11s (TTL=10s)")
	}
}

func TestInMemoryCache_PDPTTLBound(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	cache := NewInMemoryCache(withNowFunc(clock))

	pdpTTL := 5
	resp := &DecisionResponse{Decision: DecisionAllow, DecisionID: "d1", TTL: &pdpTTL}

	// maxTTL (badge expiry) is 30s, but PDP TTL is 5s → effective TTL = 5s
	cache.Put("key1", resp, 30*time.Second)

	// Hit at t+4s
	now = now.Add(4 * time.Second)
	if _, ok := cache.Get("key1"); !ok {
		t.Error("expected cache hit at t+4s (effective TTL=5s from PDP)")
	}

	// Miss at t+6s
	now = now.Add(2 * time.Second)
	if _, ok := cache.Get("key1"); ok {
		t.Error("expected cache miss at t+6s (effective TTL=5s from PDP)")
	}
}

func TestInMemoryCache_BadgeExpiryBound(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	cache := NewInMemoryCache(withNowFunc(clock))

	pdpTTL := 300 // PDP says cache for 5 minutes
	resp := &DecisionResponse{Decision: DecisionAllow, DecisionID: "d1", TTL: &pdpTTL}

	// Badge expires in 10s → maxTTL = 10s, effective TTL = min(300, 10) = 10
	cache.Put("key1", resp, 10*time.Second)

	// Hit at t+9s
	now = now.Add(9 * time.Second)
	if _, ok := cache.Get("key1"); !ok {
		t.Error("expected cache hit at t+9s (badge expires at t+10s)")
	}

	// Miss at t+11s
	now = now.Add(2 * time.Second)
	if _, ok := cache.Get("key1"); ok {
		t.Error("expected cache miss at t+11s (badge expired)")
	}
}

func TestInMemoryCache_DenyNotCachedByDefault(t *testing.T) {
	cache := NewInMemoryCache()
	resp := &DecisionResponse{Decision: DecisionDeny, DecisionID: "deny-1"}

	cache.Put("key1", resp, 30*time.Second)

	if _, ok := cache.Get("key1"); ok {
		t.Error("DENY should not be cached by default (RFC-005 §6.3)")
	}
}

func TestInMemoryCache_DenyCachedWhenEnabled(t *testing.T) {
	cache := NewInMemoryCache(WithCacheDeny(true))
	resp := &DecisionResponse{Decision: DecisionDeny, DecisionID: "deny-1"}

	cache.Put("key1", resp, 30*time.Second)

	if _, ok := cache.Get("key1"); !ok {
		t.Error("DENY should be cached when WithCacheDeny(true)")
	}
}

func TestInMemoryCache_NegativeMaxTTL(t *testing.T) {
	cache := NewInMemoryCache()
	resp := &DecisionResponse{Decision: DecisionAllow, DecisionID: "d1"}

	// Negative maxTTL means badge is already expired — should not cache
	cache.Put("key1", resp, -1*time.Second)

	if _, ok := cache.Get("key1"); ok {
		t.Error("should not cache when maxTTL is negative (badge expired)")
	}
}

func TestInMemoryCache_ZeroMaxTTL(t *testing.T) {
	cache := NewInMemoryCache()
	resp := &DecisionResponse{Decision: DecisionAllow, DecisionID: "d1"}

	cache.Put("key1", resp, 0)

	if _, ok := cache.Get("key1"); ok {
		t.Error("should not cache when maxTTL is zero")
	}
}

func TestInMemoryCache_NilResponse(t *testing.T) {
	cache := NewInMemoryCache()

	// Should not panic
	cache.Put("key1", nil, 30*time.Second)

	if _, ok := cache.Get("key1"); ok {
		t.Error("should not cache nil response")
	}
}
