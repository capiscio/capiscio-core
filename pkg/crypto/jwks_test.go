package crypto

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
)

func TestDefaultJWKSFetcher_Fetch_Success(t *testing.T) {
	// Generate a key to serve
	key := []byte("secret")
	jwk := jose.JSONWebKey{
		Key:       key,
		KeyID:     "kid1",
		Algorithm: "HS256",
		Use:       "sig",
	}
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	fetcher := NewDefaultJWKSFetcher()
	fetchedJWKS, err := fetcher.Fetch(context.Background(), server.URL)

	assert.NoError(t, err)
	assert.NotNil(t, fetchedJWKS)
	assert.Len(t, fetchedJWKS.Keys, 1)
	assert.Equal(t, "kid1", fetchedJWKS.Keys[0].KeyID)
}

func TestDefaultJWKSFetcher_Fetch_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	fetcher := NewDefaultJWKSFetcher()
	_, err := fetcher.Fetch(context.Background(), server.URL)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status 404")
}

func TestDefaultJWKSFetcher_Fetch_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	fetcher := NewDefaultJWKSFetcher()
	_, err := fetcher.Fetch(context.Background(), server.URL)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode JWKS")
}

func TestDefaultJWKSFetcher_Fetch_NetworkError(t *testing.T) {
	fetcher := NewDefaultJWKSFetcher()
	_, err := fetcher.Fetch(context.Background(), "http://127.0.0.1:0")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to fetch JWKS")
}

func TestDefaultJWKSFetcher_Caching(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		jwks := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{
					Key:       []byte("secret"),
					KeyID:     "kid1",
					Algorithm: "HS256",
					Use:       "sig",
				},
			},
		}
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	fetcher := NewDefaultJWKSFetcher()

	// 1. First fetch - should hit server
	_, err := fetcher.Fetch(context.Background(), server.URL)
	assert.NoError(t, err)
	assert.Equal(t, 1, requestCount)

	// 2. Second fetch - should hit cache
	_, err = fetcher.Fetch(context.Background(), server.URL)
	assert.NoError(t, err)
	assert.Equal(t, 1, requestCount)

	// 3. Flush cache
	fetcher.FlushCache()

	// 4. Third fetch - should hit server again
	_, err = fetcher.Fetch(context.Background(), server.URL)
	assert.NoError(t, err)
	assert.Equal(t, 2, requestCount)
}

func TestDefaultJWKSFetcher_TTL(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		jwks := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{
					Key:       []byte("secret"),
					KeyID:     "kid1",
					Algorithm: "HS256",
					Use:       "sig",
				},
			},
		}
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	fetcher := NewDefaultJWKSFetcher()
	fetcher.SetTTL(1 * time.Millisecond) // Very short TTL

	// 1. First fetch
	_, err := fetcher.Fetch(context.Background(), server.URL)
	assert.NoError(t, err)
	assert.Equal(t, 1, requestCount)

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// 2. Second fetch - should hit server due to expiration
	_, err = fetcher.Fetch(context.Background(), server.URL)
	assert.NoError(t, err)
	assert.Equal(t, 2, requestCount)
}
