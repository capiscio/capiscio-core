package registry_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/capiscio/capiscio-core/pkg/registry"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalRegistry(t *testing.T) {
	// 1. Generate Key and Save to File
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	jwk := jose.JSONWebKey{Key: pub, KeyID: "test-key", Algorithm: string(jose.EdDSA)}
	jwkBytes, _ := json.Marshal(jwk)

	tmpFile, err := os.CreateTemp("", "key-*.jwk")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.Write(jwkBytes)
	require.NoError(t, err)
	tmpFile.Close()

	// 2. Test Registry
	reg := registry.NewLocalRegistry(tmpFile.Name())
	
	fetchedKey, err := reg.GetPublicKey(context.Background(), "any-issuer")
	require.NoError(t, err)
	assert.Equal(t, pub, fetchedKey)
}

func TestCloudRegistry(t *testing.T) {
	// 1. Setup Mock Server
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	jwk := jose.JSONWebKey{Key: pub, KeyID: "cloud-key", Algorithm: string(jose.EdDSA)}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jwk)
	}))
	defer server.Close()

	// 2. Test Registry
	reg := registry.NewCloudRegistry(server.URL)

	fetchedKey, err := reg.GetPublicKey(context.Background(), "any-issuer")
	require.NoError(t, err)
	assert.Equal(t, pub, fetchedKey)

	// 3. Test Cache (Stop Server and fetch again)
	server.Close() 
	// Note: In a real test we might want to verify no network call is made, 
	// but here we rely on the fact that if cache failed, this would error out 
	// because the server is closed.
	cachedKey, err := reg.GetPublicKey(context.Background(), "any-issuer")
	require.NoError(t, err)
	assert.Equal(t, pub, cachedKey)
}
