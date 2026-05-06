package gateway

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractLeafAuthority(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set(HeaderAuthority, "eyJ0eXAi.payload.sig")
		assert.Equal(t, "eyJ0eXAi.payload.sig", ExtractLeafAuthority(r))
	})

	t.Run("absent", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		assert.Equal(t, "", ExtractLeafAuthority(r))
	})
}

func TestExtractAuthorityChain(t *testing.T) {
	encode := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}

	t.Run("absent header returns nil nil", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		chain, err := ExtractAuthorityChain(r)
		assert.NoError(t, err)
		assert.Nil(t, chain)
	})

	t.Run("valid chain", func(t *testing.T) {
		jws := []string{"root.payload.sig", "leaf.payload.sig"}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set(HeaderAuthorityChain, encode(jws))

		chain, err := ExtractAuthorityChain(r)
		require.NoError(t, err)
		assert.Equal(t, jws, chain)
	})

	t.Run("invalid base64url", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set(HeaderAuthorityChain, "!!!invalid-base64!!!")

		_, err := ExtractAuthorityChain(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ENVELOPE_MALFORMED")
	})

	t.Run("invalid JSON", func(t *testing.T) {
		raw := base64.RawURLEncoding.EncodeToString([]byte("{not json"))
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set(HeaderAuthorityChain, raw)

		_, err := ExtractAuthorityChain(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ENVELOPE_MALFORMED")
	})

	t.Run("empty array", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set(HeaderAuthorityChain, encode([]string{}))

		_, err := ExtractAuthorityChain(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty array")
	})
}

func TestExtractBadgeMap(t *testing.T) {
	encode := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}

	t.Run("absent header returns nil nil", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		m, err := ExtractBadgeMap(r)
		assert.NoError(t, err)
		assert.Nil(t, m)
	})

	t.Run("valid badge map", func(t *testing.T) {
		expected := map[string]string{
			"did:web:alice.example": "badge-alice.payload.sig",
			"did:key:zBob":         "badge-bob.payload.sig",
		}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set(HeaderBadgeMap, encode(expected))

		m, err := ExtractBadgeMap(r)
		require.NoError(t, err)
		assert.Equal(t, expected, m)
	})

	t.Run("invalid base64url", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set(HeaderBadgeMap, "!!!invalid!!!")

		_, err := ExtractBadgeMap(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ENVELOPE_MALFORMED")
	})
}

func TestValidateChainLeafConsistency(t *testing.T) {
	t.Run("consistent", func(t *testing.T) {
		err := ValidateChainLeafConsistency("leaf.jws", []string{"root.jws", "leaf.jws"})
		assert.NoError(t, err)
	})

	t.Run("inconsistent", func(t *testing.T) {
		err := ValidateChainLeafConsistency("different.jws", []string{"root.jws", "leaf.jws"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ENVELOPE_CHAIN_BROKEN")
	})

	t.Run("nil chain is ok", func(t *testing.T) {
		err := ValidateChainLeafConsistency("leaf.jws", nil)
		assert.NoError(t, err)
	})

	t.Run("empty chain is ok", func(t *testing.T) {
		err := ValidateChainLeafConsistency("leaf.jws", []string{})
		assert.NoError(t, err)
	})
}
