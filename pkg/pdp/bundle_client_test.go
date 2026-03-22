package pdp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBundleClient_RequiresBundleURL(t *testing.T) {
	_, err := NewBundleClient("", "my-key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bundle URL is required")
}

func TestNewBundleClient_RequiresAPIKey(t *testing.T) {
	_, err := NewBundleClient("http://localhost/v1/bundles/ws1", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API key is required")
}

func TestBundleClient_FetchSuccess(t *testing.T) {
	bundle := BundleContents{
		Modules: map[string]string{
			"policy.rego": "package capiscio.policy\ndefault allow = true",
		},
		Data: map[string]interface{}{
			"agents": []interface{}{},
		},
		Revision: "abc123",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "test-api-key", r.Header.Get("X-Capiscio-Registry-Key"))
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		assert.Equal(t, http.MethodGet, r.Method)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(bundle)
	}))
	defer srv.Close()

	client, err := NewBundleClient(srv.URL+"/v1/bundles/ws1", "test-api-key")
	require.NoError(t, err)

	result, err := client.Fetch(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "abc123", result.Revision)
	assert.Contains(t, result.Modules, "policy.rego")
	assert.NotNil(t, result.Data)
}

func TestBundleClient_FetchUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	client, err := NewBundleClient(srv.URL+"/v1/bundles/ws1", "bad-key")
	require.NoError(t, err)

	_, err = client.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed")
}

func TestBundleClient_FetchForbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	client, err := NewBundleClient(srv.URL+"/v1/bundles/ws1", "no-perm-key")
	require.NoError(t, err)

	_, err = client.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed (403)")
}

func TestBundleClient_FetchServiceUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client, err := NewBundleClient(srv.URL+"/v1/bundles/ws1", "test-key")
	require.NoError(t, err)

	_, err = client.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not yet available")
}

func TestBundleClient_FetchEmptyModules(t *testing.T) {
	bundle := BundleContents{
		Modules: map[string]string{},
		Data:    map[string]interface{}{},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(bundle)
	}))
	defer srv.Close()

	client, err := NewBundleClient(srv.URL+"/v1/bundles/ws1", "test-key")
	require.NoError(t, err)

	_, err = client.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no Rego modules")
}

func TestBundleClient_FetchServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	client, err := NewBundleClient(srv.URL+"/v1/bundles/ws1", "test-key")
	require.NoError(t, err)

	_, err = client.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestBundleClient_FetchContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow server — context should be cancelled
		<-r.Context().Done()
	}))
	defer srv.Close()

	client, err := NewBundleClient(srv.URL+"/v1/bundles/ws1", "test-key")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err = client.Fetch(ctx)
	require.Error(t, err)
}

func TestBundleClient_BundleURL(t *testing.T) {
	client, err := NewBundleClient("https://api.test.com/v1/bundles/ws1", "key")
	require.NoError(t, err)
	assert.Equal(t, "https://api.test.com/v1/bundles/ws1", client.BundleURL())
}

func TestBundleClient_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	client, err := NewBundleClient(srv.URL+"/v1/bundles/ws1", "test-key")
	require.NoError(t, err)

	_, err = client.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode bundle response")
}

func TestBundleClient_Fetch_EmptyModuleSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(BundleContents{
			Modules:  map[string]string{"policy.rego": "  "},
			Revision: "rev-empty",
		})
	}))
	defer srv.Close()

	client, err := NewBundleClient(srv.URL+"/v1/bundles/ws1", "test-key")
	require.NoError(t, err)

	_, err = client.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty source")
	assert.Contains(t, err.Error(), "policy.rego")
}
