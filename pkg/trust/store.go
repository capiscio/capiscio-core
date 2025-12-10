// Package trust provides a local trust store for CA public keys.
// This enables offline badge verification without network access.
// See RFC-002 §13.1.
package trust

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/go-jose/go-jose/v4"
)

// Common errors returned by this package.
var (
	ErrKeyNotFound    = errors.New("key not found in trust store")
	ErrIssuerNotFound = errors.New("issuer not found in trust store")
	ErrInvalidKey     = errors.New("invalid key format")
)

// Store is the interface for a trust store.
type Store interface {
	// Add adds a key to the trust store.
	Add(key jose.JSONWebKey) error

	// Get retrieves a key by kid.
	Get(kid string) (*jose.JSONWebKey, error)

	// GetByIssuer retrieves all keys for an issuer URL.
	GetByIssuer(issuerURL string) ([]jose.JSONWebKey, error)

	// List returns all keys in the store.
	List() ([]jose.JSONWebKey, error)

	// Remove removes a key by kid.
	Remove(kid string) error

	// AddIssuerMapping maps an issuer URL to a key kid.
	AddIssuerMapping(issuerURL, kid string) error
}

// FileStore implements Store using the filesystem.
// Default location: ~/.capiscio/trust/
type FileStore struct {
	dir string
	mu  sync.RWMutex
}

// DefaultTrustDir returns the default trust store directory.
func DefaultTrustDir() string {
	if envPath := os.Getenv("CAPISCIO_TRUST_PATH"); envPath != "" {
		return envPath
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".capiscio/trust"
	}
	return filepath.Join(home, ".capiscio", "trust")
}

// NewFileStore creates a new file-based trust store.
func NewFileStore(dir string) (*FileStore, error) {
	if dir == "" {
		dir = DefaultTrustDir()
	}

	// Ensure directory exists
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create trust directory: %w", err)
	}

	return &FileStore{dir: dir}, nil
}

// keyPath returns the path for a key file.
func (s *FileStore) keyPath(kid string) string {
	// Sanitize kid to be a valid filename
	safe := sanitizeFilename(kid)
	return filepath.Join(s.dir, safe+".jwk")
}

// issuersPath returns the path for the issuers mapping file.
func (s *FileStore) issuersPath() string {
	return filepath.Join(s.dir, "issuers.json")
}

// Add adds a key to the trust store.
func (s *FileStore) Add(key jose.JSONWebKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if key.KeyID == "" {
		return fmt.Errorf("%w: missing kid", ErrInvalidKey)
	}

	// Serialize key
	data, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}

	// Write to file
	path := s.keyPath(key.KeyID)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write key: %w", err)
	}

	return nil
}

// Get retrieves a key by kid.
func (s *FileStore) Get(kid string) (*jose.JSONWebKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	path := s.keyPath(kid)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read key: %w", err)
	}

	var key jose.JSONWebKey
	if err := json.Unmarshal(data, &key); err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
	}

	return &key, nil
}

// GetByIssuer retrieves all keys for an issuer URL.
func (s *FileStore) GetByIssuer(issuerURL string) ([]jose.JSONWebKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Load issuers mapping
	issuers, err := s.loadIssuers()
	if err != nil {
		return nil, err
	}

	kids, ok := issuers[issuerURL]
	if !ok || len(kids) == 0 {
		return nil, ErrIssuerNotFound
	}

	var keys []jose.JSONWebKey
	for _, kid := range kids {
		path := s.keyPath(kid)
		data, err := os.ReadFile(path)
		if err != nil {
			continue // Skip missing keys
		}

		var key jose.JSONWebKey
		if err := json.Unmarshal(data, &key); err != nil {
			continue // Skip invalid keys
		}
		keys = append(keys, key)
	}

	if len(keys) == 0 {
		return nil, ErrKeyNotFound
	}

	return keys, nil
}

// List returns all keys in the store.
func (s *FileStore) List() ([]jose.JSONWebKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read trust directory: %w", err)
	}

	var keys []jose.JSONWebKey
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".jwk" {
			continue
		}

		path := filepath.Join(s.dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		var key jose.JSONWebKey
		if err := json.Unmarshal(data, &key); err != nil {
			continue
		}
		keys = append(keys, key)
	}

	return keys, nil
}

// Remove removes a key by kid.
func (s *FileStore) Remove(kid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := s.keyPath(kid)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return ErrKeyNotFound
	}

	if err := os.Remove(path); err != nil {
		return fmt.Errorf("failed to remove key: %w", err)
	}

	// Also remove from issuers mapping
	issuers, err := s.loadIssuers()
	if err == nil {
		for issuer, kids := range issuers {
			for i, k := range kids {
				if k == kid {
					issuers[issuer] = append(kids[:i], kids[i+1:]...)
					break
				}
			}
		}
		_ = s.saveIssuers(issuers)
	}

	return nil
}

// AddIssuerMapping maps an issuer URL to a key kid.
func (s *FileStore) AddIssuerMapping(issuerURL, kid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	issuers, err := s.loadIssuers()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if issuers == nil {
		issuers = make(map[string][]string)
	}

	// Check if already mapped
	kids := issuers[issuerURL]
	for _, k := range kids {
		if k == kid {
			return nil // Already mapped
		}
	}

	issuers[issuerURL] = append(kids, kid)
	return s.saveIssuers(issuers)
}

// loadIssuers loads the issuers mapping file.
func (s *FileStore) loadIssuers() (map[string][]string, error) {
	data, err := os.ReadFile(s.issuersPath())
	if err != nil {
		return nil, err
	}

	var issuers map[string][]string
	if err := json.Unmarshal(data, &issuers); err != nil {
		return nil, fmt.Errorf("failed to parse issuers file: %w", err)
	}

	return issuers, nil
}

// saveIssuers saves the issuers mapping file.
func (s *FileStore) saveIssuers(issuers map[string][]string) error {
	data, err := json.MarshalIndent(issuers, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal issuers: %w", err)
	}

	if err := os.WriteFile(s.issuersPath(), data, 0600); err != nil {
		return fmt.Errorf("failed to write issuers file: %w", err)
	}

	return nil
}

// sanitizeFilename converts a kid to a safe filename.
func sanitizeFilename(kid string) string {
	// Replace problematic characters
	safe := make([]byte, 0, len(kid))
	for _, c := range []byte(kid) {
		switch c {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|':
			safe = append(safe, '_')
		default:
			safe = append(safe, c)
		}
	}
	return string(safe)
}

// AddFromJWKS adds all keys from a JWKS and optionally maps them to an issuer.
func (s *FileStore) AddFromJWKS(jwks *jose.JSONWebKeySet, issuerURL string) error {
	for _, key := range jwks.Keys {
		if err := s.Add(key); err != nil {
			return fmt.Errorf("failed to add key %s: %w", key.KeyID, err)
		}
		if issuerURL != "" {
			if err := s.AddIssuerMapping(issuerURL, key.KeyID); err != nil {
				return fmt.Errorf("failed to map key %s to issuer: %w", key.KeyID, err)
			}
		}
	}
	return nil
}
