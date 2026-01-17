// Package mcp provides evidence storage implementations for RFC-006.
package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ============================================================================
// Evidence Store Interface (already defined in guard.go, re-documented here)
// ============================================================================

// EvidenceStoreMode determines the storage backend
type EvidenceStoreMode string

const (
	// EvidenceStoreModeLocal stores evidence to local files
	EvidenceStoreModeLocal EvidenceStoreMode = "local"

	// EvidenceStoreModeRegistry streams evidence to registry server
	EvidenceStoreModeRegistry EvidenceStoreMode = "registry"

	// EvidenceStoreModeHybrid stores locally AND streams to registry
	EvidenceStoreModeHybrid EvidenceStoreMode = "hybrid"
)

// ============================================================================
// Local File Evidence Store
// ============================================================================

// LocalEvidenceStore stores evidence records to local JSON files.
// Each file is named by date (YYYY-MM-DD.jsonl) in JSONL format.
type LocalEvidenceStore struct {
	dir       string
	mu        sync.Mutex
	file      *os.File
	currentFn string
}

// NewLocalEvidenceStore creates a new local evidence store.
// If dir is empty, uses ~/.capiscio/evidence/
func NewLocalEvidenceStore(dir string) (*LocalEvidenceStore, error) {
	if dir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		dir = filepath.Join(homeDir, ".capiscio", "evidence")
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create evidence directory: %w", err)
	}

	return &LocalEvidenceStore{dir: dir}, nil
}

// Store writes an evidence record to the local file.
func (s *LocalEvidenceStore) Store(ctx context.Context, record EvidenceRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get current date-based filename
	fn := filepath.Join(s.dir, time.Now().UTC().Format("2006-01-02")+".jsonl")

	// Rotate file if date changed
	if s.currentFn != fn {
		if s.file != nil {
			_ = s.file.Close()
		}

		file, err := os.OpenFile(fn, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return fmt.Errorf("failed to open evidence file: %w", err)
		}
		s.file = file
		s.currentFn = fn
	}

	// Write record as JSON line
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal evidence: %w", err)
	}

	if _, err := s.file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("failed to write evidence: %w", err)
	}

	return nil
}

// Close closes the local evidence store.
func (s *LocalEvidenceStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}

// ============================================================================
// Registry Streaming Evidence Store
// ============================================================================

// RegistryEvidenceStore streams evidence to the registry server's events endpoint.
// It implements batching and rate limiting to avoid overwhelming the server.
type RegistryEvidenceStore struct {
	endpoint   string
	apiKey     string
	httpClient *http.Client

	// Batching
	batchSize     int
	flushInterval time.Duration
	buffer        []EvidenceRecord
	bufferMu      sync.Mutex

	// Rate limiting for repetitive logs
	rateLimiter *EvidenceRateLimiter

	// Background flush
	quit chan struct{}
	wg   sync.WaitGroup
}

// RegistryEvidenceStoreConfig configures the registry evidence store
type RegistryEvidenceStoreConfig struct {
	// Endpoint is the registry events endpoint URL
	Endpoint string

	// APIKey for authentication
	APIKey string

	// BatchSize is the number of records to batch before flushing (default: 100)
	BatchSize int

	// FlushInterval is the max time between flushes (default: 5s)
	FlushInterval time.Duration

	// RateLimitWindow is the deduplication window (default: 60s)
	RateLimitWindow time.Duration

	// RateLimitMaxPerWindow is max events per fingerprint per window (default: 10)
	RateLimitMaxPerWindow int
}

// NewRegistryEvidenceStore creates a new registry streaming evidence store.
func NewRegistryEvidenceStore(cfg RegistryEvidenceStoreConfig) *RegistryEvidenceStore {
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = 5 * time.Second
	}
	if cfg.RateLimitWindow == 0 {
		cfg.RateLimitWindow = 60 * time.Second
	}
	if cfg.RateLimitMaxPerWindow == 0 {
		cfg.RateLimitMaxPerWindow = 10
	}

	s := &RegistryEvidenceStore{
		endpoint:      cfg.Endpoint,
		apiKey:        cfg.APIKey,
		httpClient:    &http.Client{Timeout: 10 * time.Second},
		batchSize:     cfg.BatchSize,
		flushInterval: cfg.FlushInterval,
		buffer:        make([]EvidenceRecord, 0, cfg.BatchSize),
		rateLimiter:   NewEvidenceRateLimiter(cfg.RateLimitWindow, cfg.RateLimitMaxPerWindow),
		quit:          make(chan struct{}),
	}

	// Start background flush goroutine
	s.wg.Add(1)
	go s.flushLoop()

	return s
}

// Store adds an evidence record to the buffer for streaming.
func (s *RegistryEvidenceStore) Store(ctx context.Context, record EvidenceRecord) error {
	// Check rate limiter - skip if this fingerprint is rate limited
	if s.rateLimiter.IsRateLimited(record) {
		return nil // Silently skip rate-limited records
	}

	s.bufferMu.Lock()
	s.buffer = append(s.buffer, record)
	shouldFlush := len(s.buffer) >= s.batchSize
	s.bufferMu.Unlock()

	if shouldFlush {
		go s.flush() // Non-blocking flush
	}

	return nil
}

// flushLoop runs the periodic flush timer.
func (s *RegistryEvidenceStore) flushLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.flush()
		case <-s.quit:
			s.flush() // Final flush
			return
		}
	}
}

// flush sends buffered records to the registry.
func (s *RegistryEvidenceStore) flush() {
	s.bufferMu.Lock()
	if len(s.buffer) == 0 {
		s.bufferMu.Unlock()
		return
	}

	batch := s.buffer
	s.buffer = make([]EvidenceRecord, 0, s.batchSize)
	s.bufferMu.Unlock()

	// Build request payload
	payload := map[string]interface{}{
		"events": batch,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		// Log error but don't fail - evidence is best-effort
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", s.endpoint, nil)
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/json")
	if s.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.apiKey)
	}
	req.Body = io.NopCloser(json.NewDecoder(nil).Buffered())

	// Actually set body
	req, _ = http.NewRequestWithContext(ctx, "POST", s.endpoint, nil)
	req.Header.Set("Content-Type", "application/json")
	if s.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.apiKey)
	}

	// Re-create request with body
	req2, _ := http.NewRequestWithContext(ctx, "POST", s.endpoint, nil)
	req2.Header = req.Header.Clone()
	req2.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(json.NewDecoder(nil).Buffered()), nil
	}

	// Send via http client
	// Simplify - just POST the data
	resp, err := s.httpClient.Post(s.endpoint, "application/json", io.NopCloser(
		&jsonReader{data: data},
	))
	if err != nil {
		// Log but don't fail
		return
	}
	defer resp.Body.Close()

	// 2xx is success
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// Success
	}
}

type jsonReader struct {
	data   []byte
	offset int
}

func (r *jsonReader) Read(p []byte) (n int, err error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}

// Close stops the registry evidence store.
func (s *RegistryEvidenceStore) Close() error {
	close(s.quit)
	s.wg.Wait()
	return nil
}

// ============================================================================
// Evidence Rate Limiter
// ============================================================================

// EvidenceRateLimiter prevents repetitive log flooding.
// It deduplicates evidence by fingerprint (tool + agent + decision).
type EvidenceRateLimiter struct {
	window    time.Duration
	maxPerWin int
	counts    map[string]*rateLimitEntry
	mu        sync.Mutex
}

type rateLimitEntry struct {
	count     int
	windowEnd time.Time
}

// NewEvidenceRateLimiter creates a new rate limiter.
func NewEvidenceRateLimiter(window time.Duration, maxPerWindow int) *EvidenceRateLimiter {
	return &EvidenceRateLimiter{
		window:    window,
		maxPerWin: maxPerWindow,
		counts:    make(map[string]*rateLimitEntry),
	}
}

// IsRateLimited checks if an evidence record should be rate-limited.
func (r *EvidenceRateLimiter) IsRateLimited(record EvidenceRecord) bool {
	fingerprint := r.computeFingerprint(record)

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	entry, exists := r.counts[fingerprint]

	if !exists || now.After(entry.windowEnd) {
		// New window
		r.counts[fingerprint] = &rateLimitEntry{
			count:     1,
			windowEnd: now.Add(r.window),
		}
		return false
	}

	entry.count++
	if entry.count > r.maxPerWin {
		return true // Rate limited
	}

	return false
}

// computeFingerprint creates a unique key for deduplication.
// Groups by: tool name + agent DID + decision + auth level
func (r *EvidenceRateLimiter) computeFingerprint(record EvidenceRecord) string {
	data := fmt.Sprintf("%s|%s|%s|%s",
		record.Target,
		record.AgentDID,
		record.Decision,
		record.AuthLevel,
	)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8]) // First 8 bytes is enough
}

// ============================================================================
// Hybrid Evidence Store
// ============================================================================

// HybridEvidenceStore stores evidence both locally and to registry.
type HybridEvidenceStore struct {
	local    *LocalEvidenceStore
	registry *RegistryEvidenceStore
}

// NewHybridEvidenceStore creates a store that writes to both local and registry.
func NewHybridEvidenceStore(localDir string, registryCfg RegistryEvidenceStoreConfig) (*HybridEvidenceStore, error) {
	local, err := NewLocalEvidenceStore(localDir)
	if err != nil {
		return nil, err
	}

	registry := NewRegistryEvidenceStore(registryCfg)

	return &HybridEvidenceStore{
		local:    local,
		registry: registry,
	}, nil
}

// Store writes to both local and registry stores.
func (s *HybridEvidenceStore) Store(ctx context.Context, record EvidenceRecord) error {
	// Always write locally (sync)
	if err := s.local.Store(ctx, record); err != nil {
		// Log but continue - local failure shouldn't stop registry
	}

	// Stream to registry (async via buffer)
	_ = s.registry.Store(ctx, record)

	return nil
}

// Close closes both stores.
func (s *HybridEvidenceStore) Close() error {
	var errs []error
	if err := s.local.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := s.registry.Close(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}
