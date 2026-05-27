// Copyright (c) CapiscIO, Inc.
// Licensed under the MIT License.

package mediation

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

// EventSink receives emitted events for processing.
//
// Implementations handle event persistence, forwarding, or aggregation.
// All methods MUST be safe for concurrent use.
type EventSink interface {
	// Receive processes an event. MUST NOT block.
	Receive(event *Event)

	// Flush ensures all buffered events are processed.
	// Called during graceful shutdown.
	Flush(ctx context.Context) error

	// Close releases resources held by the sink.
	Close() error
}

// AsyncEmitter implements EventEmitter with non-blocking event emission.
//
// Per RFC-011 §4.2 and §7.3, event emission MUST NOT block on network I/O.
// Events are buffered locally and forwarded asynchronously to sinks.
type AsyncEmitter struct {
	emitter  EmitterInfo
	sinks    []EventSink
	eventCh  chan *Event
	doneCh   chan struct{}
	wg       sync.WaitGroup
	mu       sync.RWMutex
	closed   bool

	// bufferSize is the channel buffer capacity.
	bufferSize int

	// dropOnFull determines behavior when buffer is full.
	// If true, new events are dropped; if false, oldest events are dropped.
	dropOnFull bool

	// droppedCount tracks events dropped due to buffer overflow.
	droppedCount uint64
}

// AsyncEmitterConfig configures the async emitter.
type AsyncEmitterConfig struct {
	// ComponentID identifies this emitter instance.
	ComponentID string

	// ComponentType is one of: sdk, sidecar, gateway, pep.
	ComponentType ComponentType

	// Version is the component version string.
	Version string

	// BufferSize is the event channel capacity. Default: 1000.
	BufferSize int

	// DropOnFull, if true, drops new events when buffer is full.
	// If false (default), emits events synchronously as fallback.
	DropOnFull bool

	// Sinks are the event receivers.
	Sinks []EventSink
}

// NewAsyncEmitter creates an async event emitter.
func NewAsyncEmitter(config AsyncEmitterConfig) *AsyncEmitter {
	bufferSize := config.BufferSize
	if bufferSize <= 0 {
		bufferSize = 1000
	}

	e := &AsyncEmitter{
		emitter: EmitterInfo{
			ComponentID:   config.ComponentID,
			ComponentType: config.ComponentType,
			Version:       config.Version,
		},
		sinks:      config.Sinks,
		eventCh:    make(chan *Event, bufferSize),
		doneCh:     make(chan struct{}),
		bufferSize: bufferSize,
		dropOnFull: config.DropOnFull,
	}

	// Start the event processing goroutine
	e.wg.Add(1)
	go e.processEvents()

	return e
}

// processEvents runs in a goroutine, forwarding events to sinks.
func (e *AsyncEmitter) processEvents() {
	defer e.wg.Done()

	for {
		select {
		case event := <-e.eventCh:
			e.deliverToSinks(event)
		case <-e.doneCh:
			// Drain remaining events
			for {
				select {
				case event := <-e.eventCh:
					e.deliverToSinks(event)
				default:
					return
				}
			}
		}
	}
}

// deliverToSinks sends an event to all registered sinks.
func (e *AsyncEmitter) deliverToSinks(event *Event) {
	e.mu.RLock()
	sinks := e.sinks
	e.mu.RUnlock()

	for _, sink := range sinks {
		sink.Receive(event)
	}
}

// emit sends an event to the processing channel.
func (e *AsyncEmitter) emit(event *Event) {
	e.mu.RLock()
	closed := e.closed
	e.mu.RUnlock()

	if closed {
		return
	}

	select {
	case e.eventCh <- event:
		// Event queued successfully
	default:
		// Buffer full
		if e.dropOnFull {
			e.mu.Lock()
			e.droppedCount++
			e.mu.Unlock()
		} else {
			// Synchronous fallback - deliver directly.
			// WARNING: This CAN block the mediation path if sinks are slow.
			// For strict RFC-011 §4.2 compliance, use DropOnFull=true.
			e.deliverToSinks(event)
		}
	}
}

// EmitDecision implements EventEmitter.
func (e *AsyncEmitter) EmitDecision(mctx *Context, result *Result, request Request) {
	var eventType EventType
	switch result.Decision {
	case DecisionAllow:
		eventType = e.allowEventType(request)
	case DecisionDeny:
		eventType = e.denyEventType(request)
	case DecisionDelegate:
		eventType = EventAuthorityDelegated
	default:
		return
	}

	event := NewEvent(eventType, e.emitter)
	if mctx != nil {
		event.WithContext(mctx.TraceID, mctx.TxnID, mctx.HopID)
		event.WithPayload("subject_did", mctx.SubjectDID)
		event.WithPayload("trust_level", mctx.TrustLevel)
		if mctx.Envelope != nil {
			event.WithPayload("envelope_hash", HashForEvent(mctx.Envelope.Raw))
		}
	}

	event.WithPayload("decision", string(result.Decision))
	event.WithPayload("reason", result.Reason)
	event.WithPayload("policy_ref", result.PolicyRef)

	if request != nil {
		event.WithPayload("domain", request.Domain())
		event.WithPayload("capability", request.Capability())
	}

	e.emit(event)
}

// EmitCapabilityCheck implements EventEmitter.
func (e *AsyncEmitter) EmitCapabilityCheck(mctx *Context, capability string, granted bool) {
	var eventType EventType
	if granted {
		eventType = EventAuthorityGranted
	} else {
		eventType = EventAuthorityDenied
	}

	event := NewEvent(eventType, e.emitter)
	if mctx != nil {
		event.WithContext(mctx.TraceID, mctx.TxnID, mctx.HopID)
		event.WithPayload("subject_did", mctx.SubjectDID)
	}

	event.WithPayload("capability", capability)
	event.WithPayload("granted", granted)

	e.emit(event)
}

// EmitIdentityVerified emits an identity.verified event.
func (e *AsyncEmitter) EmitIdentityVerified(mctx *Context, badgeJTI string, trustLevel, ial int) {
	event := NewEvent(EventIdentityVerified, e.emitter)
	if mctx != nil {
		event.WithContext(mctx.TraceID, mctx.TxnID, mctx.HopID)
		event.WithPayload("subject_did", mctx.SubjectDID)
	}

	event.WithPayload("badge_jti", badgeJTI)
	event.WithPayload("trust_level", trustLevel)
	event.WithPayload("ial", ial)

	e.emit(event)
}

// EmitIdentityInvalid emits an identity.invalid event.
func (e *AsyncEmitter) EmitIdentityInvalid(mctx *Context, badgeJTI, errorCode, reason string) {
	event := NewEvent(EventIdentityInvalid, e.emitter)
	if mctx != nil {
		event.WithContext(mctx.TraceID, mctx.TxnID, mctx.HopID)
	}

	event.WithPayload("badge_jti", badgeJTI)
	event.WithPayload("error_code", errorCode)
	event.WithPayload("reason", reason)

	e.emit(event)
}

// EmitToolRequested emits a tool.requested event.
func (e *AsyncEmitter) EmitToolRequested(mctx *Context, toolName, serverDID string) {
	event := NewEvent(EventToolRequested, e.emitter)
	if mctx != nil {
		event.WithContext(mctx.TraceID, mctx.TxnID, mctx.HopID)
		event.WithPayload("subject_did", mctx.SubjectDID)
		if mctx.Envelope != nil {
			event.WithPayload("envelope_hash", HashForEvent(mctx.Envelope.Raw))
		}
	}

	event.WithPayload("tool_name", toolName)
	event.WithPayload("server_did", serverDID)

	e.emit(event)
}

// EmitToolExecuted emits a tool.executed event.
func (e *AsyncEmitter) EmitToolExecuted(mctx *Context, toolName, serverDID, outcome string, durationMs int64) {
	event := NewEvent(EventToolExecuted, e.emitter)
	if mctx != nil {
		event.WithContext(mctx.TraceID, mctx.TxnID, mctx.HopID)
	}

	event.WithPayload("tool_name", toolName)
	event.WithPayload("server_did", serverDID)
	event.WithPayload("outcome", outcome)
	event.WithPayload("duration_ms", durationMs)

	e.emit(event)
}

// EmitResourceNetwork emits a resource.network.* event.
func (e *AsyncEmitter) EmitResourceNetwork(
	mctx *Context,
	eventType EventType,
	scheme, host string,
	port int,
	pathClassification, method, reason string,
) {
	event := NewEvent(eventType, e.emitter)
	if mctx != nil {
		event.WithContext(mctx.TraceID, mctx.TxnID, mctx.HopID)
		event.WithPayload("subject_did", mctx.SubjectDID)
	}

	event.WithPayload("scheme", scheme)
	event.WithPayload("target_host", host)
	event.WithPayload("target_port", port)
	event.WithPayload("path_classification", pathClassification)
	event.WithPayload("method", method)
	if reason != "" {
		event.WithPayload("reason", reason)
	}

	e.emit(event)
}

// EmitResourceFilesystem emits a resource.filesystem.* event.
func (e *AsyncEmitter) EmitResourceFilesystem(
	mctx *Context,
	eventType EventType,
	pathClassification, pathHash, operation, reason string,
) {
	event := NewEvent(eventType, e.emitter)
	if mctx != nil {
		event.WithContext(mctx.TraceID, mctx.TxnID, mctx.HopID)
		event.WithPayload("subject_did", mctx.SubjectDID)
	}

	event.WithPayload("path_classification", pathClassification)
	event.WithPayload("path_hash", pathHash)
	event.WithPayload("operation", operation)
	if reason != "" {
		event.WithPayload("reason", reason)
	}

	e.emit(event)
}

// EmitResourceShell emits a resource.shell.* event.
func (e *AsyncEmitter) EmitResourceShell(
	mctx *Context,
	eventType EventType,
	commandHash, commandClassification, reason string,
) {
	event := NewEvent(eventType, e.emitter)
	if mctx != nil {
		event.WithContext(mctx.TraceID, mctx.TxnID, mctx.HopID)
		event.WithPayload("subject_did", mctx.SubjectDID)
	}

	event.WithPayload("command_hash", commandHash)
	event.WithPayload("command_classification", commandClassification)
	if reason != "" {
		event.WithPayload("reason", reason)
	}

	e.emit(event)
}

// EmitExecutionStarted emits an execution.started event.
func (e *AsyncEmitter) EmitExecutionStarted(mctx *Context) {
	event := NewEvent(EventExecutionStarted, e.emitter)
	if mctx != nil {
		event.WithContext(mctx.TraceID, mctx.TxnID, mctx.HopID)
		event.WithPayload("subject_did", mctx.SubjectDID)
		if mctx.Envelope != nil {
			event.WithPayload("envelope_hash", HashForEvent(mctx.Envelope.Raw))
		}
	}

	e.emit(event)
}

// EmitExecutionCompleted emits an execution.completed event.
func (e *AsyncEmitter) EmitExecutionCompleted(mctx *Context, outcome string, durationMs int64) {
	event := NewEvent(EventExecutionCompleted, e.emitter)
	if mctx != nil {
		event.WithContext(mctx.TraceID, mctx.TxnID, mctx.HopID)
	}

	event.WithPayload("outcome", outcome)
	event.WithPayload("duration_ms", durationMs)

	e.emit(event)
}

// EmitTrustRevocationChecked emits a trust.revocation.checked event.
func (e *AsyncEmitter) EmitTrustRevocationChecked(mctx *Context, jti string, revoked bool, cacheAgeSeconds int) {
	event := NewEvent(EventTrustRevocationChecked, e.emitter)
	if mctx != nil {
		event.WithContext(mctx.TraceID, mctx.TxnID, mctx.HopID)
	}

	event.WithPayload("jti", jti)
	event.WithPayload("revoked", revoked)
	event.WithPayload("cache_age_seconds", cacheAgeSeconds)

	e.emit(event)
}

// allowEventType returns the appropriate allow event type for a request domain.
func (e *AsyncEmitter) allowEventType(request Request) EventType {
	if request == nil {
		return EventAuthorityGranted
	}
	switch request.Domain() {
	case "tool":
		return EventToolPermitted
	case "file":
		return EventResourceFilesystemPermitted
	case "network":
		return EventResourceNetworkPermitted
	case "shell":
		return EventResourceShellPermitted
	default:
		return EventAuthorityGranted
	}
}

// denyEventType returns the appropriate deny event type for a request domain.
func (e *AsyncEmitter) denyEventType(request Request) EventType {
	if request == nil {
		return EventAuthorityDenied
	}
	switch request.Domain() {
	case "tool":
		return EventToolDenied
	case "file":
		return EventResourceFilesystemDenied
	case "network":
		return EventResourceNetworkDenied
	case "shell":
		return EventResourceShellDenied
	default:
		return EventAuthorityDenied
	}
}

// AddSink adds a sink to receive events.
func (e *AsyncEmitter) AddSink(sink EventSink) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sinks = append(e.sinks, sink)
}

// DroppedCount returns the number of events dropped due to buffer overflow.
func (e *AsyncEmitter) DroppedCount() uint64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.droppedCount
}

// Flush drains buffered events and flushes all sinks.
func (e *AsyncEmitter) Flush(ctx context.Context) error {
	e.mu.RLock()
	sinks := e.sinks
	e.mu.RUnlock()

	for _, sink := range sinks {
		if err := sink.Flush(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Close stops the emitter and releases resources.
func (e *AsyncEmitter) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	e.mu.Unlock()

	// Signal shutdown and wait for drain
	close(e.doneCh)
	e.wg.Wait()

	// Close all sinks
	e.mu.RLock()
	sinks := e.sinks
	e.mu.RUnlock()

	for _, sink := range sinks {
		_ = sink.Close() // Best-effort cleanup; errors logged by sinks
	}

	return nil
}

// ChannelSink is a simple sink that forwards events to a channel.
// Useful for testing and for piping events to goroutines.
type ChannelSink struct {
	ch     chan *Event
	closed bool
	mu     sync.Mutex
}

// NewChannelSink creates a sink that forwards events to a channel.
func NewChannelSink(bufferSize int) *ChannelSink {
	return &ChannelSink{
		ch: make(chan *Event, bufferSize),
	}
}

// Receive implements EventSink.
func (s *ChannelSink) Receive(event *Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	select {
	case s.ch <- event:
	default:
		// Drop if full
	}
}

// Flush implements EventSink.
func (s *ChannelSink) Flush(ctx context.Context) error {
	return nil
}

// Close implements EventSink.
func (s *ChannelSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		close(s.ch)
	}
	return nil
}

// Events returns the event channel for reading.
func (s *ChannelSink) Events() <-chan *Event {
	return s.ch
}

// JSONSink writes events as newline-delimited JSON.
// Typically used with an io.Writer for file or network output.
type JSONSink struct {
	encoder *json.Encoder
	mu      sync.Mutex
}

// NewJSONSink creates a sink that writes JSON to the given writer.
func NewJSONSink(w interface{ Write([]byte) (int, error) }) *JSONSink {
	return &JSONSink{
		encoder: json.NewEncoder(w),
	}
}

// Receive implements EventSink.
func (s *JSONSink) Receive(event *Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.encoder.Encode(event) // Errors are intentionally ignored; sink is best-effort
}

// Flush implements EventSink.
func (s *JSONSink) Flush(ctx context.Context) error {
	return nil
}

// Close implements EventSink.
func (s *JSONSink) Close() error {
	return nil
}

// BatchSink collects events and flushes them in batches.
type BatchSink struct {
	batch     []*Event
	batchSize int
	flushFn   func([]*Event) error
	mu        sync.Mutex
	lastFlush time.Time
}

// NewBatchSink creates a sink that batches events.
func NewBatchSink(batchSize int, flushFn func([]*Event) error) *BatchSink {
	return &BatchSink{
		batch:     make([]*Event, 0, batchSize),
		batchSize: batchSize,
		flushFn:   flushFn,
		lastFlush: time.Now(),
	}
}

// Receive implements EventSink.
func (s *BatchSink) Receive(event *Event) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.batch = append(s.batch, event)
	if len(s.batch) >= s.batchSize {
		s.flushLocked()
	}
}

// flushLocked flushes the batch (must hold mu).
func (s *BatchSink) flushLocked() {
	if len(s.batch) == 0 {
		return
	}
	batch := s.batch
	s.batch = make([]*Event, 0, s.batchSize)
	s.lastFlush = time.Now()
	
	// Release lock during flush callback
	s.mu.Unlock()
	_ = s.flushFn(batch) // Errors are logged by caller; sink continues operating
	s.mu.Lock()
}

// Flush implements EventSink.
func (s *BatchSink) Flush(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flushLocked()
	return nil
}

// Close implements EventSink.
func (s *BatchSink) Close() error {
	return s.Flush(context.Background())
}
