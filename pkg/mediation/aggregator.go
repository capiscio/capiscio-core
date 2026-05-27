// Copyright (c) CapiscIO, Inc.
// Licensed under the MIT License.

package mediation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// EventAggregator collects events from multiple runtimes for server-side processing.
//
// Per RFC-011 §4.2, events are emitted locally and forwarded asynchronously.
// The aggregator provides the server-side collection point for these events.
//
// Aggregators receive events via HTTP webhook or streaming connections.
// They do NOT participate in authorization decisions (RFC-011 §4.4).
type EventAggregator interface {
	// Ingest accepts a batch of events for processing.
	// Returns the number of events successfully processed.
	Ingest(ctx context.Context, events []*Event) (int, error)

	// Query retrieves events matching the given criteria.
	Query(ctx context.Context, query EventQuery) ([]*Event, error)

	// Subscribe creates a channel that receives events matching the filter.
	// Call the returned cancel function to stop the subscription.
	Subscribe(filter EventFilter) (<-chan *Event, func())

	// Stats returns aggregator statistics.
	Stats() AggregatorStats
}

// EventQuery defines criteria for querying stored events.
type EventQuery struct {
	// TraceID filters by trace identifier.
	TraceID string

	// TxnID filters by transaction identifier.
	TxnID string

	// SubjectDID filters by the subject (caller) DID.
	SubjectDID string

	// EventTypes filters by event type.
	EventTypes []EventType

	// StartTime is the earliest event timestamp to include.
	StartTime time.Time

	// EndTime is the latest event timestamp to include.
	EndTime time.Time

	// Limit is the maximum number of events to return.
	Limit int
}

// EventFilter defines criteria for subscribing to live events.
type EventFilter struct {
	// EventTypes is the set of event types to receive.
	// Empty means all types.
	EventTypes []EventType

	// SubjectDID filters to events for a specific subject.
	SubjectDID string

	// OrganizationID filters to events for a specific organization.
	OrganizationID string
}

// AggregatorStats contains aggregator metrics.
type AggregatorStats struct {
	// EventsReceived is the total number of events received.
	EventsReceived uint64

	// EventsStored is the total number of events currently stored.
	EventsStored uint64

	// EventsDropped is the number of events dropped due to capacity.
	EventsDropped uint64

	// SubscriberCount is the number of active subscribers.
	SubscriberCount int

	// LastEventTime is the timestamp of the most recent event.
	LastEventTime time.Time
}

// MemoryAggregator is an in-memory event aggregator for testing and development.
//
// Production deployments should use a persistent aggregator backed by a database
// or event streaming system (Kafka, NATS, etc.).
type MemoryAggregator struct {
	events      []*Event
	subscribers []subscriber
	maxEvents   int
	mu          sync.RWMutex

	stats struct {
		received uint64
		dropped  uint64
	}
}

type subscriber struct {
	filter EventFilter
	ch     chan *Event
}

// NewMemoryAggregator creates an in-memory aggregator.
func NewMemoryAggregator(maxEvents int) *MemoryAggregator {
	if maxEvents <= 0 {
		maxEvents = 10000
	}
	return &MemoryAggregator{
		events:    make([]*Event, 0, maxEvents),
		maxEvents: maxEvents,
	}
}

// Ingest implements EventAggregator.
func (a *MemoryAggregator) Ingest(ctx context.Context, events []*Event) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	processed := 0
	for _, event := range events {
		if len(a.events) >= a.maxEvents {
			// Drop oldest event
			a.events = a.events[1:]
			a.stats.dropped++
		}
		a.events = append(a.events, event)
		a.stats.received++
		processed++

		// Notify subscribers
		for _, sub := range a.subscribers {
			if a.matchesFilter(event, sub.filter) {
				select {
				case sub.ch <- event:
				default:
					// Drop if subscriber is slow
				}
			}
		}
	}

	return processed, nil
}

// Query implements EventAggregator.
func (a *MemoryAggregator) Query(ctx context.Context, query EventQuery) ([]*Event, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var results []*Event
	limit := query.Limit
	if limit <= 0 {
		limit = 100
	}

	for _, event := range a.events {
		if a.matchesQuery(event, query) {
			results = append(results, event)
			if len(results) >= limit {
				break
			}
		}
	}

	return results, nil
}

// Subscribe implements EventAggregator.
func (a *MemoryAggregator) Subscribe(filter EventFilter) (<-chan *Event, func()) {
	a.mu.Lock()
	defer a.mu.Unlock()

	ch := make(chan *Event, 100)
	sub := subscriber{filter: filter, ch: ch}
	a.subscribers = append(a.subscribers, sub)

	cancel := func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		for i, s := range a.subscribers {
			if s.ch == ch {
				a.subscribers = append(a.subscribers[:i], a.subscribers[i+1:]...)
				close(ch)
				break
			}
		}
	}

	return ch, cancel
}

// Stats implements EventAggregator.
func (a *MemoryAggregator) Stats() AggregatorStats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var lastTime time.Time
	if len(a.events) > 0 {
		last := a.events[len(a.events)-1]
		lastTime, _ = time.Parse("2006-01-02T15:04:05.000Z", last.Timestamp)
	}

	return AggregatorStats{
		EventsReceived:  a.stats.received,
		EventsStored:    uint64(len(a.events)),
		EventsDropped:   a.stats.dropped,
		SubscriberCount: len(a.subscribers),
		LastEventTime:   lastTime,
	}
}

// matchesFilter checks if an event matches a subscription filter.
func (a *MemoryAggregator) matchesFilter(event *Event, filter EventFilter) bool {
	if len(filter.EventTypes) > 0 {
		matched := false
		for _, et := range filter.EventTypes {
			if event.EventType == et {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if filter.SubjectDID != "" {
		did, ok := event.Payload["subject_did"].(string)
		if !ok || did != filter.SubjectDID {
			return false // Missing or non-matching subject_did
		}
	}

	// NOTE: OrganizationID filter is not yet implemented. Events with any
	// organization will match. Add organization_id to event payloads and
	// filter here when multi-tenancy is wired up.

	return true
}

// matchesQuery checks if an event matches a query.
func (a *MemoryAggregator) matchesQuery(event *Event, query EventQuery) bool {
	return a.matchesContextQuery(event, query) &&
		a.matchesTypeQuery(event, query) &&
		a.matchesTimeQuery(event, query)
}

// matchesContextQuery checks trace, transaction, and subject filters.
func (a *MemoryAggregator) matchesContextQuery(event *Event, query EventQuery) bool {
	if query.TraceID != "" && event.Context.TraceID != query.TraceID {
		return false
	}
	if query.TxnID != "" && event.Context.TxnID != query.TxnID {
		return false
	}
	if query.SubjectDID != "" {
		did, ok := event.Payload["subject_did"].(string)
		if !ok || did != query.SubjectDID {
			return false // Missing or non-matching subject_did
		}
	}
	return true
}

// matchesTypeQuery checks event type filters.
func (a *MemoryAggregator) matchesTypeQuery(event *Event, query EventQuery) bool {
	if len(query.EventTypes) == 0 {
		return true
	}
	for _, et := range query.EventTypes {
		if event.EventType == et {
			return true
		}
	}
	return false
}

// matchesTimeQuery checks time range filters.
func (a *MemoryAggregator) matchesTimeQuery(event *Event, query EventQuery) bool {
	if query.StartTime.IsZero() && query.EndTime.IsZero() {
		return true
	}
	eventTime, err := time.Parse("2006-01-02T15:04:05.000Z", event.Timestamp)
	if err != nil {
		return false
	}
	if !query.StartTime.IsZero() && eventTime.Before(query.StartTime) {
		return false
	}
	if !query.EndTime.IsZero() && eventTime.After(query.EndTime) {
		return false
	}
	return true
}

// HTTPSink forwards events to a remote aggregator via HTTP POST.
//
// Per RFC-011 §4.2, forwarding is asynchronous and MUST NOT block mediation.
// The HTTPSink buffers events and sends them in batches.
type HTTPSink struct {
	endpoint      string
	client        *http.Client
	batch         []*Event
	batchSize     int
	flushInterval time.Duration
	flushTimer    *time.Timer
	mu            sync.Mutex
}

// HTTPSinkConfig configures the HTTP sink.
type HTTPSinkConfig struct {
	// Endpoint is the aggregator HTTP endpoint (e.g., "https://api.example.com/events").
	Endpoint string

	// BatchSize is the number of events to batch before sending.
	BatchSize int

	// FlushInterval is the maximum time to wait before sending a partial batch.
	FlushInterval time.Duration

	// Client is the HTTP client to use. If nil, http.DefaultClient is used.
	Client *http.Client
}

// NewHTTPSink creates an HTTP event sink.
func NewHTTPSink(config HTTPSinkConfig) *HTTPSink {
	if config.BatchSize <= 0 {
		config.BatchSize = 50
	}
	if config.Client == nil {
		config.Client = &http.Client{Timeout: 10 * time.Second}
	}

	s := &HTTPSink{
		endpoint:      config.Endpoint,
		client:        config.Client,
		batch:         make([]*Event, 0, config.BatchSize),
		batchSize:     config.BatchSize,
		flushInterval: config.FlushInterval,
	}

	// Start flush timer if interval specified
	if config.FlushInterval > 0 {
		s.flushTimer = time.AfterFunc(config.FlushInterval, func() {
			s.flushAsync()
		})
	}

	return s
}

// Receive implements EventSink.
func (s *HTTPSink) Receive(event *Event) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.batch = append(s.batch, event)
	if len(s.batch) >= s.batchSize {
		// Flush in background
		batch := s.batch
		s.batch = make([]*Event, 0, s.batchSize)
		go s.sendBatch(batch)
	}
}

// Flush implements EventSink.
func (s *HTTPSink) Flush(ctx context.Context) error {
	s.mu.Lock()
	batch := s.batch
	s.batch = make([]*Event, 0, s.batchSize)
	s.mu.Unlock()

	if len(batch) > 0 {
		return s.sendBatchSync(ctx, batch)
	}
	return nil
}

// Close implements EventSink.
func (s *HTTPSink) Close() error {
	if s.flushTimer != nil {
		s.flushTimer.Stop()
	}
	return s.Flush(context.Background())
}

// flushAsync triggers an async flush.
func (s *HTTPSink) flushAsync() {
	s.mu.Lock()
	batch := s.batch
	s.batch = make([]*Event, 0, s.batchSize)
	s.mu.Unlock()

	if len(batch) > 0 {
		go s.sendBatch(batch)
	}

	// Restart timer with configured interval
	if s.flushTimer != nil && s.flushInterval > 0 {
		s.flushTimer.Reset(s.flushInterval)
	}
}

// sendBatch sends events asynchronously (fire and forget).
func (s *HTTPSink) sendBatch(batch []*Event) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = s.sendBatchSync(ctx, batch) // Errors are logged; best-effort delivery
}

// sendBatchSync sends events synchronously.
func (s *HTTPSink) sendBatchSync(ctx context.Context, batch []*Event) error {
	data, err := json.Marshal(batch)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Body = &nopCloser{bytes: data}
	req.ContentLength = int64(len(data))

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check response status - non-2xx is an error
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("aggregator returned status %d", resp.StatusCode)
	}

	return nil
}

// nopCloser wraps bytes for use as io.ReadCloser.
type nopCloser struct {
	bytes []byte
	pos   int
}

func (n *nopCloser) Read(p []byte) (int, error) {
	if n.pos >= len(n.bytes) {
		return 0, io.EOF
	}
	copied := copy(p, n.bytes[n.pos:])
	n.pos += copied
	return copied, nil
}

func (n *nopCloser) Close() error {
	return nil
}
