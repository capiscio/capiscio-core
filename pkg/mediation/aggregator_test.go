// Copyright (c) CapiscIO, Inc.
// Licensed under the MIT License.

package mediation

import (
	"context"
	"testing"
	"time"
)

func TestMemoryAggregator_Ingest(t *testing.T) {
	agg := NewMemoryAggregator(100)

	events := []*Event{
		NewEvent(EventAuthorityGranted, EmitterInfo{ComponentID: "test"}),
		NewEvent(EventToolPermitted, EmitterInfo{ComponentID: "test"}),
	}

	n, err := agg.Ingest(context.Background(), events)
	if err != nil {
		t.Fatalf("Ingest failed: %v", err)
	}
	if n != 2 {
		t.Errorf("Ingest returned %d, want 2", n)
	}

	stats := agg.Stats()
	if stats.EventsReceived != 2 {
		t.Errorf("EventsReceived = %d, want 2", stats.EventsReceived)
	}
	if stats.EventsStored != 2 {
		t.Errorf("EventsStored = %d, want 2", stats.EventsStored)
	}
}

func TestMemoryAggregator_Capacity(t *testing.T) {
	agg := NewMemoryAggregator(3)

	// Ingest more events than capacity
	for i := 0; i < 5; i++ {
		event := NewEvent(EventAuthorityGranted, EmitterInfo{ComponentID: "test"})
		event.WithPayload("index", i)
		_, err := agg.Ingest(context.Background(), []*Event{event})
		if err != nil {
			t.Fatalf("Ingest failed: %v", err)
		}
	}

	stats := agg.Stats()
	if stats.EventsStored != 3 {
		t.Errorf("EventsStored = %d, want 3 (capacity limit)", stats.EventsStored)
	}
	if stats.EventsDropped != 2 {
		t.Errorf("EventsDropped = %d, want 2", stats.EventsDropped)
	}
}

func TestMemoryAggregator_Query(t *testing.T) {
	agg := NewMemoryAggregator(100)

	// Create events with different trace IDs
	e1 := NewEvent(EventAuthorityGranted, EmitterInfo{})
	e1.WithContext("trace-1", "", "")
	e1.WithPayload("subject_did", "did:web:agent1")

	e2 := NewEvent(EventToolDenied, EmitterInfo{})
	e2.WithContext("trace-2", "", "")
	e2.WithPayload("subject_did", "did:web:agent2")

	e3 := NewEvent(EventAuthorityGranted, EmitterInfo{})
	e3.WithContext("trace-1", "", "")
	e3.WithPayload("subject_did", "did:web:agent1")

	agg.Ingest(context.Background(), []*Event{e1, e2, e3})

	// Query by trace ID
	results, err := agg.Query(context.Background(), EventQuery{TraceID: "trace-1"})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("Query(trace-1) returned %d events, want 2", len(results))
	}

	// Query by event type
	results, err = agg.Query(context.Background(), EventQuery{
		EventTypes: []EventType{EventToolDenied},
	})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("Query(EventToolDenied) returned %d events, want 1", len(results))
	}

	// Query by subject DID
	results, err = agg.Query(context.Background(), EventQuery{SubjectDID: "did:web:agent1"})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("Query(agent1) returned %d events, want 2", len(results))
	}
}

func TestMemoryAggregator_Subscribe(t *testing.T) {
	agg := NewMemoryAggregator(100)

	// Subscribe to tool events only
	ch, cancel := agg.Subscribe(EventFilter{
		EventTypes: []EventType{EventToolPermitted, EventToolDenied},
	})
	defer cancel()

	// Ingest events
	events := []*Event{
		NewEvent(EventAuthorityGranted, EmitterInfo{}), // Should NOT be received
		NewEvent(EventToolPermitted, EmitterInfo{}),    // Should be received
		NewEvent(EventToolDenied, EmitterInfo{}),       // Should be received
	}
	agg.Ingest(context.Background(), events)

	// Collect received events
	var received []*Event
	timeout := time.After(100 * time.Millisecond)
loop:
	for {
		select {
		case event := <-ch:
			received = append(received, event)
		case <-timeout:
			break loop
		}
	}

	if len(received) != 2 {
		t.Errorf("received %d events, want 2 (tool events only)", len(received))
	}
}

func TestMemoryAggregator_Stats(t *testing.T) {
	agg := NewMemoryAggregator(100)

	// Initial stats
	stats := agg.Stats()
	if stats.EventsReceived != 0 {
		t.Errorf("initial EventsReceived = %d, want 0", stats.EventsReceived)
	}

	// After ingesting
	agg.Ingest(context.Background(), []*Event{
		NewEvent(EventAuthorityGranted, EmitterInfo{}),
	})

	stats = agg.Stats()
	if stats.EventsReceived != 1 {
		t.Errorf("EventsReceived = %d, want 1", stats.EventsReceived)
	}

	// Subscribe and check count
	ch, cancel := agg.Subscribe(EventFilter{})
	stats = agg.Stats()
	if stats.SubscriberCount != 1 {
		t.Errorf("SubscriberCount = %d, want 1", stats.SubscriberCount)
	}
	cancel()
	// Drain channel after cancel
	for range ch {
	}

	stats = agg.Stats()
	if stats.SubscriberCount != 0 {
		t.Errorf("after cancel SubscriberCount = %d, want 0", stats.SubscriberCount)
	}
}

func TestEventQuery_TimeRange(t *testing.T) {
	agg := NewMemoryAggregator(100)

	// Create events with specific timestamps
	e1 := NewEvent(EventAuthorityGranted, EmitterInfo{})
	e1.Timestamp = "2026-05-27T10:00:00.000Z"

	e2 := NewEvent(EventAuthorityGranted, EmitterInfo{})
	e2.Timestamp = "2026-05-27T12:00:00.000Z"

	e3 := NewEvent(EventAuthorityGranted, EmitterInfo{})
	e3.Timestamp = "2026-05-27T14:00:00.000Z"

	agg.Ingest(context.Background(), []*Event{e1, e2, e3})

	// Query with time range
	startTime, _ := time.Parse("2006-01-02T15:04:05.000Z", "2026-05-27T11:00:00.000Z")
	endTime, _ := time.Parse("2006-01-02T15:04:05.000Z", "2026-05-27T13:00:00.000Z")

	results, err := agg.Query(context.Background(), EventQuery{
		StartTime: startTime,
		EndTime:   endTime,
	})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("Query with time range returned %d events, want 1", len(results))
	}
}
