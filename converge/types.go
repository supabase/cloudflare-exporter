package converge

import (
	"context"
	"time"
)

// Observation is a single data point from an upstream source. The Key is a
// pre-serialized Prometheus metric identity (e.g. metric_name{k="v"}) that
// serves as both the tracker map key and the downstream wire format.
type Observation struct {
	Key    string
	Value  uint64
	Bucket time.Time // source time bucket this observation belongs to
}

// Sample is a push-ready value. Produced by the engine when a tracker
// determines a value is ready to sync.
type Sample struct {
	Key       string
	Value     uint64
	Timestamp time.Time
}

// Fetcher retrieves observations for a time range. Implementations handle
// authentication, query construction, and response flattening.
type Fetcher interface {
	Fetch(ctx context.Context, start, end time.Time) ([]Observation, error)
}

// Sink receives push-ready samples. Implementations handle serialization,
// batching, retries, and transport.
type Sink interface {
	Push(ctx context.Context, samples []Sample) error
}

// Stats provides a snapshot of engine state for monitoring.
type Stats struct {
	OpenWindows  int
	TrackerCount int
}
