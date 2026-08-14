package converge

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Label is a name/value pair attached to a metric series.
type Label struct {
	Name  string
	Value string
}

// Key identifies a metric series: a metric name plus an ordered set of labels.
// It carries structured data through the pipeline so producers (Fetcher) and
// consumers (Sink) never need to serialize/parse a wire format.
//
// The engine needs a comparable map key, so Key caches a canonical string form
// built on first call to String(). Two Keys with the same Name and Labels in
// the same order produce the same string.
type Key struct {
	Name   string
	Labels []Label
	str    string // cached canonical form
}

// String returns the canonical Prometheus-style representation:
// name{k1="v1",k2="v2"}. Labels are sorted by name to ensure that
// two Keys with the same labels in different order produce the same
// string, which is critical for counter chain identity.
func (k *Key) String() string {
	if k.str != "" {
		return k.str
	}
	if len(k.Labels) == 0 {
		k.str = k.Name
		return k.str
	}
	sorted := make([]Label, len(k.Labels))
	copy(sorted, k.Labels)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Name < sorted[j].Name
	})
	var b strings.Builder
	b.WriteString(k.Name)
	b.WriteByte('{')
	repl := strings.NewReplacer("\\", "\\\\", "\n", "\\n", "\"", "\\\"")
	for i, l := range sorted {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `%s="%s"`, l.Name, repl.Replace(l.Value))
	}
	b.WriteByte('}')
	k.str = b.String()
	return k.str
}

// NewKey creates a Key with the given name and label pairs. Labels are
// provided as alternating name, value strings: NewKey("http_requests", "zone", "foo", "status", "200").
func NewKey(name string, labelPairs ...string) Key {
	var labels []Label
	for i := 0; i+1 < len(labelPairs); i += 2 {
		labels = append(labels, Label{Name: labelPairs[i], Value: labelPairs[i+1]})
	}
	return Key{Name: name, Labels: labels}
}

// Observation is a single data point from an upstream source.
type Observation struct {
	Key    Key
	Value  uint64
	Bucket time.Time // source time bucket this observation belongs to
}

// Sample is a push-ready value. Produced by the engine when a tracker
// determines a value is ready to sync.
type Sample struct {
	Key       Key
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

// Pinger is an optional interface a Sink can implement to support pre-flight
// validation. Run checks for this before entering the main loop.
type Pinger interface {
	Ping(ctx context.Context) error
}

// ChainSeeder is an optional interface a Sink can implement to provide
// last known counter values for seeding chain bases on startup. This
// prevents counter resets when the exporter restarts.
type ChainSeeder interface {
	LastValues(ctx context.Context, selector string, lookback time.Duration) (map[string]Sample, error)
}

// Stats provides a snapshot of engine state for monitoring.
type Stats struct {
	OpenWindows          int
	TrackerCount         int
	ExpireCount          uint64
	PostStabilizeUpdates uint64
	GaugeDownRevisions   uint64 // CF revised a gauge value downward
	CounterRegressions   uint64 // computed counter was lower than previous emission
	OldestBucket         time.Time
	NewestBucket         time.Time
}

// TickStats captures per-tick activity for external metrics collection.
// Passed to Config.OnTick after each runner tick.
type TickStats struct {
	// Engine state (gauges).
	OpenWindows  int
	TrackerCount int

	// Per-tick deltas (counters). These are the counts from this tick only,
	// not cumulative.
	LiveObservations     int    // observations from the live fetch
	BackfillObservations int    // observations from backfill fetches
	IngestSamples        int    // samples emitted by Ingest
	KeepAliveSamples     int    // samples re-pushed to keep idle series from going stale
	ExpireSamples        int    // samples emitted by Expire
	ExpireFlushes        uint64 // windows force-flushed (never stabilized)
	SnapshotSamples      int    // samples emitted by post-backfill Snapshot
	PostStabilizeUpdates uint64 // values that changed after stabilization
	GaugeDownRevisions   uint64 // CF revised a gauge downward this tick
	CounterRegressions   uint64 // counter went below previous emission this tick
	PushErrors           int    // failed Push calls this tick
}

func (s Stats) String() string {
	return fmt.Sprintf("windows=%d trackers=%d expires=%d rewrites=%d",
		s.OpenWindows, s.TrackerCount, s.ExpireCount, s.PostStabilizeUpdates)
}
