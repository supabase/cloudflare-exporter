package converge

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func cfg(threshold int) Config {
	c := DefaultConfig()
	c.Threshold = threshold
	return c
}

func obs(name string, value uint64, bucket time.Time) Observation {
	return Observation{Key: NewKey(name), Value: value, Bucket: bucket}
}

func TestIngestStabilizes(t *testing.T) {
	e := NewEngine(cfg(3))

	assert.Empty(t, e.Ingest([]Observation{obs("req", 100, t0)}))
	assert.Empty(t, e.Ingest([]Observation{obs("req", 100, t0)}))

	samples := e.Ingest([]Observation{obs("req", 100, t0)})
	require.Len(t, samples, 1)
	assert.Equal(t, "req", samples[0].Key.Name)
	assert.Equal(t, uint64(100), samples[0].Value)
	assert.Equal(t, t0, samples[0].Timestamp)
}

func TestIngestThresholdOne(t *testing.T) {
	e := NewEngine(cfg(1))

	samples := e.Ingest([]Observation{obs("req", 50, t0)})
	require.Len(t, samples, 1)
	assert.Equal(t, uint64(50), samples[0].Value)
}

func TestIngestValueChange(t *testing.T) {
	e := NewEngine(cfg(1))

	samples := e.Ingest([]Observation{obs("req", 100, t0)})
	require.Len(t, samples, 1)

	// Same value, already synced, no new sample.
	assert.Empty(t, e.Ingest([]Observation{obs("req", 100, t0)}))

	// New value triggers new sample.
	samples = e.Ingest([]Observation{obs("req", 200, t0)})
	require.Len(t, samples, 1)
	assert.Equal(t, uint64(200), samples[0].Value)
}

func TestIngestMultipleBuckets(t *testing.T) {
	e := NewEngine(cfg(1))
	t1 := t0.Add(time.Minute)

	samples := e.Ingest([]Observation{
		obs("req", 100, t0),
		obs("req", 200, t1),
	})
	require.Len(t, samples, 2)
	assert.Equal(t, 2, e.Stats().OpenWindows)
}

func TestIngestMultipleSeries(t *testing.T) {
	e := NewEngine(cfg(1))

	samples := e.Ingest([]Observation{
		obs("req", 100, t0),
		obs("bytes", 9000, t0),
	})
	require.Len(t, samples, 2)
	assert.Equal(t, 1, e.Stats().OpenWindows)
	assert.Equal(t, 2, e.Stats().TrackerCount)
}

func TestExpireTTL(t *testing.T) {
	c := cfg(3) // won't stabilize with just 1 observation
	c.WindowTTL = 5 * time.Minute
	e := NewEngine(c)

	e.Ingest([]Observation{obs("req", 100, t0)})
	assert.Equal(t, 1, e.Stats().OpenWindows)

	// Not yet expired (bucket + 4m < bucket + TTL).
	assert.Empty(t, e.Expire(t0.Add(4*time.Minute)))
	assert.Equal(t, 1, e.Stats().OpenWindows)

	// TTL exceeded (bucket + 6m > bucket + 5m TTL).
	samples := e.Expire(t0.Add(6 * time.Minute))
	require.Len(t, samples, 1)
	assert.Equal(t, uint64(100), samples[0].Value)
	assert.Equal(t, 0, e.Stats().OpenWindows)
}

func TestExpireTTLNoPushIfAlreadyPushed(t *testing.T) {
	c := cfg(1)
	c.WindowTTL = 5 * time.Minute
	e := NewEngine(c)

	// Threshold=1, so this stabilizes and pushes immediately.
	samples := e.Ingest([]Observation{obs("req", 100, t0)})
	require.Len(t, samples, 1)

	// TTL expires: window was already pushed, no duplicate.
	expired := e.Expire(t0.Add(6 * time.Minute))
	assert.Empty(t, expired)
	assert.Equal(t, 0, e.Stats().OpenWindows)
}

func TestExpireTTLCleansPushedWindows(t *testing.T) {
	c := cfg(1)
	c.WindowTTL = 5 * time.Minute
	e := NewEngine(c)

	// Threshold=1 so it pushes immediately.
	e.Ingest([]Observation{obs("req", 100, t0)})

	// Window stays open before TTL, accepting further observations.
	e.Expire(t0.Add(3 * time.Minute))
	assert.Equal(t, 1, e.Stats().OpenWindows)

	// TTL exceeded: window removed, no duplicate push.
	expired := e.Expire(t0.Add(6 * time.Minute))
	assert.Empty(t, expired)
	assert.Equal(t, 0, e.Stats().OpenWindows)
}

func TestFlush(t *testing.T) {
	e := NewEngine(cfg(3))

	e.Ingest([]Observation{
		obs("req", 100, t0),
		obs("bytes", 9000, t0.Add(time.Minute)),
	})

	samples := e.Flush()
	require.Len(t, samples, 2)
	assert.Equal(t, 0, e.Stats().OpenWindows)
}

func TestStatsEmpty(t *testing.T) {
	e := NewEngine(cfg(3))
	s := e.Stats()
	assert.Equal(t, 0, s.OpenWindows)
	assert.Equal(t, 0, s.TrackerCount)
}

func TestConvergenceSequence(t *testing.T) {
	// Simulates a CF bucket aggregating over several polls.
	e := NewEngine(cfg(3))
	bucket := t0

	// Values increasing as CF aggregates.
	assert.Empty(t, e.Ingest([]Observation{obs("req", 100, bucket)}))
	assert.Empty(t, e.Ingest([]Observation{obs("req", 150, bucket)}))
	assert.Empty(t, e.Ingest([]Observation{obs("req", 180, bucket)}))
	assert.Empty(t, e.Ingest([]Observation{obs("req", 200, bucket)}))

	// Value settles.
	assert.Empty(t, e.Ingest([]Observation{obs("req", 200, bucket)}))

	samples := e.Ingest([]Observation{obs("req", 200, bucket)})
	require.Len(t, samples, 1)
	assert.Equal(t, uint64(200), samples[0].Value)

	// Late data bumps the value.
	samples = e.Ingest([]Observation{obs("req", 210, bucket)})
	assert.Empty(t, samples) // run reset, not stable yet

	// Re-stabilizes.
	e.Ingest([]Observation{obs("req", 210, bucket)})
	samples = e.Ingest([]Observation{obs("req", 210, bucket)})
	require.Len(t, samples, 1)
	assert.Equal(t, uint64(210), samples[0].Value)
}
