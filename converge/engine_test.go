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
	c.Lookback = 5 * time.Minute
	e := NewEngine(c)

	e.Ingest([]Observation{obs("req", 100, t0)})
	assert.Equal(t, 1, e.Stats().OpenWindows)

	// Not yet expired (bucket + 4m < bucket + TTL).
	assert.Empty(t, e.Expire(t0.Add(4*time.Minute), true))
	assert.Equal(t, 1, e.Stats().OpenWindows)

	// TTL exceeded (bucket + 6m > bucket + 5m TTL).
	samples := e.Expire(t0.Add(6*time.Minute), true)
	require.Len(t, samples, 1)
	assert.Equal(t, uint64(100), samples[0].Value)
	assert.Equal(t, 0, e.Stats().OpenWindows)
}

func TestExpireTTLNoPushIfAlreadyPushed(t *testing.T) {
	c := cfg(1)
	c.Lookback = 5 * time.Minute
	e := NewEngine(c)

	// Threshold=1, so this stabilizes and pushes immediately.
	samples := e.Ingest([]Observation{obs("req", 100, t0)})
	require.Len(t, samples, 1)

	// TTL expires: window was already pushed, no duplicate.
	expired := e.Expire(t0.Add(6*time.Minute), true)
	assert.Empty(t, expired)
	assert.Equal(t, 0, e.Stats().OpenWindows)
}

func TestExpireTTLCleansPushedWindows(t *testing.T) {
	c := cfg(1)
	c.Lookback = 5 * time.Minute
	e := NewEngine(c)

	// Threshold=1 so it pushes immediately.
	e.Ingest([]Observation{obs("req", 100, t0)})

	// Window stays open before TTL, accepting further observations.
	e.Expire(t0.Add(3*time.Minute), true)
	assert.Equal(t, 1, e.Stats().OpenWindows)

	// TTL exceeded: window removed, no duplicate push.
	expired := e.Expire(t0.Add(6*time.Minute), true)
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

// TestExpireDropsUnstabilizedSeriesWhenWindowPartiallyPushed demonstrates that
// when one series in a bucket stabilizes (setting the per-window pushed flag)
// but a sibling series never stabilizes, the unstabilized series is silently
// dropped on TTL expiry instead of being force-flushed.
func TestExpireDropsUnstabilizedSeriesWhenWindowPartiallyPushed(t *testing.T) {
	c := cfg(3)
	c.Lookback = 5 * time.Minute
	e := NewEngine(c)

	// "req" stabilizes after 3 identical observations (threshold=3).
	e.Ingest([]Observation{
		obs("req", 100, t0),
		obs("bytes", 5000, t0),
	})
	e.Ingest([]Observation{
		obs("req", 100, t0),
		obs("bytes", 6000, t0), // value changed, run resets
	})
	samples := e.Ingest([]Observation{
		obs("req", 100, t0),
		obs("bytes", 7000, t0), // value changed again, run resets
	})

	// "req" hit threshold=3 with value 100 and was pushed.
	require.Len(t, samples, 1)
	assert.Equal(t, "req", samples[0].Key.Name)

	// "bytes" never stabilized (value changed every observation).
	// The window's pushed flag is true because "req" was pushed.

	// Now TTL expires. "bytes" should be force-flushed with its last observed
	// value (7000), but the current code skips the flush because w.pushed is
	// already true.
	expired := e.Expire(t0.Add(6*time.Minute), true)

	// This assertion captures the expected correct behavior: "bytes" should
	// appear in the expired samples with its last observed value.
	require.Len(t, expired, 1, "unstabilized series must be force-flushed on TTL expiry")
	assert.Equal(t, "bytes", expired[0].Key.Name)
	assert.Equal(t, uint64(7000), expired[0].Value)
	assert.Equal(t, 0, e.Stats().OpenWindows)
}

func TestIngestCounterAccumulation(t *testing.T) {
	// Two buckets for the same series: sample values are cumulative counters.
	e := NewEngine(cfg(1))
	t1 := t0.Add(time.Minute)

	samples := e.Ingest([]Observation{
		obs("req", 100, t0),
		obs("req", 200, t1),
	})

	require.Len(t, samples, 2)
	assert.Equal(t, t0, samples[0].Timestamp)
	assert.Equal(t, uint64(100), samples[0].Value) // counter at t0
	assert.Equal(t, t1, samples[1].Timestamp)
	assert.Equal(t, uint64(300), samples[1].Value) // counter at t1: 100+200
}

func TestIngestCounterCascade(t *testing.T) {
	// An earlier bucket re-converging cascades corrected counter values
	// to later buckets.
	e := NewEngine(cfg(3))
	t1 := t0.Add(time.Minute)

	// t0 stabilizes at 100, t1 stabilizes at 200.
	e.Ingest([]Observation{obs("req", 100, t0), obs("req", 200, t1)})
	e.Ingest([]Observation{obs("req", 100, t0), obs("req", 200, t1)})
	samples := e.Ingest([]Observation{obs("req", 100, t0), obs("req", 200, t1)})

	require.Len(t, samples, 2)
	assert.Equal(t, uint64(100), samples[0].Value) // t0 counter
	assert.Equal(t, uint64(300), samples[1].Value) // t1 counter: 100+200

	// t0 re-converges from 100 → 150. This cascades to t1.
	e.Ingest([]Observation{obs("req", 150, t0)})
	e.Ingest([]Observation{obs("req", 150, t0)})
	samples = e.Ingest([]Observation{obs("req", 150, t0)})

	require.Len(t, samples, 2)
	assert.Equal(t, t0, samples[0].Timestamp)
	assert.Equal(t, uint64(150), samples[0].Value) // t0: 150
	assert.Equal(t, t1, samples[1].Timestamp)
	assert.Equal(t, uint64(350), samples[1].Value) // t1: 150+200
}

func TestExpireMultipleWindowsEvictInOrder(t *testing.T) {
	// Two windows for the same series expire simultaneously. The chain
	// must evict oldest-first; nondeterministic map iteration would cause
	// the newer bucket's Evict to fail silently.
	c := cfg(1)
	c.Lookback = 5 * time.Minute
	e := NewEngine(c)
	t1 := t0.Add(time.Minute)
	t2 := t0.Add(2 * time.Minute)

	e.Ingest([]Observation{obs("req", 100, t0)}) // counter: 100
	e.Ingest([]Observation{obs("req", 200, t1)}) // counter: 300
	e.Ingest([]Observation{obs("req", 300, t2)}) // counter: 600

	// Expire all three at once (now = t0 + 8m, all are > 5m old).
	expired := e.Expire(t0.Add(8*time.Minute), true)
	assert.Empty(t, expired) // all were already pushed

	// All three should have been evicted from the chain. The base should
	// hold the full sum. Verify by adding a new bucket.
	t3 := t0.Add(10 * time.Minute)
	samples := e.Ingest([]Observation{obs("req", 50, t3)})
	require.Len(t, samples, 1)
	assert.Equal(t, uint64(650), samples[0].Value) // base(600) + 50
}

func TestExpireCounterEviction(t *testing.T) {
	// After a bucket is expired, its value is folded into the chain base
	// and subsequent buckets still produce correct counters.
	c := cfg(1)
	c.Lookback = 5 * time.Minute
	e := NewEngine(c)
	t1 := t0.Add(time.Minute)
	t2 := t0.Add(10 * time.Minute)

	e.Ingest([]Observation{obs("req", 100, t0)}) // counter: 100
	e.Ingest([]Observation{obs("req", 200, t1)}) // counter: 300

	// Expire t0 (age 6m > TTL 5m). chain.Set(t0, 100) is a no-op (unchanged),
	// then evict folds 100 into base.
	expired := e.Expire(t0.Add(6*time.Minute), true)
	assert.Empty(t, expired) // no new emissions, value unchanged

	// t1 also expires at 6m30s.
	expired = e.Expire(t0.Add(6*time.Minute+30*time.Second), true)
	assert.Empty(t, expired) // same, already pushed

	// New bucket after both evictions should accumulate from base.
	samples := e.Ingest([]Observation{obs("req", 400, t2)})
	require.Len(t, samples, 1)
	assert.Equal(t, uint64(700), samples[0].Value) // base(300) + 400
}

func TestExpireCounterCapturesPostStabilizationDrift(t *testing.T) {
	// A tracker stabilizes at 100 but then sees 110, 115 without
	// re-stabilizing. On expire, the engine feeds the latest value (115)
	// to the chain.
	c := cfg(3)
	c.Lookback = 5 * time.Minute
	e := NewEngine(c)

	// Stabilize at 100.
	e.Ingest([]Observation{obs("req", 100, t0)})
	e.Ingest([]Observation{obs("req", 100, t0)})
	samples := e.Ingest([]Observation{obs("req", 100, t0)})
	require.Len(t, samples, 1)
	assert.Equal(t, uint64(100), samples[0].Value)

	// Value drifts up without re-stabilizing (run resets each time).
	e.Ingest([]Observation{obs("req", 110, t0)})
	e.Ingest([]Observation{obs("req", 115, t0)})

	// On expire, the engine feeds currentValue (115) to the chain.
	expired := e.Expire(t0.Add(6*time.Minute), true)
	require.Len(t, expired, 1)
	assert.Equal(t, uint64(115), expired[0].Value) // updated counter
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

// TestExpireBoundaryDoubleCount demonstrates a bug when WindowTTL == Lookback.
// A bucket at exactly the boundary is expired (gauge folded into base), then
// re-fetched on the next tick. The re-inserted entry gets counter =
// base (which already includes the gauge) + gauge again = double-counted.
// The counter should never go backwards or double-count.
func TestExpireBoundaryDoubleCount(t *testing.T) {
	c := cfg(1)
	c.Lookback = 5 * time.Minute

	e := NewEngine(c)

	// Build up 3 buckets with gauge=100 each.
	t1 := t0
	t2 := t0.Add(1 * time.Minute)
	t3 := t0.Add(2 * time.Minute)

	samples := e.Ingest([]Observation{obs("req", 100, t1)})
	require.Len(t, samples, 1)
	assert.Equal(t, uint64(100), samples[0].Value) // counter: 0+100=100

	samples = e.Ingest([]Observation{obs("req", 100, t2)})
	require.Len(t, samples, 1)
	assert.Equal(t, uint64(200), samples[0].Value) // counter: 100+100=200

	samples = e.Ingest([]Observation{obs("req", 100, t3)})
	require.Len(t, samples, 1)
	assert.Equal(t, uint64(300), samples[0].Value) // counter: 200+100=300

	// Expire t1 (exactly at boundary: now - t1 == Lookback).
	// With >= this expires; with > it wouldn't.
	now := t1.Add(5 * time.Minute)
	e.Expire(now, true)

	// Simulate next tick: live fetch returns t1 again (it's within [now-Lookback, now]).
	// This creates a new window and tracker for t1.
	samples = e.Ingest([]Observation{obs("req", 100, t1)})

	// BUG: if the chain evicted t1 and folded gauge into base, then
	// re-inserting t1 produces counter = base(100) + gauge(100) = 200.
	// But the counter at t1 was already pushed as 100. The later buckets
	// cascade: t2 becomes 300, t3 becomes 400. Everything shifted up by 100.
	//
	// CORRECT: t1's counter should still be 100 (no change, no re-emission).
	if len(samples) > 0 {
		for _, s := range samples {
			t.Logf("re-emitted: bucket=%s counter=%d", s.Timestamp.Format(time.RFC3339), s.Value)
		}
		t.Error("bucket at Lookback boundary was expired and re-ingested, causing counter double-count")
	}
}

// TestKeyStringLabelOrder demonstrates that Keys with the same labels in
// different order produce different String() values, which causes the
// engine to create separate counter chains for what should be the same series.
func TestKeyStringLabelOrder(t *testing.T) {
	k1 := NewKey("metric", "zone", "example.com", "status", "200")
	k2 := NewKey("metric", "status", "200", "zone", "example.com")

	// These represent the same metric series but produce different strings.
	s1 := k1.String()
	s2 := k2.String()

	t.Logf("k1: %s", s1)
	t.Logf("k2: %s", s2)

	// BUG: these should be equal (same labels, same values) but aren't
	// because String() preserves insertion order.
	assert.Equal(t, s1, s2,
		"Keys with same labels in different order should produce the same string; "+
			"different strings cause separate counter chains for the same VM series")
}
