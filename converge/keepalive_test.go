package converge

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKeepAliveRepushesIdleKeyUnchanged reproduces the pattern seen behind
// the 2026-08-14 CloudflareZone5xxZscoreWarn alerts: Cloudflare's Adaptive
// Groups API only returns a (zone, status) group when that status had at
// least one request in the bucket. Rare status codes (507, 523, 555 on
// supabase.co; 504, 530 on snapcloud.dev) went 5-17 minutes between requests
// during those alert windows. Ingest never receives an Observation for an
// idle key, so it never re-emits that key's counter. Once the gap outlives
// VictoriaMetrics' staleness window, the series drops out of any
// sum()/rate()/delta() over the zone's total 5xx count - producing a phantom
// drop that "recovers" the instant the status code reappears.
func TestKeepAliveRepushesIdleKeyUnchanged(t *testing.T) {
	e := NewEngine(cfg(1))

	samples := e.Ingest([]Observation{obs("cf_5xx_507", 1, t0)})
	require.Len(t, samples, 1)
	assert.Equal(t, uint64(1), samples[0].Value)

	// A minute passes; status=507 has zero requests, so Cloudflare returns
	// no group for it at all - not a "0" observation, an absent one.
	t1 := t0.Add(time.Minute)
	assert.Empty(t, e.Ingest(nil), "no observation arrives for the idle key")

	// KeepAlive must re-affirm the last known counter value at a fresh
	// timestamp for any key that had no real observation this tick, so the
	// series never goes stale in VictoriaMetrics.
	keepAlive := e.KeepAlive(t1, map[string]bool{})
	require.Len(t, keepAlive, 1)
	assert.Equal(t, uint64(1), keepAlive[0].Value, "counter value must be unchanged, not reset")
	assert.Equal(t, t1, keepAlive[0].Timestamp, "timestamp must advance to now, not replay the old bucket")
}

func TestKeepAliveSkipsTouchedKeys(t *testing.T) {
	e := NewEngine(cfg(1))
	e.Ingest([]Observation{obs("cf_5xx_500", 100, t0)})

	t1 := t0.Add(time.Minute)
	e.Ingest([]Observation{obs("cf_5xx_500", 150, t1)})

	k := NewKey("cf_5xx_500")
	touched := map[string]bool{k.String(): true}
	assert.Empty(t, e.KeepAlive(t1, touched), "a key with a fresh observation this tick needs no keep-alive")
}

func TestKeepAliveIgnoresKeysNeverObserved(t *testing.T) {
	e := NewEngine(cfg(1))
	assert.Empty(t, e.KeepAlive(t0, map[string]bool{}), "nothing to keep alive before any observation has arrived")
}
