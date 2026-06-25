package converge

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Fixture types matching the recorded JSON format from the integration
// recording wrapper. Each file represents one Fetch() call result.
type fixtureFile struct {
	Seq          int                `json:"seq"`
	Start        time.Time          `json:"start"`
	End          time.Time          `json:"end"`
	Observations []fixtureObserving `json:"observations"`
}

type fixtureObserving struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
	Value  uint64            `json:"value"`
	Bucket time.Time         `json:"bucket"`
}

func loadFixtures(t *testing.T) []fixtureFile {
	t.Helper()
	files, err := filepath.Glob("testdata/fetch_*.json")
	require.NoError(t, err)
	require.NotEmpty(t, files, "no fixture files in testdata/")

	sort.Strings(files)
	var fixtures []fixtureFile
	for _, f := range files {
		data, err := os.ReadFile(f)
		require.NoError(t, err)
		var ff fixtureFile
		require.NoError(t, json.Unmarshal(data, &ff))
		fixtures = append(fixtures, ff)
	}
	return fixtures
}

func fixtureToObservations(ff fixtureFile) []Observation {
	obs := make([]Observation, len(ff.Observations))
	for i, fo := range ff.Observations {
		var labels []Label
		for k, v := range fo.Labels {
			labels = append(labels, Label{Name: k, Value: v})
		}
		obs[i] = Observation{
			Key:    Key{Name: fo.Name, Labels: labels},
			Value:  fo.Value,
			Bucket: fo.Bucket,
		}
	}
	return obs
}

// computeRates takes pushed samples grouped by series key, sorts by time,
// and computes per-minute deltas. Returns all non-negative rate values.
func computeRates(samples []Sample) []float64 {
	type tsValue struct {
		ts    time.Time
		value uint64
	}
	byKey := make(map[string][]tsValue)
	for _, s := range samples {
		byKey[s.Key.String()] = append(byKey[s.Key.String()], tsValue{ts: s.Timestamp, value: s.Value})
	}

	var rates []float64
	for _, values := range byKey {
		sort.Slice(values, func(i, j int) bool { return values[i].ts.Before(values[j].ts) })
		for i := 1; i < len(values); i++ {
			dt := values[i].ts.Sub(values[i-1].ts).Minutes()
			if dt <= 0 {
				continue
			}
			dv := float64(values[i].value) - float64(values[i-1].value)
			if dv < 0 {
				continue
			}
			rate := dv / dt
			if rate > 0 && !math.IsNaN(rate) && !math.IsInf(rate, 0) {
				rates = append(rates, rate)
			}
		}
	}
	return rates
}

// TestSpikeDetectionFromFixtures replays recorded Cloudflare fetch data
// through the engine simulating the runner's live + backfill pattern, then
// checks for rate spikes in the pushed samples.
//
// The fixture data was captured from a real run against supabase.co.
// fetch_000 is the live fetch, fetch_001..006 are backfill chunks.
//
// On the current (pre-fix) code path this test SHOULD detect spikes,
// demonstrating the counter chain cascade bug. After the evictChains
// fix is applied, the test should pass.
func TestSpikeDetectionFromFixtures(t *testing.T) {
	fixtures := loadFixtures(t)
	require.GreaterOrEqual(t, len(fixtures), 2, "need at least a live fetch and one backfill chunk")

	liveFixture := fixtures[0]
	backfillFixtures := fixtures[1:]

	t.Logf("live: %d obs [%s, %s]", len(liveFixture.Observations),
		liveFixture.Start.Format(time.RFC3339), liveFixture.End.Format(time.RFC3339))
	for i, bf := range backfillFixtures {
		t.Logf("backfill %d: %d obs [%s, %s]", i, len(bf.Observations),
			bf.Start.Format(time.RFC3339), bf.End.Format(time.RFC3339))
	}

	// Use the live fetch end time as "now" for the simulation.
	now := liveFixture.End

	eng := NewEngine(Config{
		Threshold:            1,
		WindowTTL:            15 * time.Minute,
		PollInterval:         10 * time.Second,
		Lookback:             10 * time.Minute,
		MaxBackfill:          60 * time.Minute,
		BackfillChunk:        10 * time.Minute,
		BackfillCallsPerTick: 10,
	})

	// Simulate the pre-fix runner behavior where every Ingest result was
	// immediately pushed. This is what causes the cascade: each backfill
	// chunk shifts earlier buckets' prefix sums, and the intermediate
	// counter values get pushed to the sink. The sink (VM) then sees the
	// counter at a given timestamp jump repeatedly, which rate()
	// interprets as enormous throughput spikes.
	var samples []Sample

	// Tick 1: live fetch — pushed immediately (pre-fix behavior).
	samples = append(samples, eng.Ingest(fixtureToObservations(liveFixture))...)
	samples = append(samples, eng.Expire(now)...)

	// Tick 1: backfill chunks — each push leaks intermediate prefix sums.
	for _, bf := range backfillFixtures {
		samples = append(samples, eng.Ingest(fixtureToObservations(bf))...)
	}

	require.NotEmpty(t, samples, "should have pushed samples")
	t.Logf("snapshot: %d samples", len(samples))

	// Compute rates and check for spikes.
	rates := computeRates(samples)
	require.NotEmpty(t, rates, "no rate values computed")

	sort.Float64s(rates)
	median := rates[len(rates)/2]
	maxRate := rates[len(rates)-1]
	spikeMultiplier := 10.0

	t.Logf("rate samples:    %d", len(rates))
	t.Logf("median rate:     %.2f req/min", median)
	t.Logf("max rate:        %.2f req/min", maxRate)
	t.Logf("max/median:      %.1fx", maxRate/median)
	t.Logf("spike threshold: %.2f req/min (%.0fx median)", median*spikeMultiplier, spikeMultiplier)

	assert.LessOrEqual(t, maxRate, median*spikeMultiplier,
		fmt.Sprintf("rate spike detected: max %.2f exceeds %.0fx median (%.2f); "+
			"counter chain cascade artifact during backfill",
			maxRate, spikeMultiplier, median))
}
