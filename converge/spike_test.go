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

func loadFixtures(t *testing.T, prefix ...string) []fixtureFile {
	t.Helper()
	pattern := "fetch"
	if len(prefix) > 0 {
		pattern = prefix[0]
	}
	files, err := filepath.Glob(fmt.Sprintf("testdata/%s_*.json", pattern))
	require.NoError(t, err)
	require.NotEmpty(t, files, "no fixture files matching %s in testdata/", pattern)

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

// runPreFix simulates the old runner behavior where every Ingest result
// was pushed immediately, causing cascade spikes.
func runPreFix(t *testing.T, fixtures []fixtureFile) (median, maxRate float64) {
	t.Helper()
	liveFixture, backfillFixtures := fixtures[0], fixtures[1:]
	now := liveFixture.End

	eng := NewEngine(Config{Threshold: 1, Lookback: 15 * time.Minute})

	var samples []Sample
	samples = append(samples, eng.Ingest(fixtureToObservations(liveFixture))...)
	samples = append(samples, eng.Expire(now, true)...)
	for _, bf := range backfillFixtures {
		samples = append(samples, eng.Ingest(fixtureToObservations(bf))...)
	}

	require.NotEmpty(t, samples)
	rates := computeRates(samples)
	require.NotEmpty(t, rates)

	sort.Float64s(rates)
	median = rates[len(rates)/2]
	maxRate = rates[len(rates)-1]

	t.Logf("PRE-FIX: %d samples, %d rates, median=%.0f max=%.0f (%.1fx)",
		len(samples), len(rates), median, maxRate, maxRate/median)
	return median, maxRate
}

// runPostFix simulates the fixed runner: suppress pushes during backfill,
// expire with evictChains=false, then snapshot.
func runPostFix(t *testing.T, fixtures []fixtureFile) (median, maxRate float64) {
	t.Helper()
	liveFixture, backfillFixtures := fixtures[0], fixtures[1:]
	now := liveFixture.End

	eng := NewEngine(Config{Threshold: 1, Lookback: 15 * time.Minute})

	eng.Ingest(fixtureToObservations(liveFixture))
	eng.Expire(now, false)
	for _, bf := range backfillFixtures {
		eng.Ingest(fixtureToObservations(bf))
	}

	samples := eng.Snapshot()
	require.NotEmpty(t, samples)

	rates := computeRates(samples)
	require.NotEmpty(t, rates)

	sort.Float64s(rates)
	median = rates[len(rates)/2]
	maxRate = rates[len(rates)-1]

	t.Logf("POST-FIX: %d samples, %d rates, median=%.0f max=%.0f (%.1fx)",
		len(samples), len(rates), median, maxRate, maxRate/median)
	return median, maxRate
}

// TestSpikeDetection_PreFix demonstrates the counter chain cascade bug
// across multiple captured incidents.
func TestSpikeDetection_PreFix(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
	}{
		{"supabase_co_0624", "fetch"},
		{"zone_0626_60m", "spike_0626_60m"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixtures := loadFixtures(t, tc.prefix)
			median, maxRate := runPreFix(t, fixtures)
			assert.Greater(t, maxRate, median*10,
				"expected spike in pre-fix simulation; fixture data may not reproduce the bug")
		})
	}
}

// TestSpikeDetection_PostFix verifies the fix produces clean monotonic
// counters with no spikes across multiple captured incidents.
func TestSpikeDetection_PostFix(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
	}{
		{"supabase_co_0624", "fetch"},
		{"zone_0626_60m", "spike_0626_60m"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixtures := loadFixtures(t, tc.prefix)
			median, maxRate := runPostFix(t, fixtures)
			spikeMultiplier := 10.0
			t.Logf("spike threshold: %.0f (%.0fx median)", median*spikeMultiplier, spikeMultiplier)
			assert.LessOrEqual(t, maxRate, median*spikeMultiplier,
				fmt.Sprintf("rate spike detected: max %.2f exceeds %.0fx median (%.2f); "+
					"counter chain cascade artifact during backfill",
					maxRate, spikeMultiplier, median))
		})
	}
}
