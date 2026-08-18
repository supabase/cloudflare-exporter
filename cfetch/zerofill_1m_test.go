package cfetch

import (
	"testing"
	"time"

	"github.com/lablabs/cloudflare-exporter/converge"
	"github.com/lablabs/cloudflare-exporter/metricnames"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mk1mGroup builds an http1mGroup with only the status breakdown populated.
func mk1mGroup(bucket time.Time, statuses map[int]uint64) http1mGroup {
	var g http1mGroup
	g.Dimensions.Datetime = bucket.Format(time.RFC3339)
	for status, count := range statuses {
		g.Sum.ResponseStatus = append(g.Sum.ResponseStatus, struct {
			Requests           uint64 `json:"requests"`
			EdgeResponseStatus int    `json:"edgeResponseStatus"`
		}{Requests: count, EdgeResponseStatus: status})
	}
	return g
}

// TestFlatten1mGroupsZeroFillsKnownAbsentStatus mirrors the adaptive-groups
// case: httpRequests1mGroups has the same gap pattern.
func TestFlatten1mGroupsZeroFillsKnownAbsentStatus(t *testing.T) {
	f := &Fetcher{knownStatuses1m: make(map[string]map[int]bool)}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Minute)

	first := zoneData{
		ZoneTag:      "zone1",
		HTTP1mGroups: []http1mGroup{mk1mGroup(t0, map[int]uint64{500: 100, 507: 3})},
	}
	obs := f.flattenHTTP1mGroups(first, "supabase.co", nil)
	requireStatusCount(t, obs, 2)

	second := zoneData{
		ZoneTag:      "zone1",
		HTTP1mGroups: []http1mGroup{mk1mGroup(t1, map[int]uint64{500: 120})},
	}
	obs = f.flattenHTTP1mGroups(second, "supabase.co", nil)

	values := map[string]uint64{}
	for _, o := range obs {
		if o.Key.Name != metricnames.ZoneRequestsStatus {
			continue
		}
		assert.Equal(t, t1, o.Bucket)
		values[statusLabel(o)] = o.Value
	}
	assert.Equal(t, uint64(120), values["500"])
	assert.Equal(t, uint64(0), values["507"], "507 must be zero-filled, not silently dropped")
}

func TestFlatten1mGroupsNeverSeenStatusNotZeroFilled(t *testing.T) {
	f := &Fetcher{knownStatuses1m: make(map[string]map[int]bool)}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	obs := f.flattenHTTP1mGroups(zoneData{
		ZoneTag:      "zone1",
		HTTP1mGroups: []http1mGroup{mk1mGroup(t0, map[int]uint64{500: 10})},
	}, "supabase.co", nil)
	requireStatusCount(t, obs, 1)
}

func TestFlatten1mGroupsZeroFillIsPerZone(t *testing.T) {
	f := &Fetcher{knownStatuses1m: make(map[string]map[int]bool)}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Minute)

	f.flattenHTTP1mGroups(zoneData{
		ZoneTag:      "zone1",
		HTTP1mGroups: []http1mGroup{mk1mGroup(t0, map[int]uint64{507: 3})},
	}, "supabase.co", nil)

	obs := f.flattenHTTP1mGroups(zoneData{
		ZoneTag:      "zone2",
		HTTP1mGroups: []http1mGroup{mk1mGroup(t1, map[int]uint64{500: 10})},
	}, "snapcloud.dev", nil)
	requireStatusCount(t, obs, 1)
}

// TestFlatten1mGroupsOtherMetricsUnaffected confirms the refactor didn't
// disturb the function's other metrics.
func TestFlatten1mGroupsOtherMetricsUnaffected(t *testing.T) {
	f := &Fetcher{knownStatuses1m: make(map[string]map[int]bool)}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	g := mk1mGroup(t0, map[int]uint64{500: 10})
	g.Sum.Requests = 500
	g.Sum.CachedRequests = 200
	g.Sum.Bytes = 12345
	g.Uniq.Uniques = 42
	g.Sum.ContentType = append(g.Sum.ContentType, struct {
		Requests                uint64 `json:"requests"`
		Bytes                   uint64 `json:"bytes"`
		EdgeResponseContentType string `json:"edgeResponseContentTypeName"`
	}{Requests: 5, Bytes: 100, EdgeResponseContentType: "text/html"})

	obs := f.flattenHTTP1mGroups(zoneData{ZoneTag: "zone1", HTTP1mGroups: []http1mGroup{g}}, "supabase.co", nil)

	byMetric := map[string]uint64{}
	for _, o := range obs {
		byMetric[o.Key.Name] = o.Value
	}
	assert.Equal(t, uint64(500), byMetric[metricnames.ZoneRequestsTotal])
	assert.Equal(t, uint64(200), byMetric[metricnames.ZoneRequestsCached])
	assert.Equal(t, uint64(12345), byMetric[metricnames.ZoneBandwidthTotal])
	assert.Equal(t, uint64(42), byMetric[metricnames.ZoneUniquesTotal])
	assert.Equal(t, uint64(5), byMetric[metricnames.ZoneRequestsContentType])
}

func requireStatusCount(t *testing.T, obs []converge.Observation, n int) {
	t.Helper()
	count := 0
	for _, o := range obs {
		if o.Key.Name == metricnames.ZoneRequestsStatus {
			count++
		}
	}
	require.Equal(t, n, count, "expected %d status observations, got %d", n, count)
}
