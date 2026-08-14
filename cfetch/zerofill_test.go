package cfetch

import (
	"testing"
	"time"

	"github.com/lablabs/cloudflare-exporter/converge"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mkAdaptiveGroup(bucket time.Time, status int, count uint64) httpAdaptiveGroup {
	g := httpAdaptiveGroup{Count: count}
	g.Dimensions.DatetimeMinute = bucket.Format(time.RFC3339)
	g.Dimensions.EdgeResponseStatus = status
	return g
}

func statusLabel(o converge.Observation) string {
	for _, l := range o.Key.Labels {
		if l.Name == "status" {
			return l.Value
		}
	}
	return ""
}

// TestFlattenAdaptiveGroupsZeroFillsKnownAbsentStatus reproduces the real
// bug behind the CloudflareZone5xxZscoreWarn noise: Cloudflare's Adaptive
// Groups API only returns a (zone, status) row for a minute when that status
// had at least one request. A status code that's seen before but goes quiet
// for a minute is *confirmed* zero by that minute's row still coming back
// without it - not ambiguous, not something to guess about with a timer.
func TestFlattenAdaptiveGroupsZeroFillsKnownAbsentStatus(t *testing.T) {
	f := &Fetcher{knownStatuses: make(map[string]map[int]bool)}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Minute)

	first := adaptiveZoneData{
		ZoneTag: "zone1",
		HTTPAdaptiveGroups: []httpAdaptiveGroup{
			mkAdaptiveGroup(t0, 500, 100),
			mkAdaptiveGroup(t0, 507, 3),
		},
	}
	obs := f.flattenHTTPAdaptiveGroups(first, "supabase.co", nil)
	require.Len(t, obs, 2)

	// Minute 1: only status 500 occurs. 507 is absent from this minute's
	// response entirely - Cloudflare's own data says zero, not "unknown".
	second := adaptiveZoneData{
		ZoneTag: "zone1",
		HTTPAdaptiveGroups: []httpAdaptiveGroup{
			mkAdaptiveGroup(t1, 500, 120),
		},
	}
	obs = f.flattenHTTPAdaptiveGroups(second, "supabase.co", nil)
	require.Len(t, obs, 2, "expected the real 500 observation plus a zero-fill for the previously-seen 507")

	values := map[string]uint64{}
	for _, o := range obs {
		assert.Equal(t, t1, o.Bucket)
		values[statusLabel(o)] = o.Value
	}
	assert.Equal(t, uint64(120), values["500"])
	assert.Equal(t, uint64(0), values["507"])
}

func TestFlattenAdaptiveGroupsNeverSeenStatusNotZeroFilled(t *testing.T) {
	f := &Fetcher{knownStatuses: make(map[string]map[int]bool)}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	obs := f.flattenHTTPAdaptiveGroups(adaptiveZoneData{
		ZoneTag:            "zone1",
		HTTPAdaptiveGroups: []httpAdaptiveGroup{mkAdaptiveGroup(t0, 500, 10)},
	}, "supabase.co", nil)
	require.Len(t, obs, 1, "nothing known yet to zero-fill against")
}

func TestFlattenAdaptiveGroupsZeroFillIsPerZone(t *testing.T) {
	f := &Fetcher{knownStatuses: make(map[string]map[int]bool)}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Minute)

	f.flattenHTTPAdaptiveGroups(adaptiveZoneData{
		ZoneTag:            "zone1",
		HTTPAdaptiveGroups: []httpAdaptiveGroup{mkAdaptiveGroup(t0, 507, 3)},
	}, "supabase.co", nil)

	// A different zone that has never seen 507 shouldn't get it zero-filled.
	obs := f.flattenHTTPAdaptiveGroups(adaptiveZoneData{
		ZoneTag:            "zone2",
		HTTPAdaptiveGroups: []httpAdaptiveGroup{mkAdaptiveGroup(t1, 500, 10)},
	}, "snapcloud.dev", nil)
	require.Len(t, obs, 1, "zero-fill knowledge must not leak across zones")
}

func TestFlattenAdaptiveGroupsRespectsEnabledFilter(t *testing.T) {
	f := &Fetcher{knownStatuses: make(map[string]map[int]bool)}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	obs := f.flattenHTTPAdaptiveGroups(adaptiveZoneData{
		ZoneTag:            "zone1",
		HTTPAdaptiveGroups: []httpAdaptiveGroup{mkAdaptiveGroup(t0, 500, 10)},
	}, "supabase.co", map[string]bool{"some_other_metric": true})
	assert.Empty(t, obs, "metric not in the enabled set should be filtered out entirely")
}
