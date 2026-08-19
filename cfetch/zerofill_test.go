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

// TestFlattenAdaptiveGroupsZeroFillsKnownAbsentStatus: a known status absent
// from a returned minute is a confirmed zero, not a gap.
func TestFlattenAdaptiveGroupsZeroFillsKnownAbsentStatus(t *testing.T) {
	f := &Fetcher{knownStatusesV2: make(map[string]map[int]bool)}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Minute)

	first := adaptiveZoneData{
		ZoneTag: "zone1",
		HTTPAdaptiveGroups: []httpAdaptiveGroup{
			mkAdaptiveGroup(t0, 500, 100),
			mkAdaptiveGroup(t0, 507, 3),
		},
	}
	obs := f.flattenHTTPAdaptiveGroups(first, "supabase.co")
	require.Len(t, obs, 2)

	// Minute 1: only status 500 occurs. 507 is absent from this minute's
	// response entirely - Cloudflare's own data says zero, not "unknown".
	second := adaptiveZoneData{
		ZoneTag: "zone1",
		HTTPAdaptiveGroups: []httpAdaptiveGroup{
			mkAdaptiveGroup(t1, 500, 120),
		},
	}
	obs = f.flattenHTTPAdaptiveGroups(second, "supabase.co")
	require.Len(t, obs, 2, "expected the real 500 observation plus a zero-fill for the previously-seen 507")

	values := map[string]uint64{}
	for _, o := range obs {
		assert.Equal(t, t1, o.Bucket)
		values[statusLabel(o)] = o.Value
	}
	assert.Equal(t, uint64(120), values["500"])
	assert.Equal(t, uint64(0), values["507"])
}

// TestFlattenAdaptiveGroupsBackfillsWithinSingleMultiMinuteBatch: a status
// seen only in the newest minute of a batch must still zero-fill the earlier
// minutes in that same batch.
func TestFlattenAdaptiveGroupsBackfillsWithinSingleMultiMinuteBatch(t *testing.T) {
	f := &Fetcher{knownStatusesV2: make(map[string]map[int]bool)}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Minute)
	t2 := t0.Add(2 * time.Minute)

	obs := f.flattenHTTPAdaptiveGroups(adaptiveZoneData{
		ZoneTag: "zone1",
		HTTPAdaptiveGroups: []httpAdaptiveGroup{
			mkAdaptiveGroup(t0, 500, 100),
			mkAdaptiveGroup(t1, 500, 110),
			mkAdaptiveGroup(t2, 500, 120),
			mkAdaptiveGroup(t2, 507, 3), // 507 only shows up in the newest minute
		},
	}, "supabase.co")

	byBucketStatus := map[time.Time]map[string]uint64{}
	for _, o := range obs {
		if byBucketStatus[o.Bucket] == nil {
			byBucketStatus[o.Bucket] = map[string]uint64{}
		}
		byBucketStatus[o.Bucket][statusLabel(o)] = o.Value
	}

	require.Contains(t, byBucketStatus, t0)
	require.Contains(t, byBucketStatus, t1)
	require.Contains(t, byBucketStatus, t2)
	assert.Equal(t, uint64(0), byBucketStatus[t0]["507"], "507 must be zero-filled into t0 even though it's only ever seen at t2")
	assert.Equal(t, uint64(0), byBucketStatus[t1]["507"], "507 must be zero-filled into t1 even though it's only ever seen at t2")
	assert.Equal(t, uint64(3), byBucketStatus[t2]["507"])
}

func TestFlattenAdaptiveGroupsNeverSeenStatusNotZeroFilled(t *testing.T) {
	f := &Fetcher{knownStatusesV2: make(map[string]map[int]bool)}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	obs := f.flattenHTTPAdaptiveGroups(adaptiveZoneData{
		ZoneTag:            "zone1",
		HTTPAdaptiveGroups: []httpAdaptiveGroup{mkAdaptiveGroup(t0, 500, 10)},
	}, "supabase.co")
	require.Len(t, obs, 1, "nothing known yet to zero-fill against")
}

func TestFlattenAdaptiveGroupsZeroFillIsPerZone(t *testing.T) {
	f := &Fetcher{knownStatusesV2: make(map[string]map[int]bool)}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Minute)

	f.flattenHTTPAdaptiveGroups(adaptiveZoneData{
		ZoneTag:            "zone1",
		HTTPAdaptiveGroups: []httpAdaptiveGroup{mkAdaptiveGroup(t0, 507, 3)},
	}, "supabase.co")

	// A different zone that has never seen 507 shouldn't get it zero-filled.
	obs := f.flattenHTTPAdaptiveGroups(adaptiveZoneData{
		ZoneTag:            "zone2",
		HTTPAdaptiveGroups: []httpAdaptiveGroup{mkAdaptiveGroup(t1, 500, 10)},
	}, "snapcloud.dev")
	require.Len(t, obs, 1, "zero-fill knowledge must not leak across zones")
}

func TestFlattenAdaptiveGroupsRespectsEnabledFilter(t *testing.T) {
	f := &Fetcher{
		knownStatusesV2: make(map[string]map[int]bool),
		enabled:         map[string]bool{"some_other_metric": true},
	}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	obs := f.flattenHTTPAdaptiveGroups(adaptiveZoneData{
		ZoneTag:            "zone1",
		HTTPAdaptiveGroups: []httpAdaptiveGroup{mkAdaptiveGroup(t0, 500, 10)},
	}, "supabase.co")
	assert.Empty(t, obs, "metric not in the enabled set should be filtered out entirely")
}
