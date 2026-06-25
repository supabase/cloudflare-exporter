package cfetchdns

import (
	"context"
	"errors"
	"testing"
	"time"

	cfzones "github.com/cloudflare/cloudflare-go/v4/zones"
	"github.com/lablabs/cloudflare-exporter/cfgql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockGQLClient struct {
	resp *rangeResponse
	err  error
}

func (m *mockGQLClient) RunGQL(_ context.Context, _ *cfgql.GQLRequest, dest any) error {
	if m.err != nil {
		return m.err
	}
	*dest.(*rangeResponse) = *m.resp
	return nil
}

func makeDims(dt, rc, qt, ipv string) struct {
	DatetimeMinute string `json:"datetimeMinute"`
	ResponseCode   string `json:"responseCode"`
	QueryType      string `json:"queryType"`
	IpVersion      string `json:"ipVersion"`
} {
	return struct {
		DatetimeMinute string `json:"datetimeMinute"`
		ResponseCode   string `json:"responseCode"`
		QueryType      string `json:"queryType"`
		IpVersion      string `json:"ipVersion"`
	}{DatetimeMinute: dt, ResponseCode: rc, QueryType: qt, IpVersion: ipv}
}

func makeSum(stale, uncached uint64) struct {
	CountStale                uint64 `json:"countStale"`
	CountNotCachedAndNotStale uint64 `json:"countNotCachedAndNotStale"`
} {
	return struct {
		CountStale                uint64 `json:"countStale"`
		CountNotCachedAndNotStale uint64 `json:"countNotCachedAndNotStale"`
	}{CountStale: stale, CountNotCachedAndNotStale: uncached}
}

func TestFetch(t *testing.T) {
	ts := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	resp := &rangeResponse{}
	resp.Viewer.Zones = []zoneData{
		{
			ZoneTag: "zone-abc",
			DNSGroups: []dnsGroup{
				{
					Count:      42,
					Dimensions: makeDims(ts.Format(time.RFC3339), "NOERROR", "A", "4"),
					Sum:        makeSum(0, 40),
				},
				{
					Count:      7,
					Dimensions: makeDims(ts.Format(time.RFC3339), "NXDOMAIN", "AAAA", "6"),
					Sum:        makeSum(1, 5),
				},
			},
		},
	}

	mock := &mockGQLClient{resp: resp}
	zones := []cfzones.Zone{{ID: "zone-abc", Name: "example.com"}}
	f := New(mock, zones, nil)

	obs, err := f.Fetch(context.Background(), ts, ts.Add(time.Minute))
	require.NoError(t, err)
	// 2 queries_total + 1 stale_total + 1 uncached_total (aggregated per bucket)
	require.Len(t, obs, 4)

	// find observations by metric name for stable assertions
	byMetric := map[string][]struct {
		value  uint64
		labels map[string]string
	}{}
	for _, o := range obs {
		lm := map[string]string{}
		for _, l := range o.Key.Labels {
			lm[l.Name] = l.Value
		}
		byMetric[o.Key.Name] = append(byMetric[o.Key.Name], struct {
			value  uint64
			labels map[string]string
		}{o.Value, lm})
	}

	// queries_total: two rows
	require.Len(t, byMetric["cloudflare_zone_dns_queries_total"], 2)
	for _, o := range byMetric["cloudflare_zone_dns_queries_total"] {
		assert.Equal(t, "example.com", o.labels["zone"])
		assert.NotEmpty(t, o.labels["response_code"])
		assert.NotEmpty(t, o.labels["query_type"])
		assert.NotEmpty(t, o.labels["ip_version"])
	}

	// stale_total: one zone-level observation (0+1=1)
	require.Len(t, byMetric["cloudflare_zone_dns_stale_total"], 1)
	assert.Equal(t, uint64(1), byMetric["cloudflare_zone_dns_stale_total"][0].value)
	assert.Equal(t, "example.com", byMetric["cloudflare_zone_dns_stale_total"][0].labels["zone"])
	assert.Empty(t, byMetric["cloudflare_zone_dns_stale_total"][0].labels["response_code"])

	// uncached_total: one zone-level observation (40+5=45)
	require.Len(t, byMetric["cloudflare_zone_dns_uncached_total"], 1)
	assert.Equal(t, uint64(45), byMetric["cloudflare_zone_dns_uncached_total"][0].value)
	assert.Equal(t, "example.com", byMetric["cloudflare_zone_dns_uncached_total"][0].labels["zone"])
}

func TestFetchSkipsChunkOnError(t *testing.T) {
	mock := &mockGQLClient{err: errors.New("gql unavailable")}
	zones := []cfzones.Zone{{ID: "zone-abc", Name: "example.com"}}
	f := New(mock, zones, nil)

	obs, err := f.Fetch(context.Background(), time.Now(), time.Now().Add(time.Minute))
	require.NoError(t, err)
	assert.Empty(t, obs)
}

func TestFetchEnabledFilter(t *testing.T) {
	ts := time.Now().UTC().Truncate(time.Second)

	resp := &rangeResponse{}
	resp.Viewer.Zones = []zoneData{
		{
			ZoneTag: "zone-abc",
			DNSGroups: []dnsGroup{
				{
					Count:      42,
					Dimensions: makeDims(ts.Format(time.RFC3339), "NOERROR", "A", "4"),
					Sum:        makeSum(0, 40),
				},
			},
		},
	}

	zones := []cfzones.Zone{{ID: "zone-abc", Name: "example.com"}}

	// empty enabled map — nothing passes
	f := New(&mockGQLClient{resp: resp}, zones, map[string]bool{})
	obs, err := f.Fetch(context.Background(), ts, ts.Add(time.Minute))
	require.NoError(t, err)
	assert.Empty(t, obs)

	// only queries_total enabled
	f2 := New(&mockGQLClient{resp: resp}, zones, map[string]bool{"cloudflare_zone_dns_queries_total": true})
	obs2, err := f2.Fetch(context.Background(), ts, ts.Add(time.Minute))
	require.NoError(t, err)
	require.Len(t, obs2, 1)
	assert.Equal(t, "cloudflare_zone_dns_queries_total", obs2[0].Key.Name)

	// all three enabled
	f3 := New(&mockGQLClient{resp: resp}, zones, map[string]bool{
		"cloudflare_zone_dns_queries_total":  true,
		"cloudflare_zone_dns_stale_total":    true,
		"cloudflare_zone_dns_uncached_total": true,
	})
	obs3, err := f3.Fetch(context.Background(), ts, ts.Add(time.Minute))
	require.NoError(t, err)
	assert.Len(t, obs3, 3)
}
