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

func TestFetch(t *testing.T) {
	ts := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	resp := &rangeResponse{}
	resp.Viewer.Zones = []zoneData{
		{
			ZoneTag: "zone-abc",
			DNSGroups: []dnsGroup{
				{
					Count: 42,
					Dimensions: struct {
						DatetimeMinute string `json:"datetimeMinute"`
						ResponseCode   string `json:"responseCode"`
						QueryType      string `json:"queryType"`
					}{
						DatetimeMinute: ts.Format(time.RFC3339),
						ResponseCode:   "NOERROR",
						QueryType:      "A",
					},
				},
				{
					Count: 7,
					Dimensions: struct {
						DatetimeMinute string `json:"datetimeMinute"`
						ResponseCode   string `json:"responseCode"`
						QueryType      string `json:"queryType"`
					}{
						DatetimeMinute: ts.Format(time.RFC3339),
						ResponseCode:   "NXDOMAIN",
						QueryType:      "AAAA",
					},
				},
			},
		},
	}

	mock := &mockGQLClient{resp: resp}
	zones := []cfzones.Zone{{ID: "zone-abc", Name: "example.com"}}
	f := New(mock, zones, nil)

	obs, err := f.Fetch(context.Background(), ts, ts.Add(time.Minute))
	require.NoError(t, err)
	require.Len(t, obs, 2)

	assert.Equal(t, "cloudflare_zone_dns_queries_total", obs[0].Key.Name)
	assert.Equal(t, uint64(42), obs[0].Value)
	assert.Equal(t, ts, obs[0].Bucket)

	labels0 := obs[0].Key.Labels
	assert.Equal(t, "zone", labels0[0].Name)
	assert.Equal(t, "example.com", labels0[0].Value)
	assert.Equal(t, "response_code", labels0[1].Name)
	assert.Equal(t, "NOERROR", labels0[1].Value)
	assert.Equal(t, "query_type", labels0[2].Name)
	assert.Equal(t, "A", labels0[2].Value)

	assert.Equal(t, "cloudflare_zone_dns_queries_total", obs[1].Key.Name)
	assert.Equal(t, uint64(7), obs[1].Value)
	assert.Equal(t, ts, obs[1].Bucket)

	labels1 := obs[1].Key.Labels
	assert.Equal(t, "zone", labels1[0].Name)
	assert.Equal(t, "example.com", labels1[0].Value)
	assert.Equal(t, "response_code", labels1[1].Name)
	assert.Equal(t, "NXDOMAIN", labels1[1].Value)
	assert.Equal(t, "query_type", labels1[2].Name)
	assert.Equal(t, "AAAA", labels1[2].Value)
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
					Count: 42,
					Dimensions: struct {
						DatetimeMinute string `json:"datetimeMinute"`
						ResponseCode   string `json:"responseCode"`
						QueryType      string `json:"queryType"`
					}{
						DatetimeMinute: ts.Format(time.RFC3339),
						ResponseCode:   "NOERROR",
						QueryType:      "A",
					},
				},
			},
		},
	}

	zones := []cfzones.Zone{{ID: "zone-abc", Name: "example.com"}}

	// enabled map that excludes dns_queries_total
	f := New(&mockGQLClient{resp: resp}, zones, map[string]bool{})
	obs, err := f.Fetch(context.Background(), ts, ts.Add(time.Minute))
	require.NoError(t, err)
	assert.Empty(t, obs)

	// enabled map that includes dns_queries_total
	f2 := New(&mockGQLClient{resp: resp}, zones, map[string]bool{"cloudflare_zone_dns_queries_total": true})
	obs2, err := f2.Fetch(context.Background(), ts, ts.Add(time.Minute))
	require.NoError(t, err)
	assert.NotEmpty(t, obs2)
}
