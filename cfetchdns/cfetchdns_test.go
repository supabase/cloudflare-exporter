package cfetchdns

import (
	"context"
	"testing"
	"time"

	cfzones "github.com/cloudflare/cloudflare-go/v4/zones"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockGQLClient struct {
	resp rangeResponse
}

func (m *mockGQLClient) RunGQL(_ context.Context, _ *GQLRequest, dest any) error {
	*dest.(*rangeResponse) = m.resp
	return nil
}

func TestFetch(t *testing.T) {
	ts := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	mock := &mockGQLClient{
		resp: rangeResponse{},
	}
	mock.resp.Viewer.Zones = []zoneData{
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

	zones := []cfzones.Zone{{ID: "zone-abc", Name: "example.com"}}
	f := New(mock, zones, nil)

	obs, err := f.Fetch(context.Background(), ts, ts.Add(time.Minute))
	require.NoError(t, err)
	require.Len(t, obs, 2)

	assert.Equal(t, "cfp_zone_dns_queries_total", obs[0].Key.Name)
	assert.Equal(t, uint64(42), obs[0].Value)
	assert.Equal(t, ts, obs[0].Bucket)

	labels0 := obs[0].Key.Labels
	assert.Equal(t, "zone", labels0[0].Name)
	assert.Equal(t, "example.com", labels0[0].Value)
	assert.Equal(t, "response_code", labels0[1].Name)
	assert.Equal(t, "NOERROR", labels0[1].Value)
	assert.Equal(t, "query_type", labels0[2].Name)
	assert.Equal(t, "A", labels0[2].Value)

	assert.Equal(t, "cfp_zone_dns_queries_total", obs[1].Key.Name)
	assert.Equal(t, uint64(7), obs[1].Value)

	labels1 := obs[1].Key.Labels
	assert.Equal(t, "NXDOMAIN", labels1[1].Value)
	assert.Equal(t, "AAAA", labels1[2].Value)
}
