package cfetch_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	cfzones "github.com/cloudflare/cloudflare-go/v4/zones"
	"github.com/lablabs/cloudflare-exporter/cfetch"
	"github.com/lablabs/cloudflare-exporter/cfgql"
	"github.com/lablabs/cloudflare-exporter/metricnames"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const cfGraphQLEndpoint = "https://api.cloudflare.com/client/v4/graphql/"

// liveGQLClient implements cfgql.GQLClient against the real Cloudflare API.
type liveGQLClient struct {
	token string
}

type gqlResponse struct {
	Data   any         `json:"data"`
	Errors []*gqlError `json:"errors"`
}

type gqlError struct {
	Message string `json:"message"`
}

func (e *gqlError) Error() string { return e.Message }

func (c *liveGQLClient) RunGQL(ctx context.Context, req *cfgql.GQLRequest, dest any) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(req); err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, cfGraphQLEndpoint, &body)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	httpReq.Header.Set("Accept", "application/json; charset=utf-8")
	httpReq.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	gResp := gqlResponse{Data: dest}
	if err := json.NewDecoder(resp.Body).Decode(&gResp); err != nil {
		return fmt.Errorf("decode: %w", err)
	}

	errs := make([]error, 0, len(gResp.Errors))
	for _, e := range gResp.Errors {
		errs = append(errs, e)
	}
	return errors.Join(errs...)
}

// TestIntegrationFetchReturnsAllMetrics verifies that a real Cloudflare fetch
// returns observations for every expected metric name.
//
// Requires: CF_API_TOKEN, CF_TEST_ZONE_ID
func TestIntegrationFetchReturnsAllMetrics(t *testing.T) {
	token := os.Getenv("CF_API_TOKEN")
	zoneID := os.Getenv("CF_TEST_ZONE_ID")
	if token == "" || zoneID == "" {
		t.Skip("skipping: CF_API_TOKEN and CF_TEST_ZONE_ID required")
	}

	client := &liveGQLClient{token: token}
	zones := []cfzones.Zone{{ID: zoneID, Name: "integration-test"}}

	end := time.Now().Add(-2 * time.Minute).Truncate(time.Minute)
	start := end.Add(-10 * time.Minute)

	fetcher := cfetch.New(client, zones, nil)
	obs, err := fetcher.Fetch(context.Background(), start, end)
	require.NoError(t, err)
	require.NotEmpty(t, obs, "expected observations for zone %s in [%s, %s]", zoneID, start, end)

	// Collect unique metric names from the observations.
	got := make(map[string]bool)
	for _, o := range obs {
		got[o.Key.Name] = true
	}

	t.Logf("fetched %d observations across %d metric names in [%s, %s]",
		len(obs), len(got), start.Format(time.RFC3339), end.Format(time.RFC3339))
	for name := range got {
		t.Logf("  %s", name)
	}

	// httpRequests1mGroups scalar metrics (always present for active zones)
	expected1m := []string{
		metricnames.ZoneRequestsTotal,
		metricnames.ZoneRequestsCached,
		metricnames.ZoneRequestsSSLEncrypted,
		metricnames.ZoneBandwidthTotal,
		metricnames.ZoneBandwidthCached,
		metricnames.ZoneBandwidthSSLEncrypted,
		metricnames.ZoneThreatsTotal,
		metricnames.ZoneUniquesTotal,
	}
	for _, name := range expected1m {
		assert.True(t, got[name], "missing 1m metric: %s", name)
	}

	// httpRequestsAdaptiveGroups
	assert.True(t, got[metricnames.ZoneRequestsStatusV2],
		"missing adaptive metric: %s", metricnames.ZoneRequestsStatusV2)

	// Dimensional metrics (may be absent for very low-traffic zones,
	// so log warnings instead of failing).
	dimensional := []string{
		metricnames.ZoneRequestsContentType,
		metricnames.ZoneBandwidthContentType,
		metricnames.ZoneRequestsCountry,
		metricnames.ZoneBandwidthCountry,
		metricnames.ZoneRequestsStatus,
		metricnames.ZoneRequestsBrowserMap,
	}
	for _, name := range dimensional {
		if !got[name] {
			t.Logf("WARN: dimensional metric not returned (may be expected for low-traffic zones): %s", name)
		}
	}
}
