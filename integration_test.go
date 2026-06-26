package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	cfzones "github.com/cloudflare/cloudflare-go/v4/zones"
	"github.com/lablabs/cloudflare-exporter/cfetch"
	"github.com/lablabs/cloudflare-exporter/cfgql"
	"github.com/lablabs/cloudflare-exporter/converge"
	"github.com/lablabs/cloudflare-exporter/vmpush"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

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

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.cloudflare.com/client/v4/graphql/", &body)
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

func skipUnlessIntegration(t *testing.T) (token, zoneID string) {
	t.Helper()
	token = os.Getenv("CF_API_TOKEN")
	zoneID = os.Getenv("CF_TEST_ZONE_ID")
	if token == "" || zoneID == "" {
		t.Skip("skipping: CF_API_TOKEN and CF_TEST_ZONE_ID required")
	}
	return token, zoneID
}

func skipUnlessVM(t *testing.T) string {
	t.Helper()
	ep := os.Getenv("VM_PUSH_ENDPOINT")
	if ep == "" {
		t.Skip("skipping: VM_PUSH_ENDPOINT required")
	}
	return ep
}

func newSink(t *testing.T, endpoint string) *vmpush.Sink {
	t.Helper()
	sink := vmpush.New(vmpush.Config{
		Endpoint: endpoint,
		Username: os.Getenv("VM_PUSH_USER"),
		Password: os.Getenv("VM_PUSH_PASSWORD"),
	})
	require.NoError(t, sink.Ping(context.Background()), "VM endpoint unreachable")
	return sink
}

// vmQueryBaseURL derives the query base from the push endpoint.
// http://host:port/api/v1/write → http://host:port
func vmQueryBaseURL(pushEndpoint string) string {
	return strings.Replace(pushEndpoint, "/api/v1/write", "", 1)
}

// vmQueryRange issues a query_range request and returns the parsed result.
type vmSeries struct {
	Metric map[string]string
	Values []vmSample
}

type vmSample struct {
	Time  time.Time
	Value float64
}

func vmQueryRange(t *testing.T, pushEndpoint, query string, start, end time.Time, step int) []vmSeries {
	t.Helper()

	queryURL := vmQueryBaseURL(pushEndpoint) + "/api/v1/query_range"
	params := url.Values{
		"query": {query},
		"start": {strconv.FormatInt(start.Unix(), 10)},
		"end":   {strconv.FormatInt(end.Unix(), 10)},
		"step":  {strconv.Itoa(step)},
	}

	resp, err := http.Get(queryURL + "?" + params.Encode())
	require.NoError(t, err, "VM query failed")
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "VM query status: %s", string(body))

	var raw struct {
		Status string `json:"status"`
		Data   struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Values [][]any           `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &raw), "VM response: %s", string(body))
	require.Equal(t, "success", raw.Status, "VM query failed: %s", string(body))

	var out []vmSeries
	for _, r := range raw.Data.Result {
		s := vmSeries{Metric: r.Metric}
		for _, v := range r.Values {
			ts := time.Unix(int64(v[0].(float64)), 0)
			val, err := strconv.ParseFloat(v[1].(string), 64)
			if err != nil {
				continue
			}
			s.Values = append(s.Values, vmSample{Time: ts, Value: val})
		}
		out = append(out, s)
	}
	return out
}

// runConvergeUntilBackfill starts the full converge.Run loop and blocks
// until the backfill snapshot is pushed or the timeout expires.
func runConvergeUntilBackfill(t *testing.T, cfg converge.Config, fetcher converge.Fetcher, sink converge.Sink, timeout time.Duration) {
	t.Helper()

	backfillDone := make(chan struct{})
	backfillDoneCB := func() {
		close(
			backfillDone)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	logCtx := converge.ContextWithLogger(ctx,
		logrus.WithField("component", t.Name()))

	go func() {
		if err := converge.Run(logCtx, cfg, fetcher, sink, backfillDoneCB); err != nil && ctx.Err() == nil {
			t.Errorf("converge.Run failed: %v", err)
		}
	}()

	select {
	case <-backfillDone:
		t.Log("backfill snapshot pushed")
	case <-ctx.Done():
		t.Fatal("timed out waiting for backfill to complete")
	}

	// Let VM index the data.
	time.Sleep(1 * time.Second)
	cancel()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestIntegrationBackfillAndPush exercises the full pipeline: fetch from
// Cloudflare, run the converge runner with backfill, push the snapshot to
// VictoriaMetrics, then query VM to verify the pushed data spans the
// expected time range.
//
// Requires: CF_API_TOKEN, CF_TEST_ZONE_ID, VM_PUSH_ENDPOINT
func TestIntegrationBackfillAndPush(t *testing.T) {
	token, zoneID := skipUnlessIntegration(t)
	vmEndpoint := skipUnlessVM(t)
	sink := newSink(t, vmEndpoint)

	client := &liveGQLClient{token: token}
	zones := []cfzones.Zone{{ID: zoneID, Name: "integration-test"}}
	fetcher := cfetch.New(client, zones, nil)

	startTime := time.Now()
	cfg := converge.Config{
		Threshold:            1,
		PollInterval:         10 * time.Second,
		Lookback:             10 * time.Minute,
		MaxBackfill:          20 * time.Minute,
		BackfillChunk:        10 * time.Minute,
		BackfillCallsPerTick: 5,
	}

	runConvergeUntilBackfill(t, cfg, fetcher, sink, 2*time.Minute)

	// Query VM to verify data spans the expected range.
	expectedOldest := startTime.Add(-cfg.MaxBackfill)
	expectedNewest := startTime.Add(-2 * time.Minute)

	results := vmQueryRange(t, vmEndpoint,
		`cloudflare_zone_requests_total{zone="integration-test"}`,
		expectedOldest.Add(-5*time.Minute), time.Now(), 60)
	require.NotEmpty(t, results, "no cloudflare_zone_requests_total data in VM")

	var oldest, newest time.Time
	for _, series := range results {
		for _, v := range series.Values {
			if oldest.IsZero() || v.Time.Before(oldest) {
				oldest = v.Time
			}
			if newest.IsZero() || v.Time.After(newest) {
				newest = v.Time
			}
		}
	}

	t.Logf("VM data range: %s to %s", oldest.Format(time.RFC3339), newest.Format(time.RFC3339))
	assert.WithinDuration(t, expectedOldest, oldest, 5*time.Minute,
		"oldest data point should be near the backfill start")
	assert.WithinDuration(t, expectedNewest, newest, 5*time.Minute,
		"newest data point should be recent")
}

// TestIntegrationNoRateSpikes runs a 60-minute backfill through the full
// converge pipeline, then queries VM for rate() values and asserts that
// no single data point exceeds 10x the median rate. A spike like that
// indicates the counter chain cascade bug where intermediate prefix-sum
// states leak to the sink during backfill.
//
// Requires: CF_API_TOKEN, CF_TEST_ZONE_ID, VM_PUSH_ENDPOINT
func TestIntegrationNoRateSpikes(t *testing.T) {
	token, zoneID := skipUnlessIntegration(t)
	vmEndpoint := skipUnlessVM(t)
	sink := newSink(t, vmEndpoint)

	client := &liveGQLClient{token: token}
	zones := []cfzones.Zone{{ID: zoneID, Name: "integration-spike-test"}}
	fetcher := cfetch.New(client, zones, nil)

	startTime := time.Now()
	cfg := converge.Config{
		Threshold:            1,
		PollInterval:         10 * time.Second,
		Lookback:             10 * time.Minute,
		MaxBackfill:          60 * time.Minute,
		BackfillChunk:        10 * time.Minute,
		BackfillCallsPerTick: 10,
	}

	runConvergeUntilBackfill(t, cfg, fetcher, sink, 3*time.Minute)

	// Query the per-minute rate over the full backfill window.
	queryStart := startTime.Add(-cfg.MaxBackfill)
	results := vmQueryRange(t, vmEndpoint,
		`rate(cloudflare_zone_requests_total{zone="integration-spike-test"}[2m]) * 60`,
		queryStart, time.Now(), 60)
	require.NotEmpty(t, results, "no rate data returned from VM")

	// Collect all non-zero rate values across all series.
	var allRates []float64
	for _, series := range results {
		for _, v := range series.Values {
			if v.Value > 0 && !math.IsNaN(v.Value) && !math.IsInf(v.Value, 0) {
				allRates = append(allRates, v.Value)
			}
		}
	}
	require.NotEmpty(t, allRates, "no non-zero rate values found")

	sort.Float64s(allRates)
	median := allRates[len(allRates)/2]
	maxRate := allRates[len(allRates)-1]
	spikeMultiplier := 10.0

	t.Logf("rate samples: %d", len(allRates))
	t.Logf("median rate:  %.2f req/min", median)
	t.Logf("max rate:     %.2f req/min", maxRate)
	t.Logf("p95 rate:     %.2f req/min", allRates[int(float64(len(allRates))*0.95)])
	t.Logf("p99 rate:     %.2f req/min", allRates[int(float64(len(allRates))*0.99)])
	t.Logf("spike threshold (%.0fx median): %.2f req/min", spikeMultiplier, median*spikeMultiplier)

	if maxRate > median*spikeMultiplier {
		// Log the spike timestamps for debugging.
		threshold := median * spikeMultiplier
		t.Logf("SPIKES above %.2f req/min:", threshold)
		for _, series := range results {
			for _, v := range series.Values {
				if v.Value > threshold {
					t.Logf("  %s  %.2f req/min (%.1fx median)",
						v.Time.Format(time.RFC3339), v.Value, v.Value/median)
				}
			}
		}
	}

	assert.LessOrEqual(t, maxRate, median*spikeMultiplier,
		"rate spike detected: max %.2f req/min exceeds %.0fx median (%.2f req/min); "+
			"this indicates counter chain cascade artifacts during backfill",
		maxRate, spikeMultiplier, median)
}
