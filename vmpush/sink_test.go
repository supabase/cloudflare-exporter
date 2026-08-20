package vmpush

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/snappy"
	"github.com/lablabs/cloudflare-exporter/converge"
	"github.com/prometheus/prometheus/prompb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyStringSimple(t *testing.T) {
	k := converge.NewKey("cloudflare_zone_requests_total", "zone", "example.com")
	assert.Equal(t, "cloudflare_zone_requests_total", k.Name)
	assert.Equal(t, `cloudflare_zone_requests_total{zone="example.com"}`, k.String())
}

func TestKeyStringMultipleLabels(t *testing.T) {
	k := converge.NewKey("cloudflare_zone_requests_country", "zone", "example.com", "country", "US")
	assert.Equal(t, "cloudflare_zone_requests_country", k.Name)
	assert.Equal(t, []converge.Label{
		{Name: "zone", Value: "example.com"},
		{Name: "country", Value: "US"},
	}, k.Labels)
}

func TestKeyStringNoLabels(t *testing.T) {
	k := converge.NewKey("cloudflare_zone_requests_total")
	assert.Equal(t, "cloudflare_zone_requests_total", k.String())
	assert.Nil(t, k.Labels)
}

// TestPushSplitsIntoBatchesUnderCap reproduces the prod incident: a single
// post-backfill snapshot with more series than fit in one VM request. Push
// must split it into multiple requests, each within maxBatchSeries.
func TestPushSplitsIntoBatchesUnderCap(t *testing.T) {
	var requestCount atomic.Int32
	var maxSeriesSeen atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		decompressed, err := snappy.Decode(nil, body)
		require.NoError(t, err)

		var wr prompb.WriteRequest
		require.NoError(t, wr.Unmarshal(decompressed))
		if n := int32(len(wr.Timeseries)); n > maxSeriesSeen.Load() {
			maxSeriesSeen.Store(n)
		}
		require.LessOrEqual(t, len(wr.Timeseries), maxBatchSeries,
			"a single request must never exceed maxBatchSeries")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink := New(Config{Endpoint: srv.URL})

	// More than 2 batches worth of series, so we exercise the loop.
	total := maxBatchSeries*2 + 1
	samples := make([]converge.Sample, total)
	for i := range samples {
		samples[i] = converge.Sample{
			Key:       converge.NewKey("cloudflare_zone_requests_status_v2", "zone", fmt.Sprintf("zone-%d.example.com", i), "status", "200"),
			Value:     uint64(i),
			Timestamp: time.Now(),
		}
	}

	err := sink.Push(context.Background(), samples)
	require.NoError(t, err)
	assert.Equal(t, int32(3), requestCount.Load(), "expected 3 batches: 2 full + 1 remainder")
	assert.LessOrEqual(t, int(maxSeriesSeen.Load()), maxBatchSeries)
}
