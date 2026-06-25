// Package vmpush implements converge.Sink for VictoriaMetrics using the
// Prometheus remote write protocol (protobuf + snappy over HTTPS with
// Basic Auth).
package vmpush

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/golang/snappy"
	"github.com/prometheus/prometheus/prompb"

	"github.com/lablabs/cloudflare-exporter/converge"
)

// Sink pushes converge.Samples to VictoriaMetrics.
type Sink struct {
	endpoint string
	username string
	password string
	client   *http.Client
}

// Config holds the settings for creating a Sink.
type Config struct {
	Endpoint string
	Username string
	Password string
}

// New creates a Sink configured to push to the given VM endpoint.
func New(cfg Config) *Sink {
	return &Sink{
		endpoint: cfg.Endpoint,
		username: cfg.Username,
		password: cfg.Password,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

// Ping checks that the endpoint is reachable and credentials are not rejected.
// It issues a GET against the write endpoint. This confirms network
// connectivity and catches auth failures, but does not validate that the
// write path itself will accept data.
func (s *Sink) Ping(ctx context.Context) error {
	if s.endpoint == "" {
		return fmt.Errorf("vmpush: endpoint not configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint, nil)
	if err != nil {
		return fmt.Errorf("vmpush: ping: %w", err)
	}
	if len(s.username) > 0 || len(s.password) > 0 {
		req.SetBasicAuth(s.username, s.password)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("vmpush: ping: %w", err)
	}
	resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("vmpush: ping: authentication failed (status %d)", resp.StatusCode)
	case http.StatusNotFound:
		return fmt.Errorf("vmpush: ping: endpoint not found (status %d)", resp.StatusCode)
	}

	return nil
}

// Push sends samples to VictoriaMetrics using Prometheus remote write.
func (s *Sink) Push(ctx context.Context, samples []converge.Sample) error {
	if len(samples) == 0 {
		return nil
	}

	ts := make([]prompb.TimeSeries, 0, len(samples))
	for _, sample := range samples {
		pbLabels := make([]prompb.Label, 0, len(sample.Key.Labels)+1)
		pbLabels = append(pbLabels, prompb.Label{Name: "__name__", Value: sample.Key.Name})
		for _, lbl := range sample.Key.Labels {
			pbLabels = append(pbLabels, prompb.Label{Name: lbl.Name, Value: lbl.Value})
		}
		ts = append(ts, prompb.TimeSeries{
			Labels: pbLabels,
			Samples: []prompb.Sample{{
				Value:     float64(sample.Value),
				Timestamp: sample.Timestamp.UnixMilli(),
			}},
		})
	}

	wr := &prompb.WriteRequest{Timeseries: ts}
	data, err := wr.Marshal()
	if err != nil {
		return fmt.Errorf("vmpush: marshal: %w", err)
	}
	// TODO:
	//
	// reduce allocations with buffer pools, the
	// - protobuf
	// - snappy encoding.
	//
	// protobuf: has MarshalTo which can write into an existing byte slice
	// snappy.Encode: allows using the first argument for this
	compressed := snappy.Encode(nil, data)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(compressed))
	if err != nil {
		return fmt.Errorf("vmpush: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Content-Encoding", "snappy")
	req.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")
	if len(s.username) > 0 || len(s.password) > 0 {
		req.SetBasicAuth(s.username, s.password)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("vmpush: send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// protects against unbounded error body reading
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return fmt.Errorf("vmpush: status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// LastValues queries VM for the most recent value of each series matching
// the given metric selector (e.g. `{__name__=~"cloudflare_zone_.*"}`).
// The lookback controls how far back to search. Returns a map keyed by
// converge.Key.String() to the last counter value.
//
// The query endpoint is derived from the write endpoint by replacing
// /api/v1/write with /api/v1/query.
func (s *Sink) LastValues(ctx context.Context, selector string, lookback time.Duration) (map[string]converge.Sample, error) {
	queryURL := strings.Replace(s.endpoint, "/api/v1/write", "/api/v1/query", 1)

	query := fmt.Sprintf(`last_over_time(%s[%s])`, selector, lookback.String())
	params := url.Values{
		"query": {query},
		"time":  {strconv.FormatInt(time.Now().Unix(), 10)},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("vmpush: last values: %w", err)
	}
	if len(s.username) > 0 || len(s.password) > 0 {
		req.SetBasicAuth(s.username, s.password)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vmpush: last values: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("vmpush: last values read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vmpush: last values status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Status string `json:"status"`
		Data   struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Value  []any             `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("vmpush: last values decode: %w", err)
	}
	if result.Status != "success" {
		return nil, fmt.Errorf("vmpush: last values query failed: %s", string(body))
	}

	out := make(map[string]converge.Sample, len(result.Data.Result))
	for _, r := range result.Data.Result {
		name := r.Metric["__name__"]
		delete(r.Metric, "__name__")

		var labels []converge.Label
		for k, v := range r.Metric {
			labels = append(labels, converge.Label{Name: k, Value: v})
		}
		key := converge.Key{Name: name, Labels: labels}

		val, err := strconv.ParseFloat(r.Value[1].(string), 64)
		if err != nil {
			continue
		}
		ts := time.Unix(int64(r.Value[0].(float64)), 0)

		out[key.String()] = converge.Sample{
			Key:       key,
			Value:     uint64(val),
			Timestamp: ts,
		}
	}

	return out, nil
}
