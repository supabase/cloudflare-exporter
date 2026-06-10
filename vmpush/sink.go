// Package vmpush implements converge.Sink for VictoriaMetrics using the
// Prometheus remote write protocol (protobuf + snappy over HTTPS with
// Basic Auth).
package vmpush

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
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
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("vmpush: status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
