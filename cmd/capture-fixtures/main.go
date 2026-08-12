// Command capture-fixtures fetches Cloudflare observations for a time range
// and writes them as trimmed JSON fixtures for use in spike_test.go.
//
// Usage:
//
//	go run ./cmd/capture-fixtures \
//	  -zone 43c0ec06d9a970d6707dee37374c1b13 \
//	  -start 2026-06-26T14:00:00Z \
//	  -end   2026-06-26T14:22:00Z \
//	  -lookback 25m \
//	  -prefix spike_0626 \
//	  -metric cloudflare_zone_requests_total \
//	  -outdir converge/testdata
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	cfzones "github.com/cloudflare/cloudflare-go/v7/zones"
	"github.com/lablabs/cloudflare-exporter/cfetch"
	"github.com/lablabs/cloudflare-exporter/cfgql"
	"github.com/lablabs/cloudflare-exporter/converge"
)

type gqlClient struct{ token string }

type gqlResponse struct {
	Data   any        `json:"data"`
	Errors []gqlError `json:"errors"`
}
type gqlError struct {
	Message string `json:"message"`
}

func (c *gqlClient) RunGQL(ctx context.Context, req *cfgql.GQLRequest, dest any) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	body, _ := json.Marshal(req)
	httpReq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.cloudflare.com/client/v4/graphql/",
		bytes.NewReader(body))
	httpReq.Header.Set("Accept", "application/json; charset=utf-8")
	httpReq.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var gResp gqlResponse
	gResp.Data = dest
	if err := json.NewDecoder(resp.Body).Decode(&gResp); err != nil {
		return err
	}
	for _, e := range gResp.Errors {
		return fmt.Errorf("graphql: %s", e.Message)
	}
	return nil
}

type recordedFetch struct {
	Seq          int                   `json:"seq"`
	Start        time.Time             `json:"start"`
	End          time.Time             `json:"end"`
	Observations []recordedObservation `json:"observations"`
}

type recordedObservation struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
	Value  uint64            `json:"value"`
	Bucket time.Time         `json:"bucket"`
}

func main() {
	var (
		zoneID = flag.String("zone", "", "Cloudflare zone ID")
		startS = flag.String("start", "", "start time (RFC3339)")
		endS   = flag.String("end", "", "end time (RFC3339)")
		lookb  = flag.Duration("lookback", 25*time.Minute, "lookback duration for the live fetch")
		chunk  = flag.Duration("chunk", 10*time.Minute, "backfill chunk size")
		prefix = flag.String("prefix", "spike", "filename prefix")
		metric = flag.String("metric", "cloudflare_zone_requests_total", "metric to keep (empty = all)")
		outdir = flag.String("outdir", "converge/testdata", "output directory")
	)
	flag.Parse()

	token := os.Getenv("CF_API_TOKEN")
	if token == "" {
		log.Fatal("CF_API_TOKEN required")
	}
	if *zoneID == "" || *startS == "" || *endS == "" {
		log.Fatal("-zone, -start, -end are required")
	}

	start, err := time.Parse(time.RFC3339, *startS)
	if err != nil {
		log.Fatalf("bad -start: %v", err)
	}
	end, err := time.Parse(time.RFC3339, *endS)
	if err != nil {
		log.Fatalf("bad -end: %v", err)
	}

	client := &gqlClient{token: token}
	zones := []cfzones.Zone{{ID: *zoneID, Name: "captured"}}
	fetcher := cfetch.New(client, zones, nil)
	ctx := context.Background()

	os.MkdirAll(*outdir, 0755)

	seq := 0

	// Live fetch: [end - lookback, end]
	liveStart := end.Add(-*lookb)
	writeFetch(ctx, fetcher, liveStart, end, seq, *prefix, *metric, *outdir)
	seq++

	// Backfill: [start, end - lookback] in chunks
	cursor := start
	limit := end.Add(-*lookb)
	for cursor.Before(limit) {
		chunkEnd := cursor.Add(*chunk)
		if chunkEnd.After(limit) {
			chunkEnd = limit
		}
		writeFetch(ctx, fetcher, cursor, chunkEnd, seq, *prefix, *metric, *outdir)
		seq++
		cursor = chunkEnd
	}

	log.Printf("wrote %d fixture files to %s", seq, *outdir)
}

func writeFetch(ctx context.Context, f converge.Fetcher, start, end time.Time, seq int, prefix, metric, outdir string) {
	obs, err := f.Fetch(ctx, start, end)
	if err != nil {
		log.Printf("WARN: fetch [%s, %s] failed: %v", start, end, err)
		return
	}

	rec := recordedFetch{
		Seq:   seq,
		Start: start,
		End:   end,
	}
	for _, o := range obs {
		if metric != "" && o.Key.Name != metric {
			continue
		}
		labels := make(map[string]string, len(o.Key.Labels))
		for _, l := range o.Key.Labels {
			labels[l.Name] = l.Value
		}
		rec.Observations = append(rec.Observations, recordedObservation{
			Name:   o.Key.Name,
			Labels: labels,
			Value:  o.Value,
			Bucket: o.Bucket,
		})
	}

	path := fmt.Sprintf("%s/%s_%03d.json", outdir, prefix, seq)
	data, _ := json.MarshalIndent(rec, "", "  ")
	os.WriteFile(path, data, 0600)
	log.Printf("%s: %d obs (filtered from %d) [%s, %s]",
		path, len(rec.Observations), len(obs),
		start.Format(time.RFC3339), end.Format(time.RFC3339))
}
