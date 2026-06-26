// Package cfetchdns implements converge.Fetcher for Cloudflare DNS analytics metrics.
//
// It queries dnsAnalyticsAdaptiveGroups over a time range and flattens the response
// into converge.Observations. The GraphQL client is injected at construction
// time via the cfgql.GQLClient interface.
package cfetchdns

import (
	"context"
	"fmt"
	"time"

	cfzones "github.com/cloudflare/cloudflare-go/v4/zones"
	"github.com/lablabs/cloudflare-exporter/cfgql"
	"github.com/lablabs/cloudflare-exporter/converge"
)

const gqlQueryLimit = 9999

const (
	metricDNSQueriesTotal  = "cloudflare_zone_dns_queries_total"
	metricDNSStaleTotal    = "cloudflare_zone_dns_stale_total"
	metricDNSUncachedTotal = "cloudflare_zone_dns_uncached_total"
)

// Fetcher implements converge.Fetcher by querying Cloudflare's GraphQL API
// for zone DNS analytics over a time range.
type Fetcher struct {
	client  cfgql.GQLClient
	zones   []cfzones.Zone
	enabled map[string]bool // metric suffixes to emit; nil = emit all
}

// New creates a Fetcher that queries the given zones using the provided
// GraphQL client. The caller is responsible for filtering out free-plan zones
// before passing them in. If enabled is non-nil, only metric suffixes present
// in the map are emitted as observations.
func New(client cfgql.GQLClient, zones []cfzones.Zone, enabled map[string]bool) *Fetcher {
	return &Fetcher{client: client, zones: zones, enabled: enabled}
}

func (f *Fetcher) Fetch(ctx context.Context, start, end time.Time) ([]converge.Observation, error) {
	return cfgql.FetchZones(ctx, f.zones, "cfetchdns", func(ctx context.Context, chunk []cfzones.Zone, ids []string) ([]converge.Observation, error) {
		resp, err := f.fetchRange(ctx, ids, start, end)
		if err != nil {
			return nil, err
		}
		var obs []converge.Observation
		for _, z := range resp.Viewer.Zones {
			obs = append(obs, flattenDNSGroups(z, cfgql.FindZoneName(chunk, z.ZoneTag), f.enabled)...)
		}
		return obs, nil
	})
}

// --- GraphQL query and response types ----------------------------------------

type rangeResponse struct {
	Viewer struct {
		Zones []zoneData `json:"zones"`
	} `json:"viewer"`
}

type zoneData struct {
	ZoneTag   string     `json:"zoneTag"`
	DNSGroups []dnsGroup `json:"dnsAnalyticsAdaptiveGroups"`
}

type dnsGroup struct {
	Count      uint64 `json:"count"`
	Dimensions struct {
		DatetimeMinute string `json:"datetimeMinute"`
		ResponseCode   string `json:"responseCode"`
		QueryType      string `json:"queryType"`
		IPVersion      string `json:"ipVersion"`
	} `json:"dimensions"`
	Sum struct {
		CountStale                uint64 `json:"countStale"`
		CountNotCachedAndNotStale uint64 `json:"countNotCachedAndNotStale"`
	} `json:"sum"`
}

const rangeQuery = `
query ($zoneIDs: [String!], $startTime: Time!, $endTime: Time!, $limit: Int!) {
	viewer {
		zones(filter: { zoneTag_in: $zoneIDs }) {
			zoneTag
			dnsAnalyticsAdaptiveGroups(
				limit: $limit,
				filter: { datetime_geq: $startTime, datetime_lt: $endTime },
				orderBy: [datetimeMinute_ASC]
			) {
				count
				dimensions {
					datetimeMinute
					responseCode
					queryType
					ipVersion
				}
				sum {
					countStale
					countNotCachedAndNotStale
				}
			}
		}
	}
}
`

func (f *Fetcher) fetchRange(ctx context.Context, zoneIDs []string, start, end time.Time) (*rangeResponse, error) {
	req := &cfgql.GQLRequest{
		Query: rangeQuery,
		Variables: map[string]any{
			"zoneIDs":   zoneIDs,
			"startTime": start.UTC().Format(time.RFC3339),
			"endTime":   end.UTC().Format(time.RFC3339),
			"limit":     gqlQueryLimit,
		},
	}

	var resp rangeResponse
	if err := f.client.RunGQL(ctx, req, &resp); err != nil {
		return nil, fmt.Errorf("fetchDNSRange: %w", err)
	}

	return &resp, nil
}

// --- Flatten -----------------------------------------------------------------

func flattenDNSGroups(z zoneData, zoneName string, enabled map[string]bool) []converge.Observation {
	var obs []converge.Observation

	emit := func(metric string, value uint64, bucket time.Time, extraLabels ...string) {
		if enabled != nil && !enabled[metric] {
			return
		}
		labelPairs := append([]string{"zone", zoneName}, extraLabels...)
		obs = append(obs, converge.Observation{
			Key:    converge.NewKey(metric, labelPairs...),
			Value:  value,
			Bucket: bucket,
		})
	}

	type bucketAgg struct {
		stale    uint64
		uncached uint64
	}
	buckets := map[time.Time]*bucketAgg{}

	for _, g := range z.DNSGroups {
		bucket, err := time.Parse(time.RFC3339, g.Dimensions.DatetimeMinute)
		if err != nil {
			continue
		}

		emit(metricDNSQueriesTotal, g.Count, bucket,
			"response_code", g.Dimensions.ResponseCode,
			"query_type", g.Dimensions.QueryType,
			"ip_version", g.Dimensions.IPVersion,
		)

		if _, ok := buckets[bucket]; !ok {
			buckets[bucket] = &bucketAgg{}
		}
		buckets[bucket].stale += g.Sum.CountStale
		buckets[bucket].uncached += g.Sum.CountNotCachedAndNotStale
	}

	for bucket, agg := range buckets {
		emit(metricDNSStaleTotal, agg.stale, bucket)
		emit(metricDNSUncachedTotal, agg.uncached, bucket)
	}

	return obs
}
