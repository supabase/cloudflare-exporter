// Package cfetchdns implements converge.Fetcher for Cloudflare DNS analytics metrics.
//
// It queries dnsAnalyticsAdaptiveGroups over a time range and flattens the response
// into converge.Observations. The GraphQL client is injected at construction
// time via the cfgql.GQLClient interface.
package cfetchdns

import (
	"context"
	"fmt"
	"slices"
	"time"

	cfzones "github.com/cloudflare/cloudflare-go/v4/zones"
	"github.com/lablabs/cloudflare-exporter/cfgql"
	"github.com/lablabs/cloudflare-exporter/converge"
)

const (
	maxZonesPerQuery = 10
	gqlQueryLimit    = 9999
	metricPrefix     = "cfp_zone_"
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
	var allObs []converge.Observation

	l := converge.LoggerFromContext(ctx)
	for chunk := range slices.Chunk(f.zones, maxZonesPerQuery) {
		ids := zoneIDs(chunk)
		resp, err := f.fetchRange(ctx, ids, start, end)
		if err != nil {
			l.WithError(err).Warn("cfetchdns: skipping chunk")
			continue
		}

		for _, z := range resp.Viewer.Zones {
			name := findZoneName(chunk, z.ZoneTag)
			allObs = append(allObs, flattenDNSGroups(z, name, f.enabled)...)
		}
	}

	return allObs, nil
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
	} `json:"dimensions"`
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

	for _, g := range z.DNSGroups {
		bucket, err := time.Parse(time.RFC3339, g.Dimensions.DatetimeMinute)
		if err != nil {
			continue
		}

		o := func(metric string, value uint64, extraLabels ...string) {
			if enabled != nil && !enabled[metric] {
				return
			}
			labelPairs := append([]string{"zone", zoneName}, extraLabels...)
			obs = append(obs, converge.Observation{
				Key:    converge.NewKey(metricPrefix+metric, labelPairs...),
				Value:  value,
				Bucket: bucket,
			})
		}

		o("dns_queries_total", g.Count, "response_code", g.Dimensions.ResponseCode, "query_type", g.Dimensions.QueryType)
	}

	return obs
}

// --- Helpers -----------------------------------------------------------------

func zoneIDs(zones []cfzones.Zone) []string {
	ids := make([]string, len(zones))
	for i, z := range zones {
		ids[i] = z.ID
	}
	return ids
}

func findZoneName(zones []cfzones.Zone, id string) string {
	for _, z := range zones {
		if z.ID == id {
			return z.Name
		}
	}
	return id
}
