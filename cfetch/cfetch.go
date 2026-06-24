// Package cfetch implements converge.Fetcher for Cloudflare zone traffic metrics.
//
// It queries httpRequests1mGroups over a time range and flattens the response
// into converge.Observations. The GraphQL client is injected at construction
// time via the cfgql.GQLClient interface.
package cfetch

import (
	"context"
	"fmt"
	"time"

	cfzones "github.com/cloudflare/cloudflare-go/v4/zones"
	"github.com/lablabs/cloudflare-exporter/cfgql"
	"github.com/lablabs/cloudflare-exporter/converge"
)

const gqlQueryLimit = 9999

// Fetcher implements converge.Fetcher by querying Cloudflare's GraphQL API
// for zone traffic metrics over a time range.
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
	obs, err := cfgql.FetchZones(ctx, f.zones, "cfetch", func(ctx context.Context, chunk []cfzones.Zone, ids []string) ([]converge.Observation, error) {
		resp, err := f.fetchRange(ctx, ids, start, end)
		if err != nil {
			return nil, err
		}
		var obs []converge.Observation
		for _, z := range resp.Viewer.Zones {
			obs = append(obs, flattenHTTP1mGroups(z, cfgql.FindZoneName(chunk, z.ZoneTag), f.enabled)...)
		}
		return obs, nil
	})
	if err != nil {
		return nil, err
	}

	adaptiveObs, err := cfgql.FetchZones(ctx, f.zones, "cfetch-adaptive", func(ctx context.Context, chunk []cfzones.Zone, ids []string) ([]converge.Observation, error) {
		resp, err := f.fetchAdaptiveRange(ctx, ids, start, end)
		if err != nil {
			return nil, err
		}
		var obs []converge.Observation
		for _, z := range resp.Viewer.Zones {
			obs = append(obs, flattenHTTPAdaptiveGroups(z, cfgql.FindZoneName(chunk, z.ZoneTag), f.enabled)...)
		}
		return obs, nil
	})
	if err != nil {
		return nil, err
	}

	return append(obs, adaptiveObs...), nil
}

// --- GraphQL query and response types ----------------------------------------

type rangeResponse struct {
	Viewer struct {
		Zones []zoneData `json:"zones"`
	} `json:"viewer"`
}

type zoneData struct {
	ZoneTag      string        `json:"zoneTag"`
	HTTP1mGroups []http1mGroup `json:"httpRequests1mGroups"`
}

type http1mGroup struct {
	Uniq struct {
		Uniques uint64 `json:"uniques"`
	} `json:"uniq"`
	Sum struct {
		Requests          uint64 `json:"requests"`
		CachedRequests    uint64 `json:"cachedRequests"`
		EncryptedRequests uint64 `json:"encryptedRequests"`
		Bytes             uint64 `json:"bytes"`
		CachedBytes       uint64 `json:"cachedBytes"`
		EncryptedBytes    uint64 `json:"encryptedBytes"`
		PageViews         uint64 `json:"pageViews"`
		Threats           uint64 `json:"threats"`
		ContentType       []struct {
			Requests                uint64 `json:"requests"`
			Bytes                   uint64 `json:"bytes"`
			EdgeResponseContentType string `json:"edgeResponseContentTypeName"`
		} `json:"contentTypeMap"`
		Country []struct {
			Requests          uint64 `json:"requests"`
			Bytes             uint64 `json:"bytes"`
			Threats           uint64 `json:"threats"`
			ClientCountryName string `json:"clientCountryName"`
		} `json:"countryMap"`
		ResponseStatus []struct {
			Requests           uint64 `json:"requests"`
			EdgeResponseStatus int    `json:"edgeResponseStatus"`
		} `json:"responseStatusMap"`
		BrowserMap []struct {
			PageViews       uint64 `json:"pageViews"`
			UaBrowserFamily string `json:"uaBrowserFamily"`
		} `json:"browserMap"`
		ThreatPathing []struct {
			Requests uint64 `json:"requests"`
			Name     string `json:"threatPathingName"`
		} `json:"threatPathingMap"`
	} `json:"sum"`
	Dimensions struct {
		Datetime string `json:"datetime"`
	} `json:"dimensions"`
}

const rangeQuery = `
query ($zoneIDs: [String!], $startTime: Time!, $endTime: Time!, $limit: Int!) {
	viewer {
		zones(filter: { zoneTag_in: $zoneIDs }) {
			zoneTag
			httpRequests1mGroups(limit: $limit, filter: { datetime_geq: $startTime, datetime_lt: $endTime }) {
				uniq {
					uniques
				}
				sum {
					browserMap {
						pageViews
						uaBrowserFamily
					}
					bytes
					cachedBytes
					cachedRequests
					contentTypeMap {
						bytes
						requests
						edgeResponseContentTypeName
					}
					countryMap {
						bytes
						clientCountryName
						requests
						threats
					}
					encryptedBytes
					encryptedRequests
					pageViews
					requests
					responseStatusMap {
						edgeResponseStatus
						requests
					}
					threatPathingMap {
						requests
						threatPathingName
					}
					threats
				}
				dimensions {
					datetime
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
		return nil, fmt.Errorf("fetchZoneTrafficRange: %w", err)
	}

	return &resp, nil
}

// --- Adaptive groups (httpRequestsAdaptiveGroups) ----------------------------

type adaptiveRangeResponse struct {
	Viewer struct {
		Zones []adaptiveZoneData `json:"zones"`
	} `json:"viewer"`
}

type adaptiveZoneData struct {
	ZoneTag            string              `json:"zoneTag"`
	HTTPAdaptiveGroups []httpAdaptiveGroup `json:"httpRequestsAdaptiveGroups"`
}

type httpAdaptiveGroup struct {
	Count      uint64 `json:"count"`
	Dimensions struct {
		DatetimeMinute     string `json:"datetimeMinute"`
		EdgeResponseStatus int    `json:"edgeResponseStatus"`
	} `json:"dimensions"`
}

const adaptiveRangeQuery = `
query ($zoneIDs: [String!], $startTime: Time!, $endTime: Time!, $limit: Int!) {
	viewer {
		zones(filter: { zoneTag_in: $zoneIDs }) {
			zoneTag
			httpRequestsAdaptiveGroups(limit: $limit, filter: { datetime_geq: $startTime, datetime_lt: $endTime }, orderBy: [datetimeMinute_ASC]) {
				count
				dimensions {
					datetimeMinute
					edgeResponseStatus
				}
			}
		}
	}
}
`

func (f *Fetcher) fetchAdaptiveRange(ctx context.Context, zoneIDs []string, start, end time.Time) (*adaptiveRangeResponse, error) {
	req := &cfgql.GQLRequest{
		Query: adaptiveRangeQuery,
		Variables: map[string]any{
			"zoneIDs":   zoneIDs,
			"startTime": start.UTC().Format(time.RFC3339),
			"endTime":   end.UTC().Format(time.RFC3339),
			"limit":     gqlQueryLimit,
		},
	}

	var resp adaptiveRangeResponse
	if err := f.client.RunGQL(ctx, req, &resp); err != nil {
		return nil, fmt.Errorf("fetchZoneAdaptiveRange: %w", err)
	}

	return &resp, nil
}

func flattenHTTPAdaptiveGroups(z adaptiveZoneData, zoneName string, enabled map[string]bool) []converge.Observation {
	const metric = "cloudflare_zone_requests_status_v2"
	if enabled != nil && !enabled[metric] {
		return nil
	}

	var obs []converge.Observation
	for _, g := range z.HTTPAdaptiveGroups {
		bucket, err := time.Parse(time.RFC3339, g.Dimensions.DatetimeMinute)
		if err != nil {
			continue
		}
		obs = append(obs, converge.Observation{
			Key:    converge.NewKey(metric, "zone", zoneName, "status", fmt.Sprintf("%d", g.Dimensions.EdgeResponseStatus)),
			Value:  g.Count,
			Bucket: bucket,
		})
	}
	return obs
}

// --- Flatten -----------------------------------------------------------------

func flattenHTTP1mGroups(z zoneData, zoneName string, enabled map[string]bool) []converge.Observation {
	var obs []converge.Observation

	for _, g := range z.HTTP1mGroups {
		bucket, err := time.Parse(time.RFC3339, g.Dimensions.Datetime)
		if err != nil {
			continue
		}

		o := func(metric string, value uint64, extraLabels ...string) {
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

		// Scalar metrics
		o("cloudflare_zone_requests_total", g.Sum.Requests)
		o("cloudflare_zone_requests_cached", g.Sum.CachedRequests)
		o("cloudflare_zone_requests_ssl_encrypted", g.Sum.EncryptedRequests)
		o("cloudflare_zone_bandwidth_total", g.Sum.Bytes)
		o("cloudflare_zone_bandwidth_cached", g.Sum.CachedBytes)
		o("cloudflare_zone_bandwidth_ssl_encrypted", g.Sum.EncryptedBytes)
		o("cloudflare_zone_pageviews_total", g.Sum.PageViews)
		o("cloudflare_zone_threats_total", g.Sum.Threats)
		o("cloudflare_zone_uniques_total", g.Uniq.Uniques)

		// By content type
		for _, ct := range g.Sum.ContentType {
			o("cloudflare_zone_requests_content_type", ct.Requests, "content_type", ct.EdgeResponseContentType)
			o("cloudflare_zone_bandwidth_content_type", ct.Bytes, "content_type", ct.EdgeResponseContentType)
		}

		// By country
		for _, c := range g.Sum.Country {
			o("cloudflare_zone_requests_country", c.Requests, "country", c.ClientCountryName)
			o("cloudflare_zone_bandwidth_country", c.Bytes, "country", c.ClientCountryName)
			o("cloudflare_zone_threats_country", c.Threats, "country", c.ClientCountryName)
		}

		// By status code
		for _, s := range g.Sum.ResponseStatus {
			o("cloudflare_zone_requests_status", s.Requests, "status",
				fmt.Sprintf("%d", s.EdgeResponseStatus))
		}

		// By browser
		for _, b := range g.Sum.BrowserMap {
			o("cloudflare_zone_requests_browser_map_page_views_count", b.PageViews, "browser", b.UaBrowserFamily)
		}

		// By threat type
		for _, t := range g.Sum.ThreatPathing {
			o("cloudflare_zone_threats_type", t.Requests, "type", t.Name)
		}
	}

	return obs
}
