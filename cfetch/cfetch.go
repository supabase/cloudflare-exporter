// Package cfetch implements converge.Fetcher for Cloudflare zone traffic metrics.
//
// It queries httpRequests1mGroups over a time range and flattens the response
// into converge.Observations. The GraphQL client is injected at construction
// time via the GQLClient interface.
package cfetch

import (
	"context"
	"fmt"
	"time"

	cfzones "github.com/cloudflare/cloudflare-go/v4/zones"
	"github.com/lablabs/cloudflare-exporter/converge"
)

// GQLClient executes a GraphQL query. The request is JSON-encoded and POSTed.
// The root package's *GraphQL type does not satisfy this directly (it takes
// *GraphQLRequest, not *GQLRequest), so main.go wraps it with a thin adapter.
type GQLClient interface {
	RunGQL(ctx context.Context, req *GQLRequest, dest any) error
}

// GQLRequest is the GraphQL request payload.
type GQLRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

const (
	maxZonesPerQuery = 10
	gqlQueryLimit    = 9999
	metricPrefix     = "cfp_zone_"
)

// Fetcher implements converge.Fetcher by querying Cloudflare's GraphQL API
// for zone traffic metrics over a time range.
type Fetcher struct {
	client  GQLClient
	zones   []cfzones.Zone
	enabled map[string]bool // metric suffixes to emit; nil = emit all
}

// New creates a Fetcher that queries the given zones using the provided
// GraphQL client. The caller is responsible for filtering out free-plan zones
// before passing them in. If enabled is non-nil, only metric suffixes present
// in the map are emitted as observations.
func New(client GQLClient, zones []cfzones.Zone, enabled map[string]bool) *Fetcher {
	return &Fetcher{client: client, zones: zones, enabled: enabled}
}

func (f *Fetcher) Fetch(ctx context.Context, start, end time.Time) ([]converge.Observation, error) {
	var allObs []converge.Observation

	l := converge.LoggerFromContext(ctx)
	for chunk := range chunkZones(f.zones, maxZonesPerQuery) {
		ids := zoneIDs(chunk)
		resp, err := f.fetchRange(ctx, ids, start, end)
		if err != nil {
			l.WithError(err).Warn("cfetch: skipping chunk")
			continue
		}
		for _, z := range resp.Viewer.Zones {
			name := findZoneName(f.zones, z.ZoneTag)
			allObs = append(allObs, flattenHTTP1mGroups(z, name, f.enabled)...)
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
	req := &GQLRequest{
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
				Key:    converge.NewKey(metricPrefix+metric, labelPairs...),
				Value:  value,
				Bucket: bucket,
			})
		}

		// Scalar metrics
		o("requests_total", g.Sum.Requests)
		o("requests_cached", g.Sum.CachedRequests)
		o("requests_ssl_encrypted", g.Sum.EncryptedRequests)
		o("bandwidth_total", g.Sum.Bytes)
		o("bandwidth_cached", g.Sum.CachedBytes)
		o("bandwidth_ssl_encrypted", g.Sum.EncryptedBytes)
		o("pageviews_total", g.Sum.PageViews)
		o("threats_total", g.Sum.Threats)
		o("uniques_total", g.Uniq.Uniques)

		// By content type
		for _, ct := range g.Sum.ContentType {
			o("requests_content_type", ct.Requests, "content_type", ct.EdgeResponseContentType)
			o("bandwidth_content_type", ct.Bytes, "content_type", ct.EdgeResponseContentType)
		}

		// By country
		for _, c := range g.Sum.Country {
			o("requests_country", c.Requests, "country", c.ClientCountryName)
			o("bandwidth_country", c.Bytes, "country", c.ClientCountryName)
			o("threats_country", c.Threats, "country", c.ClientCountryName)
		}

		// By status code
		for _, s := range g.Sum.ResponseStatus {
			o("requests_status", s.Requests, "status",
				fmt.Sprintf("%d", s.EdgeResponseStatus))
		}

		// By browser
		for _, b := range g.Sum.BrowserMap {
			o("requests_browser_map", b.PageViews, "browser", b.UaBrowserFamily)
		}

		// By threat type
		for _, t := range g.Sum.ThreatPathing {
			o("threats_type", t.Requests, "type", t.Name)
		}
	}

	return obs
}

// --- Helpers -----------------------------------------------------------------

func chunkZones(zones []cfzones.Zone, size int) func(func([]cfzones.Zone) bool) {
	return func(yield func([]cfzones.Zone) bool) {
		for i := 0; i < len(zones); i += size {
			end := i + size
			if end > len(zones) {
				end = len(zones)
			}
			if !yield(zones[i:end]) {
				return
			}
		}
	}
}

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
