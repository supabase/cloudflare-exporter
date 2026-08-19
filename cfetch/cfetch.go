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

	cfzones "github.com/cloudflare/cloudflare-go/v7/zones"
	"github.com/lablabs/cloudflare-exporter/cfgql"
	"github.com/lablabs/cloudflare-exporter/converge"
	"github.com/lablabs/cloudflare-exporter/metricnames"
)

const gqlQueryLimit = 9999

// Fetcher implements converge.Fetcher by querying Cloudflare's GraphQL API
// for zone traffic metrics over a time range.
type Fetcher struct {
	client  cfgql.GQLClient
	zones   []cfzones.Zone
	enabled map[string]bool // metric suffixes to emit; nil = emit all

	// Per-zone known statuses for zero-filling (see flattenStatusCounts).
	// Unlocked: Fetch only ever runs on one goroutine (converge/runner.go).
	knownStatusesV2 map[string]map[int]bool
	knownStatuses1m map[string]map[int]bool
}

// New creates a Fetcher that queries the given zones using the provided
// GraphQL client. The caller is responsible for filtering out free-plan zones
// before passing them in. If enabled is non-nil, only metric suffixes present
// in the map are emitted as observations.
func New(client cfgql.GQLClient, zones []cfzones.Zone, enabled map[string]bool) *Fetcher {
	return &Fetcher{
		client:          client,
		zones:           zones,
		enabled:         enabled,
		knownStatusesV2: make(map[string]map[int]bool),
		knownStatuses1m: make(map[string]map[int]bool),
	}
}

func (f *Fetcher) Fetch(ctx context.Context, start, end time.Time) ([]converge.Observation, error) {
	obs, err := cfgql.FetchZones(ctx, f.zones, "cfetch", func(ctx context.Context, chunk []cfzones.Zone, ids []string) ([]converge.Observation, error) {
		resp, err := f.fetchRange(ctx, ids, start, end)
		if err != nil {
			return nil, err
		}
		var obs []converge.Observation
		for _, z := range resp.Viewer.Zones {
			obs = append(obs, f.flattenHTTP1mGroups(z, cfgql.FindZoneName(chunk, z.ZoneTag))...)
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
			obs = append(obs, f.flattenHTTPAdaptiveGroups(z, cfgql.FindZoneName(chunk, z.ZoneTag))...)
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

// zoneStatusSet returns the get-or-create known-status set for a zone within
// the given per-path registry.
func zoneStatusSet(registry map[string]map[int]bool, zoneTag string) map[int]bool {
	known := registry[zoneTag]
	if known == nil {
		known = make(map[int]bool)
		registry[zoneTag] = known
	}
	return known
}

// flattenStatusCounts emits one Observation per (bucket, status) in known -
// the real count, or zero if that status was absent (a confirmed zero, not a gap).
func flattenStatusCounts(metric, zoneName string, known map[int]bool, bucketCounts map[time.Time]map[int]uint64) []converge.Observation {
	var obs []converge.Observation
	for bucket, counts := range bucketCounts {
		for status := range known {
			obs = append(obs, converge.Observation{
				Key:    converge.NewKey(metric, "zone", zoneName, "status", fmt.Sprintf("%d", status)),
				Value:  counts[status], // zero value if status absent from counts == confirmed zero
				Bucket: bucket,
			})
		}
	}
	return obs
}

// flattenHTTPAdaptiveGroups converts one zone's adaptive groups response into
// Observations, zero-filling absent known statuses (see flattenStatusCounts).
func (f *Fetcher) flattenHTTPAdaptiveGroups(z adaptiveZoneData, zoneName string) []converge.Observation {
	const metric = metricnames.ZoneRequestsStatusV2
	if f.enabled != nil && !f.enabled[metric] {
		return nil
	}

	known := zoneStatusSet(f.knownStatusesV2, z.ZoneTag)

	byBucket := make(map[time.Time]map[int]uint64)
	for _, g := range z.HTTPAdaptiveGroups {
		bucket, err := time.Parse(time.RFC3339, g.Dimensions.DatetimeMinute)
		if err != nil {
			continue
		}
		if byBucket[bucket] == nil {
			byBucket[bucket] = make(map[int]uint64)
		}
		byBucket[bucket][g.Dimensions.EdgeResponseStatus] = g.Count
		known[g.Dimensions.EdgeResponseStatus] = true
	}

	return flattenStatusCounts(metric, zoneName, known, byBucket)
}

// --- Flatten -----------------------------------------------------------------

// flattenHTTP1mGroups converts one zone's 1-minute-group response into
// Observations, zero-filling the status breakdown the same way as
// flattenHTTPAdaptiveGroups (see flattenStatusCounts). Every other
// metric here is emitted as before.
func (f *Fetcher) flattenHTTP1mGroups(z zoneData, zoneName string) []converge.Observation {
	var obs []converge.Observation

	known := zoneStatusSet(f.knownStatuses1m, z.ZoneTag)
	statusByBucket := make(map[time.Time]map[int]uint64)
	const statusMetric = metricnames.ZoneRequestsStatus
	statusEnabled := f.enabled == nil || f.enabled[statusMetric]

	for _, g := range z.HTTP1mGroups {
		bucket, err := time.Parse(time.RFC3339, g.Dimensions.Datetime)
		if err != nil {
			continue
		}

		o := func(metric string, value uint64, extraLabels ...string) {
			if f.enabled != nil && !f.enabled[metric] {
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
		o(metricnames.ZoneRequestsTotal, g.Sum.Requests)
		o(metricnames.ZoneRequestsCached, g.Sum.CachedRequests)
		o(metricnames.ZoneRequestsSSLEncrypted, g.Sum.EncryptedRequests)
		o(metricnames.ZoneBandwidthTotal, g.Sum.Bytes)
		o(metricnames.ZoneBandwidthCached, g.Sum.CachedBytes)
		o(metricnames.ZoneBandwidthSSLEncrypted, g.Sum.EncryptedBytes)
		o(metricnames.ZonePageviewsTotal, g.Sum.PageViews)
		o(metricnames.ZoneThreatsTotal, g.Sum.Threats)
		o(metricnames.ZoneUniquesTotal, g.Uniq.Uniques)

		// By content type
		for _, ct := range g.Sum.ContentType {
			o(metricnames.ZoneRequestsContentType, ct.Requests, "content_type", ct.EdgeResponseContentType)
			o(metricnames.ZoneBandwidthContentType, ct.Bytes, "content_type", ct.EdgeResponseContentType)
		}

		// By country
		for _, c := range g.Sum.Country {
			o(metricnames.ZoneRequestsCountry, c.Requests, "country", c.ClientCountryName)
			o(metricnames.ZoneBandwidthCountry, c.Bytes, "country", c.ClientCountryName)
			o(metricnames.ZoneThreatsCountry, c.Threats, "country", c.ClientCountryName)
		}

		// By status code - collected for zero-fill below, skipped if disabled.
		if statusEnabled {
			if statusByBucket[bucket] == nil {
				statusByBucket[bucket] = make(map[int]uint64)
			}
			for _, s := range g.Sum.ResponseStatus {
				statusByBucket[bucket][s.EdgeResponseStatus] = s.Requests
				known[s.EdgeResponseStatus] = true
			}
		}

		// By browser
		for _, b := range g.Sum.BrowserMap {
			o(metricnames.ZoneRequestsBrowserMap, b.PageViews, "browser", b.UaBrowserFamily)
		}

		// By threat type
		for _, t := range g.Sum.ThreatPathing {
			o(metricnames.ZoneThreatsType, t.Requests, "type", t.Name)
		}
	}

	if statusEnabled {
		obs = append(obs, flattenStatusCounts(statusMetric, zoneName, known, statusByBucket)...)
	}

	return obs
}
