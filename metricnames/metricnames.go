// Package metricnames defines canonical metric name strings shared across fetcher packages.
package metricnames

const (
	// HTTP / bandwidth
	ZoneRequestsTotal              = "cloudflare_zone_requests_total"
	ZoneRequestsCached             = "cloudflare_zone_requests_cached"
	ZoneRequestsSSLEncrypted       = "cloudflare_zone_requests_ssl_encrypted"
	ZoneRequestsContentType        = "cloudflare_zone_requests_content_type"
	ZoneRequestsCountry            = "cloudflare_zone_requests_country"
	ZoneRequestsStatus             = "cloudflare_zone_requests_status"
	ZoneRequestsStatusV2           = "cloudflare_zone_requests_status_v2"
	ZoneRequestsBrowserMap         = "cloudflare_zone_requests_browser_map_page_views_count"
	ZoneBandwidthTotal             = "cloudflare_zone_bandwidth_total"
	ZoneBandwidthCached            = "cloudflare_zone_bandwidth_cached"
	ZoneBandwidthSSLEncrypted      = "cloudflare_zone_bandwidth_ssl_encrypted"
	ZoneBandwidthContentType       = "cloudflare_zone_bandwidth_content_type"
	ZoneBandwidthCountry           = "cloudflare_zone_bandwidth_country"
	ZoneThreatsTotal               = "cloudflare_zone_threats_total"
	ZoneThreatsCountry             = "cloudflare_zone_threats_country"
	ZoneThreatsType                = "cloudflare_zone_threats_type"
	ZonePageviewsTotal             = "cloudflare_zone_pageviews_total"
	ZoneUniquesTotal               = "cloudflare_zone_uniques_total"

	// DNS analytics — converge-only, no scrape path equivalent
	ZoneDNSQueriesTotal  = "cloudflare_zone_dns_queries_total"
	ZoneDNSStaleTotal    = "cloudflare_zone_dns_stale_total"
	ZoneDNSUncachedTotal = "cloudflare_zone_dns_uncached_total"
)
