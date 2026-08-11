// Package metricnames defines canonical metric name strings for all Cloudflare exporter metrics.
package metricnames

const (
	// HTTP requests / bandwidth
	ZoneRequestsTotal                   = "cloudflare_zone_requests_total"
	ZoneRequestsCached                  = "cloudflare_zone_requests_cached"
	ZoneRequestsSSLEncrypted            = "cloudflare_zone_requests_ssl_encrypted"
	ZoneRequestsContentType             = "cloudflare_zone_requests_content_type"
	ZoneRequestsCountry                 = "cloudflare_zone_requests_country"
	ZoneRequestsStatus                  = "cloudflare_zone_requests_status"
	ZoneRequestsStatusV2                = "cloudflare_zone_requests_status_v2"
	ZoneRequestsBrowserMap              = "cloudflare_zone_requests_browser_map_page_views_count"
	ZoneRequestsOriginStatusCountryHost = "cloudflare_zone_requests_origin_status_country_host"
	ZoneRequestsStatusCountryHost       = "cloudflare_zone_requests_status_country_host"
	ZoneBandwidthTotal                  = "cloudflare_zone_bandwidth_total"
	ZoneBandwidthCached                 = "cloudflare_zone_bandwidth_cached"
	ZoneBandwidthSSLEncrypted           = "cloudflare_zone_bandwidth_ssl_encrypted"
	ZoneBandwidthContentType            = "cloudflare_zone_bandwidth_content_type"
	ZoneBandwidthCountry                = "cloudflare_zone_bandwidth_country"
	ZoneThreatsTotal                    = "cloudflare_zone_threats_total"
	ZoneThreatsCountry                  = "cloudflare_zone_threats_country"
	ZoneThreatsType                     = "cloudflare_zone_threats_type"
	ZonePageviewsTotal                  = "cloudflare_zone_pageviews_total"
	ZoneUniquesTotal                    = "cloudflare_zone_uniques_total"

	// Colocation
	ZoneColocationVisits            = "cloudflare_zone_colocation_visits"
	ZoneColocationEdgeResponseBytes = "cloudflare_zone_colocation_edge_response_bytes"
	ZoneColocationRequestsTotal     = "cloudflare_zone_colocation_requests_total"

	// Firewall / health checks
	ZoneFirewallEventsCount          = "cloudflare_zone_firewall_events_count"
	ZoneHealthCheckEventsOriginCount = "cloudflare_zone_health_check_events_origin_count"

	// Workers
	ZoneWorkerRequestsStatus = "cloudflare_zone_worker_requests_status"
	WorkerRequests           = "cloudflare_worker_requests_count"
	WorkerErrors             = "cloudflare_worker_errors_count"
	WorkerCPUTime            = "cloudflare_worker_cpu_time"
	WorkerDuration           = "cloudflare_worker_duration"
	WorkerDeployments        = "cloudflare_worker_deployments"

	// Load balancer pools
	PoolHealthStatus       = "cloudflare_zone_pool_health_status"
	PoolRequestsTotal      = "cloudflare_zone_pool_requests_total"
	PoolOriginHealthStatus = "cloudflare_pool_origin_health_status"

	// Logpush
	LogpushFailedJobsAccount = "cloudflare_logpush_failed_jobs_account_count"
	LogpushFailedJobsZone    = "cloudflare_logpush_failed_jobs_zone_count"

	// R2 storage
	R2StorageTotal = "cloudflare_r2_storage_total_bytes"
	R2Storage      = "cloudflare_r2_storage_bytes"
	R2Operation    = "cloudflare_r2_operation_count"

	// Custom hostnames
	ZoneCustomHostnamesTotal             = "cloudflare_zone_custom_hostnames_total"
	AccountCustomHostnamesQuotaAllocated = "cloudflare_account_custom_hostnames_quota_allocated"
	AccountCustomHostnamesQuotaUsed      = "cloudflare_account_custom_hostnames_quota_used"

	// DNS record quotas
	ZoneDNSRecordQuotaAllocated    = "cloudflare_zone_dns_record_quota_allocated"
	ZoneDNSRecordQuotaUsed         = "cloudflare_zone_dns_record_quota_used"
	AccountDNSRecordQuotaAllocated = "cloudflare_account_dns_record_quota_allocated"
	AccountDNSRecordQuotaUsed      = "cloudflare_account_dns_record_quota_used"

	// DNS analytics — converge-only, no scrape path equivalent
	ZoneDNSQueriesTotal  = "cloudflare_zone_dns_queries_total"
	ZoneDNSStaleTotal    = "cloudflare_zone_dns_stale_total"
	ZoneDNSUncachedTotal = "cloudflare_zone_dns_uncached_total"
)
