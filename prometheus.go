package main

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	cfaccounts "github.com/cloudflare/cloudflare-go/v4/accounts"
	cfzones "github.com/cloudflare/cloudflare-go/v4/zones"
	"github.com/prometheus/client_golang/prometheus"
)

type MetricName string

func (mn MetricName) String() string {
	return string(mn)
}

const (
	zoneRequestTotalMetricName                     MetricName = "cloudflare_zone_requests_total"
	zoneRequestCachedMetricName                    MetricName = "cloudflare_zone_requests_cached"
	zoneRequestSSLEncryptedMetricName              MetricName = "cloudflare_zone_requests_ssl_encrypted"
	zoneRequestContentTypeMetricName               MetricName = "cloudflare_zone_requests_content_type"
	zoneRequestCountryMetricName                   MetricName = "cloudflare_zone_requests_country"
	zoneRequestHTTPStatusMetricName                MetricName = "cloudflare_zone_requests_status"
	zoneRequestHTTPStatusV2MetricName              MetricName = "cloudflare_zone_requests_status_v2"
	zoneRequestBrowserMapMetricName                MetricName = "cloudflare_zone_requests_browser_map_page_views_count"
	zoneRequestOriginStatusCountryHostMetricName   MetricName = "cloudflare_zone_requests_origin_status_country_host"
	zoneRequestStatusCountryHostMetricName         MetricName = "cloudflare_zone_requests_status_country_host"
	zoneBandwidthTotalMetricName                   MetricName = "cloudflare_zone_bandwidth_total"
	zoneBandwidthCachedMetricName                  MetricName = "cloudflare_zone_bandwidth_cached"
	zoneBandwidthSSLEncryptedMetricName            MetricName = "cloudflare_zone_bandwidth_ssl_encrypted"
	zoneBandwidthContentTypeMetricName             MetricName = "cloudflare_zone_bandwidth_content_type"
	zoneBandwidthCountryMetricName                 MetricName = "cloudflare_zone_bandwidth_country"
	zoneThreatsTotalMetricName                     MetricName = "cloudflare_zone_threats_total"
	zoneThreatsCountryMetricName                   MetricName = "cloudflare_zone_threats_country"
	zoneThreatsTypeMetricName                      MetricName = "cloudflare_zone_threats_type"
	zonePageviewsTotalMetricName                   MetricName = "cloudflare_zone_pageviews_total"
	zoneUniquesTotalMetricName                     MetricName = "cloudflare_zone_uniques_total"
	zoneColocationVisitsMetricName                 MetricName = "cloudflare_zone_colocation_visits"
	zoneColocationEdgeResponseBytesMetricName      MetricName = "cloudflare_zone_colocation_edge_response_bytes"
	zoneColocationRequestsTotalMetricName          MetricName = "cloudflare_zone_colocation_requests_total"
	zoneFirewallEventsCountMetricName              MetricName = "cloudflare_zone_firewall_events_count"
	zoneHealthCheckEventsOriginCountMetricName     MetricName = "cloudflare_zone_health_check_events_origin_count"
	zoneWorkerRequestHTTPStatusMetricName          MetricName = "cloudflare_zone_worker_requests_status"
	workerRequestsMetricName                       MetricName = "cloudflare_worker_requests_count"
	workerErrorsMetricName                         MetricName = "cloudflare_worker_errors_count"
	workerCPUTimeMetricName                        MetricName = "cloudflare_worker_cpu_time"
	workerDurationMetricName                       MetricName = "cloudflare_worker_duration"
	workerDeploymentsMetricName                    MetricName = "cloudflare_worker_deployments"
	poolHealthStatusMetricName                     MetricName = "cloudflare_zone_pool_health_status"
	poolRequestsTotalMetricName                    MetricName = "cloudflare_zone_pool_requests_total"
	poolOriginHealthStatusMetricName               MetricName = "cloudflare_pool_origin_health_status"
	logpushFailedJobsAccountMetricName             MetricName = "cloudflare_logpush_failed_jobs_account_count"
	logpushFailedJobsZoneMetricName                MetricName = "cloudflare_logpush_failed_jobs_zone_count"
	r2StorageTotalMetricName                       MetricName = "cloudflare_r2_storage_total_bytes"
	r2StorageMetricName                            MetricName = "cloudflare_r2_storage_bytes"
	r2OperationMetricName                          MetricName = "cloudflare_r2_operation_count"
	zoneCustomHostnamesTotalMetricName             MetricName = "cloudflare_zone_custom_hostnames_total"
	accountCustomHostnamesQuotaAllocatedMetricName MetricName = "cloudflare_account_custom_hostnames_quota_allocated"
	accountCustomHostnamesQuotaUsedMetricName      MetricName = "cloudflare_account_custom_hostnames_quota_used"
)

type MetricsMap map[MetricName]trackedMetric

func recordError(action string, err error) {
	exporterErrors.WithLabelValues(action).Inc()
	log.Error(err)
}

var (
	exporterErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cloudflare_exporter_errors",
			Help: "Number of errors when attempting to pull metrics",
		},
		[]string{"action"},
	)

	trackedMetrics = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "cloudflare_exporter_tracked_metrics",
			Help: "Number of metrics tracked",
		},
	)

	expiredMetrics = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "cloudflare_exporter_expired_metrics",
			Help: "Count of metrics deleted due to expiration",
		},
	)

	// Requests
	zoneRequestTotal = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: zoneRequestTotalMetricName.String(),
			Help: "Number of requests for zone",
		},
		[]string{"zone", "account"},
	))

	zoneRequestCached = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: zoneRequestCachedMetricName.String(),
			Help: "Number of cached requests for zone",
		},
		[]string{"zone", "account"},
	))

	zoneRequestSSLEncrypted = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: zoneRequestSSLEncryptedMetricName.String(),
			Help: "Number of encrypted requests for zone",
		},
		[]string{"zone", "account"},
	))

	zoneRequestContentType = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: zoneRequestContentTypeMetricName.String(),
			Help: "Number of request for zone per content type",
		},
		[]string{"zone", "account", "content_type"},
	))

	zoneRequestCountry = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: zoneRequestCountryMetricName.String(),
			Help: "Number of request for zone per country",
		},
		[]string{"zone", "account", "country"},
	))

	zoneRequestHTTPStatus = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: zoneRequestHTTPStatusMetricName.String(),
			Help: "Number of request for zone per HTTP status",
		},
		[]string{"zone", "account", "status"},
	))

	zoneRequestHTTPStatusV2 = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: zoneRequestHTTPStatusV2MetricName.String(),
			Help: "Number of request for zone per HTTP status from adaptive groups",
		},
		[]string{"zone", "account", "status"},
	))

	zoneRequestBrowserMap = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: zoneRequestBrowserMapMetricName.String(),
			Help: "Number of successful requests for HTML pages per zone",
		},
		[]string{"zone", "account", "family"},
	))

	zoneRequestOriginStatusCountryHost = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: zoneRequestOriginStatusCountryHostMetricName.String(),
			Help: "Count of not cached requests for zone per origin HTTP status per country per host",
		},
		[]string{"zone", "account", "status", "country", "host"},
	))

	zoneRequestStatusCountryHost = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: zoneRequestStatusCountryHostMetricName.String(),
			Help: "Count of requests for zone per edge HTTP status per country per host",
		},
		[]string{"zone", "account", "status", "country", "host"},
	))

	zoneBandwidthTotal = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: zoneBandwidthTotalMetricName.String(),
			Help: "Total bandwidth per zone in bytes",
		},
		[]string{"zone", "account"},
	))

	zoneBandwidthCached = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: zoneBandwidthCachedMetricName.String(),
			Help: "Cached bandwidth per zone in bytes",
		},
		[]string{"zone", "account"},
	))

	zoneBandwidthSSLEncrypted = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: zoneBandwidthSSLEncryptedMetricName.String(),
			Help: "Encrypted bandwidth per zone in bytes",
		},
		[]string{"zone", "account"},
	))

	zoneBandwidthContentType = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: zoneBandwidthContentTypeMetricName.String(),
			Help: "Bandwidth per zone per content type",
		},
		[]string{"zone", "account", "content_type"},
	))

	zoneBandwidthCountry = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: zoneBandwidthCountryMetricName.String(),
			Help: "Bandwidth per country per zone",
		},
		[]string{"zone", "account", "country"},
	))

	zoneThreatsTotal = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: zoneThreatsTotalMetricName.String(),
			Help: "Threats per zone",
		},
		[]string{"zone", "account"},
	))

	zoneThreatsCountry = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: zoneThreatsCountryMetricName.String(),
			Help: "Threats per zone per country",
		},
		[]string{"zone", "account", "country"},
	))

	zoneThreatsType = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: zoneThreatsTypeMetricName.String(),
			Help: "Threats per zone per type",
		},
		[]string{"zone", "account", "type"},
	))

	zonePageviewsTotal = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: zonePageviewsTotalMetricName.String(),
			Help: "Pageviews per zone",
		},
		[]string{"zone", "account"},
	))

	zoneUniquesTotal = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: zoneUniquesTotalMetricName.String(),
			Help: "Uniques per zone",
		},
		[]string{"zone", "account"},
	))

	zoneColocationVisits = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: zoneColocationVisitsMetricName.String(),
			Help: "Total visits per colocation",
		},
		[]string{"zone", "account", "colocation", "host"},
	))

	zoneColocationEdgeResponseBytes = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: zoneColocationEdgeResponseBytesMetricName.String(),
			Help: "Edge response bytes per colocation",
		},
		[]string{"zone", "account", "colocation", "host"},
	))

	zoneColocationRequestsTotal = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: zoneColocationRequestsTotalMetricName.String(),
			Help: "Total requests per colocation",
		},
		[]string{"zone", "account", "colocation", "host"},
	))

	zoneFirewallEventsCount = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: zoneFirewallEventsCountMetricName.String(),
			Help: "Count of Firewall events",
		},
		[]string{"zone", "account", "action", "source", "rule", "host", "country"},
	))

	zoneHealthCheckEventsOriginCount = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: zoneHealthCheckEventsOriginCountMetricName.String(),
			Help: "Number of Heath check events per region per origin",
		},
		[]string{"zone", "account", "health_status", "origin_ip", "region", "fqdn"},
	))

	zoneWorkerRequestHTTPStatus = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: zoneWorkerRequestHTTPStatusMetricName.String(),
			Help: "Number of requests processed by zone and script ID",
		},
		[]string{"zone", "script_id", "status"},
	))

	workerRequests = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: workerRequestsMetricName.String(),
			Help: "Number of requests sent to worker by script name",
		},
		[]string{"script_name", "account", "status"},
	))

	workerErrors = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: workerErrorsMetricName.String(),
			Help: "Number of errors by script name",
		},
		[]string{"script_name", "account", "status"},
	))

	workerCPUTime = NewTrackedGauge(prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: workerCPUTimeMetricName.String(),
			Help: "CPU time quantiles by script name",
		},
		[]string{"script_name", "account", "status", "quantile"},
	))

	workerDuration = NewTrackedGauge(prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: workerDurationMetricName.String(),
			Help: "Duration quantiles by script name (GB*s)",
		},
		[]string{"script_name", "account", "status", "quantile"},
	))

	workerDeployments = NewTrackedGauge(prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: workerDeploymentsMetricName.String(),
			Help: "Deployment version percentages",
		},
		[]string{"script_name", "account", "version"},
	))

	poolHealthStatus = NewTrackedGauge(prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: poolHealthStatusMetricName.String(),
			Help: "Reports the health of a pool, 1 for healthy, 0 for unhealthy.",
		},
		[]string{"zone", "account", "load_balancer_name", "pool_name"},
	))

	poolOriginHealthStatus = NewTrackedGauge(prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: poolOriginHealthStatusMetricName.String(),
			Help: "Reports the origin health of a pool, 1 for healthy, 0 for unhealthy.",
		},
		[]string{"account", "pool_name", "origin_name", "ip"},
	))

	poolRequestsTotal = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: poolRequestsTotalMetricName.String(),
			Help: "Requests per pool",
		},
		[]string{"zone", "account", "load_balancer_name", "pool_name", "origin_name"},
	))

	// TODO: Update this to counter vec and use counts from the query to add
	logpushFailedJobsAccount = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: logpushFailedJobsAccountMetricName.String(),
			Help: "Number of failed logpush jobs on the account level",
		},
		[]string{"account", "destination", "job_id", "final"},
	))

	logpushFailedJobsZone = NewTrackedCounter(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: logpushFailedJobsZoneMetricName.String(),
			Help: "Number of failed logpush jobs on the zone level",
		},
		[]string{"destination", "job_id", "final"},
	))

	r2StorageTotal = NewTrackedGauge(prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: r2StorageTotalMetricName.String(),
			Help: "Total storage used by R2",
		},
		[]string{"account"},
	))

	r2Storage = NewTrackedGauge(prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: r2StorageMetricName.String(),
			Help: "Storage used by R2",
		},
		[]string{"account", "bucket"},
	))

	r2Operation = NewTrackedGauge(prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: r2OperationMetricName.String(),
			Help: "Number of operations performed by R2",
		},
		[]string{"account", "bucket", "operation"},
	))

	zoneCustomHostnamesTotal = NewTrackedGauge(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: zoneCustomHostnamesTotalMetricName.String(),
		Help: "Total number of custom hostnames configured for the zone",
	}, []string{"zone", "account"}))

	accountCustomHostnamesQuotaAllocated = NewTrackedGauge(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: accountCustomHostnamesQuotaAllocatedMetricName.String(),
		Help: "Allocated quota for custom hostnames for the account",
	}, []string{"account"}))

	accountCustomHostnamesQuotaUsed = NewTrackedGauge(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: accountCustomHostnamesQuotaUsedMetricName.String(),
		Help: "Used custom hostnames quota for the account",
	}, []string{"account"}))

	metricsMap = MetricsMap{}
)

func init() {
	prometheus.MustRegister(exporterErrors)
	prometheus.MustRegister(trackedMetrics)
	prometheus.MustRegister(expiredMetrics)

	metricsMap[zoneRequestTotalMetricName] = zoneRequestTotal
	metricsMap[zoneRequestCachedMetricName] = zoneRequestCached
	metricsMap[zoneRequestSSLEncryptedMetricName] = zoneRequestSSLEncrypted
	metricsMap[zoneRequestContentTypeMetricName] = zoneRequestContentType
	metricsMap[zoneRequestCountryMetricName] = zoneRequestCountry
	metricsMap[zoneRequestHTTPStatusMetricName] = zoneRequestHTTPStatus
	metricsMap[zoneRequestHTTPStatusV2MetricName] = zoneRequestHTTPStatusV2
	metricsMap[zoneRequestBrowserMapMetricName] = zoneRequestBrowserMap
	metricsMap[zoneRequestOriginStatusCountryHostMetricName] = zoneRequestOriginStatusCountryHost
	metricsMap[zoneRequestStatusCountryHostMetricName] = zoneRequestStatusCountryHost
	metricsMap[zoneBandwidthTotalMetricName] = zoneBandwidthTotal
	metricsMap[zoneBandwidthCachedMetricName] = zoneBandwidthCached
	metricsMap[zoneBandwidthSSLEncryptedMetricName] = zoneBandwidthSSLEncrypted
	metricsMap[zoneBandwidthContentTypeMetricName] = zoneBandwidthContentType
	metricsMap[zoneBandwidthCountryMetricName] = zoneBandwidthCountry
	metricsMap[zoneThreatsTotalMetricName] = zoneThreatsTotal
	metricsMap[zoneThreatsCountryMetricName] = zoneThreatsCountry
	metricsMap[zoneThreatsTypeMetricName] = zoneThreatsType
	metricsMap[zonePageviewsTotalMetricName] = zonePageviewsTotal
	metricsMap[zoneUniquesTotalMetricName] = zoneUniquesTotal
	metricsMap[zoneColocationVisitsMetricName] = zoneColocationVisits
	metricsMap[zoneColocationEdgeResponseBytesMetricName] = zoneColocationEdgeResponseBytes
	metricsMap[zoneColocationRequestsTotalMetricName] = zoneColocationRequestsTotal
	metricsMap[zoneFirewallEventsCountMetricName] = zoneFirewallEventsCount
	metricsMap[zoneHealthCheckEventsOriginCountMetricName] = zoneHealthCheckEventsOriginCount
	metricsMap[zoneWorkerRequestHTTPStatusMetricName] = zoneWorkerRequestHTTPStatus
	metricsMap[workerRequestsMetricName] = workerRequests
	metricsMap[workerErrorsMetricName] = workerErrors
	metricsMap[workerCPUTimeMetricName] = workerCPUTime
	metricsMap[workerDurationMetricName] = workerDuration
	metricsMap[workerDeploymentsMetricName] = workerDeployments
	metricsMap[poolHealthStatusMetricName] = poolHealthStatus
	metricsMap[poolOriginHealthStatusMetricName] = poolOriginHealthStatus
	metricsMap[poolRequestsTotalMetricName] = poolRequestsTotal
	metricsMap[logpushFailedJobsAccountMetricName] = logpushFailedJobsAccount
	metricsMap[logpushFailedJobsZoneMetricName] = logpushFailedJobsZone
	metricsMap[r2StorageTotalMetricName] = r2StorageTotal
	metricsMap[r2StorageMetricName] = r2Storage
	metricsMap[r2OperationMetricName] = r2Operation
	metricsMap[zoneCustomHostnamesTotalMetricName] = zoneCustomHostnamesTotal
	metricsMap[accountCustomHostnamesQuotaAllocatedMetricName] = accountCustomHostnamesQuotaAllocated
	metricsMap[accountCustomHostnamesQuotaUsedMetricName] = accountCustomHostnamesQuotaUsed
}

func buildDeniedMetricsSet(metricsDenylist []string) (MetricsMap, error) {
	out := maps.Clone(metricsMap)
	for _, metric := range metricsDenylist {
		name := MetricName(metric)
		if _, found := out[name]; !found {
			return nil, fmt.Errorf("metric %s doesn't exists", name)
		}
		delete(out, name)
	}
	return out, nil
}

func buildAllowedMetricsSet(allowList []string) (MetricsMap, error) {
	out := MetricsMap{}
	for _, metric := range allowList {
		name := MetricName(metric)
		metric, found := metricsMap[name]
		if !found {
			return nil, fmt.Errorf("metric %s doesn't exists", name)
		}
		out[name] = metric
	}
	return out, nil
}

// check if none of the `metricNames` are in `metrics` we can skip
func shouldSkip(ctx context.Context, metricNames ...MetricName) bool {
	metricsCtx := MetricsCtxFromContext(ctx)
	for name := range metricsCtx.metrics {
		if slices.Contains(metricNames, name) {
			return false
		}
	}
	return true
}

func fetchLoadblancerPoolsHealth(ctx context.Context, account cfaccounts.Account) {
	if shouldSkip(ctx, poolOriginHealthStatusMetricName) {
		return
	}

	pools := fetchLoadbalancerPools(ctx, account)
	if pools == nil {
		return
	}

	for _, pool := range pools {
		if !pool.Enabled { // not enabled, no health values
			continue
		}
		if pool.Monitor == "" { // No monitor, no health values
			continue
		}
		for _, o := range pool.Origins {
			if !o.Enabled { // not enabled, no health values
				continue
			}
			healthy := 1 // Assume healthy
			if o.JSON.ExtraFields["healthy"].Raw() == "false" {
				healthy = 0 // Unhealthy
			}
			poolOriginHealthStatus.Set(
				float64(healthy),
				account.Name, // account_name
				pool.Name,    // pool_name
				o.Name,       // origin_name
				o.Address,    // ip
			)
		}
	}
}

func fetchWorkerDeployments(ctx context.Context, account cfaccounts.Account) {
	if shouldSkip(ctx, workerDeploymentsMetricName) {
		return
	}

	deployedVersions, err := getWorkerDeployments(ctx, account.ID)
	if err != nil {
		recordError("getWorkerDeployments", fmt.Errorf("failed to fetch worker deployments for account %q: %w", account.ID, err))
		return
	}

	for _, version := range deployedVersions {
		workerDeployments.Set(
			version.Percentage,
			version.ID,        // script_name
			account.ID,        // account
			version.VersionID, // version
		)
	}
}

func fetchWorkerAnalytics(ctx context.Context, account cfaccounts.Account) {
	if shouldSkip(
		ctx,
		workerRequestsMetricName,
		workerErrorsMetricName,
		workerCPUTimeMetricName,
		workerDurationMetricName,
	) {
		return
	}

	r, err := fetchWorkerTotals(ctx, account.ID)
	if err != nil {
		recordError("fetchWorkerTotals", fmt.Errorf("failed to fetch worker analytics for account %q: %w", account.ID, err))
		return
	}

	// Replace spaces with hyphens and convert to lowercase
	accountName := strings.ToLower(strings.ReplaceAll(account.Name, " ", "-"))

	for _, a := range r.Viewer.Accounts {
		for _, w := range a.WorkersInvocationsAdaptive {
			workerRequests.Add(float64(w.Sum.Requests), w.Dimensions.ScriptName, accountName, w.Dimensions.Status)
			workerErrors.Add(float64(w.Sum.Errors), w.Dimensions.ScriptName, accountName, w.Dimensions.Status)

			workerCPUTime.Set(float64(w.Quantiles.CPUTimeP50), w.Dimensions.ScriptName, accountName, w.Dimensions.Status, "P50")
			workerCPUTime.Set(float64(w.Quantiles.CPUTimeP75), w.Dimensions.ScriptName, accountName, w.Dimensions.Status, "P75")
			workerCPUTime.Set(float64(w.Quantiles.CPUTimeP99), w.Dimensions.ScriptName, accountName, w.Dimensions.Status, "P99")
			workerCPUTime.Set(float64(w.Quantiles.CPUTimeP999), w.Dimensions.ScriptName, accountName, w.Dimensions.Status, "P999")

			workerDuration.Set(float64(w.Quantiles.DurationP50), w.Dimensions.ScriptName, accountName, w.Dimensions.Status, "P50")
			workerDuration.Set(float64(w.Quantiles.DurationP75), w.Dimensions.ScriptName, accountName, w.Dimensions.Status, "P75")
			workerDuration.Set(float64(w.Quantiles.DurationP99), w.Dimensions.ScriptName, accountName, w.Dimensions.Status, "P99")
			workerDuration.Set(float64(w.Quantiles.DurationP999), w.Dimensions.ScriptName, accountName, w.Dimensions.Status, "P999")
		}
	}
}

func fetchLogpushAnalyticsForAccount(ctx context.Context, account cfaccounts.Account) {
	if shouldSkip(ctx, logpushFailedJobsAccountMetricName) {
		return
	}

	r, err := fetchLogpushAccount(ctx, account.ID)

	if err != nil {
		recordError("fetchLogpushAccount", fmt.Errorf("failed to fetch logpush analytics for account %q: %w", account.ID, err))
		return
	}

	for _, acc := range r.Viewer.Accounts {
		for _, LogpushHealthAdaptiveGroup := range acc.LogpushHealthAdaptiveGroups {
			logpushFailedJobsAccount.Add(
				float64(LogpushHealthAdaptiveGroup.Count),
				account.ID,
				LogpushHealthAdaptiveGroup.Dimensions.DestinationType,
				strconv.Itoa(LogpushHealthAdaptiveGroup.Dimensions.JobID),
				strconv.Itoa(LogpushHealthAdaptiveGroup.Dimensions.Final),
			)
		}
	}
}

func fetchR2StorageForAccount(ctx context.Context, account cfaccounts.Account) {
	if shouldSkip(
		ctx,
		r2StorageMetricName,
		r2OperationMetricName,
		r2StorageTotalMetricName,
	) {
		return
	}

	r, err := fetchR2Account(ctx, account.ID)
	if err != nil {
		recordError("fetchR2Account", fmt.Errorf("failed to fetch R2 account %q: %w", account.ID, err))
		return
	}

	for _, acc := range r.Viewer.Accounts {
		var totalStorage uint64
		for _, bucket := range acc.R2StorageGroups {
			totalStorage += bucket.Max.PayloadSize
			r2Storage.Set(
				float64(bucket.Max.PayloadSize),
				account.Name,                 // account
				bucket.Dimensions.BucketName, // bucket
			)
		}
		for _, operation := range acc.R2StorageOperations {
			r2Operation.Set(
				float64(operation.Sum.Requests),
				account.Name,                    // account
				operation.Dimensions.BucketName, // bucket
				operation.Dimensions.Action,     // operation
			)
		}
		r2StorageTotal.Set(
			float64(totalStorage),
			account.Name, // account
		)
	}
}

func fetchLogpushAnalyticsForZone(ctx context.Context, zones []cfzones.Zone) {
	if shouldSkip(ctx, logpushFailedJobsZoneMetricName) {
		return
	}

	zones = filterNonFreePlanZones(zones)

	zoneIDs := extractZoneIDs(zones)
	if len(zoneIDs) == 0 {
		return
	}

	r, err := fetchLogpushZone(ctx, zoneIDs)
	if err != nil {
		recordError("fetchLogpushZone", fmt.Errorf("failed to fetch logpush analytics for zones %v: %w", zoneIDs, err))
		return
	}

	for _, zone := range r.Viewer.Zones {
		for _, LogpushHealthAdaptiveGroup := range zone.LogpushHealthAdaptiveGroups {
			logpushFailedJobsZone.Add(
				float64(LogpushHealthAdaptiveGroup.Count),
				LogpushHealthAdaptiveGroup.Dimensions.DestinationType,
				strconv.Itoa(LogpushHealthAdaptiveGroup.Dimensions.JobID),
				strconv.Itoa(LogpushHealthAdaptiveGroup.Dimensions.Final),
			)
		}
	}
}

func fetchZoneColocationAnalytics(ctx context.Context, zones []cfzones.Zone) {
	if shouldSkip(
		ctx,
		zoneColocationVisitsMetricName,
		zoneColocationEdgeResponseBytesMetricName,
		zoneColocationRequestsTotalMetricName,
	) {
		return
	}

	// Colocation metrics are not available in non-enterprise zones
	zones = filterNonFreePlanZones(zones)

	zoneIDs := extractZoneIDs(zones)
	if len(zoneIDs) == 0 {
		return
	}

	r, err := fetchColoTotals(ctx, zoneIDs)
	if err != nil {
		recordError("fetchColoTotals", fmt.Errorf("failed to fetch colocation analytics for zones %v: %w", zoneIDs, err))
		return
	}
	for _, z := range r.Viewer.Zones {
		cg := z.ColoGroups
		name, account := findZoneAccountName(zones, z.ZoneTag)
		for _, c := range cg {
			zoneColocationVisits.Add(float64(c.Sum.Visits), name, account, c.Dimensions.ColoCode, c.Dimensions.Host)
			zoneColocationEdgeResponseBytes.Add(float64(c.Sum.EdgeResponseBytes), name, account, c.Dimensions.ColoCode, c.Dimensions.Host)
			zoneColocationRequestsTotal.Add(float64(c.Count), name, account, c.Dimensions.ColoCode, c.Dimensions.Host)
		}
	}
}
func fetchZoneWorkerAnalytics(ctx context.Context, zones []cfzones.Zone) {
	if shouldSkip(ctx, zoneWorkerRequestHTTPStatusMetricName) {
		return
	}

	zoneIDs := extractZoneIDs(zones)
	if len(zoneIDs) == 0 {
		return
	}

	r, err := fetchZoneWorkerRequestTotals(ctx, zoneIDs)
	if err != nil {
		recordError("fetchZoneWorkerRequestTotals", fmt.Errorf("failed to fetch worker request analytics for zones %v: %w", zoneIDs, err))
		return
	}
	for _, z := range r.Viewer.Zones {
		for _, d := range z.Data {
			zoneWorkerRequestHTTPStatus.Add(
				float64(d.Sum.Requests),
				z.ZoneID,
				strconv.FormatUint(d.Dimensions.ScriptID, 10),
				strconv.FormatUint(d.Dimensions.Status, 10),
			)
		}
	}
}

func fetchZoneAnalytics(ctx context.Context, zones []cfzones.Zone) {
	if shouldSkip(
		ctx,
		zoneRequestTotalMetricName,
		zoneRequestCachedMetricName,
		zoneRequestSSLEncryptedMetricName,
		zoneRequestContentTypeMetricName,
		zoneBandwidthContentTypeMetricName,
		zoneRequestCountryMetricName,
		zoneBandwidthCountryMetricName,
		zoneThreatsCountryMetricName,
		zoneRequestHTTPStatusMetricName,
		zoneRequestHTTPStatusV2MetricName,
		zoneRequestBrowserMapMetricName,
		zoneBandwidthTotalMetricName,
		zoneBandwidthCachedMetricName,
		zoneBandwidthSSLEncryptedMetricName,
		zoneThreatsTotalMetricName,
		zoneThreatsTypeMetricName,
		zonePageviewsTotalMetricName,
		zoneUniquesTotalMetricName,

		zoneFirewallEventsCountMetricName,

		zoneHealthCheckEventsOriginCountMetricName,

		zoneRequestOriginStatusCountryHostMetricName,
		zoneRequestStatusCountryHostMetricName,
	) {
		return
	}

	// None of the below referenced metrics are available in the free tier
	zones = filterNonFreePlanZones(zones)

	zoneIDs := extractZoneIDs(zones)
	if len(zoneIDs) == 0 {
		return
	}

	r, err := fetchZoneTotals(ctx, zoneIDs)
	if err != nil {
		recordError("fetchZoneTotals", fmt.Errorf("failed to fetch zone analytics %v: %w", zoneIDs, err))
		return
	}

	for _, z := range r.Viewer.Zones {
		name, account := findZoneAccountName(zones, z.ZoneTag)
		z := z

		addHTTPGroups(&z, name, account)
		addFirewallGroups(ctx, &z, name, account)
		addHealthCheckGroups(&z, name, account)
		addHTTPAdaptiveGroups(&z, name, account)
	}

	// Fetch v2 status metrics using adaptive groups
	if !shouldSkip(ctx, zoneRequestHTTPStatusV2MetricName) {
		r2, err := fetchZoneStatusAdaptive(ctx, zoneIDs)
		if err != nil {
			recordError("fetchZoneStatusAdaptive", fmt.Errorf("failed to fetch zone status adaptive analytics %v: %w", zoneIDs, err))
		} else {
			for _, z := range r2.Viewer.Zones {
				name, account := findZoneAccountName(zones, z.ZoneTag)
				for _, g := range z.HTTPRequestsAdaptiveGroups {
					zoneRequestHTTPStatusV2.Add(
						float64(g.Count),
						name,
						account,
						strconv.Itoa(int(g.Dimensions.EdgeResponseStatus)),
					)
				}
			}
		}
	}
}

func addHTTPGroups(z *zoneResp, name string, account string) {
	// Nothing to do.
	if len(z.HTTP1mGroups) == 0 {
		return
	}

	zt := z.HTTP1mGroups[0]

	zoneRequestTotal.Add(float64(zt.Sum.Requests), name, account)
	zoneRequestCached.Add(float64(zt.Sum.CachedRequests), name, account)
	zoneRequestSSLEncrypted.Add(float64(zt.Sum.EncryptedRequests), name, account)

	for _, ct := range zt.Sum.ContentType {
		zoneRequestContentType.Add(float64(ct.Requests), name, account, ct.EdgeResponseContentType)
		zoneBandwidthContentType.Add(float64(ct.Bytes), name, account, ct.EdgeResponseContentType)
	}

	for _, country := range zt.Sum.Country {
		zoneRequestCountry.Add(float64(country.Requests), name, account, country.ClientCountryName)
		zoneBandwidthCountry.Add(float64(country.Bytes), name, account, country.ClientCountryName)
		zoneThreatsCountry.Add(float64(country.Threats), name, account, country.ClientCountryName)
	}

	for _, status := range zt.Sum.ResponseStatus {
		zoneRequestHTTPStatus.Add(float64(status.Requests), name, account, strconv.Itoa(status.EdgeResponseStatus))
	}

	for _, browser := range zt.Sum.BrowserMap {
		zoneRequestBrowserMap.Add(float64(browser.PageViews), name, account, browser.UaBrowserFamily)
	}

	zoneBandwidthTotal.Add(float64(zt.Sum.Bytes), name, account)
	zoneBandwidthCached.Add(float64(zt.Sum.CachedBytes), name, account)
	zoneBandwidthSSLEncrypted.Add(float64(zt.Sum.EncryptedBytes), name, account)

	zoneThreatsTotal.Add(float64(zt.Sum.Threats), name, account)

	for _, t := range zt.Sum.ThreatPathing {
		zoneThreatsType.Add(float64(t.Requests), name, account, t.Name)
	}

	zonePageviewsTotal.Add(float64(zt.Sum.PageViews), name, account)

	// Uniques
	zoneUniquesTotal.Add(float64(zt.Unique.Uniques), name, account)
}

func addFirewallGroups(ctx context.Context, z *zoneResp, name string, account string) {
	if shouldSkip(ctx, zoneFirewallEventsCountMetricName) {
		return
	}

	// Nothing to do.
	if len(z.FirewallEventsAdaptiveGroups) == 0 {
		return
	}
	rulesMap := fetchFirewallRules(ctx, z.ZoneTag)
	for _, g := range z.FirewallEventsAdaptiveGroups {
		zoneFirewallEventsCount.Add(
			float64(g.Count),
			name,
			account,
			g.Dimensions.Action,
			g.Dimensions.Source,
			normalizeRuleName(rulesMap[g.Dimensions.RuleID]),
			g.Dimensions.ClientRequestHTTPHost,
			g.Dimensions.ClientCountryName,
		)
	}
}

func normalizeRuleName(initialText string) string {
	maxLength := 200
	nonSpaceName := strings.ReplaceAll(strings.ToLower(initialText), " ", "_")
	if len(nonSpaceName) > maxLength {
		return nonSpaceName[:maxLength]
	}
	return nonSpaceName
}

func addHealthCheckGroups(z *zoneResp, name string, account string) {
	if len(z.HealthCheckEventsAdaptiveGroups) == 0 {
		return
	}

	for _, g := range z.HealthCheckEventsAdaptiveGroups {
		zoneHealthCheckEventsOriginCount.Add(
			float64(g.Count),
			name,
			account,
			g.Dimensions.HealthStatus,
			g.Dimensions.OriginIP,
			g.Dimensions.Region,
			g.Dimensions.Fqdn,
		)
	}
}

func addHTTPAdaptiveGroups(z *zoneResp, name string, account string) {
	for _, g := range z.HTTPRequestsAdaptiveGroups {
		zoneRequestOriginStatusCountryHost.Add(
			float64(g.Count),
			name,
			account,
			strconv.Itoa(int(g.Dimensions.OriginResponseStatus)),
			g.Dimensions.ClientCountryName,
			g.Dimensions.ClientRequestHTTPHost,
		)
	}

	for _, g := range z.HTTPRequestsEdgeCountryHost {
		zoneRequestStatusCountryHost.Add(
			float64(g.Count),
			name,
			account,
			strconv.Itoa(int(g.Dimensions.EdgeResponseStatus)),
			g.Dimensions.ClientCountryName,
			g.Dimensions.ClientRequestHTTPHost,
		)
	}
}

func fetchLoadBalancerAnalytics(ctx context.Context, zones []cfzones.Zone) {
	if shouldSkip(
		ctx,
		poolHealthStatusMetricName,
		poolRequestsTotalMetricName,
	) {
		return
	}
	// None of the below referenced metrics are available in the free tier
	zones = filterNonFreePlanZones(zones)

	zoneIDs := extractZoneIDs(zones)
	if len(zoneIDs) == 0 {
		return
	}

	l, err := fetchLoadBalancerTotals(ctx, zoneIDs)
	if err != nil {
		recordError("fetchLoadBalancerTotals", fmt.Errorf("failed to fetch load balancer analytics for zones %v: %w", zoneIDs, err))
		return
	}
	for _, lb := range l.Viewer.Zones {
		name, account := findZoneAccountName(zones, lb.ZoneTag)
		lb := lb
		addLoadBalancingRequestsAdaptive(&lb, name, account)
		addLoadBalancingRequestsAdaptiveGroups(&lb, name, account)
	}
}

func addLoadBalancingRequestsAdaptiveGroups(z *lbResp, name string, account string) {
	for _, g := range z.LoadBalancingRequestsAdaptiveGroups {
		poolRequestsTotal.Add(
			float64(g.Count),
			name,
			account,
			g.Dimensions.LbName,
			g.Dimensions.SelectedPoolName,
			g.Dimensions.SelectedOriginName,
		)
	}
}

func addLoadBalancingRequestsAdaptive(z *lbResp, name string, account string) {
	for _, g := range z.LoadBalancingRequestsAdaptive {
		for _, p := range g.Pools {
			poolHealthStatus.Set(
				float64(p.Healthy),
				name,       // zone
				account,    // account
				g.LbName,   // load_balancer_name
				p.PoolName, // pool_name
			)
		}
	}
}

func fetchCustomHostnamesMetrics(ctx context.Context, zones []cfzones.Zone) {
	skipTotal := shouldSkip(ctx, zoneCustomHostnamesTotalMetricName)
	skipQuota := shouldSkip(ctx, accountCustomHostnamesQuotaAllocatedMetricName, accountCustomHostnamesQuotaUsedMetricName)

	if skipTotal && skipQuota {
		return
	}

	for _, zone := range zones {
		// Fetch count if needed
		if !skipTotal {
			count, err := fetchCustomHostnamesCount(ctx, zone.ID)
			if err != nil {
				log.Errorf("failed to fetch custom hostnames count for zone %s: %v", zone.Name, err)
			} else {
				zoneCustomHostnamesTotal.Set(float64(count), zone.Name, zone.Account.Name)
			}
		}

		// Fetch quota if needed
		if !skipQuota {
			// the endpoint requires zone ID but returns account level quota
			quota, err := fetchCustomHostnamesQuota(ctx, zone.ID)
			if err != nil {
				log.Errorf("failed to fetch custom hostnames quota for zone %s: %v", zone.Name, err)
			} else {
				accountCustomHostnamesQuotaAllocated.Set(float64(quota.Allocated), zone.Account.Name)
				accountCustomHostnamesQuotaUsed.Set(float64(quota.Used), zone.Account.Name)
			}
		}
	}
}
