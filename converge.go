package main

import (
	"context"
	"strings"

	cfzones "github.com/cloudflare/cloudflare-go/v4/zones"
	"github.com/lablabs/cloudflare-exporter/cfetch"
	"github.com/lablabs/cloudflare-exporter/cfetchdns"
	"github.com/lablabs/cloudflare-exporter/converge"
	"github.com/lablabs/cloudflare-exporter/vmpush"
	"github.com/spf13/viper"
)

const (
	argConvergeThreshold       = "converge_threshold"
	argConvergeWindowTTL       = "converge_window_ttl"
	argConvergePollInterval    = "converge_poll_interval"
	argConvergeLookback        = "converge_lookback"
	argConvergeMaxBackfill     = "converge_max_backfill"
	argConvergeBackfillChunk   = "converge_backfill_chunk"
	argConvergeBackfillPerTick = "converge_backfill_per_tick"

	argConvergeMetrics = "metrics_converge_allowlist"

	argVMPushEndpoint = "vm_push_endpoint"
	argVMPushUser     = "vm_push_user"
	argVMPushPasswd   = "vm_push_password"
)

func getConvergeMetricsList() []string {
	if len(viper.GetString(argConvergeMetrics)) > 0 {
		return strings.Split(viper.GetString(argConvergeMetrics), ",")
	}
	return []string{}
}

// cfetchMetricNames maps canonical MetricName values to the metric name
// strings used by the cfetch package when building Observation keys.
var cfetchdnsMetricNames = map[MetricName]string{
	zoneDNSQueriesMetricName: string(zoneDNSQueriesMetricName),
}

var cfetchMetricNames = map[MetricName]string{
	zoneRequestTotalMetricName:          string(zoneRequestTotalMetricName),
	zoneRequestCachedMetricName:         string(zoneRequestCachedMetricName),
	zoneRequestSSLEncryptedMetricName:   string(zoneRequestSSLEncryptedMetricName),
	zoneRequestContentTypeMetricName:    string(zoneRequestContentTypeMetricName),
	zoneRequestCountryMetricName:        string(zoneRequestCountryMetricName),
	zoneRequestHTTPStatusMetricName:     string(zoneRequestHTTPStatusMetricName),
	zoneRequestBrowserMapMetricName:     string(zoneRequestBrowserMapMetricName),
	zoneBandwidthTotalMetricName:        string(zoneBandwidthTotalMetricName),
	zoneBandwidthCachedMetricName:       string(zoneBandwidthCachedMetricName),
	zoneBandwidthSSLEncryptedMetricName: string(zoneBandwidthSSLEncryptedMetricName),
	zoneBandwidthContentTypeMetricName:  string(zoneBandwidthContentTypeMetricName),
	zoneBandwidthCountryMetricName:      string(zoneBandwidthCountryMetricName),
	zoneThreatsTotalMetricName:          string(zoneThreatsTotalMetricName),
	zoneThreatsCountryMetricName:        string(zoneThreatsCountryMetricName),
	zoneThreatsTypeMetricName:           string(zoneThreatsTypeMetricName),
	zonePageviewsTotalMetricName:        string(zonePageviewsTotalMetricName),
	zoneUniquesTotalMetricName:          string(zoneUniquesTotalMetricName),
}

// cfetchEnabledSet builds the set of cfetch metric names to emit.
//
// When metrics_converge_allowlist is set, it is used directly (no intersection
// with the main metrics set, since the scrape and push paths are independent).
// When unset, all metrics whose canonical MetricName appears in the main
// enabled set are included. Returns nil (emit everything) when no filtering
// is needed.
func cfetchEnabledSet(enabled MetricsMap) map[string]bool {
	convergeList := getConvergeMetricsList()

	// Explicit converge allowlist: use it directly.
	if len(convergeList) > 0 {
		out := make(map[string]bool, len(convergeList))
		for _, k := range convergeList {
			if mn, ok := cfetchMetricNames[MetricName(k)]; ok {
				out[mn] = true
			}
		}
		return out
	}

	// No converge allowlist and full main metrics set: no filtering needed.
	if len(enabled) == len(metricsMap) {
		return nil
	}

	// No converge allowlist, restricted main metrics: filter to intersection.
	out := make(map[string]bool, len(cfetchMetricNames))
	for name, mn := range cfetchMetricNames {
		if _, ok := enabled[name]; ok {
			out[mn] = true
		}
	}
	return out
}

func cfetchdnsEnabledSet() map[string]bool {
	convergeList := getConvergeMetricsList()

	// No explicit converge allowlist: emit all DNS metrics unconditionally.
	// DNS metrics are converge-only and not in metricsMap.
	if len(convergeList) == 0 {
		return nil
	}

	// Explicit allowlist: only emit DNS metrics named in it.
	out := make(map[string]bool)
	for _, k := range convergeList {
		if mn, ok := cfetchdnsMetricNames[MetricName(k)]; ok {
			out[mn] = true
		}
	}
	return out
}

func convergeConfig() converge.Config {
	cfg := converge.DefaultConfig()
	cfg.Threshold = viper.GetInt(argConvergeThreshold)
	cfg.WindowTTL = viper.GetDuration(argConvergeWindowTTL)
	cfg.PollInterval = viper.GetDuration(argConvergePollInterval)
	cfg.Lookback = viper.GetDuration(argConvergeLookback)
	cfg.MaxBackfill = viper.GetDuration(argConvergeMaxBackfill)
	cfg.BackfillChunk = viper.GetDuration(argConvergeBackfillChunk)
	cfg.BackfillCallsPerTick = viper.GetInt(argConvergeBackfillPerTick)
	return cfg
}

func setupConvergerWithFetcher(ctx context.Context, component string, fetcher converge.Fetcher) (func(context.Context) error, error) {
	sink := vmpush.New(vmpush.Config{
		Endpoint: viper.GetString(argVMPushEndpoint),
		Username: viper.GetString(argVMPushUser),
		Password: viper.GetString(argVMPushPasswd),
	})
	if err := sink.Ping(ctx); err != nil {
		return nil, err
	}
	cfg := convergeConfig()
	return func(ctx context.Context) error {
		return converge.Run(
			converge.ContextWithLogger(ctx, log.WithField("component", component)),
			cfg, fetcher, sink,
		)
	}, nil
}

func setupDNSConverger(ctx context.Context, zones []cfzones.Zone, gql *GraphQL) (func(context.Context) error, error) {
	fetcher := cfetchdns.New(
		&gqlAdapter{gql},
		filterExcludedZones(zones, getExcludedZones()),
		cfetchdnsEnabledSet(),
	)
	return setupConvergerWithFetcher(ctx, "converge-dns", fetcher)
}

func setupConverger(ctx context.Context, convergeZones []cfzones.Zone, metrics MetricsMap, gql *GraphQL) (func(context.Context) error, error) {
	enabled := cfetchEnabledSet(metrics)
	log.WithField("enabled_count", len(enabled)).WithField("enabled", enabled).Info("cfetch enabled set")
	fetcher := cfetch.New(
		&gqlAdapter{gql},
		filterExcludedZones(convergeZones, getExcludedZones()),
		enabled,
	)
	return setupConvergerWithFetcher(ctx, "converge", fetcher)
}
