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

// cfetchSuffixes maps canonical MetricName values to the short metric suffix
// strings used by the cfetch package when building Observation keys. This is
// the single place that bridges the two naming schemes.
var cfetchSuffixes = map[MetricName]string{
	zoneRequestTotalMetricName:          "requests_total",
	zoneRequestCachedMetricName:         "requests_cached",
	zoneRequestSSLEncryptedMetricName:   "requests_ssl_encrypted",
	zoneRequestContentTypeMetricName:    "requests_content_type",
	zoneRequestCountryMetricName:        "requests_country",
	zoneRequestHTTPStatusMetricName:     "requests_status",
	zoneRequestBrowserMapMetricName:     "requests_browser_map",
	zoneBandwidthTotalMetricName:        "bandwidth_total",
	zoneBandwidthCachedMetricName:       "bandwidth_cached",
	zoneBandwidthSSLEncryptedMetricName: "bandwidth_ssl_encrypted",
	zoneBandwidthContentTypeMetricName:  "bandwidth_content_type",
	zoneBandwidthCountryMetricName:      "bandwidth_country",
	zoneThreatsTotalMetricName:          "threats_total",
	zoneThreatsCountryMetricName:        "threats_country",
	zoneThreatsTypeMetricName:           "threats_type",
	zonePageviewsTotalMetricName:        "pageviews_total",
	zoneUniquesTotalMetricName:          "uniques_total",
}

// cfetchEnabledSet builds the set of cfetch metric suffixes to emit.
//
// When metrics_converge_allowlist is set, only those metrics (intersected with
// the main enabled set) are included. When unset, all suffixes whose canonical
// MetricName appears in the main enabled set are included. Returns nil (emit
// everything) when no filtering is needed.
func cfetchEnabledSet(enabled MetricsMap) map[string]bool {
	convergeList := getConvergeMetricsList()

	// No converge allowlist and full main metrics set: no filtering needed.
	if len(convergeList) == 0 && len(enabled) == len(metricsMap) {
		return nil
	}

	// Determine which canonical names to consider.
	candidates := cfetchSuffixes
	if len(convergeList) > 0 {
		candidates = make(map[MetricName]string, len(convergeList))
		for _, k := range convergeList {
			if suffix, ok := cfetchSuffixes[MetricName(k)]; ok {
				candidates[MetricName(k)] = suffix
			}
		}
	}

	out := make(map[string]bool, len(candidates))
	for name, suffix := range candidates {
		if _, ok := enabled[name]; ok {
			out[suffix] = true
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

func setupDNSConverger(ctx context.Context, zones []cfzones.Zone, gql *GraphQL) (func(context.Context) error, error) {
	sink := vmpush.New(vmpush.Config{
		Endpoint: viper.GetString(argVMPushEndpoint),
		Username: viper.GetString(argVMPushUser),
		Password: viper.GetString(argVMPushPasswd),
	})
	if err := sink.Ping(ctx); err != nil {
		return nil, err
	}
	fetcher := cfetchdns.New(
		&gqlDNSAdapter{gql},
		filterExcludedZones(zones, getExcludedZones()),
		nil,
	)
	return func(ctx context.Context) error {
		return converge.Run(
			converge.ContextWithLogger(ctx, log.WithField("component", "converge-dns")),
			convergeConfig(), fetcher, sink,
		)
	}, nil
}

// setupConverger validates the sink and returns a closure that runs the
// converge loop. The caller decides whether to run it in a goroutine.
func setupConverger(ctx context.Context, convergeZones []cfzones.Zone, metrics MetricsMap, gql *GraphQL,
) (func(context.Context) error, error) {
	sink := vmpush.New(vmpush.Config{
		Endpoint: viper.GetString(argVMPushEndpoint),
		Username: viper.GetString(argVMPushUser),
		Password: viper.GetString(argVMPushPasswd),
	})

	if err := sink.Ping(ctx); err != nil {
		return nil, err
	}

	cfg := convergeConfig()
	fetcher := cfetch.New(
		&gqlAdapter{gql},
		filterExcludedZones(convergeZones, getExcludedZones()),
		cfetchEnabledSet(metrics),
	)

	return func(ctx context.Context) error {
		return converge.Run(
			converge.ContextWithLogger(ctx, log.WithField("component", "converge")),
			cfg, fetcher, sink,
		)
	}, nil
}
