package main

import (
	"context"
	"strings"

	cfzones "github.com/cloudflare/cloudflare-go/v4/zones"
	"github.com/lablabs/cloudflare-exporter/cfetch"
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

// cfetchEnabledSet translates an enabled MetricsMap into the set of cfetch
// metric suffixes. Returns nil (all enabled) when the full metricsMap is used.
func cfetchEnabledSet(enabled MetricsMap) map[string]bool {
	if len(enabled) == len(metricsMap) {
		return nil
	}

	cMetrics := make(map[string]string)

	// copy over configured after looking up in static mapping
	//
	for _, k := range getConvergeMetricsList() {
		if v, ok := cfetchSuffixes[MetricName(k)]; ok {
			cMetrics[k] = v
		}
	}

	out := make(map[string]bool, len(cfetchSuffixes))
	for name, suffix := range cMetrics {
		if _, ok := enabled[MetricName(name)]; ok {
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

func runConverger(ctx context.Context, convergeZones []cfzones.Zone, metrics MetricsMap, gql *GraphQL,
) {
	vmCfg := vmpush.Config{
		Endpoint: viper.GetString(argVMPushEndpoint),
		Username: viper.GetString(argVMPushUser),
		Password: viper.GetString(argVMPushPasswd),
	}

	go converge.Run(
		converge.ContextWithLogger(ctx,
			log.WithField("component", "converge"),
		),
		convergeConfig(),
		cfetch.New(
			&gqlAdapter{gql},
			filterExcludedZones(convergeZones, getExcludedZones()),
			cfetchEnabledSet(metrics),
		),
		vmpush.New(vmCfg),
	)
}
