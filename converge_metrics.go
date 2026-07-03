package main

import "github.com/prometheus/client_golang/prometheus"

var (
	// Convergence behavior counters. These help tune Threshold, Lookback,
	// and MaxBackfill by making the tradeoffs observable.

	// convergeIngestSamples counts samples emitted by Ingest (tracker
	// stabilizations). Higher values with a low threshold indicate
	// aggressive early pushes.
	convergeIngestSamples = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "converge_ingest_samples_total",
		Help: "Samples emitted by tracker stabilization during Ingest",
	}, []string{"component"})

	// convergePostStabilizeUpdates counts observations that changed a
	// value after the tracker had already stabilized and pushed. High
	// values suggest the threshold is too low (pushing before CF data
	// settles).
	convergePostStabilizeUpdates = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "converge_post_stabilize_updates_total",
		Help: "Observations that changed a value after initial stabilization",
	}, []string{"component"})

	// convergeExpireFlushes counts windows that were force-flushed on
	// TTL expiry because their values never stabilized. High values
	// suggest the threshold is too high (values never converge within
	// the lookback window).
	convergeExpireFlushes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "converge_expire_flushes_total",
		Help: "Windows force-flushed on TTL expiry without prior stabilization",
	}, []string{"component"})

	// convergeExpireSamples counts samples emitted by Expire (TTL
	// evictions that produced counter corrections).
	convergeExpireSamples = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "converge_expire_samples_total",
		Help: "Samples emitted during window expiry",
	}, []string{"component"})

	// convergeLiveFetchObservations counts observations received from
	// live fetches.
	convergeLiveFetchObservations = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "converge_live_fetch_observations_total",
		Help: "Observations received from live lane fetches",
	}, []string{"component"})

	// convergeBackfillFetchObservations counts observations received from
	// backfill fetches.
	convergeBackfillFetchObservations = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "converge_backfill_fetch_observations_total",
		Help: "Observations received from backfill fetches",
	}, []string{"component"})

	// convergeSnapshotSamples counts samples emitted by the post-backfill
	// snapshot push.
	convergeSnapshotSamples = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "converge_snapshot_samples_total",
		Help: "Samples emitted by the post-backfill snapshot",
	}, []string{"component"})

	// convergeOpenWindows is a gauge tracking the current number of open
	// windows in the engine.
	convergeOpenWindows = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "converge_open_windows",
		Help: "Current number of open time-bucket windows",
	}, []string{"component"})

	// convergeTrackerCount is a gauge tracking the current number of
	// active trackers across all windows.
	convergeTrackerCount = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "converge_tracker_count",
		Help: "Current number of active trackers across all windows",
	}, []string{"component"})

	// convergePushErrors counts failed Push calls to the sink.
	convergePushErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "converge_push_errors_total",
		Help: "Failed sample pushes to the sink",
	}, []string{"component"})

	// Anomaly detection counters. Both should be zero in normal operation.

	convergeGaugeDownRevisions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "converge_gauge_down_revisions_total",
		Help: "CF revised a gauge value downward (source data correction). Should be near zero.",
	}, []string{"component"})

	convergeCounterRegressions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "converge_counter_regressions_total",
		Help: "Computed counter was lower than previous emission. Should always be zero.",
	}, []string{"component"})
)

func init() {
	prometheus.MustRegister(
		convergeIngestSamples,
		convergePostStabilizeUpdates,
		convergeExpireFlushes,
		convergeExpireSamples,
		convergeLiveFetchObservations,
		convergeBackfillFetchObservations,
		convergeSnapshotSamples,
		convergeOpenWindows,
		convergeTrackerCount,
		convergePushErrors,
		convergeGaugeDownRevisions,
		convergeCounterRegressions,
	)
}
