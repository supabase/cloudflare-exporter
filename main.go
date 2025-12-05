package main

import (
	"context"
	"maps"
	"net/http"
	_ "net/http/pprof" // #nosec G108 - pprof is controlled via enable_pprof flag
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nelkinda/health-go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	cf "github.com/cloudflare/cloudflare-go/v4"
	cfaccounts "github.com/cloudflare/cloudflare-go/v4/accounts"
	cfoption "github.com/cloudflare/cloudflare-go/v4/option"
	cfzones "github.com/cloudflare/cloudflare-go/v4/zones"
	"github.com/sirupsen/logrus"
)

var (
	cfclient *cf.Client
	gql      *GraphQL
	log      = logrus.New()
)

// var (
// 	cfgListen          = ":8080"
// 	cfgCfAPIKey        = ""
// 	cfgCfAPIEmail      = ""
// 	cfgCfAPIToken      = ""
// 	cfgMetricsPath     = "/metrics"
// 	cfgZones           = ""
// 	cfgExcludeZones    = ""
// 	cfgScrapeDelay     = 300
// 	cfgFreeTier        = false
// 	cfgMetricsDenylist = ""
// )

func getTargetZones() []string {
	var zoneIDs []string

	if len(viper.GetString("cf_zones")) > 0 {
		zoneIDs = strings.Split(viper.GetString("cf_zones"), ",")
	}
	return zoneIDs
}

func getExcludedZones() []string {
	var zoneIDs []string

	if len(viper.GetString("cf_exclude_zones")) > 0 {
		zoneIDs = strings.Split(viper.GetString("cf_exclude_zones"), ",")
	}
	return zoneIDs
}

func filterZones(all []cfzones.Zone, target []string) []cfzones.Zone {
	var filtered []cfzones.Zone

	if (len(target)) == 0 {
		return all
	}

	for _, tz := range target {
		for _, z := range all {
			if tz == z.ID {
				filtered = append(filtered, z)
				log.Debug("Filtering zone: ", z.ID, " ", z.Name)
			}
		}
	}

	return filtered
}

func filterExcludedZones(all []cfzones.Zone, exclude []string) []cfzones.Zone {
	var filtered []cfzones.Zone

	if (len(exclude)) == 0 {
		return all
	}

	for _, z := range all {
		if slices.Contains(exclude, z.ID) {
			log.Info("Exclude zone: ", z.ID, " ", z.Name)
		} else {
			filtered = append(filtered, z)
		}
	}

	return filtered
}

type metricsCtx struct {
	startTime time.Time
	endTime   time.Time
	metrics   MetricsMap
}

type metricsCtxKeyType string

const metricsCtxKey = metricsCtxKeyType("metricsCtx")

func ContextWithMetricsCtx(ctx context.Context, startTime, endTime time.Time, metrics MetricsMap) context.Context {
	return context.WithValue(ctx, metricsCtxKey, &metricsCtx{startTime, endTime, metrics})
}

func MetricsCtxFromContext(ctx context.Context) *metricsCtx {
	return ctx.Value(metricsCtxKey).(*metricsCtx)
}

func fetchMetrics(ctx context.Context, accounts []cfaccounts.Account, zones []cfzones.Zone) {
	var wg sync.WaitGroup

	for _, a := range accounts {
		wg.Go(func() { fetchWorkerDeployments(ctx, a) })
		wg.Go(func() { fetchWorkerAnalytics(ctx, a) })
		wg.Go(func() { fetchLogpushAnalyticsForAccount(ctx, a) })
		wg.Go(func() { fetchR2StorageForAccount(ctx, a) })
		wg.Go(func() { fetchLoadblancerPoolsHealth(ctx, a) })
	}

	// if target zones weren't provided, pull zones each loop
	// that way we catch zones that get added since the exporter
	// was started
	if len(zones) == 0 {
		zones = fetchZones(ctx, accounts)
		ezones := getExcludedZones()
		zones = filterExcludedZones(zones, ezones)
	}

	for zonesChunk := range slices.Chunk(zones, cfgraphqlreqlimit) {
		wg.Go(func() { fetchZoneAnalytics(ctx, zonesChunk) })
		wg.Go(func() { fetchZoneWorkerAnalytics(ctx, zonesChunk) })
		wg.Go(func() { fetchZoneColocationAnalytics(ctx, zonesChunk) })
		wg.Go(func() { fetchLoadBalancerAnalytics(ctx, zonesChunk) })
		wg.Go(func() { fetchLogpushAnalyticsForZone(ctx, zonesChunk) })
	}

	wg.Wait()
}

func runExporter() {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit
		log.Info("Shutting down...")
		cancel()
	}()

	var revision string
	var modified string
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				revision = setting.Value
			case "vcs.modified":
				modified = setting.Value
			}
		}
	}
	log.Info("Starting... GitSha:", revision, " Modified:", modified)

	cfgMetricsPath := viper.GetString("metrics_path")

	// Handle pprof configuration
	if !viper.GetBool("enable_pprof") {
		// Remove pprof handlers from default mux if disabled
		http.DefaultServeMux = http.NewServeMux()
		log.Info("pprof disabled")
	} else {
		log.Warn("pprof enabled - profiling endpoints available at /debug/pprof/")
	}

	var enabledMetrics MetricsMap

	denylist := viper.GetString("metrics_denylist")
	allowlist := viper.GetString("metrics_allowlist")

	if denylist != "" && allowlist != "" {
		log.Fatalf("Only one of `metrics_denylist` or `metrics_allowlist` can be set")
	}

	if denylist != "" {
		var err error
		enabledMetrics, err = buildDeniedMetricsSet(strings.Split(denylist, ","))
		if err != nil {
			log.Fatalf("Error building metrics set: %v", err)
		}
	} else if allowlist != "" {
		var err error
		enabledMetrics, err = buildAllowedMetricsSet(strings.Split(allowlist, ","))
		if err != nil {
			log.Fatalf("Error building metrics set: %v", err)
		}
	} else {
		enabledMetrics = metricsMap
	}

	log.Infof("Metrics set: %v", slices.Sorted(maps.Keys(enabledMetrics)))
	for _, metric := range enabledMetrics {
		prometheus.MustRegister(metric)
	}

	scrapeInterval := time.Duration(viper.GetInt("scrape_interval")) * time.Second
	log.Info("Scrape interval set to ", scrapeInterval)

	scrapeDelay := viper.GetDuration("scrape_delay")
	log.Info("Scrape delay set to ", scrapeDelay)

	go func() {
		accounts := fetchAccounts(ctx)

		// if the target zones argument is set, we only
		// need to pull zone info once
		var zones []cfzones.Zone
		tzones := getTargetZones()
		if len(tzones) > 0 {
			zones = fetchZones(ctx, accounts)
			zones = filterZones(zones, tzones)
		}

		endTime := time.Now().Truncate(scrapeInterval)
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.Tick(scrapeInterval):
				startTime := endTime
				endTime = time.Now().Truncate(scrapeInterval)
				go fetchMetrics(ContextWithMetricsCtx(ctx, startTime.Add(-scrapeDelay), endTime.Add(-scrapeDelay), enabledMetrics), accounts, zones)
			}
		}
	}()

	// This section will start the HTTP server and expose
	// any metrics on the /metrics endpoint.
	if !strings.HasPrefix(viper.GetString("metrics_path"), "/") {
		cfgMetricsPath = "/" + viper.GetString("metrics_path")
	}

	http.Handle(cfgMetricsPath, promhttp.Handler())
	h := health.New(health.Health{})
	http.HandleFunc("/health", h.Handler)

	log.Info("Beginning to serve metrics on ", viper.GetString("listen"), cfgMetricsPath)

	server := &http.Server{
		Addr:              viper.GetString("listen"),
		ReadHeaderTimeout: 3 * time.Second,
	}

	go func() {
		<-ctx.Done()
		server.Close()
	}()

	log.Fatal(server.ListenAndServe())
}

func main() {
	cmd := &cobra.Command{
		Use:   "cloudflare_exporter",
		Short: "Prometheus exporter exposing Cloudflare Analytics dashboard data on a per-zone basis, as well as Worker metrics",
		Run: func(_ *cobra.Command, _ []string) {
			runExporter()
		},
	}

	viper.AutomaticEnv()

	flags := cmd.Flags()

	flags.String("listen", ":8080", "listen on addr:port (default :8080), omit addr to listen on all interfaces")
	viper.BindEnv("listen")
	viper.SetDefault("listen", ":8080")

	flags.String("metrics_path", "/metrics", "path for metrics, default /metrics")
	viper.BindEnv("metrics_path")
	viper.SetDefault("metrics_path", "/metrics")

	flags.String("cf_api_key", "", "cloudflare api key, required with api_email flag")
	viper.BindEnv("cf_api_key")

	flags.String("cf_api_email", "", "cloudflare api email, required with api_key flag")
	viper.BindEnv("cf_api_email")

	flags.String("cf_api_token", "", "cloudflare api token (preferred)")
	viper.BindEnv("cf_api_token")

	flags.String("cf_zones", "", "cloudflare zones to export, comma delimited list of zone ids")
	viper.BindEnv("cf_zones")
	viper.SetDefault("cf_zones", "")

	flags.String("cf_exclude_zones", "", "cloudflare zones to exclude, comma delimited list of zone ids")
	viper.BindEnv("cf_exclude_zones")
	viper.SetDefault("cf_exclude_zones", "")

	flags.Duration("scrape_delay", 4*time.Minute, "shift the time window earlier by this amount, defaults to 4m")
	viper.BindEnv("scrape_delay")
	viper.SetDefault("scrape_delay", 4*time.Minute)

	flags.Int("scrape_interval", 60, "scrape interval in seconds, defaults to 60")
	viper.BindEnv("scrape_interval")
	viper.SetDefault("scrape_interval", 60)

	flags.Duration("cf_timeout", 10*time.Second, "cloudflare request timeout, default 10 seconds")
	viper.BindEnv("cf_timeout")
	viper.SetDefault("cf_timeout", 10*time.Second)

	flags.String("metrics_denylist", "", "metrics to not expose, comma delimited list")
	viper.BindEnv("metrics_denylist")
	viper.SetDefault("metrics_denylist", "")

	flags.String("metrics_allowlist", "", "exclusive set of metrics to expose, comma delimited list")
	viper.BindEnv("metrics_allowlist")
	viper.SetDefault("metrics_allowlist", "")

	flags.String("log_level", "info", "log level")
	viper.BindEnv("log_level")
	viper.SetDefault("log_level", "info")

	flags.Bool("enable_pprof", false, "enable pprof profiling endpoints at /debug/pprof/")
	viper.BindEnv("enable_pprof")
	viper.SetDefault("enable_pprof", false)

	viper.BindPFlags(flags)

	logLevel := viper.GetString("log_level")
	switch logLevel {
	case "debug":
		log.Level = logrus.DebugLevel
		log.SetReportCaller(true)
	case "warn":
		log.Level = logrus.WarnLevel
	case "error":
		log.Level = logrus.ErrorLevel
	default:
		log.Level = logrus.InfoLevel
	}

	log.SetFormatter(&logrus.TextFormatter{
		TimestampFormat: "2006-01-02 15:04:05",
		FullTimestamp:   true,
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			funcPath := strings.Split(f.File, "/")
			file := funcPath[len(funcPath)-1]
			return "file:" + file, " func:" + f.Function
		},
	})

	cfTimeout := viper.GetDuration("cf_timeout")
	headers := http.Header{}

	if len(viper.GetString("cf_api_token")) > 0 {
		cfclient = cf.NewClient(
			cfoption.WithAPIToken(viper.GetString("cf_api_token")),
			cfoption.WithRequestTimeout(cfTimeout),
		)
		headers.Set("Authorization", "Bearer "+viper.GetString("cf_api_token"))
	} else if len(viper.GetString("cf_api_email")) > 0 && len(viper.GetString("cf_api_key")) > 0 {
		cfclient = cf.NewClient(
			cfoption.WithAPIKey(viper.GetString("cf_api_key")),
			cfoption.WithAPIEmail(viper.GetString("cf_api_email")),
			cfoption.WithRequestTimeout(cfTimeout),
		)

		headers.Set("X-AUTH-EMAIL", viper.GetString("cf_api_email"))
		headers.Set("X-AUTH-KEY", viper.GetString("cf_api_key"))
	} else {
		log.Fatal("Please provide CF_API_KEY+CF_API_EMAIL or CF_API_TOKEN")
	}

	gql = NewGraphQLClient(headers, cfTimeout)

	cmd.Execute()
}
