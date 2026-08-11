package main

import (
	"context"
	"testing"
	"time"

	cfaccounts "github.com/cloudflare/cloudflare-go/v7/accounts"
	cfzones "github.com/cloudflare/cloudflare-go/v7/zones"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

// enableDNSRecordQuotaGauges marks the DNS record quota gauges registered so
// that Set() is not a no-op, and clears them before and after the test.
func enableDNSRecordQuotaGauges(t *testing.T) {
	t.Helper()

	gauges := []*trackedGauge{
		zoneDNSRecordQuotaAllocated,
		zoneDNSRecordQuotaUsed,
		accountDNSRecordQuotaAllocated,
		accountDNSRecordQuotaUsed,
	}

	reset := func(tg *trackedGauge) {
		tg.registered = false
		tg.gauge.Reset()
		tg.expirations = map[string]time.Time{}
	}

	for _, tg := range gauges {
		reset(tg)
		tg.registered = true
		t.Cleanup(func() { reset(tg) })
	}
}

func dnsRecordQuotaCtx() context.Context {
	now := time.Now()
	return ContextWithMetricsCtx(context.Background(), now.Add(-time.Minute), now, MetricsMap{
		zoneDNSRecordQuotaAllocatedMetricName:    zoneDNSRecordQuotaAllocated,
		zoneDNSRecordQuotaUsedMetricName:         zoneDNSRecordQuotaUsed,
		accountDNSRecordQuotaAllocatedMetricName: accountDNSRecordQuotaAllocated,
		accountDNSRecordQuotaUsedMetricName:      accountDNSRecordQuotaUsed,
	})
}

func TestFetchZoneDNSRecordQuota(t *testing.T) {
	zones := []cfzones.Zone{{
		ID:      "zone-id",
		Name:    "example.com",
		Account: cfzones.ZoneAccount{ID: "account-id", Name: "test-account"},
	}}

	t.Run("zone level quota is exported", func(t *testing.T) {
		enableDNSRecordQuotaGauges(t)
		serveCloudflareAPI(t, `{"success":true,"errors":[],"messages":[],"result":{"record_quota":3500,"record_usage":42}}`)

		fetchZoneDNSRecordQuota(dnsRecordQuotaCtx(), zones)

		assert.Equal(t, 3500.0, testutil.ToFloat64(zoneDNSRecordQuotaAllocated.gauge.WithLabelValues("example.com", "test-account")))
		assert.Equal(t, 42.0, testutil.ToFloat64(zoneDNSRecordQuotaUsed.gauge.WithLabelValues("example.com", "test-account")))
	})

	t.Run("null quota emits no allocated series", func(t *testing.T) {
		enableDNSRecordQuotaGauges(t)
		serveCloudflareAPI(t, `{"success":true,"errors":[],"messages":[],"result":{"record_quota":null,"record_usage":42}}`)

		fetchZoneDNSRecordQuota(dnsRecordQuotaCtx(), zones)

		assert.Equal(t, 0, testutil.CollectAndCount(zoneDNSRecordQuotaAllocated.gauge), "allocated gauge should have no series when record_quota is null")
		assert.Equal(t, 1, testutil.CollectAndCount(zoneDNSRecordQuotaUsed.gauge))
		assert.Equal(t, 42.0, testutil.ToFloat64(zoneDNSRecordQuotaUsed.gauge.WithLabelValues("example.com", "test-account")))
	})

	t.Run("skips when no metric is enabled", func(t *testing.T) {
		enableDNSRecordQuotaGauges(t)
		serveCloudflareAPI(t, `{"success":true,"errors":[],"messages":[],"result":{"record_quota":3500,"record_usage":42}}`)

		now := time.Now()
		ctx := ContextWithMetricsCtx(context.Background(), now.Add(-time.Minute), now, MetricsMap{})
		fetchZoneDNSRecordQuota(ctx, zones)

		assert.Equal(t, 0, testutil.CollectAndCount(zoneDNSRecordQuotaAllocated.gauge))
		assert.Equal(t, 0, testutil.CollectAndCount(zoneDNSRecordQuotaUsed.gauge))
	})
}

func TestFetchAccountDNSRecordQuota(t *testing.T) {
	account := cfaccounts.Account{ID: "account-id", Name: "test-account"}

	t.Run("account level quota is exported", func(t *testing.T) {
		enableDNSRecordQuotaGauges(t)
		serveCloudflareAPI(t, `{"success":true,"errors":[],"messages":[],"result":{"record_quota":12000,"record_usage":150}}`)

		fetchAccountDNSRecordQuota(dnsRecordQuotaCtx(), account)

		assert.Equal(t, 12000.0, testutil.ToFloat64(accountDNSRecordQuotaAllocated.gauge.WithLabelValues("test-account")))
		assert.Equal(t, 150.0, testutil.ToFloat64(accountDNSRecordQuotaUsed.gauge.WithLabelValues("test-account")))
	})

	t.Run("null quota emits no allocated series", func(t *testing.T) {
		enableDNSRecordQuotaGauges(t)
		serveCloudflareAPI(t, `{"success":true,"errors":[],"messages":[],"result":{"record_quota":null,"record_usage":150}}`)

		fetchAccountDNSRecordQuota(dnsRecordQuotaCtx(), account)

		assert.Equal(t, 0, testutil.CollectAndCount(accountDNSRecordQuotaAllocated.gauge), "allocated gauge should have no series when record_quota is null")
		assert.Equal(t, 150.0, testutil.ToFloat64(accountDNSRecordQuotaUsed.gauge.WithLabelValues("test-account")))
	})
}
