package main

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestReportableMetricsReport(t *testing.T) {
	// Save and restore original registeredMetrics
	originalMetrics := registeredMetrics
	defer func() { registeredMetrics = originalMetrics }()

	// Create a test gauge to report to
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "test_total",
		Help: "Test gauge",
	})

	// Create test metric trackers with various expiration counts
	tracker1 := &metricTracker{
		expirations: map[string]time.Time{
			"key1": time.Now(),
			"key2": time.Now(),
		},
	}
	tracker2 := &metricTracker{
		expirations: map[string]time.Time{
			"key3": time.Now(),
			"key4": time.Now(),
			"key5": time.Now(),
		},
	}

	metrics := reportableMetrics{tracker1, tracker2}
	metrics.Report(gauge)

	// Should report total of 5 expirations
	assert.Equal(t, 5.0, testutil.ToFloat64(gauge))
}

func TestRegister(t *testing.T) {
	// Save and restore original registeredMetrics
	originalMetrics := registeredMetrics
	defer func() { registeredMetrics = originalMetrics }()

	registeredMetrics = reportableMetrics{}

	tracker := &metricTracker{}
	register(tracker)

	assert.Equal(t, 1, len(registeredMetrics))
	assert.Equal(t, tracker, registeredMetrics[0])
}

func TestNewMetricTracker(t *testing.T) {
	// Save and restore original registeredMetrics
	originalMetrics := registeredMetrics
	defer func() { registeredMetrics = originalMetrics }()

	registeredMetrics = reportableMetrics{}

	collector := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "test",
		Help: "Test",
	}, []string{"label"})

	delCalled := false
	delFunc := func(_ ...string) bool {
		delCalled = true
		return true
	}

	tracker := newMetricTracker(collector, delFunc)

	assert.False(t, tracker.registered, "newMetricTracker() should create unregistered tracker")
	assert.Equal(t, collector, tracker.collector)
	assert.NotNil(t, tracker.expirations)

	// Test that delete function was set
	tracker.del()
	assert.True(t, delCalled, "newMetricTracker() did not set delete function correctly")

	// Test that tracker was registered
	assert.Equal(t, 1, len(registeredMetrics))
}

func TestMetricTrackerUpdate(t *testing.T) {
	collector := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "test",
		Help: "Test",
	}, []string{"label"})

	tracker := newMetricTracker(collector, func(...string) bool { return true })

	t.Run("unregistered tracker does not update", func(t *testing.T) {
		fnCalled := false
		tracker.update([]string{"label1"}, func() {
			fnCalled = true
		})

		assert.False(t, fnCalled, "update() called function on unregistered tracker")
		assert.Equal(t, 0, len(tracker.expirations))
	})

	t.Run("registered tracker updates", func(t *testing.T) {
		tracker.registered = true
		fnCalled := false

		tracker.update([]string{"label1", "label2"}, func() {
			fnCalled = true
		})

		assert.True(t, fnCalled, "update() did not call function on registered tracker")

		key := "label1|label2"
		expTime, exists := tracker.expirations[key]
		assert.True(t, exists, "update() did not add expiration")
		assert.False(t, expTime.Before(time.Now()), "update() set expiration in the past")
		assert.False(t, expTime.After(time.Now().Add(maxAge+time.Minute)), "update() set expiration too far in the future")
	})
}

func TestMetricTrackerMustRegisterWith(t *testing.T) {
	collector := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "test_register",
		Help: "Test",
	}, []string{"label"})

	tracker := newMetricTracker(collector, func(...string) bool { return true })

	assert.False(t, tracker.registered, "tracker should start unregistered")

	registry := prometheus.NewRegistry()
	tracker.MustRegisterWith(registry)

	assert.True(t, tracker.registered, "MustRegisterWith() did not set registered to true")
}

func TestMetricTrackerCollect(t *testing.T) {
	// Save and restore expiredMetrics
	originalExpired := expiredMetrics
	testExpiredMetrics := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "test_expired",
		Help: "Test expired metrics",
	})
	expiredMetrics = testExpiredMetrics
	defer func() { expiredMetrics = originalExpired }()

	gaugeVec := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "test_collect",
		Help: "Test",
	}, []string{"label"})

	tracker := newMetricTracker(gaugeVec, gaugeVec.DeleteLabelValues)
	tracker.registered = true

	// Add some expirations: one expired, one not expired
	pastTime := time.Now().Add(-2 * time.Hour)
	futureTime := time.Now().Add(2 * time.Hour)

	tracker.expirations["expired"] = pastTime
	tracker.expirations["valid"] = futureTime

	// Set some values so we can verify collection works
	gaugeVec.WithLabelValues("expired").Set(1.0)
	gaugeVec.WithLabelValues("valid").Set(2.0)

	metricCh := make(chan prometheus.Metric, 10)
	tracker.Collect(metricCh)
	close(metricCh)

	// Check that expired key was removed
	_, exists := tracker.expirations["expired"]
	assert.False(t, exists, "Collect() did not remove expired key")

	// Check that valid key still exists
	_, exists = tracker.expirations["valid"]
	assert.True(t, exists, "Collect() removed non-expired key")

	// Check that expiredMetrics counter was incremented
	assert.Equal(t, 1.0, testutil.ToFloat64(testExpiredMetrics))

	// Check that metrics were collected
	count := 0
	for range metricCh {
		count++
	}

	assert.Greater(t, count, 0, "Collect() did not forward metrics from collector")
}

func TestNewTrackedGauge(t *testing.T) {
	gaugeVec := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "test_gauge",
		Help: "Test",
	}, []string{"label"})

	tg := NewTrackedGauge(gaugeVec)

	assert.Equal(t, gaugeVec, tg.gauge)
	assert.NotNil(t, tg.metricTracker)
}

func TestTrackedGaugeSet(t *testing.T) {
	gaugeVec := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "test_gauge_set",
		Help: "Test",
	}, []string{"label"})

	tg := NewTrackedGauge(gaugeVec)

	t.Run("unregistered gauge does not set", func(t *testing.T) {
		tg.Set(42.0, "label1")

		// Should not add expiration
		assert.Equal(t, 0, len(tg.expirations))
	})

	t.Run("registered gauge sets value", func(t *testing.T) {
		tg.registered = true
		tg.Set(42.0, "label1")

		// Should add expiration
		_, exists := tg.expirations["label1"]
		assert.True(t, exists, "Set() did not add expiration")

		// Should set the actual gauge value
		assert.Equal(t, 42.0, testutil.ToFloat64(gaugeVec.WithLabelValues("label1")))
	})

	t.Run("multiple labels", func(t *testing.T) {
		gaugeVec2 := prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "test_gauge_multi",
			Help: "Test",
		}, []string{"label1", "label2"})
		labelVals := []string{"value1", "value2"}

		tg2 := NewTrackedGauge(gaugeVec2)
		tg2.registered = true

		tg2.Set(100.0, labelVals...)

		key := strings.Join(labelVals, joinChar)
		_, exists := tg2.expirations[key]
		assert.True(t, exists, "Set() did not create correct key for multiple labels")

		assert.Equal(t, 100.0, testutil.ToFloat64(gaugeVec2.WithLabelValues(labelVals...)))
	})
}

func TestNewTrackedCounter(t *testing.T) {
	counterVec := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "test_counter",
		Help: "Test",
	}, []string{"label"})

	tc := NewTrackedCounter(counterVec)

	assert.Equal(t, counterVec, tc.counter)
	assert.NotNil(t, tc.metricTracker)
}

func TestTrackedCounterAdd(t *testing.T) {
	counterVec := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "test_counter_add",
		Help: "Test",
	}, []string{"label"})

	tc := NewTrackedCounter(counterVec)

	t.Run("unregistered counter does not add", func(t *testing.T) {
		tc.Add(5.0, "label1")

		// Should not add expiration
		assert.Equal(t, 0, len(tc.expirations))
	})

	t.Run("registered counter adds value", func(t *testing.T) {
		tc.registered = true
		tc.Add(5.0, "label1")

		// Should add expiration
		_, exists := tc.expirations["label1"]
		assert.True(t, exists, "Add() did not add expiration")

		// Should add to the actual counter value
		assert.Equal(t, 5.0, testutil.ToFloat64(counterVec.WithLabelValues("label1")))

		// Add more to the same labels
		tc.Add(3.0, "label1")
		assert.Equal(t, 8.0, testutil.ToFloat64(counterVec.WithLabelValues("label1")))
	})

	t.Run("multiple labels", func(t *testing.T) {
		counterVec2 := prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "test_counter_multi",
			Help: "Test",
		}, []string{"label1", "label2"})

		labelVals := []string{"value1", "value2"}

		tc2 := NewTrackedCounter(counterVec2)
		tc2.registered = true

		tc2.Add(10.0, labelVals...)

		key := strings.Join(labelVals, joinChar)
		_, exists := tc2.expirations[key]
		assert.True(t, exists, "Add() did not create correct key for multiple labels")

		assert.Equal(t, 10.0, testutil.ToFloat64(counterVec2.WithLabelValues(labelVals...)))
	})
}
