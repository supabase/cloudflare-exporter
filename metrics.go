package main

import (
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const joinChar = "|"
const maxAge = 1 * time.Hour

type trackedMetric interface {
	MustRegisterWith(prometheus.Registerer)
}

type reportableMetrics []*metricTracker

var registeredMetrics = reportableMetrics{}

func (rm reportableMetrics) Report(gauge prometheus.Gauge) {
	total := 0
	for _, m := range rm {
		total += len(m.expirations)
	}
	gauge.Set(float64(total))
}

func register(m *metricTracker) {
	registeredMetrics = append(registeredMetrics, m)
}

type metricTracker struct {
	sync.Mutex
	registered  bool
	collector   prometheus.Collector
	del         func(...string) bool
	expirations map[string]time.Time
}

func newMetricTracker(collector prometheus.Collector, del func(...string) bool) *metricTracker {
	mt := &metricTracker{
		registered:  false,
		collector:   collector,
		del:         del,
		expirations: map[string]time.Time{},
	}
	register(mt)
	return mt
}

func (mt *metricTracker) update(labels []string, fn func()) {
	if !mt.registered {
		return
	}

	mt.Lock()
	mt.expirations[strings.Join(labels, joinChar)] = time.Now().Add(maxAge)
	defer mt.Unlock()

	fn()
}

func (mt *metricTracker) MustRegisterWith(registry prometheus.Registerer) {
	mt.registered = true
	registry.MustRegister(mt)
}

func (mt *metricTracker) Describe(ch chan<- *prometheus.Desc) {
	mt.collector.Describe(ch)
}

func (mt *metricTracker) Collect(ch chan<- prometheus.Metric) {
	mt.Lock()
	defer mt.Unlock()
	now := time.Now()
	for k, v := range mt.expirations {
		if v.Before(now) {
			delete(mt.expirations, k)
			if mt.del(strings.Split(k, joinChar)...) {
				expiredMetrics.Inc()
			}
		}
	}
	mt.collector.Collect(ch)
}

type trackedGauge struct {
	*metricTracker
	gauge *prometheus.GaugeVec
}

func NewTrackedGauge(gauge *prometheus.GaugeVec) *trackedGauge {
	return &trackedGauge{
		metricTracker: newMetricTracker(gauge, gauge.DeleteLabelValues),
		gauge:         gauge,
	}
}

func (tg *trackedGauge) Set(val float64, labels ...string) {
	tg.update(labels, func() {
		tg.gauge.WithLabelValues(labels...).Set(val)
	})
}

type trackedCounter struct {
	*metricTracker
	counter *prometheus.CounterVec
}

func NewTrackedCounter(counter *prometheus.CounterVec) *trackedCounter {
	return &trackedCounter{
		metricTracker: newMetricTracker(counter, counter.DeleteLabelValues),
		counter:       counter,
	}
}

func (tc *trackedCounter) Add(val float64, labels ...string) {
	tc.update(labels, func() {
		tc.counter.WithLabelValues(labels...).Add(val)
	})
}
