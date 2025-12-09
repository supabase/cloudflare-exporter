package main

import (
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const joinChar = "|"
const maxAge = 1 * time.Hour

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
	expirations map[string]time.Time
}

func newMetricTracker() *metricTracker {
	mt := &metricTracker{expirations: map[string]time.Time{}}
	register(mt)
	return mt
}

func (m *metricTracker) touch(labels []string) {
	m.Lock()
	defer m.Unlock()
	m.expirations[strings.Join(labels, joinChar)] = time.Now().Add(maxAge)
}

func (m *metricTracker) collect(del func(...string) bool) {
	m.Lock()
	defer m.Unlock()
	now := time.Now()
	for k, v := range m.expirations {
		if v.Before(now) {
			delete(m.expirations, k)
			if del(strings.Split(k, joinChar)...) {
				expiredMetrics.Inc()
			}
		}
	}
}

type trackedGauge struct {
	tracker *metricTracker
	gauge   *prometheus.GaugeVec
}

func NewTrackedGauge(gauge *prometheus.GaugeVec) *trackedGauge {
	return &trackedGauge{
		tracker: newMetricTracker(),
		gauge:   gauge,
	}
}

func (tg *trackedGauge) Describe(ch chan<- *prometheus.Desc) {
	tg.gauge.Describe(ch)
}

func (tg *trackedGauge) Collect(ch chan<- prometheus.Metric) {
	tg.tracker.collect(tg.gauge.DeleteLabelValues)
	tg.gauge.Collect(ch)
}

func (tg *trackedGauge) Set(val float64, labels ...string) {
	tg.gauge.WithLabelValues(labels...).Set(val)
	tg.tracker.touch(labels)
}

type trackedCounter struct {
	tracker *metricTracker
	counter *prometheus.CounterVec
}

func NewTrackedCounter(counter *prometheus.CounterVec) *trackedCounter {
	return &trackedCounter{
		tracker: newMetricTracker(),
		counter: counter,
	}
}

func (tc *trackedCounter) Describe(ch chan<- *prometheus.Desc) {
	tc.counter.Describe(ch)
}

func (tc *trackedCounter) Collect(ch chan<- prometheus.Metric) {
	tc.tracker.collect(tc.counter.DeleteLabelValues)
	tc.counter.Collect(ch)
}

func (tc *trackedCounter) Add(val float64, labels ...string) {
	tc.counter.WithLabelValues(labels...).Add(val)
	tc.tracker.touch(labels)
}
