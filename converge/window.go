package converge

import "time"

// window represents a single time bucket being observed. It owns one tracker
// per unique series key and tracks whether any values have been pushed.
type window struct {
	bucket   time.Time
	trackers map[string]*tracker
	created  time.Time
	pushed   bool // true after at least one sample has been emitted
}

func newWindow(bucket, created time.Time) *window {
	return &window{
		bucket:   bucket,
		trackers: make(map[string]*tracker),
		created:  created,
	}
}

// flush returns a Sample for every tracker that has any observed value,
// regardless of stability or sync state. Used for forced pushes on TTL
// expiry and graceful shutdown.
func (w *window) flush() []Sample {
	samples := make([]Sample, 0, len(w.trackers))
	for key, t := range w.trackers {
		if v, ok := t.currentValue(); ok {
			samples = append(samples, Sample{
				Key:       key,
				Value:     v,
				Timestamp: w.bucket,
			})
		}
	}
	return samples
}
