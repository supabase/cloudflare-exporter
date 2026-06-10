package converge

import "time"

// trackerEntry pairs a tracker with its structured Key so that flush can
// reconstruct Samples without parsing the string map key.
type trackerEntry struct {
	key     Key
	tracker *tracker
}

// window represents a single time bucket being observed. It owns one tracker
// per unique series key and tracks whether any values have been pushed.
// Window age is measured from the bucket timestamp, not from when the window
// was first created in memory.
type window struct {
	bucket   time.Time
	trackers map[string]*trackerEntry
	pushed   bool // true after at least one sample has been emitted
}

func newWindow(bucket time.Time) *window {
	return &window{
		bucket:   bucket,
		trackers: make(map[string]*trackerEntry),
	}
}

// flush returns a Sample for every tracker that has any observed value,
// regardless of stability or sync state. Used for forced pushes on TTL
// expiry and graceful shutdown.
func (w *window) flush() []Sample {
	samples := make([]Sample, 0, len(w.trackers))
	for _, e := range w.trackers {
		if v, ok := e.tracker.currentValue(); ok {
			samples = append(samples, Sample{
				Key:       e.key,
				Value:     v,
				Timestamp: w.bucket,
			})
		}
	}
	return samples
}
