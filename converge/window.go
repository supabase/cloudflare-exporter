package converge

import "time"

// trackerEntry pairs a tracker with its structured Key so that flush can
// reconstruct Samples without parsing the string map key.
type trackerEntry struct {
	key     Key
	tracker *tracker
	pushed  bool // true after this tracker's value has been emitted via Ingest
}

// window represents a single time bucket being observed. It owns one tracker
// per unique series key. Window age is measured from the bucket timestamp, not
// from when the window was first created in memory.
type window struct {
	bucket   time.Time
	trackers map[string]*trackerEntry
}

func newWindow(bucket time.Time) *window {
	return &window{
		bucket:   bucket,
		trackers: make(map[string]*trackerEntry),
	}
}

// flush returns a Sample for every tracker that has any observed value,
// regardless of stability or sync state. Used for graceful shutdown.
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

// flushUnpushed returns a Sample for every tracker that was never emitted
// via Ingest (i.e. never stabilized). Used on TTL expiry so that series
// which stabilized are not duplicated while unstabilized series are not lost.
func (w *window) flushUnpushed() []Sample {
	var samples []Sample
	for _, e := range w.trackers {
		if e.pushed {
			continue
		}
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
