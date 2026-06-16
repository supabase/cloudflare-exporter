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
