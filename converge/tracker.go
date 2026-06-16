package converge

import "time"

type observeResult int

const (
	obsNOOP observeResult = iota
	obsConverging
	obsRewrite
)

// tracker monitors a uint64 value for stabilization. A value is considered
// stable after threshold consecutive identical observations.
type tracker struct {
	threshold    int
	current      uint64
	runLen       int
	seen         bool
	lastSynced   uint64
	synced       bool
	needsSync    bool
	stabilizedAt time.Time
}

func newTracker(threshold int) *tracker {
	if threshold < 1 {
		threshold = 1
	}
	return &tracker{threshold: threshold}
}

// observe records a new value. When the run of identical values reaches the
// threshold exactly, the tracker sets the needsSync flag (unless the value
// matches the last synced value).
func (t *tracker) observe(value uint64, at time.Time) observeResult {
	out := obsConverging
	if !t.seen || value != t.current {
		t.current = value
		if t.runLen >= t.threshold {
			out = obsRewrite
		}
		t.runLen = 1
		t.seen = true
	} else {
		out = obsNOOP
		t.runLen++
	}

	if t.runLen == t.threshold {
		t.stabilizedAt = at
		if !t.synced || t.current != t.lastSynced {
			t.needsSync = true
		}
	}
	return out
}

// needsSyncAndConsume reports whether a new stable value is pending sync.
// The flag is consumed on read: calling it records the current stable value
// as synced, so a second call returns false.
func (t *tracker) needsSyncAndConsume() bool {
	if t.needsSync {
		t.needsSync = false
		t.synced = true
		t.lastSynced = t.current
		return true
	}
	return false
}

// value returns the best known stable value. If currently stable, returns
// the current value. If not stable but previously synced, returns that.
// Otherwise returns 0 and false.
func (t *tracker) value() (uint64, bool) { //nolint:unused // used by upcoming Fetcher integration
	if t.runLen >= t.threshold && t.seen {
		return t.current, true
	}
	if t.synced {
		return t.lastSynced, true
	}
	return 0, false
}

// currentValue returns whatever value has been observed most recently,
// regardless of stability. Returns 0 and false only if nothing has been
// observed. Used by forced flush paths (TTL expiry, shutdown).
func (t *tracker) currentValue() (uint64, bool) {
	if t.seen {
		return t.current, true
	}
	return 0, false
}

// stable reports whether the run length has reached or exceeded the threshold.
func (t *tracker) stable() bool {
	return t.seen && t.runLen >= t.threshold
}
