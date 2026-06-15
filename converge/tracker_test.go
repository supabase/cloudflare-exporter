package converge

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var tt0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func TestTrackerStabilizes(t *testing.T) {
	tr := newTracker(3)

	assert.Equal(t, obsConverging, tr.observe(100, tt0))
	assert.Equal(t, obsNOOP, tr.observe(100, tt0))
	assert.False(t, tr.stable())

	assert.Equal(t, obsNOOP, tr.observe(100, tt0))
	assert.True(t, tr.stable())
	assert.True(t, tr.needsSyncAndConsume())

	v, ok := tr.value()
	require.True(t, ok)
	assert.Equal(t, uint64(100), v)
}

func TestTrackerNeedsSyncConsumed(t *testing.T) {
	tr := newTracker(2)

	tr.observe(50, tt0)
	tr.observe(50, tt0)

	assert.True(t, tr.needsSyncAndConsume())
	assert.False(t, tr.needsSyncAndConsume())
}

func TestTrackerDriftThenRestabilize(t *testing.T) {
	tr := newTracker(2)

	tr.observe(10, tt0)
	tr.observe(10, tt0)
	tr.needsSyncAndConsume()

	assert.Equal(t, obsRewrite, tr.observe(20, tt0))
	assert.False(t, tr.stable())

	tr.observe(20, tt0) // re-stabilize
	assert.True(t, tr.needsSyncAndConsume())

	v, ok := tr.value()
	require.True(t, ok)
	assert.Equal(t, uint64(20), v)
}

func TestTrackerRestabilizeSameValueNoSync(t *testing.T) {
	tr := newTracker(2)

	tr.observe(10, tt0)
	tr.observe(10, tt0)
	tr.needsSyncAndConsume() // synced at 10

	assert.Equal(t, obsRewrite, tr.observe(20, tt0))
	tr.observe(10, tt0) // back to 10
	tr.observe(10, tt0) // re-stabilize at 10, same as last synced

	assert.False(t, tr.needsSyncAndConsume())
}

func TestTrackerThresholdOne(t *testing.T) {
	tr := newTracker(1)

	assert.Equal(t, obsConverging, tr.observe(42, tt0))
	assert.True(t, tr.stable())
	assert.True(t, tr.needsSyncAndConsume())
}

func TestTrackerThresholdClamped(t *testing.T) {
	tr := newTracker(0)
	tr.observe(1, tt0)
	assert.True(t, tr.stable())

	tr2 := newTracker(-5)
	tr2.observe(1, tt0)
	assert.True(t, tr2.stable())
}

func TestTrackerInterleavedNeverStabilizes(t *testing.T) {
	tr := newTracker(2)

	for i := range 10 {
		if i%2 == 0 {
			tr.observe(5, tt0)
		} else {
			tr.observe(7, tt0)
		}
		assert.False(t, tr.stable())
		assert.False(t, tr.needsSyncAndConsume())
	}
}

func TestTrackerValueDuringDrift(t *testing.T) {
	tr := newTracker(2)

	tr.observe(10, tt0)
	tr.observe(10, tt0)
	tr.needsSyncAndConsume()

	assert.Equal(t, obsRewrite, tr.observe(20, tt0))
	assert.False(t, tr.stable())

	v, ok := tr.value()
	require.True(t, ok)
	assert.Equal(t, uint64(10), v, "returns last synced value during drift")
}

func TestTrackerValueBeforeObservation(t *testing.T) {
	tr := newTracker(2)

	v, ok := tr.value()
	assert.False(t, ok)
	assert.Equal(t, uint64(0), v)
}

func TestTrackerCurrentValueBeforeObservation(t *testing.T) {
	tr := newTracker(2)

	v, ok := tr.currentValue()
	assert.False(t, ok)
	assert.Equal(t, uint64(0), v)
}

func TestTrackerCurrentValueUnstable(t *testing.T) {
	tr := newTracker(3)

	assert.Equal(t, obsConverging, tr.observe(100, tt0))
	// Not stable, value() returns nothing.
	_, ok := tr.value()
	assert.False(t, ok)

	// But currentValue always returns whatever was seen.
	v, ok := tr.currentValue()
	require.True(t, ok)
	assert.Equal(t, uint64(100), v)
}

func TestTrackerStabilizedAt(t *testing.T) {
	tr := newTracker(2)

	assert.True(t, tr.stabilizedAt.IsZero())

	t1 := tt0.Add(time.Minute)
	t2 := tt0.Add(2 * time.Minute)

	tr.observe(10, t1)
	tr.observe(10, t2) // threshold crossed here

	assert.Equal(t, t2, tr.stabilizedAt)
}

func TestTrackerUnconsumedSyncNewStabilization(t *testing.T) {
	tr := newTracker(2)

	tr.observe(10, tt0)
	tr.observe(10, tt0) // stable at 10, needsSync set

	// Don't consume. Drift and re-stabilize at new value.
	assert.Equal(t, obsRewrite, tr.observe(20, tt0))
	tr.observe(20, tt0) // stable at 20, needsSync still true

	assert.True(t, tr.needsSyncAndConsume())

	v, ok := tr.value()
	require.True(t, ok)
	assert.Equal(t, uint64(20), v, "latest stable value wins")

	// Consuming recorded lastSynced = 20.
	assert.False(t, tr.needsSyncAndConsume())
}

func TestTrackerObserveOutcomeRewriteAfterExtendedStability(t *testing.T) {
	// Verifies observedRewrite fires even when runLen > threshold (not just ==).
	tr := newTracker(2)

	tr.observe(10, tt0)
	tr.observe(10, tt0) // runLen=2, stable
	tr.observe(10, tt0) // runLen=3, still stable (past threshold)

	assert.Equal(t, obsRewrite, tr.observe(20, tt0))
}
