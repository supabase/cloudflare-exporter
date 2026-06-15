package converge

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// t0 is defined in engine_test.go: 2026-01-01T00:00:00Z

func TestChainSingleBucket(t *testing.T) {
	c := newCounterChain()

	em := c.Set(t0, 500)
	require.Len(t, em, 1)
	assert.Equal(t, t0, em[0].Bucket)
	assert.Equal(t, uint64(500), em[0].Counter)
}

func TestChainTwoBucketsInOrder(t *testing.T) {
	c := newCounterChain()
	t1 := t0.Add(time.Minute)

	c.Set(t0, 500)
	em := c.Set(t1, 300)

	require.Len(t, em, 1)
	assert.Equal(t, t1, em[0].Bucket)
	assert.Equal(t, uint64(800), em[0].Counter) // 500 + 300
}

func TestChainEarlierBucketReconvergesUp(t *testing.T) {
	c := newCounterChain()
	t1 := t0.Add(time.Minute)

	c.Set(t0, 500)
	c.Set(t1, 300) // counter = 800

	// T0 re-converges from 500 → 550. Delta of +50 cascades forward.
	em := c.Set(t0, 550)

	require.Len(t, em, 2)
	// T0: counter = 550
	assert.Equal(t, t0, em[0].Bucket)
	assert.Equal(t, uint64(550), em[0].Counter)
	// T1: counter = 550 + 300 = 850
	assert.Equal(t, t1, em[1].Bucket)
	assert.Equal(t, uint64(850), em[1].Counter)
}

func TestChainEarlierBucketReconvergesDown(t *testing.T) {
	c := newCounterChain()
	t1 := t0.Add(time.Minute)

	c.Set(t0, 500)
	c.Set(t1, 300) // counter = 800

	// Gauge decrease (unusual, but the structure should handle it honestly).
	em := c.Set(t0, 400)

	require.Len(t, em, 2)
	assert.Equal(t, uint64(400), em[0].Counter)
	assert.Equal(t, uint64(700), em[1].Counter) // 400 + 300
}

func TestChainNoChangeNoEmission(t *testing.T) {
	c := newCounterChain()

	c.Set(t0, 500)

	// Same gauge again: nothing changed.
	em := c.Set(t0, 500)
	assert.Empty(t, em)
}

func TestChainOutOfOrderArrival(t *testing.T) {
	c := newCounterChain()
	t1 := t0.Add(time.Minute)

	// Later bucket arrives first.
	em := c.Set(t1, 300)
	require.Len(t, em, 1)
	assert.Equal(t, uint64(300), em[0].Counter) // only bucket, counter = 300

	// Earlier bucket arrives, shifts everything forward.
	em = c.Set(t0, 500)

	require.Len(t, em, 2)
	// T0: counter = 500
	assert.Equal(t, t0, em[0].Bucket)
	assert.Equal(t, uint64(500), em[0].Counter)
	// T1: counter = 500 + 300 = 800 (was 300)
	assert.Equal(t, t1, em[1].Bucket)
	assert.Equal(t, uint64(800), em[1].Counter)
}

func TestChainThreeBucketsMiddleChanges(t *testing.T) {
	c := newCounterChain()
	t1 := t0.Add(time.Minute)
	t2 := t0.Add(2 * time.Minute)

	c.Set(t0, 100) // counter: 100
	c.Set(t1, 200) // counter: 300
	c.Set(t2, 300) // counter: 600

	// Middle bucket re-converges 200 → 250.
	em := c.Set(t1, 250)

	require.Len(t, em, 2)
	// T0 unchanged (before the change point), not emitted.
	// T1: 100 + 250 = 350
	assert.Equal(t, t1, em[0].Bucket)
	assert.Equal(t, uint64(350), em[0].Counter)
	// T2: 100 + 250 + 300 = 650
	assert.Equal(t, t2, em[1].Bucket)
	assert.Equal(t, uint64(650), em[1].Counter)
}

func TestChainEvictOldest(t *testing.T) {
	c := newCounterChain()
	t1 := t0.Add(time.Minute)

	c.Set(t0, 500) // counter: 500
	c.Set(t1, 300) // counter: 800

	ok := c.Evict(t0)
	assert.True(t, ok)
	assert.Equal(t, 1, c.Len())
	assert.Equal(t, uint64(500), c.Base())

	// T1's counter should still be 800 (base=500 + gauge=300).
	// Adding a new bucket should accumulate correctly.
	t2 := t0.Add(2 * time.Minute)
	em := c.Set(t2, 200)
	require.Len(t, em, 1)
	assert.Equal(t, uint64(1000), em[0].Counter) // 500 + 300 + 200
}

func TestChainEvictNonOldestFails(t *testing.T) {
	c := newCounterChain()
	t1 := t0.Add(time.Minute)

	c.Set(t0, 500)
	c.Set(t1, 300)

	// Can't evict a non-oldest entry.
	ok := c.Evict(t1)
	assert.False(t, ok)
	assert.Equal(t, 2, c.Len())
}

func TestChainEvictEmptyChain(t *testing.T) {
	c := newCounterChain()

	ok := c.Evict(t0)
	assert.False(t, ok)
}

func TestChainEvictAllThenAdd(t *testing.T) {
	c := newCounterChain()
	t1 := t0.Add(time.Minute)

	c.Set(t0, 500)
	c.Set(t1, 300)

	c.Evict(t0)
	c.Evict(t1)

	assert.Equal(t, 0, c.Len())
	assert.Equal(t, uint64(800), c.Base())

	// New bucket starts from accumulated base.
	t2 := t0.Add(2 * time.Minute)
	em := c.Set(t2, 100)
	require.Len(t, em, 1)
	assert.Equal(t, uint64(900), em[0].Counter) // 800 + 100
}

func TestChainMultipleReconvergences(t *testing.T) {
	c := newCounterChain()

	c.Set(t0, 100) // counter: 100

	// Value keeps climbing as CF aggregates.
	em := c.Set(t0, 150)
	require.Len(t, em, 1)
	assert.Equal(t, uint64(150), em[0].Counter)

	em = c.Set(t0, 200)
	require.Len(t, em, 1)
	assert.Equal(t, uint64(200), em[0].Counter)

	// Settles.
	em = c.Set(t0, 200)
	assert.Empty(t, em)
}

func TestChainEvictPreservesLaterCounters(t *testing.T) {
	c := newCounterChain()
	t1 := t0.Add(time.Minute)
	t2 := t0.Add(2 * time.Minute)

	c.Set(t0, 100) // counter: 100
	c.Set(t1, 200) // counter: 300
	c.Set(t2, 300) // counter: 600

	c.Evict(t0) // base=100, entries: t1(g:200,c:300), t2(g:300,c:600)

	// T1 re-converges. Counter values should still include base.
	em := c.Set(t1, 250)
	require.Len(t, em, 2)
	// T1: base(100) + 250 = 350
	assert.Equal(t, t1, em[0].Bucket)
	assert.Equal(t, uint64(350), em[0].Counter)
	// T2: base(100) + 250 + 300 = 650
	assert.Equal(t, t2, em[1].Bucket)
	assert.Equal(t, uint64(650), em[1].Counter)
}

// TestChainRealisticConvergeScenario simulates the real pipeline: multiple
// buckets arriving, converging at different rates, being evicted as they age.
func TestChainRealisticConvergeScenario(t *testing.T) {
	c := newCounterChain()
	m := func(n int) time.Time { return t0.Add(time.Duration(n) * time.Minute) }

	// Minute 0 arrives and stabilizes quickly.
	c.Set(m(0), 1000)

	// Minute 1 arrives, still aggregating.
	c.Set(m(1), 400)

	// Minute 2 arrives.
	em := c.Set(m(2), 600)
	require.Len(t, em, 1)
	assert.Equal(t, uint64(2000), em[0].Counter) // 1000+400+600

	// Minute 1 re-converges upward (CF finalized more data).
	em = c.Set(m(1), 500)
	require.Len(t, em, 2)
	assert.Equal(t, uint64(1500), em[0].Counter) // m(1): 1000+500
	assert.Equal(t, uint64(2100), em[1].Counter) // m(2): 1000+500+600

	// Minute 0 window expires, evict it.
	c.Evict(m(0))
	assert.Equal(t, uint64(1000), c.Base())

	// Minute 3 arrives.
	em = c.Set(m(3), 700)
	require.Len(t, em, 1)
	assert.Equal(t, uint64(2800), em[0].Counter) // base(1000)+500+600+700

	// Minute 1 window expires, evict it.
	c.Evict(m(1))
	assert.Equal(t, uint64(1500), c.Base())

	// Verify minute 3 counter is still correct after evictions by updating m(2).
	em = c.Set(m(2), 650)
	require.Len(t, em, 2)
	assert.Equal(t, uint64(2150), em[0].Counter) // m(2): base(1500)+650
	assert.Equal(t, uint64(2850), em[1].Counter) // m(3): base(1500)+650+700
}
