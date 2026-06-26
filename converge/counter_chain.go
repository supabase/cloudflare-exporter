package converge

import (
	"sort"
	"time"
)

// counterEmission represents a counter value that needs to be pushed for a
// specific time bucket. The Counter field is the cumulative prefix sum at
// that bucket.
type counterEmission struct {
	Bucket  time.Time
	Counter uint64
}

// counterChain maintains per-series gauge values ordered by time bucket and
// produces monotonic counter values as cumulative prefix sums.
//
// Each bucket holds a gauge (the raw count for that 1-minute window). The
// counter value at any bucket is: base + sum(gauge[0..i]). When an earlier
// bucket's gauge changes, all later counter values shift by the same delta,
// and the chain reports which values need re-pushing.
//
// This is a prefix sum array with point-update support. For the small number
// of active buckets (bounded by Lookback / bucket_interval, roughly 15), a
// sorted slice with linear recomputation is optimal. A Fenwick tree (Binary
// Indexed Tree) solves the same problem class in O(log n) per operation but
// adds complexity that isn't justified at this scale.
type counterChain struct {
	base               uint64       // accumulated sum of evicted (expired) buckets
	entries            []chainEntry // sorted ascending by bucket time
	gaugeDownRevisions uint64       // CF revised a gauge downward
	counterRegressions uint64       // computed counter was lower than previous emission
}

type chainEntry struct {
	bucket  time.Time
	gauge   uint64 // per-bucket count (the raw value from CF)
	counter uint64 // last emitted counter value: base + prefix_sum(gauges up to here)
}

func newCounterChain() *counterChain {
	return &counterChain{}
}

// Set records or updates the gauge value for a bucket and returns emissions
// for every bucket whose counter value changed. Emissions are ordered
// ascending by time.
func (c *counterChain) Set(bucket time.Time, gauge uint64) []counterEmission {
	idx := c.find(bucket)

	if idx < len(c.entries) && c.entries[idx].bucket.Equal(bucket) {
		// Existing entry: check if gauge actually changed.
		if c.entries[idx].gauge == gauge {
			return nil
		}
		if gauge < c.entries[idx].gauge {
			c.gaugeDownRevisions++
		}
		c.entries[idx].gauge = gauge
	} else {
		// New entry: insert at sorted position.
		entry := chainEntry{bucket: bucket, gauge: gauge}
		c.entries = append(c.entries, chainEntry{})
		copy(c.entries[idx+1:], c.entries[idx:])
		c.entries[idx] = entry
	}

	// Recompute counters from idx onward and collect emissions.
	var emissions []counterEmission
	for i := idx; i < len(c.entries); i++ {
		var prev uint64
		if i == 0 {
			prev = c.base
		} else {
			prev = c.entries[i-1].counter
		}
		newCounter := prev + c.entries[i].gauge

		if newCounter != c.entries[i].counter || i == idx {
			if c.entries[i].counter > 0 && newCounter < c.entries[i].counter {
				c.counterRegressions++
			}
			c.entries[i].counter = newCounter
			emissions = append(emissions, counterEmission{
				Bucket:  c.entries[i].bucket,
				Counter: newCounter,
			})
		} else {
			// Counter unchanged from here on; delta has been absorbed.
			break
		}
	}

	return emissions
}

// Evict removes the oldest bucket from the chain, folding its gauge value
// into base. Returns false if the chain is empty or bucket doesn't match the
// oldest entry.
func (c *counterChain) Evict(bucket time.Time) bool {
	if len(c.entries) == 0 || !c.entries[0].bucket.Equal(bucket) {
		return false
	}
	c.base += c.entries[0].gauge
	c.entries = c.entries[1:]
	return true
}

// Len returns the number of active entries.
func (c *counterChain) Len() int {
	return len(c.entries)
}

// Base returns the accumulated sum of evicted buckets.
func (c *counterChain) Base() uint64 {
	return c.base
}

// find returns the index where bucket should be inserted or exists, using
// binary search over the sorted entries.
func (c *counterChain) find(bucket time.Time) int {
	return sort.Search(len(c.entries), func(i int) bool {
		return !c.entries[i].bucket.Before(bucket)
	})
}
