# converge

A state machine that watches a stream of timestamped observations and emits
push-ready samples once values stabilize.

Built for metrics that arrive incrementally (e.g. Cloudflare analytics buckets
that aggregate over several minutes). The engine detects when a value has
stopped changing, pushes it, and continues watching for late corrections.

## How it works

```
  Caller (runner, test harness, CLI tool)
    |
    |  []Observation        []Sample
    |  ──────────────►  ◄────────────
    |                  Engine
    |                  (pure state machine,
    |                   no I/O, no goroutines)
    |
    ▼
  Observations flow through three layers:

  ┌─────────────────────────────────────────────────────┐
  │ Engine                                              │
  │                                                     │
  │  windows: map[time.Time]*window                     │
  │  ┌───────────────────────────────────────────────┐  │
  │  │ Window (one per time bucket)                  │  │
  │  │                                               │  │
  │  │  trackers: map[string]*tracker                │  │
  │  │  ┌─────────────────────────────────────────┐  │  │
  │  │  │ Tracker (one per metric series)         │  │  │
  │  │  │                                         │  │  │
  │  │  │  Counts consecutive identical values.   │  │  │
  │  │  │  Fires NeedsSync when threshold met.    │  │  │
  │  │  └─────────────────────────────────────────┘  │  │
  │  └───────────────────────────────────────────────┘  │
  └─────────────────────────────────────────────────────┘
```

## Engine API

The engine is a pure state machine. It has no timers, no goroutines, no I/O.
Feed data in, get samples out.

```go
eng := converge.NewEngine(cfg)

// Feed observations. Returns samples for any tracker that just stabilized.
samples := eng.Ingest(observations)

// Check TTLs. Returns forced-push samples from expiring windows.
// Removes closed windows.
samples = eng.Expire(time.Now())

// Graceful shutdown: flush best-known values for all open windows.
samples = eng.Flush()

// Monitoring.
stats := eng.Stats() // .OpenWindows, .TrackerCount
```

## Window lifecycle

Each window maps 1:1 to a source time bucket (e.g. one Cloudflare minute).

```
  first observation
        |
        v
  +-----------+
  |   OPEN    |--- tracker stabilizes ---> push sample
  |           |                                |
  +-----------+                                v
        |                            +-----------+
        |                            |  PUSHED   |
        |                            | (watching)|<-- value changes --> re-push
        |                            +-----------+
        |                                  |
        |         window TTL reached       |
        v                                  v
  +-----------+                     +-----------+
  |  CLOSED   |                     |  CLOSED   |
  | (forced   |                     | (clean)   |
  |  flush)   |                     +-----------+
  +-----------+

  Closed windows are removed from the engine.
```

**OPEN**: Actively receiving observations. No values pushed yet.

**PUSHED**: At least one tracker has emitted a sample. Window stays open
until TTL to catch late-arriving data that might change values.

**CLOSED (clean)**: TTL reached, window had already pushed. Removed
without re-pushing.

**CLOSED (forced flush)**: TTL reached, window never pushed (values never
stabilized). Engine flushes best-known values so no data is silently dropped.

## Tracker behavior

A tracker watches a single uint64 value (one metric series within one bucket).

```
  observe(100)  observe(150)  observe(150)  observe(150)
       |             |             |             |
       v             v             v             v
    run=1         run=1         run=2        run=3  <-- threshold met
    current=100   current=150   current=150  NeedsSync!
```

With threshold=1, every new distinct value triggers a push (eager mode).
With threshold=3, you wait for convergence (conservative mode).

After NeedsSync fires and is consumed, further observations of the same
value are ignored (no redundant pushes). But if the value changes again,
the run resets and stabilization restarts.

## Runner

`Run()` is a convenience loop that wires a Fetcher and Sink to the engine:

```go
converge.Run(ctx, cfg, myFetcher, mySink)
```

It handles:
1. Live polling on a ticker (always runs first, no call limit)
2. Backfill with a capped number of Fetch calls per tick
3. Graceful shutdown (flushes all windows on context cancellation)

The runner is ~80 lines and intentionally simple. For custom scheduling
(batch replay, tests, CLI tools), construct an Engine directly and call
Ingest/Expire/Flush yourself.

## Configuration

```go
converge.Config{
    Threshold:            3,              // identical observations to stabilize
    WindowTTL:            15 * time.Minute, // window lifespan
    PollInterval:         30 * time.Second, // live lane tick
    Lookback:             10 * time.Minute, // live query range
    MaxBackfill:          2 * time.Hour,    // startup backfill cap
    BackfillChunk:        10 * time.Minute, // time range per backfill call
    BackfillCallsPerTick: 1,               // API budget for backfill per tick
}
```

Presets:

```
Eager:        Threshold=1  -- push on first sight, correct later
Conservative: Threshold=3  -- wait for convergence, push once
```

## Integration

The engine defines two interfaces:

```go
type Fetcher interface {
    Fetch(ctx context.Context, start, end time.Time) ([]Observation, error)
}

type Sink interface {
    Push(ctx context.Context, samples []Sample) error
}
```

The caller implements these, wrapping whatever data source and destination
it uses. The engine never imports or references external packages.

```
  ┌──────────────────────────────────────────────────┐
  │ Your application                                 │
  │                                                  │
  │  fetcher := &myFetcher{...}  // implements Fetch │
  │  sink    := &mySink{...}     // implements Push  │
  │  go converge.Run(ctx, cfg, fetcher, sink)        │
  └──────────────────────────────────────────────────┘
         |                              |
         | Fetcher                      | Sink
         v                              v
  ┌──────────────┐             ┌──────────────┐
  │ Data source  │             │ Destination  │
  │ (API, DB)    │             │ (TSDB, file) │
  └──────────────┘             └──────────────┘
```

## VictoriaMetrics dedup and counter restarts

The engine emits cumulative counters (prefix sums). On restart, the chain
base resets to 0, so counter values at a given timestamp will differ between
the old and new process.

VictoriaMetrics deduplication (`-dedup.minScrapeInterval`) merges duplicate
timestamps during storage compaction, but **keeps the highest value**, not
the last written value. This means:

1. Old deploy pushes counter value `50,000,000` at timestamp `17:05`
2. New deploy restarts, base resets, pushes `35,000` at `17:05`
3. VM keeps `50,000,000` (the higher value). The old data survives.

This has two implications:

**Spike artifacts are permanent.** If intermediate prefix sum states leak
to VM during backfill (the cascade bug), those inflated counter values
are higher than the correct values and will never be overwritten by
subsequent pushes. The only remedy is `delete_series` for the affected
time range.

**Correct values are also permanent.** Once the engine pushes the right
counter values (via the suppress and snapshot approach), those values are
stable. A restart that pushes lower values won't corrupt them.

The suppress and snapshot fix prevents spikes from being written in the
first place, which is the correct solution given VM's "highest value wins"
dedup semantics. Relying on dedup to overwrite bad data does not work.

### Chain base seeding

To prevent counter resets across restarts entirely, the engine supports
seeding chain bases from the sink's last known values. On startup, if
the sink implements the `ChainSeeder` interface, the runner queries VM
for the last value of each series within the `MaxBackfill` window and
calls `Engine.SeedChainBase(key, value)` for each result.

This means the first counter emitted after restart is `previous_last + gauge`
rather than `0 + gauge`. Since VM keeps the highest value on dedup, the
new values are always >= the old ones (monotonic continuation), so:

1. No counter reset visible to `rate()`.
2. No conflict with existing data in VM.
3. If VM is unreachable at startup, seeding is skipped with a warning
   and the engine falls back to base=0 (same as pre-seed behavior).

The seed query uses `last_over_time({selector}[MaxBackfill])` against
the VM query endpoint, derived from the write endpoint.

Reference: [VictoriaMetrics Storage, Retention, Merging, and Deduplication](https://victoriametrics.com/blog/vmstorage-retention-merging-deduplication/)

## File layout

```
converge/
  types.go       Observation, Sample, Fetcher, Sink, Stats
  tracker.go     per-series stability detection (unexported)
  window.go      per-bucket tracker collection (unexported)
  engine.go      Engine (exported), Config, NewEngine, Ingest/Expire/Flush
  runner.go      Run() convenience loop (exported)
  engine_test.go
  spike_test.go  regression test for counter cascade spikes (uses testdata/)
  testdata/      recorded CF fetch fixtures for spike reproduction
```
