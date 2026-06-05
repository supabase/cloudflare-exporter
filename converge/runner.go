package converge

import (
	"context"
	"log/slog"
	"time"
)

// Run drives an Engine in a loop, fetching observations from f and pushing
// stable samples to s. It handles live polling, backfill, and graceful
// shutdown. Run blocks until ctx is cancelled.
//
//	┌──────────────────────────────────────────────────────┐
//	│                    each tick                         │
//	│                                                     │
//	│  1. Live:  Fetch [now-lookback, now]                 │
//	│           ──► Engine.Ingest ──► Sink.Push            │
//	│           ──► Engine.Expire ──► Sink.Push            │
//	│                                                     │
//	│  2. Backfill (up to N calls):                        │
//	│           Fetch [cursor, cursor+chunk]               │
//	│           ──► Engine.Ingest ──► Sink.Push            │
//	│           advance cursor                             │
//	│                                                     │
//	│  3. On shutdown:                                     │
//	│           Engine.Flush ──► Sink.Push                 │
//	└──────────────────────────────────────────────────────┘
func Run(ctx context.Context, cfg Config, f Fetcher, s Sink) error {
	eng := NewEngine(cfg)
	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()

	backfillCursor := time.Now().Add(-cfg.MaxBackfill).Truncate(time.Minute)
	backfillDone := false

	for {
		select {
		case <-ctx.Done():
			samples := eng.Flush()
			if len(samples) > 0 {
				// Use a short-lived context for the final push.
				pushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				if err := s.Push(pushCtx, samples); err != nil {
					slog.Error("flush push failed", "err", err)
				}
				cancel()
			}
			return ctx.Err()

		case now := <-ticker.C:
			// Live lane: always runs, no call limit.
			liveStart := now.Add(-cfg.Lookback)
			obs, err := f.Fetch(ctx, liveStart, now)
			if err != nil {
				slog.Error("live fetch failed", "err", err)
			} else {
				pushSamples(ctx, s, eng.Ingest(obs))
			}
			pushSamples(ctx, s, eng.Expire(now))

			// Backfill lane: capped at BackfillCallsPerTick.
			if backfillDone {
				continue
			}
			if cfg.BackfillCallsPerTick <= 0 {
				backfillDone = true
				continue
			}
			limit := now.Add(-cfg.Lookback)
			for i := 0; i < cfg.BackfillCallsPerTick; i++ {
				if !backfillCursor.Before(limit) {
					backfillDone = true
					slog.Info("backfill complete")
					break
				}
				end := backfillCursor.Add(cfg.BackfillChunk)
				if end.After(limit) {
					end = limit
				}
				obs, err := f.Fetch(ctx, backfillCursor, end)
				if err != nil {
					slog.Error("backfill fetch failed", "start", backfillCursor, "end", end, "err", err)
					break // retry next tick
				}
				pushSamples(ctx, s, eng.Ingest(obs))
				backfillCursor = end
			}
		}
	}
}

func pushSamples(ctx context.Context, s Sink, samples []Sample) {
	if len(samples) == 0 {
		return
	}
	if err := s.Push(ctx, samples); err != nil {
		slog.Error("push failed", "count", len(samples), "err", err)
	}
}
