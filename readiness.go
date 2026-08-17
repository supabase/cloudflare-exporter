package main

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// readinessTracker records, per named component, whether it has stabilized
// at least once. It is a sticky boolean: once a component stabilizes it
// stays stable for the lifetime of the process.
type readinessTracker struct {
	mu       sync.Mutex
	stableAt map[string]time.Time
}

func newReadinessTracker() *readinessTracker {
	return &readinessTracker{stableAt: make(map[string]time.Time)}
}

// markStable records that component has stabilized, if it hasn't already.
func (r *readinessTracker) MarkStable(component string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.stableAt[component]; !ok {
		r.stableAt[component] = time.Now()
	}
}

// componentReadiness is the per-component detail returned by Status.
type componentReadiness struct {
	Stable      bool      `json:"stable"`
	StableSince time.Time `json:"stable_since,omitempty"`
}

// Status reports whether every component in required has stabilized at
// least once, along with per-component detail for all of them.
func (r *readinessTracker) Status(required []string) (bool, map[string]componentReadiness) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ready := true
	components := make(map[string]componentReadiness, len(required))
	for _, component := range required {
		stableAt, ok := r.stableAt[component]
		components[component] = componentReadiness{Stable: ok, StableSince: stableAt}
		if !ok {
			ready = false
		}
	}
	return ready, components
}

func (r *readinessTracker) Handler(requiredComponents []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ready, components := r.Status(requiredComponents)
		status := "ok"
		w.Header().Set("Content-Type", "application/json")
		if !ready {
			status = "not_ready"
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"status":     status,
			"components": components,
		})
	})
}
