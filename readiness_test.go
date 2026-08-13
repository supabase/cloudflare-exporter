package main

import "testing"

func TestReadinessTracker_NoRequiredComponents(t *testing.T) {
	r := newReadinessTracker()
	ready, components := r.Status(nil)
	if !ready {
		t.Error("expected ready with no required components")
	}
	if len(components) != 0 {
		t.Errorf("expected no component detail, got %v", components)
	}
}

func TestReadinessTracker_RequiredComponentNeverStable(t *testing.T) {
	r := newReadinessTracker()
	ready, components := r.Status([]string{"converge", "converge-dns"})
	if ready {
		t.Error("expected not ready when no components have stabilized")
	}
	if components["converge"].Stable || components["converge-dns"].Stable {
		t.Errorf("expected no components marked stable, got %v", components)
	}
}

func TestReadinessTracker_PartiallyStable(t *testing.T) {
	r := newReadinessTracker()
	r.MarkStable("converge")
	ready, components := r.Status([]string{"converge", "converge-dns"})
	if ready {
		t.Error("expected not ready when only one of two required components has stabilized")
	}
	if !components["converge"].Stable {
		t.Error("expected converge to be marked stable")
	}
	if components["converge-dns"].Stable {
		t.Error("expected converge-dns to not be marked stable")
	}
}

func TestReadinessTracker_AllStableStaysReady(t *testing.T) {
	r := newReadinessTracker()
	r.MarkStable("converge")
	r.MarkStable("converge-dns")

	ready, components := r.Status([]string{"converge", "converge-dns"})
	if !ready {
		t.Error("expected ready when all required components have stabilized")
	}
	for name, c := range components {
		if !c.Stable {
			t.Errorf("expected %s to be marked stable", name)
		}
		if c.StableSince.IsZero() {
			t.Errorf("expected %s to have a non-zero StableSince", name)
		}
	}

	// Stabilization is sticky: a later check still reports ready without
	// needing MarkStable to be called again.
	ready, _ = r.Status([]string{"converge", "converge-dns"})
	if !ready {
		t.Error("expected readiness to remain sticky on a later check")
	}
}

func TestReadinessTracker_MarkStableIsIdempotent(t *testing.T) {
	r := newReadinessTracker()
	r.MarkStable("converge")
	_, first := r.Status([]string{"converge"})
	r.MarkStable("converge")
	_, second := r.Status([]string{"converge"})

	if !first["converge"].StableSince.Equal(second["converge"].StableSince) {
		t.Error("expected StableSince to remain the first stabilization time")
	}
}
