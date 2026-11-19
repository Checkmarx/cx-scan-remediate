package cx1ai

import (
	"testing"
	"time"
)

func TestBudgetUnlimited(t *testing.T) {
	b := NewBudget(0)
	if b.Expired() {
		t.Error("unlimited budget must never expire")
	}
	if d, m := b.PollTimeouts(30, 600); d != 30 || m != 600 {
		t.Errorf("got %d,%d want 30,600", d, m)
	}
	if d, m := b.PollTimeouts(30, 0); d != 30 || m != 0 {
		t.Errorf("library no-limit must pass through, got %d,%d", d, m)
	}
}

func TestBudgetPollTimeouts(t *testing.T) {
	// plenty of time: the library's own limits apply
	b := NewBudget(time.Hour)
	if d, m := b.PollTimeouts(30, 600); d != 30 || m != 600 {
		t.Errorf("got %d,%d want 30,600", d, m)
	}
	// library "no limit" is bounded by the remaining time
	if _, m := b.PollTimeouts(30, 0); m < 3590 || m > 3600 {
		t.Errorf("max = %d, want about 3600", m)
	}

	// less time left than the library maximum: min(library max, remaining), delay capped
	b = NewBudget(20 * time.Second)
	d, m := b.PollTimeouts(30, 600)
	if m < 19 || m > 20 || d != m {
		t.Errorf("got %d,%d want about 20,20", d, m)
	}

	// spent budget: still a one second check
	b = Budget{end: time.Now().Add(-time.Minute)}
	if !b.Expired() {
		t.Error("expected expired")
	}
	if d, m := b.PollTimeouts(30, 600); d != 1 || m != 1 {
		t.Errorf("got %d,%d want 1,1", d, m)
	}
}
