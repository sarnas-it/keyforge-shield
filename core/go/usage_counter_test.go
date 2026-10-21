package keyforgeshield

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConsumeAllowsUpToLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.json")
	c := NewUsageCounter(path)
	now := time.Unix(1_000_000, 0)

	for i := 0; i < 3; i++ {
		allowed, remaining, err := c.Consume("api_calls", 3, 0, now)
		if err != nil {
			t.Fatalf("Consume: %v", err)
		}
		if !allowed {
			t.Fatalf("call %d: expected allowed", i)
		}
		if remaining != uint64(2-i) {
			t.Fatalf("call %d: remaining = %d, want %d", i, remaining, 2-i)
		}
	}

	allowed, _, err := c.Consume("api_calls", 3, 0, now)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if allowed {
		t.Fatal("4th call over a limit of 3 should not be allowed")
	}
}

func TestConsumePersistsAcrossInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.json")
	now := time.Unix(1_000_000, 0)

	NewUsageCounter(path).Consume("api_calls", 5, 0, now)
	NewUsageCounter(path).Consume("api_calls", 5, 0, now)

	remaining, err := NewUsageCounter(path).Remaining("api_calls", 5, 0, now)
	if err != nil {
		t.Fatalf("Remaining: %v", err)
	}
	if remaining != 3 {
		t.Fatalf("remaining = %d, want 3 after two Consume calls persisted to the same file", remaining)
	}
}

func TestConsumeResetsAfterPeriodElapses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.json")
	c := NewUsageCounter(path)
	start := time.Unix(1_000_000, 0)
	const period = uint64(100)

	for i := 0; i < 2; i++ {
		if allowed, _, err := c.Consume("documents", 2, period, start); err != nil || !allowed {
			t.Fatalf("priming consume %d: allowed=%v err=%v", i, allowed, err)
		}
	}
	if allowed, _, _ := c.Consume("documents", 2, period, start); allowed {
		t.Fatal("3rd call within the same period should be rejected")
	}

	afterPeriod := start.Add(time.Duration(period+1) * time.Second)
	allowed, remaining, err := c.Consume("documents", 2, period, afterPeriod)
	if err != nil {
		t.Fatalf("Consume after period: %v", err)
	}
	if !allowed {
		t.Fatal("call after period elapsed should be allowed again (window reset)")
	}
	if remaining != 1 {
		t.Fatalf("remaining after reset+1 consume = %d, want 1", remaining)
	}
}

func TestLifetimeLimitNeverResets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.json")
	c := NewUsageCounter(path)
	start := time.Unix(1_000_000, 0)

	for i := 0; i < 2; i++ {
		if allowed, _, err := c.Consume("documents", 2, 0, start); err != nil || !allowed {
			t.Fatalf("priming consume %d: allowed=%v err=%v", i, allowed, err)
		}
	}

	muchLater := start.Add(365 * 24 * time.Hour)
	allowed, _, err := c.Consume("documents", 2, 0, muchLater)
	if err != nil {
		t.Fatalf("Consume much later: %v", err)
	}
	if allowed {
		t.Fatal("period_secs=0 means lifetime cap — must stay rejected no matter how much time passes")
	}
}

func TestMetricsAreIndependent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.json")
	c := NewUsageCounter(path)
	now := time.Unix(1_000_000, 0)

	c.Consume("api_calls", 1, 0, now)
	allowed, _, err := c.Consume("documents", 1, 0, now)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if !allowed {
		t.Fatal("exhausting api_calls must not affect the independent documents metric")
	}
}

func TestRemainingDoesNotMutateState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.json")
	c := NewUsageCounter(path)
	now := time.Unix(1_000_000, 0)

	c.Consume("api_calls", 10, 0, now)
	r1, _ := c.Remaining("api_calls", 10, 0, now)
	r2, _ := c.Remaining("api_calls", 10, 0, now)
	if r1 != r2 {
		t.Fatalf("Remaining must be idempotent, got %d then %d", r1, r2)
	}
	if r1 != 9 {
		t.Fatalf("remaining = %d, want 9 after a single Consume", r1)
	}
}

func TestCorruptFileReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	_, _, err := NewUsageCounter(path).Consume("api_calls", 10, 0, time.Now())
	if err == nil {
		t.Fatal("expected an error reading a corrupt usage counter file, got nil")
	}
}
