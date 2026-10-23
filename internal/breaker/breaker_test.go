package breaker

import (
	"sync"
	"testing"
	"time"
)

// fakeClock is a manually advanced clock for deterministic tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestBreaker(threshold int, open time.Duration) (*Breaker, *fakeClock) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	b := New(threshold, open)
	b.now = clk.now
	return b, clk
}

func failN(b *Breaker, provider, conn string, n int) {
	for i := 0; i < n; i++ {
		b.OnResult(provider, conn, false)
	}
}

func statsFor(t *testing.T, b *Breaker, provider, conn string) KeyStats {
	t.Helper()
	for _, ks := range b.Snapshot() {
		if ks.Provider == provider && ks.ConnectionID == conn {
			return ks
		}
	}
	t.Fatalf("no snapshot entry for %s/%s", provider, conn)
	return KeyStats{}
}

func TestClosedAllowsAndSuccessResets(t *testing.T) {
	b, _ := newTestBreaker(3, 30*time.Second)
	if !b.Allow("openai", "c1") {
		t.Fatal("closed circuit must allow")
	}
	failN(b, "openai", "c1", 2)
	b.OnResult("openai", "c1", true)
	ks := statsFor(t, b, "openai", "c1")
	if ks.State != "closed" || ks.ConsecutiveFailures != 0 {
		t.Fatalf("after success: %+v", ks)
	}
	if ks.TotalFailures != 2 || ks.TotalSuccesses != 1 {
		t.Fatalf("totals: %+v", ks)
	}
	// Counter was reset: two more failures stay below the threshold.
	failN(b, "openai", "c1", 2)
	if !b.Allow("openai", "c1") {
		t.Fatal("must still be closed below threshold after reset")
	}
}

func TestTripsOpenAtThreshold(t *testing.T) {
	b, _ := newTestBreaker(3, 30*time.Second)
	failN(b, "openai", "c1", 2)
	if !b.Allow("openai", "c1") {
		t.Fatal("2 < 3 failures: must allow")
	}
	b.OnResult("openai", "c1", false)
	if b.Allow("openai", "c1") {
		t.Fatal("3 consecutive failures: circuit must be open")
	}
	ks := statsFor(t, b, "openai", "c1")
	if ks.State != "open" || ks.ConsecutiveFailures != 3 || ks.OpenedAt == nil {
		t.Fatalf("snapshot: %+v", ks)
	}
}

func TestHalfOpenProbeSuccessCloses(t *testing.T) {
	b, clk := newTestBreaker(2, 30*time.Second)
	failN(b, "openai", "c1", 2)
	if b.Allow("openai", "c1") {
		t.Fatal("open circuit must reject")
	}
	clk.advance(29 * time.Second)
	if b.Allow("openai", "c1") {
		t.Fatal("open duration not elapsed: must reject")
	}
	clk.advance(1 * time.Second)
	if !b.Allow("openai", "c1") {
		t.Fatal("open duration elapsed: probe must be admitted")
	}
	if b.Allow("openai", "c1") {
		t.Fatal("only one probe may be in flight")
	}
	b.OnResult("openai", "c1", true)
	if !b.Allow("openai", "c1") {
		t.Fatal("probe success must close the circuit")
	}
	ks := statsFor(t, b, "openai", "c1")
	if ks.State != "closed" || ks.ConsecutiveFailures != 0 {
		t.Fatalf("snapshot: %+v", ks)
	}
}

func TestHalfOpenProbeFailureReopens(t *testing.T) {
	b, clk := newTestBreaker(2, 30*time.Second)
	failN(b, "openai", "c1", 2)
	clk.advance(31 * time.Second)
	if !b.Allow("openai", "c1") {
		t.Fatal("probe must be admitted after open duration")
	}
	b.OnResult("openai", "c1", false)
	if b.Allow("openai", "c1") {
		t.Fatal("probe failure must re-open the circuit")
	}
	// Fresh window: still open just before it elapses, probe after.
	clk.advance(29 * time.Second)
	if b.Allow("openai", "c1") {
		t.Fatal("re-opened circuit must honor a fresh open window")
	}
	clk.advance(1 * time.Second)
	if !b.Allow("openai", "c1") {
		t.Fatal("second probe must be admitted after the fresh window")
	}
}

func TestRateLimitIsNotAFailure(t *testing.T) {
	// chatcore reports 429 as success (upstream answered); the breaker
	// must therefore never trip on rate limits alone.
	b, _ := newTestBreaker(2, 30*time.Second)
	for i := 0; i < 10; i++ {
		if !b.Allow("openai", "c1") {
			t.Fatal("429s must never open the circuit")
		}
		b.OnResult("openai", "c1", true) // what chatcore passes for a 429
	}
	ks := statsFor(t, b, "openai", "c1")
	if ks.TotalFailures != 0 || ks.State != "closed" {
		t.Fatalf("snapshot: %+v", ks)
	}
}

func TestPerKeyIsolation(t *testing.T) {
	b, _ := newTestBreaker(2, 30*time.Second)
	failN(b, "openai", "c1", 2)
	if b.Allow("openai", "c1") {
		t.Fatal("c1 must be open")
	}
	if !b.Allow("openai", "c2") {
		t.Fatal("c2 of the same provider must be unaffected")
	}
	if !b.Allow("claude", "c1") {
		t.Fatal("same connection id under another provider must be unaffected")
	}
}

func TestSnapshotReportsHalfOpenAfterElapsed(t *testing.T) {
	b, clk := newTestBreaker(1, 10*time.Second)
	b.OnResult("openai", "c1", false)
	if ks := statsFor(t, b, "openai", "c1"); ks.State != "open" {
		t.Fatalf("state = %q, want open", ks.State)
	}
	clk.advance(11 * time.Second)
	if ks := statsFor(t, b, "openai", "c1"); ks.State != "half_open" {
		t.Fatalf("state = %q, want half_open after elapsed window", ks.State)
	}
}

func TestDefaults(t *testing.T) {
	b := New(0, 0)
	if b.Threshold() != DefaultThreshold || b.OpenDuration() != DefaultOpenDuration {
		t.Fatalf("defaults = %d / %v", b.Threshold(), b.OpenDuration())
	}
	if got := b.Snapshot(); len(got) != 0 {
		t.Fatalf("fresh breaker snapshot = %v, want empty", got)
	}
}

func TestConcurrentUse(t *testing.T) {
	b, _ := newTestBreaker(5, time.Minute)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				_ = b.Allow("openai", "c1")
				b.OnResult("openai", "c1", i%3 != 0)
				_ = b.Snapshot()
			}
		}(g)
	}
	wg.Wait()
}
