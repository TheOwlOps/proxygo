// Package breaker implements a per-(provider, connection) circuit
// breaker for the chat pipeline (Feature Pack F2).
//
// State machine per key:
//
//	closed ──N consecutive failures──▶ open
//	open ──open duration elapsed──▶ half-open (exactly one probe)
//	half-open ──probe success──▶ closed (counters reset)
//	half-open ──probe failure──▶ open (fresh open window)
//
// A "failure" is a transport error or an upstream 5xx response, as
// classified by the caller (chatcore). 429 responses are NOT failures —
// per-account cooldown already handles rate limits — so callers report
// them as successes (any non-5xx upstream response proves the upstream
// is alive). The breaker is goroutine-safe and its clock is injectable
// for tests.
package breaker

import (
	"sort"
	"sync"
	"time"
)

// State is the circuit state for one key.
type State int

const (
	Closed State = iota
	Open
	HalfOpen
)

func (s State) String() string {
	switch s {
	case Open:
		return "open"
	case HalfOpen:
		return "half_open"
	default:
		return "closed"
	}
}

type key struct {
	provider string
	connID   string
}

type entry struct {
	state               State
	consecutiveFailures int
	totalFailures       int64
	totalSuccesses      int64
	openedAt            time.Time // when the circuit last opened
	lastFailureAt       time.Time
	probeInFlight       bool // half-open: the single probe was taken
}

// Breaker tracks circuit state per (provider, connectionID). The zero
// value is not usable; build one with New.
type Breaker struct {
	mu           sync.Mutex
	threshold    int
	openDuration time.Duration
	now          func() time.Time
	entries      map[key]*entry
}

// Defaults mirror the Feature Pack settings defaults.
const (
	DefaultThreshold    = 5
	DefaultOpenDuration = 30 * time.Second
)

// New builds a Breaker. Non-positive values fall back to the defaults
// (threshold 5 consecutive failures, 30s open duration).
func New(threshold int, openDuration time.Duration) *Breaker {
	if threshold <= 0 {
		threshold = DefaultThreshold
	}
	if openDuration <= 0 {
		openDuration = DefaultOpenDuration
	}
	return &Breaker{
		threshold:    threshold,
		openDuration: openDuration,
		now:          time.Now,
		entries:      map[key]*entry{},
	}
}

// Threshold returns the configured consecutive-failure threshold.
func (b *Breaker) Threshold() int { return b.threshold }

// OpenDuration returns the configured open duration.
func (b *Breaker) OpenDuration() time.Duration { return b.openDuration }

// Allow reports whether one attempt may proceed for the key. Closed
// circuits always allow. An open circuit rejects until the open
// duration has elapsed, then transitions to half-open and admits
// exactly one probe; further calls reject while that probe is in
// flight. A caller that takes the probe MUST report its outcome via
// OnResult, or the circuit stays half-open with the probe slot taken.
func (b *Breaker) Allow(provider, connID string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.entries[key{provider, connID}]
	if !ok {
		return true
	}
	switch e.state {
	case Open:
		if b.now().Sub(e.openedAt) >= b.openDuration {
			e.state = HalfOpen
			e.probeInFlight = true
			return true
		}
		return false
	case HalfOpen:
		if e.probeInFlight {
			return false
		}
		e.probeInFlight = true
		return true
	default: // Closed
		return true
	}
}

// OnResult records the outcome of an attempt admitted by Allow.
// success=true closes the circuit and resets the consecutive-failure
// count. success=false increments the count: in closed state the
// circuit opens once the count reaches the threshold; in half-open
// state any failure re-opens the circuit for a fresh open duration.
func (b *Breaker) OnResult(provider, connID string, success bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	k := key{provider, connID}
	e, ok := b.entries[k]
	if !ok {
		e = &entry{state: Closed}
		b.entries[k] = e
	}
	now := b.now()
	if success {
		e.totalSuccesses++
		e.consecutiveFailures = 0
		e.probeInFlight = false
		e.state = Closed
		return
	}
	e.totalFailures++
	e.consecutiveFailures++
	e.lastFailureAt = now
	switch e.state {
	case HalfOpen:
		e.state = Open
		e.openedAt = now
		e.probeInFlight = false
	case Closed:
		if e.consecutiveFailures >= b.threshold {
			e.state = Open
			e.openedAt = now
		}
	case Open:
		// A late failure from an attempt admitted before the circuit
		// opened: count it, but keep the original open window.
	}
}

// KeyStats is the snapshot of one circuit, for dashboards/APIs.
type KeyStats struct {
	Provider            string     `json:"provider"`
	ConnectionID        string     `json:"connectionId"`
	State               string     `json:"state"` // closed | open | half_open
	ConsecutiveFailures int        `json:"consecutiveFailures"`
	TotalFailures       int64      `json:"totalFailures"`
	TotalSuccesses      int64      `json:"totalSuccesses"`
	OpenedAt            *time.Time `json:"openedAt,omitempty"`
	LastFailureAt       *time.Time `json:"lastFailureAt,omitempty"`
}

// Snapshot returns per-key stats for every circuit that has recorded
// at least one result, sorted by (provider, connectionID). An open
// circuit whose open duration has already elapsed is reported as
// half_open (the next Allow call performs the transition).
func (b *Breaker) Snapshot() []KeyStats {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	out := make([]KeyStats, 0, len(b.entries))
	for k, e := range b.entries {
		st := e.state
		if st == Open && now.Sub(e.openedAt) >= b.openDuration {
			st = HalfOpen
		}
		ks := KeyStats{
			Provider:            k.provider,
			ConnectionID:        k.connID,
			State:               st.String(),
			ConsecutiveFailures: e.consecutiveFailures,
			TotalFailures:       e.totalFailures,
			TotalSuccesses:      e.totalSuccesses,
		}
		if !e.openedAt.IsZero() {
			t := e.openedAt
			ks.OpenedAt = &t
		}
		if !e.lastFailureAt.IsZero() {
			t := e.lastFailureAt
			ks.LastFailureAt = &t
		}
		out = append(out, ks)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Provider != out[j].Provider {
			return out[i].Provider < out[j].Provider
		}
		return out[i].ConnectionID < out[j].ConnectionID
	})
	return out
}
