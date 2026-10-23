// Package respcache is the in-memory response cache for the chat
// endpoints (Feature Pack F1). It is an additive, opt-in feature: the
// server middleware only consults it when the settings getter injected
// via Configure reports the cache enabled.
//
// Design:
//   - Goroutine-safe LRU (container/list) with a per-entry TTL stamped
//     at store time from the then-current configuration.
//   - Keys are content hashes (see KeyFor): identical requests share an
//     entry regardless of JSON key order or the `stream` flag, and
//     different API keys never share an entry.
//   - Entries store the full response (status, headers, raw body
//     bytes) so SSE streams replay verbatim, byte for byte.
package respcache

import (
	"bytes"
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// Defaults applied when the injected settings getter is absent or
// reports non-positive values (docs/FEATURE_PACK_13.md).
const (
	DefaultTTLSeconds = 300
	DefaultMaxEntries = 500
)

// Entry is one cached response: status line, headers and the exact
// body bytes to replay.
type Entry struct {
	Status int
	Header http.Header
	Body   []byte
}

// Stats is a point-in-time snapshot of the cache counters. Counters
// are cumulative for the life of the process (Clear empties the cache
// but does not reset counters).
type Stats struct {
	Hits      int64 `json:"hits"`
	Misses    int64 `json:"misses"`
	Stores    int64 `json:"stores"`
	Evictions int64 `json:"evictions"`
	Entries   int   `json:"entries"`
}

type element struct {
	key       string
	entry     Entry
	expiresAt time.Time
}

// Cache is a goroutine-safe LRU cache with per-entry TTL.
type Cache struct {
	mu         sync.Mutex
	ll         *list.List // front = most recently used
	items      map[string]*list.Element
	ttl        time.Duration
	maxEntries int
	getter     func() (enabled bool, ttlSeconds, maxEntries int)
	now        func() time.Time

	hits, misses, stores, evictions int64
}

// New returns a standalone cache with fixed limits. Non-positive
// values fall back to the documented defaults.
func New(maxEntries int, ttl time.Duration) *Cache {
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	if ttl <= 0 {
		ttl = DefaultTTLSeconds * time.Second
	}
	return &Cache{
		ll:         list.New(),
		items:      make(map[string]*list.Element),
		ttl:        ttl,
		maxEntries: maxEntries,
		now:        time.Now,
	}
}

// SetClock overrides the time source (tests). Not goroutine-safe with
// concurrent use; set it before handing the cache out.
func (c *Cache) SetClock(now func() time.Time) {
	if now != nil {
		c.now = now
	}
}

func (c *Cache) setGetter(g func() (bool, int, int)) {
	c.mu.Lock()
	c.getter = g
	c.mu.Unlock()
}

// limits resolves the effective (ttl, maxEntries): the injected
// settings getter wins when present, with defaults for bad values.
func (c *Cache) limits() (time.Duration, int) {
	c.mu.Lock()
	g := c.getter
	c.mu.Unlock()
	if g != nil {
		_, ttlSec, max := g()
		if ttlSec <= 0 {
			ttlSec = DefaultTTLSeconds
		}
		if max <= 0 {
			max = DefaultMaxEntries
		}
		return time.Duration(ttlSec) * time.Second, max
	}
	return c.ttl, c.maxEntries
}

// config reports the effective configuration of the default cache.
func (c *Cache) config() (bool, int, int) {
	c.mu.Lock()
	g := c.getter
	ttl, max := c.ttl, c.maxEntries
	c.mu.Unlock()
	if g == nil {
		return false, int(ttl / time.Second), max
	}
	enabled, ttlSec, maxEntries := g()
	if ttlSec <= 0 {
		ttlSec = DefaultTTLSeconds
	}
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	return enabled, ttlSec, maxEntries
}

// Get returns a copy of the cached entry for key. Expired entries
// count as misses and are dropped lazily.
func (c *Cache) Get(key string) (Entry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		c.misses++
		return Entry{}, false
	}
	e := el.Value.(*element)
	if !c.now().Before(e.expiresAt) {
		c.removeLocked(el)
		c.misses++
		return Entry{}, false
	}
	c.ll.MoveToFront(el)
	c.hits++
	return cloneEntry(e.entry), true
}

// Put stores a copy of the entry under key with a fresh TTL, evicting
// least-recently-used entries until the cache is within its limit.
func (c *Cache) Put(key string, entry Entry) {
	ttl, max := c.limits()
	c.mu.Lock()
	defer c.mu.Unlock()
	exp := c.now().Add(ttl)
	if el, ok := c.items[key]; ok {
		e := el.Value.(*element)
		e.entry = cloneEntry(entry)
		e.expiresAt = exp
		c.ll.MoveToFront(el)
		c.stores++
		return
	}
	el := c.ll.PushFront(&element{key: key, entry: cloneEntry(entry), expiresAt: exp})
	c.items[key] = el
	c.stores++
	for c.ll.Len() > max {
		back := c.ll.Back()
		if back == nil {
			break
		}
		c.removeLocked(back)
		c.evictions++
	}
}

// Clear drops every entry. Counters are left untouched.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ll.Init()
	c.items = make(map[string]*list.Element)
}

// Stats snapshots the counters and the current entry count.
func (c *Cache) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Stats{
		Hits:      c.hits,
		Misses:    c.misses,
		Stores:    c.stores,
		Evictions: c.evictions,
		Entries:   len(c.items),
	}
}

func (c *Cache) removeLocked(el *list.Element) {
	e := el.Value.(*element)
	delete(c.items, e.key)
	c.ll.Remove(el)
}

func cloneEntry(e Entry) Entry {
	out := Entry{Status: e.Status}
	if e.Header != nil {
		out.Header = e.Header.Clone()
	}
	if e.Body != nil {
		out.Body = append([]byte(nil), e.Body...)
	}
	return out
}

// ---------- Key derivation ----------

// Fingerprint returns the first 8 hex chars of the sha256 of the API
// key, or "" when there is no key. It identifies the key for cache
// isolation without storing the key itself.
func Fingerprint(apiKey string) string {
	if apiKey == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(sum[:])[:8]
}

// KeyFor derives the cache key for a chat request: sha256 over the
// canonical JSON of {path, model, canonical body}, suffixed with the
// API-key fingerprint so different keys never share an entry.
//
// The canonical body is the raw request JSON parsed and re-marshaled
// (encoding/json sorts map keys) with the top-level `stream` field
// removed — stream and non-stream requests intentionally map to the
// same entry because responses are stored and replayed as raw bytes.
// Numbers keep their literal form (UseNumber) so distinct numeric
// literals never collapse through float64 rounding.
//
// ok is false when the body is not a JSON object (nothing cacheable).
func KeyFor(path string, rawBody []byte, apiKey string) (key string, ok bool) {
	dec := json.NewDecoder(bytes.NewReader(rawBody))
	dec.UseNumber()
	var body map[string]any
	if err := dec.Decode(&body); err != nil || body == nil {
		return "", false
	}
	model, _ := body["model"].(string)
	delete(body, "stream")
	canonBody, err := json.Marshal(body)
	if err != nil {
		return "", false
	}
	wrap := map[string]any{
		"path":  path,
		"model": model,
		"body":  json.RawMessage(canonBody),
	}
	canon, err := json.Marshal(wrap)
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(canon)
	key = hex.EncodeToString(sum[:])
	if fp := Fingerprint(apiKey); fp != "" {
		key += "." + fp
	}
	return key, true
}

// ---------- Package-level default cache (used by the server) ----------

var def = New(DefaultMaxEntries, DefaultTTLSeconds*time.Second)

// Configure injects the settings getter the middleware consults on
// every request: enabled flag, TTL (seconds) and max entries. Passing
// nil removes the getter (cache disabled, documented defaults).
// Parent wires this to the settings store.
func Configure(getter func() (enabled bool, ttlSeconds, maxEntries int)) {
	def.setGetter(getter)
}

// Config reports the default cache's effective configuration.
func Config() (enabled bool, ttlSeconds, maxEntries int) {
	return def.config()
}

// Get looks up key in the default cache.
func Get(key string) (Entry, bool) { return def.Get(key) }

// Put stores entry in the default cache.
func Put(key string, entry Entry) { def.Put(key, entry) }

// Clear empties the default cache.
func Clear() { def.Clear() }

// Stats snapshots the default cache's counters.
func StatsSnapshot() Stats { return def.Stats() }
