package respcache

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestKeyForCanonicalization(t *testing.T) {
	a := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"temperature":0.5}`)
	// Same semantic body: different key order + whitespace.
	b := []byte(`{ "temperature" : 0.5, "messages" : [ { "content" : "hi", "role" : "user" } ], "model" : "gpt-4o" }`)
	ka, ok := KeyFor("/v1/chat/completions", a, "sk-1")
	if !ok {
		t.Fatal("KeyFor(a) not ok")
	}
	kb, ok := KeyFor("/v1/chat/completions", b, "sk-1")
	if !ok {
		t.Fatal("KeyFor(b) not ok")
	}
	if ka != kb {
		t.Fatalf("canonical keys differ:\n%s\n%s", ka, kb)
	}

	// stream flag must not change the key (byte-replay sharing).
	c := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"temperature":0.5,"stream":true}`)
	kc, _ := KeyFor("/v1/chat/completions", c, "sk-1")
	if kc != ka {
		t.Fatal("stream=true changed the key")
	}
	d := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"temperature":0.5,"stream":false}`)
	kd, _ := KeyFor("/v1/chat/completions", d, "sk-1")
	if kd != ka {
		t.Fatal("stream=false changed the key")
	}

	// Different model / path / content → different key.
	if k, _ := KeyFor("/v1/chat/completions", []byte(`{"model":"other","messages":[]}`), "sk-1"); k == ka {
		t.Fatal("different model produced same key")
	}
	if k, _ := KeyFor("/v1/messages", a, "sk-1"); k == ka {
		t.Fatal("different path produced same key")
	}
	if k, _ := KeyFor("/v1/chat/completions", []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"bye"}]}`), "sk-1"); k == ka {
		t.Fatal("different content produced same key")
	}
}

func TestKeyForAPIKeyIsolation(t *testing.T) {
	body := []byte(`{"model":"m","messages":[]}`)
	k1, _ := KeyFor("/v1/chat/completions", body, "sk-alpha")
	k2, _ := KeyFor("/v1/chat/completions", body, "sk-beta")
	kNone, _ := KeyFor("/v1/chat/completions", body, "")
	if k1 == k2 {
		t.Fatal("different API keys share a cache key")
	}
	if k1 == kNone || k2 == kNone {
		t.Fatal("keyed and unkeyed requests share a cache key")
	}
	// Fingerprint: first 8 hex chars of sha256(key).
	if got := Fingerprint("sk-alpha"); len(got) != 8 {
		t.Fatalf("fingerprint len = %d, want 8", len(got))
	}
	if Fingerprint("") != "" {
		t.Fatal("empty key must have empty fingerprint")
	}
	// Same key → stable fingerprint suffix.
	if k1[len(k1)-8:] != Fingerprint("sk-alpha") {
		t.Fatal("cache key does not end with the key fingerprint")
	}
}

func TestKeyForRejectsNonObjects(t *testing.T) {
	for _, raw := range []string{"", "not json", `[1,2,3]`, `"str"`, `42`, `null`} {
		if _, ok := KeyFor("/v1/chat/completions", []byte(raw), ""); ok {
			t.Fatalf("KeyFor(%q) ok, want not cacheable", raw)
		}
	}
}

func TestTTLExpiry(t *testing.T) {
	c := New(10, time.Minute)
	now := time.Unix(1_700_000_000, 0)
	c.SetClock(func() time.Time { return now })

	c.Put("k", Entry{Status: 200, Body: []byte("v")})
	if _, ok := c.Get("k"); !ok {
		t.Fatal("fresh entry missed")
	}
	now = now.Add(59 * time.Second)
	if _, ok := c.Get("k"); !ok {
		t.Fatal("entry expired before TTL")
	}
	now = now.Add(2 * time.Second) // 61s > 60s TTL
	if _, ok := c.Get("k"); ok {
		t.Fatal("entry survived past TTL")
	}
	s := c.Stats()
	if s.Hits != 2 || s.Misses != 1 {
		t.Fatalf("stats = %+v, want 2 hits / 1 miss", s)
	}
	if s.Entries != 0 {
		t.Fatalf("expired entry not dropped, entries = %d", s.Entries)
	}
}

func TestLRUEviction(t *testing.T) {
	c := New(3, time.Minute)
	put := func(k string) { c.Put(k, Entry{Status: 200, Body: []byte(k)}) }
	put("a")
	put("b")
	put("c")
	// Touch "a" so "b" becomes least recently used.
	if _, ok := c.Get("a"); !ok {
		t.Fatal("a missing")
	}
	put("d") // must evict b
	if _, ok := c.Get("b"); ok {
		t.Fatal("b should have been evicted (LRU)")
	}
	for _, k := range []string{"a", "c", "d"} {
		if _, ok := c.Get(k); !ok {
			t.Fatalf("%s should still be cached", k)
		}
	}
	s := c.Stats()
	if s.Evictions != 1 {
		t.Fatalf("evictions = %d, want 1", s.Evictions)
	}
	if s.Entries != 3 {
		t.Fatalf("entries = %d, want 3", s.Entries)
	}
	if s.Stores != 4 {
		t.Fatalf("stores = %d, want 4", s.Stores)
	}
}

func TestPutExistingKeyUpdates(t *testing.T) {
	c := New(2, time.Minute)
	c.Put("k", Entry{Status: 200, Body: []byte("v1")})
	c.Put("k", Entry{Status: 200, Body: []byte("v2")})
	e, ok := c.Get("k")
	if !ok || string(e.Body) != "v2" {
		t.Fatalf("got %q ok=%v, want v2", e.Body, ok)
	}
	if s := c.Stats(); s.Entries != 1 || s.Stores != 2 {
		t.Fatalf("stats = %+v, want 1 entry / 2 stores", s)
	}
}

func TestClearKeepsCounters(t *testing.T) {
	c := New(10, time.Minute)
	c.Put("a", Entry{Status: 200, Body: []byte("a")})
	_, _ = c.Get("a")
	c.Clear()
	if s := c.Stats(); s.Entries != 0 {
		t.Fatalf("entries after Clear = %d", s.Entries)
	}
	if _, ok := c.Get("a"); ok {
		t.Fatal("entry survived Clear")
	}
	if s := c.Stats(); s.Hits != 1 || s.Stores != 1 {
		t.Fatalf("counters reset by Clear: %+v", s)
	}
}

func TestEntryCopiesAreIsolated(t *testing.T) {
	c := New(10, time.Minute)
	body := []byte("orig")
	c.Put("k", Entry{Status: 200, Body: body})
	body[0] = 'X' // mutating the caller's slice must not corrupt the entry
	e, _ := c.Get("k")
	if string(e.Body) != "orig" {
		t.Fatalf("stored body aliased caller slice: %q", e.Body)
	}
	e.Body[0] = 'Y' // mutating a returned copy must not corrupt it either
	e2, _ := c.Get("k")
	if string(e2.Body) != "orig" {
		t.Fatalf("stored body aliased returned slice: %q", e2.Body)
	}
}

func TestConfigureAndPackageLevel(t *testing.T) {
	Configure(func() (bool, int, int) { return true, 120, 42 })
	defer Configure(nil)
	enabled, ttl, max := Config()
	if !enabled || ttl != 120 || max != 42 {
		t.Fatalf("Config = (%v,%d,%d), want (true,120,42)", enabled, ttl, max)
	}
	Clear()
	Put("pk", Entry{Status: 200, Body: []byte("v")})
	if e, ok := Get("pk"); !ok || string(e.Body) != "v" {
		t.Fatal("package-level Put/Get round-trip failed")
	}
	if s := StatsSnapshot(); s.Entries != 1 {
		t.Fatalf("package-level entries = %d, want 1", s.Entries)
	}
	Clear()
}

func TestConfigureBadValuesFallBackToDefaults(t *testing.T) {
	Configure(func() (bool, int, int) { return true, 0, -5 })
	defer Configure(nil)
	_, ttl, max := Config()
	if ttl != DefaultTTLSeconds || max != DefaultMaxEntries {
		t.Fatalf("Config = ttl %d max %d, want defaults %d/%d", ttl, max, DefaultTTLSeconds, DefaultMaxEntries)
	}
}

func TestConcurrentAccess(t *testing.T) {
	c := New(64, time.Minute)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				k := fmt.Sprintf("k%d", (g*200+i)%128)
				c.Put(k, Entry{Status: 200, Body: []byte(k)})
				_, _ = c.Get(k)
				_ = c.Stats()
			}
		}(g)
	}
	wg.Wait()
	if s := c.Stats(); s.Entries > 64 {
		t.Fatalf("entries = %d exceeds max 64", s.Entries)
	}
}
