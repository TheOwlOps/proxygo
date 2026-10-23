// Package providers is the Go port of the JS provider registry in
// open-sse/providers/registry/*.js (9Router v0.5.104).
//
// The data is NOT hand-written: tools/extract_registry.mjs dynamic-imports
// every registry file in the source repo and dumps its default export to
// registry.json, which is embedded here. Typed views (Provider, Display,
// Transport, Model) expose the fields the rest of the port relies on;
// everything else — including fields this port does not model yet — is
// preserved verbatim in Provider.Raw.
package providers

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
)

//go:embed registry.json
var registryJSON []byte

// Model is one entry of a provider's top-level `models` list.
type Model struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind,omitempty"` // llm is implied when empty; also embedding/tts/stt/image/…
}

// Display mirrors the registry `display` block.
type Display struct {
	Name     string `json:"name"`
	Icon     string `json:"icon"`
	Color    string `json:"color"`
	TextIcon string `json:"textIcon"`
	Website  string `json:"website"`
}

// Transport mirrors the registry `transport` block. Extra transport keys
// present in many registries (auth, usage, quirks, validateUrl, …) are not
// modelled here; they survive in Provider.Raw["transport"].
type Transport struct {
	BaseURL     string            `json:"baseUrl"`
	Format      string            `json:"format,omitempty"`
	URLSuffix   string            `json:"urlSuffix,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	ForceStream bool              `json:"forceStream,omitempty"`
}

// Provider is one registry entry.
type Provider struct {
	ID        string         `json:"id"`
	Priority  int            `json:"priority"`
	Alias     string         `json:"alias"`
	Category  string         `json:"category"`
	Display   Display        `json:"display"`
	Transport Transport      `json:"transport"`
	Models    []Model        `json:"models"`
	Raw       map[string]any `json:"-"` // the full registry object, unknown keys preserved
}

// ModelEntry is one flattened provider/model pair, for /v1/models.
type ModelEntry struct {
	ProviderID string `json:"providerId"`
	Model      Model  `json:"model"`
}

// ExtractionIssue records one per-file extraction failure (or skip) from
// tools/extract_registry.mjs, as stored in registry.json.
type ExtractionIssue struct {
	File  string `json:"file"`
	Error string `json:"error"`
}

type registryFile struct {
	Providers []map[string]any  `json:"providers"`
	Failures  []ExtractionIssue `json:"failures"`
	Skipped   []ExtractionIssue `json:"skipped"`
}

var (
	loadOnce  sync.Once
	all       []*Provider
	byKey     map[string]*Provider
	failures  []ExtractionIssue
	skipped   []ExtractionIssue
	loadError error
)

func load() {
	loadOnce.Do(func() {
		var rf registryFile
		if err := json.Unmarshal(registryJSON, &rf); err != nil {
			loadError = fmt.Errorf("providers: parse embedded registry.json: %w", err)
			return
		}
		failures = rf.Failures
		skipped = rf.Skipped
		byKey = make(map[string]*Provider, len(rf.Providers)*3)
		for _, raw := range rf.Providers {
			p := convert(raw)
			if p.ID == "" {
				continue
			}
			all = append(all, p)
			// Index by id first, then alias / aliases / uiAlias. First
			// writer wins, so an id can never be shadowed by an alias
			// and alias collisions resolve in registry file order.
			addKey(p.ID, p)
		}
		for _, p := range all {
			addKey(p.Alias, p)
			addKey(str(p.Raw["uiAlias"]), p)
			if list, ok := p.Raw["aliases"].([]any); ok {
				for _, a := range list {
					addKey(str(a), p)
				}
			}
		}
		sort.SliceStable(all, func(i, j int) bool {
			if all[i].Priority != all[j].Priority {
				return all[i].Priority < all[j].Priority
			}
			return all[i].ID < all[j].ID
		})
	})
}

func addKey(key string, p *Provider) {
	if key == "" {
		return
	}
	if _, taken := byKey[key]; !taken {
		byKey[key] = p
	}
}

func convert(raw map[string]any) *Provider {
	p := &Provider{
		ID:       str(raw["id"]),
		Priority: intVal(raw["priority"]),
		Alias:    str(raw["alias"]),
		Category: str(raw["category"]),
		Raw:      raw,
	}
	if d, ok := raw["display"].(map[string]any); ok {
		p.Display = Display{
			Name:     str(d["name"]),
			Icon:     str(d["icon"]),
			Color:    str(d["color"]),
			TextIcon: str(d["textIcon"]),
			Website:  str(d["website"]),
		}
	}
	if t, ok := raw["transport"].(map[string]any); ok {
		p.Transport.BaseURL = str(t["baseUrl"])
		if p.Transport.BaseURL == "" {
			// A few registries (antigravity, kiro) carry `baseUrls: [...]`
			// instead of a single baseUrl; use the first entry and keep
			// the full list in Raw["transport"].
			if urls, ok := t["baseUrls"].([]any); ok && len(urls) > 0 {
				p.Transport.BaseURL = str(urls[0])
			}
		}
		p.Transport.Format = str(t["format"])
		p.Transport.URLSuffix = str(t["urlSuffix"])
		p.Transport.ForceStream = boolVal(t["forceStream"])
		if h, ok := t["headers"].(map[string]any); ok {
			p.Transport.Headers = make(map[string]string, len(h))
			for k, v := range h {
				if s, ok := v.(string); ok {
					p.Transport.Headers[k] = s
				} else {
					p.Transport.Headers[k] = fmt.Sprintf("%v", v)
				}
			}
		}
	}
	if list, ok := raw["models"].([]any); ok {
		for _, item := range list {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			p.Models = append(p.Models, Model{
				ID:   str(m["id"]),
				Name: str(m["name"]),
				Kind: str(m["kind"]),
			})
		}
	}
	return p
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func intVal(v any) int {
	if f, ok := v.(float64); ok {
		return int(f)
	}
	return 0
}

func boolVal(v any) bool {
	b, _ := v.(bool)
	return b
}

// All returns every extracted provider, sorted by priority then id.
func All() []*Provider {
	load()
	out := make([]*Provider, len(all))
	copy(out, all)
	return out
}

// Get returns the provider with the given id, alias, any of its `aliases`,
// or its uiAlias.
func Get(idOrAlias string) (*Provider, bool) {
	load()
	p, ok := byKey[idOrAlias]
	return p, ok
}

// Models flattens every provider's top-level models, in All() order.
func Models() []ModelEntry {
	load()
	var out []ModelEntry
	for _, p := range all {
		for _, m := range p.Models {
			out = append(out, ModelEntry{ProviderID: p.ID, Model: m})
		}
	}
	return out
}

// Failures lists the per-file extraction failures recorded by
// tools/extract_registry.mjs (empty when every registry file extracted).
func Failures() []ExtractionIssue {
	load()
	return append([]ExtractionIssue(nil), failures...)
}

// Skipped lists files that were not provider registries (index.js).
func Skipped() []ExtractionIssue {
	load()
	return append([]ExtractionIssue(nil), skipped...)
}

// LoadError reports a malformed embedded registry.json, if any.
func LoadError() error {
	load()
	return loadError
}
