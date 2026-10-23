package providers

import (
	"encoding/json"
	"sort"
	"testing"
)

// The count of providers served by this package must equal the number of
// JS registries the extractor successfully dumped into registry.json —
// verified both against the embedded file itself and against the known
// extraction result for v0.5.104 (137 providers; index.js is the only
// non-provider file in the registry dir).
func TestCountMatchesExtracted(t *testing.T) {
	var rf struct {
		Providers []json.RawMessage `json:"providers"`
		Failures  []ExtractionIssue `json:"failures"`
		Skipped   []ExtractionIssue `json:"skipped"`
	}
	if err := json.Unmarshal(registryJSON, &rf); err != nil {
		t.Fatalf("parse registry.json: %v", err)
	}
	if got, want := len(All()), len(rf.Providers); got != want {
		t.Fatalf("All() = %d providers, registry.json holds %d extracted", got, want)
	}
	if len(rf.Providers) != 137 {
		t.Fatalf("extracted providers = %d, want 137 (v0.5.104 registry)", len(rf.Providers))
	}
	if len(rf.Failures) != 0 {
		t.Fatalf("extraction failures recorded in registry.json: %v", rf.Failures)
	}
	if len(Failures()) != 0 {
		t.Fatalf("Failures() = %v, want none", Failures())
	}
	sk := Skipped()
	if len(sk) != 1 || sk[0].File != "index.js" {
		t.Fatalf("Skipped() = %v, want only index.js (aggregator)", sk)
	}
	if err := LoadError(); err != nil {
		t.Fatalf("LoadError: %v", err)
	}
}

func TestOpenAISpotCheck(t *testing.T) {
	p, ok := Get("openai")
	if !ok {
		t.Fatal("Get(openai) not found")
	}
	if p.Transport.BaseURL != "https://api.openai.com/v1/chat/completions" {
		t.Errorf("openai baseUrl = %q", p.Transport.BaseURL)
	}
	// openai's registry declares no transport.format (it IS the pivot
	// format); the field must stay empty rather than be invented.
	if p.Transport.Format != "" {
		t.Errorf("openai format = %q, want empty (none declared in registry)", p.Transport.Format)
	}
	if !p.Transport.ForceStream {
		t.Error("openai forceStream = false, want true")
	}
	if p.Display.Name != "OpenAI" || p.Alias != "openai" || p.Category != "apikey" {
		t.Errorf("openai display/alias/category = %q/%q/%q", p.Display.Name, p.Alias, p.Category)
	}
	if !hasModel(p, "gpt-4o") {
		t.Errorf("openai models missing known id gpt-4o (have %d models)", len(p.Models))
	}
	// Unknown keys must be preserved in Raw.
	if _, ok := p.Raw["ttsConfig"]; !ok {
		t.Error("openai Raw lost ttsConfig")
	}
}

func TestClaudeSpotCheck(t *testing.T) {
	p, ok := Get("claude")
	if !ok {
		t.Fatal("Get(claude) not found")
	}
	if p.Transport.BaseURL != "https://api.anthropic.com/v1/messages" {
		t.Errorf("claude baseUrl = %q", p.Transport.BaseURL)
	}
	if p.Transport.Format != "claude" {
		t.Errorf("claude format = %q, want claude", p.Transport.Format)
	}
	if p.Transport.URLSuffix != "?beta=true" {
		t.Errorf("claude urlSuffix = %q, want ?beta=true", p.Transport.URLSuffix)
	}
	if got := p.Transport.Headers["Anthropic-Version"]; got != "2023-06-01" {
		t.Errorf("claude Anthropic-Version header = %q, want 2023-06-01", got)
	}
	if !hasModel(p, "claude-haiku-4-5-20251001") {
		t.Errorf("claude models missing known id claude-haiku-4-5-20251001 (have %d models)", len(p.Models))
	}
	if _, ok := p.Raw["oauth"]; !ok {
		t.Error("claude Raw lost oauth block")
	}
	// Alias lookup: claude registers alias + uiAlias "cc".
	byAlias, ok := Get("cc")
	if !ok || byAlias.ID != "claude" {
		t.Errorf("Get(cc) = %v, %v; want claude", byAlias, ok)
	}
}

func TestAllSortedByPriorityThenID(t *testing.T) {
	all := All()
	if !sort.SliceIsSorted(all, func(i, j int) bool {
		if all[i].Priority != all[j].Priority {
			return all[i].Priority < all[j].Priority
		}
		return all[i].ID < all[j].ID
	}) {
		t.Fatal("All() is not sorted by (priority, id)")
	}
	seen := map[string]bool{}
	for _, p := range all {
		if p.ID == "" {
			t.Fatal("provider with empty id")
		}
		if seen[p.ID] {
			t.Fatalf("duplicate provider id %q", p.ID)
		}
		seen[p.ID] = true
	}
}

func TestModelsFlattened(t *testing.T) {
	sum := 0
	for _, p := range All() {
		sum += len(p.Models)
	}
	flat := Models()
	if len(flat) != sum {
		t.Fatalf("Models() = %d entries, providers hold %d models", len(flat), sum)
	}
	if sum != 1133 {
		t.Fatalf("total top-level models = %d, want 1133 (v0.5.104 extraction)", sum)
	}
	found := false
	for _, e := range flat {
		if e.ProviderID == "openai" && e.Model.ID == "gpt-4o" {
			found = true
		}
		if e.ProviderID == "" || e.Model.ID == "" {
			t.Fatalf("flattened entry with empty field: %+v", e)
		}
	}
	if !found {
		t.Error("Models() missing openai/gpt-4o entry")
	}
}

func TestGetUnknown(t *testing.T) {
	if p, ok := Get("no-such-provider"); ok || p != nil {
		t.Errorf("Get(no-such-provider) = %v, %v; want nil, false", p, ok)
	}
}

func hasModel(p *Provider, id string) bool {
	for _, m := range p.Models {
		if m.ID == id {
			return true
		}
	}
	return false
}
