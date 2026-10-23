package app

import (
	"testing"

	"9router-go/internal/db"
)

// Team K wiring tests: chatcore ModelMeta answers now come from the
// extracted PROVIDER_MODELS catalogue (via providerSource), and the db
// pricing hooks resolve real rates (catalog.go's init wires them).

func TestModelMetaFromCatalog(t *testing.T) {
	ps := providerSource{}
	meta := ps.ModelMeta("minimax", "MiniMax-M3")
	if meta.TargetFormat != "claude" {
		t.Fatalf("minimax/MiniMax-M3 TargetFormat = %q, want claude (registry entry)", meta.TargetFormat)
	}
	meta = ps.ModelMeta("opencode-go", "deepseek-v4-pro")
	if len(meta.SupportedFormats) != 3 {
		t.Fatalf("opencode-go/deepseek-v4-pro SupportedFormats = %v, want 3", meta.SupportedFormats)
	}
	meta = ps.ModelMeta("cx", "gpt-5.6-sol-review")
	if meta.UpstreamID != "gpt-5.6-sol" {
		t.Fatalf("cx review UpstreamID = %q, want gpt-5.6-sol", meta.UpstreamID)
	}
	meta = ps.ModelMeta("openai", "tts-1")
	if meta.Type != "tts" {
		t.Fatalf("openai/tts-1 Type = %q, want tts", meta.Type)
	}
}

func TestPricingHooksWired(t *testing.T) {
	if db.DefaultProviderPricing == nil {
		t.Fatal("db.DefaultProviderPricing not wired (catalog.go init)")
	}
	if db.PricingResolver == nil {
		t.Fatal("db.PricingResolver not wired (catalog.go init)")
	}
	store, err := db.OpenInDir(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	rec, err := store.GetPricingForModel("openai", "gpt-4o")
	if err != nil {
		t.Fatalf("GetPricingForModel: %v", err)
	}
	if rec == nil {
		t.Fatal("gpt-4o pricing resolved to nil, want canonical MODEL_PRICING")
	}
	if v, _ := rec["input"].(float64); v != 2.5 {
		t.Fatalf("gpt-4o input = %v, want 2.5", rec["input"])
	}
	cost := db.CalculateCostFromTokens(
		db.Record{"prompt_tokens": 1_000_000.0, "completion_tokens": 1_000_000.0},
		rec,
	)
	if cost != 12.5 {
		t.Fatalf("cost for 1M in + 1M out of gpt-4o = %v, want 12.5", cost)
	}
	// Merged pricing (defaults + user overrides) must include the
	// PROVIDER_PRICING providers.
	all, err := store.GetPricing()
	if err != nil {
		t.Fatalf("GetPricing: %v", err)
	}
	if _, ok := all["tokenrouter"]; !ok {
		t.Fatalf("GetPricing missing tokenrouter defaults: keys=%v", len(all))
	}
}
