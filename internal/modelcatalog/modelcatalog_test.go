package modelcatalog

import "testing"

func TestCountsAndNoFailures(t *testing.T) {
	if err := LoadError(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if f := Failures(); len(f) != 0 {
		t.Fatalf("extraction failures recorded: %v", f)
	}
	c := Counts()
	if c["providerKeys"] < 100 {
		t.Fatalf("providerKeys = %d, want >= 100", c["providerKeys"])
	}
	if c["models"] < 1000 {
		t.Fatalf("models = %d, want >= 1000", c["models"])
	}
	if c["pricedModels"] == 0 || c["patterns"] == 0 {
		t.Fatalf("pricing counts empty: %v", c)
	}
}

func TestTargetFormatFromEntry(t *testing.T) {
	m := ModelMeta("minimax", "MiniMax-M3")
	if !m.Found {
		t.Fatal("MiniMax-M3 not found under minimax")
	}
	if m.TargetFormat != "claude" {
		t.Fatalf("TargetFormat = %q, want claude", m.TargetFormat)
	}
	m = ModelMeta("muse", "muse-spark-1.3")
	if m.TargetFormat != "openai-responses" {
		t.Fatalf("muse TargetFormat = %q, want openai-responses", m.TargetFormat)
	}
	if len(m.SupportedFormats) != 1 || m.SupportedFormats[0] != "openai-responses" {
		t.Fatalf("muse SupportedFormats = %v", m.SupportedFormats)
	}
}

func TestSupportedFormatsAndType(t *testing.T) {
	m := ModelMeta("opencode-go", "deepseek-v4-pro")
	if !m.Found {
		t.Fatal("deepseek-v4-pro not found under opencode-go")
	}
	if len(m.SupportedFormats) != 3 {
		t.Fatalf("SupportedFormats = %v, want 3 entries", m.SupportedFormats)
	}
	tts := ModelMeta("openai", "tts-1")
	if !tts.Found || tts.Type != "tts" {
		t.Fatalf("tts-1 meta = %+v, want Found + Type tts", tts)
	}
}

func TestUpstreamOverride(t *testing.T) {
	m := ModelMeta("cx", "gpt-5.6-sol-review")
	if !m.Found {
		t.Fatal("gpt-5.6-sol-review not found under cx")
	}
	if m.UpstreamID != "gpt-5.6-sol" {
		t.Fatalf("UpstreamID = %q, want gpt-5.6-sol", m.UpstreamID)
	}
	if got := UpstreamID("openai", "gpt-4o"); got != "gpt-4o" {
		t.Fatalf("UpstreamID identity = %q, want gpt-4o", got)
	}
}

func TestOpenCodeUnknownFallback(t *testing.T) {
	m := ModelMeta("opencode-go", "totally-unknown-model-xyz")
	if m.Found {
		t.Fatal("unknown model reported found")
	}
	if len(m.SupportedFormats) != 1 || m.SupportedFormats[0] != "openai" {
		t.Fatalf("unknown opencode SupportedFormats = %v, want [openai]", m.SupportedFormats)
	}
	g := ModelMeta("opencode-go", "gpt-9-unknown")
	if g.TargetFormat != "openai-responses" {
		t.Fatalf("opencode gpt family TargetFormat = %q, want openai-responses", g.TargetFormat)
	}
}

func TestPricingFor(t *testing.T) {
	rec := PricingFor("openai", "gpt-4o")
	if rec == nil || rec["input"] != 2.5 || rec["output"] != 10.0 {
		t.Fatalf("gpt-4o pricing = %v, want input 2.5 / output 10", rec)
	}
	// Provider override wins over canonical/pattern resolution.
	rec = PricingFor("tokenrouter", "openai/gpt-5.5-pro")
	if rec == nil || rec["input"] != 30.0 {
		t.Fatalf("tokenrouter override = %v, want input 30", rec)
	}
	// Free namespace → zero pricing, never the canonical rate.
	rec = PricingFor("", "cline-free/deepseek-v4.1-flash")
	if rec == nil || rec["input"] != 0.0 {
		t.Fatalf("free namespace pricing = %v, want zeros", rec)
	}
	// Pattern fallback.
	rec = PricingFor("", "claude-opus-9-9")
	if rec == nil || rec["input"] != 5.0 {
		t.Fatalf("pattern pricing = %v, want claude-opus-* input 5", rec)
	}
	if rec := PricingFor("", "no-such-model-zzz"); rec != nil {
		t.Fatalf("unknown model priced: %v", rec)
	}
}

func TestDefaultProviderPricingShape(t *testing.T) {
	d := DefaultProviderPricing()
	gh, ok := d["gh"].(map[string]any)
	if !ok {
		t.Fatalf("gh missing from DefaultProviderPricing: %v", d)
	}
	rec, ok := gh["gpt-5.3-codex"].(map[string]any)
	if !ok || rec["input"] != 1.75 {
		t.Fatalf("gh gpt-5.3-codex = %v, want input 1.75", rec)
	}
}
