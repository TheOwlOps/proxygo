package executors

import "strings"

// Registry ports open-sse/executors/index.js: a map of specialised
// executors by provider id (plus the JS aliases), with DefaultExecutor as
// the fallback for every other provider (getExecutor).
//
// Providers whose JS executor is NOT yet ported fall back to
// DefaultExecutor and are listed in NotPorted so the parent can track the
// gap. As of Team Z the list is EMPTY — every JS executor has a Go port:
//   - antigravity is ported at executor level (deep content normalisation
//     is translator territory).
//   - codebuddy-cn / codebuddy-intl have no dedicated executor: they use
//     combined-auth DefaultExecutor behaviour via their registry AuthSpec,
//     which the default path already honours (same as JS).
//   - cursor: fully ported in Phase 2 (HTTP/2 AgentService + protobuf
//     codec, cursor*.go).
//   - Team Z ports (protocol-level, fixture/httptest-verified,
//     live-unverified against real accounts): opencode trio (opencode.go),
//     grok-cli + grok-web (grok.go), perplexity-web (perplexity_web.go),
//     windsurf (windsurf.go), trae (trae.go), zed (zed.go), qoder +
//     qoder-cn (qoder.go), devin-cli (devin.go, ACP subprocess),
//     mimo-free (mimo_free.go), xiaomi-mimo (xiaomi_mimo.go).

var NotPorted = []string{}

var factories = map[string]func() Executor{
	"antigravity":         func() Executor { return NewAntigravityExecutor() },
	"azure":               func() Executor { return NewAzureExecutor() },
	"gemini-cli":          func() Executor { return NewGeminiCLIExecutor() },
	"github":              func() Executor { return NewGithubExecutor() },
	"iflow":               func() Executor { return NewIFlowExecutor() },
	"kiro":                func() Executor { return NewKiroExecutor() },
	"kimchi":              func() Executor { return NewKimchiExecutor() },
	"codex":               func() Executor { return NewCodexExecutor() },
	"cursor":              func() Executor { return NewCursorExecutor() },
	"cu":                  func() Executor { return NewCursorExecutor() }, // alias (index.js)
	"vertex":              func() Executor { return NewVertexExecutor("vertex") },
	"vertex-partner":      func() Executor { return NewVertexExecutor("vertex-partner") },
	"commandcode":         func() Executor { return NewCommandCodeExecutor() },
	"ollama-local":        func() Executor { return NewOllamaLocalExecutor() },
	"xiaomi-tokenplan":    func() Executor { return NewXiaomiTokenplanExecutor() },
	"minimax-code":        func() Executor { return NewMinimaxCodeExecutor("minimax-code") },
	"minimax-code-global": func() Executor { return NewMinimaxCodeExecutor("minimax-code-global") },
	"bedrock":             func() Executor { return NewBedrockExecutor("bedrock") },
	"br":                  func() Executor { return NewBedrockExecutor("bedrock") },     // alias
	"bedrock-xai":         func() Executor { return NewBedrockExecutor("bedrock-xai") }, // alias target
	"brx":                 func() Executor { return NewBedrockExecutor("bedrock-xai") }, // alias
	// Team Z ports.
	"opencode":       func() Executor { return NewOpencodeExecutor() },
	"opencode-go":    func() Executor { return NewOpencodeGoExecutor() },
	"opencode-zen":   func() Executor { return NewOpencodeZenExecutor() },
	"grok-cli":       func() Executor { return NewGrokCLIExecutor() },
	"grok-web":       func() Executor { return NewGrokWebExecutor() },
	"perplexity-web": func() Executor { return NewPerplexityWebExecutor() },
	"windsurf":       func() Executor { return NewWindsurfExecutor() },
	"trae":           func() Executor { return NewTraeExecutor() },
	"zed":            func() Executor { return NewZedExecutor() },
	"qoder":          func() Executor { return NewQoderExecutor("qoder") },
	"qoder-cn":       func() Executor { return NewQoderExecutor("qoder-cn") },
	"devin-cli":      func() Executor { return NewDevinCLIExecutor() },
	"mimo-free":      func() Executor { return NewMimoFreeExecutor() },
	"mmf":            func() Executor { return NewMimoFreeExecutor() }, // alias (index.js)
	"xiaomi-mimo":    func() Executor { return NewXiaomiMimoExecutor() },
}

// For returns the executor for a provider id — the specialised one when
// registered, otherwise a DefaultExecutor (executors/index.js getExecutor).
// Executors are stateless (per-request state lives in *Request), so the
// returned value may be shared across goroutines.
func For(providerID string) Executor {
	if f, ok := factories[providerID]; ok {
		return f()
	}
	return NewDefaultExecutor(providerID)
}

// HasSpecialised reports whether a provider has a specialised executor
// (index.js hasSpecializedExecutor).
func HasSpecialised(providerID string) bool {
	_, ok := factories[providerID]
	return ok
}

// IsOpenAICompatible / IsAnthropicCompatible mirror services/provider.js
// prefix checks.
func IsOpenAICompatible(providerID string) bool {
	return strings.HasPrefix(providerID, "openai-compatible-")
}

func IsAnthropicCompatible(providerID string) bool {
	return strings.HasPrefix(providerID, "anthropic-compatible-")
}
