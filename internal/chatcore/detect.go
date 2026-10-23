package chatcore

import (
	"regexp"
	"strings"
)

// Format identifiers (translator/formats.js FORMATS).
const (
	FormatOpenAI          = "openai"
	FormatOpenAIResponses = "openai-responses"
	FormatOpenAIResponse  = "openai-response"
	FormatClaude          = "claude"
	FormatGemini          = "gemini"
	FormatGeminiCLI       = "gemini-cli"
	FormatVertex          = "vertex"
	FormatCodex           = "codex"
	FormatAntigravity     = "antigravity"
	FormatKiro            = "kiro"
	FormatCursor          = "cursor"
	FormatOllama          = "ollama"
	FormatCommandCode     = "commandcode"
)

// DetectFormatByEndpoint ports translator/formats.js
// detectFormatByEndpoint: /v1/responses is always openai-responses,
// /v1/messages is always claude, /v1/chat/completions with input[] stays
// openai (Cursor CLI sends a Responses body via the chat endpoint).
// Returns "" to fall back to body-based detection.
func DetectFormatByEndpoint(pathname string, body map[string]any) string {
	if strings.Contains(pathname, "/v1/responses") {
		return FormatOpenAIResponses
	}
	if strings.Contains(pathname, "/v1/messages") {
		return FormatClaude
	}
	if strings.Contains(pathname, "/v1/chat/completions") {
		if _, isArr := body["input"].([]any); isArr {
			return FormatOpenAI
		}
	}
	return ""
}

// DetectFormat ports services/provider.js detectFormat (body-structure
// detection, check order preserved).
func DetectFormat(body map[string]any) string {
	if body == nil {
		return FormatOpenAI
	}
	// OpenAI Responses API: input (array or string) instead of messages[].
	if _, hasMessages := body["messages"]; !hasMessages {
		switch body["input"].(type) {
		case []any, string:
			return FormatOpenAIResponses
		}
	}
	// Antigravity: Gemini wrapped in body.request.
	if req, ok := body["request"].(map[string]any); ok {
		if _, hasContents := req["contents"]; hasContents && body["userAgent"] == "antigravity" {
			return FormatAntigravity
		}
	}
	// Gemini: contents array.
	if _, ok := body["contents"].([]any); ok {
		return FormatGemini
	}
	// OpenAI-specific indicators (checked BEFORE Claude).
	if _, ok := body["stream_options"]; ok {
		return FormatOpenAI
	}
	if _, ok := body["response_format"]; ok {
		return FormatOpenAI
	}
	if _, present := body["logprobs"]; present {
		return FormatOpenAI
	}
	if _, present := body["top_logprobs"]; present {
		return FormatOpenAI
	}
	if _, present := body["n"]; present {
		return FormatOpenAI
	}
	if _, present := body["presence_penalty"]; present {
		return FormatOpenAI
	}
	if _, present := body["frequency_penalty"]; present {
		return FormatOpenAI
	}
	if _, ok := body["logit_bias"]; ok {
		return FormatOpenAI
	}
	if _, ok := body["user"]; ok {
		return FormatOpenAI
	}
	// Claude: messages whose first content array uses Claude block types,
	// or Claude-specific top-level fields.
	if msgs, ok := body["messages"].([]any); ok {
		var first map[string]any
		if len(msgs) > 0 {
			first, _ = msgs[0].(map[string]any)
		}
		if first != nil {
			if content, ok := first["content"].([]any); ok && len(content) > 0 {
				firstContent, _ := content[0].(map[string]any)
				if firstContent != nil && firstContent["type"] == "text" {
					model, _ := body["model"].(string)
					if !strings.Contains(model, "/") {
						if _, hasSys := body["system"]; hasSys {
							return FormatClaude
						}
						if _, hasVersion := body["anthropic_version"]; hasVersion {
							return FormatClaude
						}
						for _, raw := range content {
							part, _ := raw.(map[string]any)
							if part == nil {
								continue
							}
							if part["type"] == "image" {
								if src, ok := part["source"].(map[string]any); ok && src["type"] == "base64" {
									return FormatClaude
								}
							}
							if part["type"] == "image_url" {
								if iu, ok := part["image_url"].(map[string]any); ok && iu["url"] != nil {
									return FormatOpenAI
								}
							}
							if part["type"] == "tool_use" || part["type"] == "tool_result" {
								return FormatClaude
							}
						}
					}
				}
			}
		}
		if _, present := body["system"]; present {
			return FormatClaude
		}
		if _, present := body["anthropic_version"]; present {
			return FormatClaude
		}
	}
	return FormatOpenAI
}

// ParseModel ports services/model.js parseModel + resolveProviderAlias
// (alias resolution itself is provider data — the Service's ProviderSource
// resolves aliases; here only the split is done, plus builtin model
// aliases and prefix inference for bare model ids).
type ModelInfo struct {
	Provider      string // resolved provider id ("" when unresolvable)
	Model         string
	ProviderAlias string // the alias as written by the client
	IsAlias       bool   // bare model (no provider prefix)
}

var builtinModelAliases = map[string]string{
	"grok-build": "gcli/grok-build",
}

func splitProviderModel(s string) (string, string) {
	idx := strings.Index(s, "/")
	return s[:idx], s[idx+1:]
}

// ParseModelString splits "provider/model" (first slash) or treats the
// whole string as a bare model/alias. resolveAlias maps a provider alias
// to its id (identity when nil).
func ParseModelString(modelStr string, resolveAlias func(string) string) ModelInfo {
	if modelStr == "" {
		return ModelInfo{}
	}
	if strings.Contains(modelStr, "/") {
		alias, model := splitProviderModel(modelStr)
		provider := alias
		if resolveAlias != nil {
			provider = resolveAlias(alias)
		}
		return ModelInfo{Provider: provider, Model: model, ProviderAlias: alias}
	}
	return ModelInfo{Model: modelStr, IsAlias: true}
}

// modelPrefixProviders ports MODEL_PREFIX_PROVIDERS (services/model.js),
// first match wins, fallback "openai".
var modelPrefixProviders = []struct {
	re       *regexp.Regexp
	provider string
}{
	{regexp.MustCompile(`^codex-auto-review$`), "codex"},
	{regexp.MustCompile(`^gpt-[56]\.`), "codex"},
	{regexp.MustCompile(`^gpt-6-`), "codex"},
	{regexp.MustCompile(`^gpt-daybreak-`), "codex"},
	{regexp.MustCompile(`^gpt-reserve`), "codex"},
	{regexp.MustCompile(`^claude-`), "anthropic"},
	{regexp.MustCompile(`^(us|eu|ap|global)\.(anthropic|meta|amazon|mistral|xai)\.`), "bedrock"},
	{regexp.MustCompile(`^gemini-`), "gemini"},
	{regexp.MustCompile(`^gpt-`), "openai"},
	{regexp.MustCompile(`^o[134]`), "openai"},
	{regexp.MustCompile(`^deepseek-`), "openrouter"},
}

// InferProviderFromModelName ports inferProviderFromModelName.
func InferProviderFromModelName(model string) string {
	if model == "" {
		return "openai"
	}
	m := strings.ToLower(model)
	for _, e := range modelPrefixProviders {
		if e.re.MatchString(m) {
			return e.provider
		}
	}
	return "openai"
}

// StripModelContextMarker ports utils/modelMarkers.js
// stripModelContextMarker: Claude Code marks a 1M-context request as
// `<model>[1m]`; the marker matches no combo/alias/provider pair and must
// not reach resolution (the capability travels in the anthropic-beta
// header). Returns the cleaned model string and the marker ("" if none).
var contextMarkerRe = regexp.MustCompile(`\[([^\]]+)\]\s*$`)

func StripModelContextMarker(modelStr string) (string, string) {
	m := contextMarkerRe.FindStringSubmatch(modelStr)
	if m == nil {
		return modelStr, ""
	}
	return strings.TrimSuffix(modelStr, m[0]), m[1]
}

// StripThinkingSuffix removes a trailing "(level)" thinking suffix and
// "-thinking" style suffixes handled by translator/concerns — here: the
// generic `model(level)` suffix (parseSuffix in thinkingUnified.js strips
// a trailing parenthesised level) and returns the clean id. chatCore does
// translatedBody.model = stripThinkingSuffix(upstreamModel).
var thinkingSuffixRe = regexp.MustCompile(`\((?:none|minimal|low|medium|high|xhigh|max|\d+)\)\s*$`)

func StripThinkingSuffix(model string) string {
	return thinkingSuffixRe.ReplaceAllString(model, "")
}
