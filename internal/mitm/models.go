package mitm

import "strings"

// Model alias resolution (config.js getMappedModel + MODEL_SYNONYMS).
// The alias map comes from the db (settings mitmAlias via the hooks, or
// a Store passed to GetMappedModelWithStore).

// AliasSource supplies {tool: {model: mapped}} entries.
type AliasSource interface {
	GetMitmAlias(tool string) (map[string]string, bool)
}

var ModelSynonyms = map[string]string{
	"gemini-3.1-pro-high":        "gemini-3.1-pro-preview",
	"gemini-3.1-pro-low":         "gemini-3.1-pro-preview",
	"gemini-3.1-pro":             "gemini-3.1-pro-preview",
	"gemini-3.1-pro-preview":     "gemini-3.1-pro-preview",
	"gemini-3-pro-high":          "gemini-3-pro-preview",
	"gemini-3-pro-low":           "gemini-3-pro-preview",
	"gemini-3-pro":               "gemini-3-pro-preview",
	"gemini-3-pro-preview":       "gemini-3-pro-preview",
	"claude-sonnet-4-5":          "claude-sonnet-4-5",
	"claude-sonnet-4.5":          "claude-sonnet-4-5",
	"claude-sonnet-4-5-20250929": "claude-sonnet-4-5",
	"claude-opus-4-5":            "claude-opus-4-5",
	"claude-opus-4.5":            "claude-opus-4-5",
	"claude-opus-4-6":            "claude-opus-4-6",
	"claude-opus-4.6":            "claude-opus-4-6",
	"claude-sonnet-4-6":          "claude-sonnet-4-6",
	"claude-sonnet-4.6":          "claude-sonnet-4-6",
	"gpt-oss-120b-medium":        "gpt-oss-120b",
	"gpt-oss-120b":               "gpt-oss-120b",
}

func normalizeModel(model string) string {
	if model == "" {
		return ""
	}
	// Drop directory prefixes + trailing brackets suffixes (config.js).
	if i := strings.LastIndex(model, "/"); i >= 0 {
		model = model[i+1:]
	}
	if i := strings.Index(model, "["); i >= 0 {
		model = model[:i]
	}
	return strings.TrimSpace(model)
}

// GetMappedModel resolves a tool's model through the alias map (hooks),
// falling back to synonyms + the original model.
func GetMappedModel(model, tool string) string {
	if hooks.aliasFor != nil {
		if alias, ok := hooks.aliasFor(tool); ok {
			return mapModel(model, alias)
		}
	}
	return mapModel(model, nil)
}

// GetMappedModelWithStore resolves via an explicit AliasSource (e.g.
// *db.Store).
func GetMappedModelWithStore(model, tool string, src AliasSource) string {
	if src != nil {
		if alias, ok := src.GetMitmAlias(tool); ok {
			return mapModel(model, alias)
		}
	}
	return mapModel(model, nil)
}

func mapModel(model string, alias map[string]string) string {
	normalized := normalizeModel(model)
	if alias != nil {
		if v, ok := alias[normalized]; ok && v != "" {
			return v
		}
		if v, ok := alias[model]; ok && v != "" {
			return v
		}
		// Prefix aliases ("gpt-5" → ...) then pattern contains.
		for prefix, target := range alias {
			if strings.HasSuffix(prefix, "*") && strings.HasPrefix(normalized, strings.TrimSuffix(prefix, "*")) {
				return target
			}
		}
		for pattern, target := range alias {
			if strings.Contains(normalized, pattern) {
				return target
			}
		}
	}
	if v, ok := ModelSynonyms[normalized]; ok {
		return v
	}
	return model
}
