package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Per-tool local config readers/writers, ported from
// cli/src/cli/commands/connectTools.js. File layouts and keys mirror
// the dashboard routes in src/app/api/cli-tools/<tool>-settings so a
// tool configured by `connect` looks identical to one applied from
// the dashboard (and to what the JS CLI writes).
//
// Port notes:
//   - JSON is edited as map[string]any, so key order is not preserved
//     on rewrite (same trade-off as the rest of this port).
//   - Codex TOML goes through mini_toml.go (subset; see its header).
//   - Oh My Pi YAML is handled with indentation text ops (the JS uses
//     a full YAML parser via confbox); the proxygo block is replaced
//     surgically and other providers are preserved byte-for-byte.

type toolModel struct{ Key, Value string }

type toolConfig struct {
	BaseURL string
	APIKey  string
	Models  []toolModel
	Active  *bool // nil = tool does not report it
}

type toolCtx struct {
	BaseURL      string // origin, no /v1
	APIKey       string
	Model        string
	ClaudeModels map[string]string // env key → model ("" = leave unset)
}

type toolDef struct {
	id         string
	name       string
	route      string // cli-tools settings route used for serverModel
	needsModel bool   // false only for omp (discovers server models)
	paths      func() []string
	show       func() (toolConfig, error)
	apply      func(ctx toolCtx) ([]string, error)
	reset      func() ([]string, error)
	// serverModel extracts the tool's model id from its server-side
	// cli-tools settings response (connectTools.js serverModel).
	serverModel func(data map[string]any) string
}

func v1(baseURL string) string {
	if strings.HasSuffix(baseURL, "/v1") {
		return baseURL
	}
	return baseURL + "/v1"
}

func isStr(v any) bool {
	s, ok := v.(string)
	return ok && s != ""
}

func strOf(v any) string {
	s, _ := v.(string)
	return s
}

func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return os.Getenv("HOME")
	}
	return h
}

// maskKey ports maskKey from connect.js.
func maskKey(key string) string {
	if len(key) < 12 {
		return "****"
	}
	return key[:6] + "…" + key[len(key)-4:]
}

// stripTrailingCommas ports connectTools.js stripTrailingCommas:
// drop commas that directly precede } or ] outside string literals.
func stripTrailingCommas(text string) string {
	var b strings.Builder
	inStr := false
	for i := 0; i < len(text); i++ {
		c := text[i]
		if inStr {
			b.WriteByte(c)
			if c == '\\' && i+1 < len(text) {
				i++
				b.WriteByte(text[i])
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
			b.WriteByte(c)
		case ',':
			j := i + 1
			for j < len(text) && (text[j] == ' ' || text[j] == '\t' || text[j] == '\n' || text[j] == '\r') {
				j++
			}
			if j < len(text) && (text[j] == '}' || text[j] == ']') {
				continue // drop the comma
			}
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// readToolJSON: missing file → (nil, nil), like readJson's ENOENT→null.
func readToolJSON(file string) (map[string]any, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(stripTrailingCommas(string(raw))), &out); err != nil {
		return nil, fmt.Errorf("cannot parse %s: %v", file, err)
	}
	return out, nil
}

func jsonChild(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	return nil
}

func jsonChildOrNew(m map[string]any, key string) map[string]any {
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	nm := map[string]any{}
	m[key] = nm
	return nm
}

// writeToolFile ports writeFile: one-time backup to <file>.bak-proxygo,
// then write with owner-only permissions.
func writeToolFile(file string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return err
	}
	backup := file + ".bak-proxygo"
	if _, err := os.Stat(file); err == nil {
		if _, err := os.Stat(backup); os.IsNotExist(err) {
			if raw, err := os.ReadFile(file); err == nil {
				_ = os.WriteFile(backup, raw, 0o600)
			}
		}
	}
	if err := os.WriteFile(file, content, 0o600); err != nil {
		return err
	}
	_ = os.Chmod(file, 0o600)
	return nil
}

// rewriteToolFile ports rewriteFile (reset path: no backup).
func rewriteToolFile(file string, content []byte) error {
	return os.WriteFile(file, content, 0o600)
}

func writeToolJSON(file string, data map[string]any) error {
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return writeToolFile(file, raw)
}

func rewriteToolJSON(file string, data map[string]any) error {
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return rewriteToolFile(file, raw)
}

// ── Claude Code ─────────────────────────────────────────────────────

type claudeTier struct{ flag, envKey string }

var claudeTiers = []claudeTier{
	{"fable", "ANTHROPIC_DEFAULT_FABLE_MODEL"},
	{"opus", "ANTHROPIC_DEFAULT_OPUS_MODEL"},
	{"sonnet", "ANTHROPIC_DEFAULT_SONNET_MODEL"},
	{"haiku", "ANTHROPIC_DEFAULT_HAIKU_MODEL"},
}

var claudeResetKeys = func() []string {
	keys := []string{"ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN"}
	for _, m := range claudeTiers {
		keys = append(keys, m.envKey)
	}
	return keys
}()

func claudePath() string { return filepath.Join(homeDir(), ".claude", "settings.json") }

var toolClaude = toolDef{
	id: "claude", name: "Claude Code", needsModel: true,
	paths: func() []string { return []string{claudePath()} },
	show: func() (toolConfig, error) {
		cfg, err := readToolJSON(claudePath())
		if err != nil {
			return toolConfig{}, err
		}
		env := jsonChild(cfg, "env")
		var models []toolModel
		if isStr(env["ANTHROPIC_MODEL"]) {
			models = append(models, toolModel{"main", strOf(env["ANTHROPIC_MODEL"])})
		}
		for _, m := range claudeTiers {
			if isStr(env[m.envKey]) {
				models = append(models, toolModel{m.flag, strOf(env[m.envKey])})
			}
		}
		return toolConfig{BaseURL: strOf(env["ANTHROPIC_BASE_URL"]), APIKey: strOf(env["ANTHROPIC_AUTH_TOKEN"]), Models: models}, nil
	},
	apply: func(ctx toolCtx) ([]string, error) {
		file := claudePath()
		cur, err := readToolJSON(file)
		if err != nil {
			return nil, err
		}
		if cur == nil {
			cur = map[string]any{}
		}
		cur["hasCompletedOnboarding"] = true
		env := jsonChildOrNew(cur, "env")
		env["ANTHROPIC_BASE_URL"] = v1(ctx.BaseURL)
		env["ANTHROPIC_AUTH_TOKEN"] = ctx.APIKey
		for _, m := range claudeTiers {
			if ctx.ClaudeModels[m.envKey] != "" {
				env[m.envKey] = ctx.ClaudeModels[m.envKey]
			} else {
				delete(env, m.envKey)
			}
		}
		if err := writeToolJSON(file, cur); err != nil {
			return nil, err
		}
		return []string{file}, nil
	},
	reset: func() ([]string, error) {
		file := claudePath()
		cur, err := readToolJSON(file)
		if err != nil {
			return nil, err
		}
		if cur == nil {
			return nil, nil
		}
		if env := jsonChild(cur, "env"); env != nil {
			for _, k := range claudeResetKeys {
				delete(env, k)
			}
			if len(env) == 0 {
				delete(cur, "env")
			}
		}
		if err := rewriteToolJSON(file, cur); err != nil {
			return nil, err
		}
		return []string{file}, nil
	},
}

// ── OpenAI Codex CLI ────────────────────────────────────────────────

func codexPath() string { return filepath.Join(homeDir(), ".codex", "config.toml") }

func readCodexDoc() (*tomlTable, error) {
	raw, err := os.ReadFile(codexPath())
	if err != nil {
		if os.IsNotExist(err) {
			return newTomlTable(), nil
		}
		return nil, err
	}
	doc, err := parseTOML(string(raw))
	if err != nil {
		return nil, fmt.Errorf("cannot parse %s: %v", codexPath(), err)
	}
	return doc, nil
}

func codexServerModel(data map[string]any) string {
	cfgText := strOf(data["config"])
	if cfgText == "" {
		return ""
	}
	doc, err := parseTOML(cfgText)
	if err != nil {
		return ""
	}
	if doc.str("model_provider") == "proxygo" && doc.str("model") != "" {
		return doc.str("model")
	}
	return ""
}

var toolCodex = toolDef{
	id: "codex", name: "OpenAI Codex CLI", needsModel: true, route: "codex-settings",
	paths:       func() []string { return []string{codexPath()} },
	serverModel: codexServerModel,
	show: func() (toolConfig, error) {
		if _, err := os.Stat(codexPath()); os.IsNotExist(err) {
			return toolConfig{}, nil
		}
		doc, err := readCodexDoc()
		if err != nil {
			return toolConfig{}, err
		}
		var p *tomlTable
		if mp := doc.child("model_providers", false); mp != nil {
			p = mp.child("proxygo", false)
		}
		var auth string
		if p != nil {
			if hh := p.child("http_headers", false); hh != nil {
				auth = strings.TrimSpace(strings.TrimPrefix(hh.str("Authorization"), "Bearer "))
				if a := hh.str("Authorization"); strings.HasPrefix(a, "Bearer ") {
					auth = a[len("Bearer "):]
				}
			}
		}
		var models []toolModel
		if doc.str("model") != "" {
			models = append(models, toolModel{"main", doc.str("model")})
		}
		if ag := doc.child("agents", false); ag != nil && ag.str("default_subagent_model") != "" {
			models = append(models, toolModel{"subagent", ag.str("default_subagent_model")})
		}
		active := doc.str("model_provider") == "proxygo"
		out := toolConfig{Models: models, Active: &active}
		if p != nil {
			out.BaseURL = p.str("base_url")
			out.APIKey = auth
		}
		return out, nil
	},
	apply: func(ctx toolCtx) ([]string, error) {
		doc, err := readCodexDoc()
		if err != nil {
			return nil, err
		}
		doc.set("model", ctx.Model)
		doc.set("model_provider", "proxygo")
		mp := doc.child("model_providers", true)
		p := mp.child("proxygo", true)
		p.set("name", "ProxyGo")
		p.set("base_url", v1(ctx.BaseURL))
		p.set("wire_api", "responses")
		hh := p.child("http_headers", true)
		hh.set("Authorization", "Bearer "+ctx.APIKey)
		ag := doc.child("agents", true)
		ag.del("subagent")
		ag.set("default_subagent_model", ctx.Model)
		if err := writeToolFile(codexPath(), []byte(stringifyTOML(doc))); err != nil {
			return nil, err
		}
		return []string{codexPath()}, nil
	},
	reset: func() ([]string, error) {
		if _, err := os.Stat(codexPath()); os.IsNotExist(err) {
			return nil, nil
		}
		doc, err := readCodexDoc()
		if err != nil {
			return nil, err
		}
		if doc.str("model_provider") == "proxygo" {
			doc.del("model")
			doc.del("model_provider")
		}
		if mp := doc.child("model_providers", false); mp != nil {
			mp.del("proxygo")
			if len(mp.order) == 0 {
				doc.del("model_providers")
			}
		}
		if ag := doc.child("agents", false); ag != nil {
			ag.del("default_subagent_model")
			ag.del("subagent")
			if len(ag.order) == 0 {
				doc.del("agents")
			}
		}
		if err := rewriteToolFile(codexPath(), []byte(stringifyTOML(doc))); err != nil {
			return nil, err
		}
		return []string{codexPath()}, nil
	},
}

// ── OpenCode ────────────────────────────────────────────────────────

func opencodePath() string { return filepath.Join(homeDir(), ".config", "opencode", "opencode.json") }

var toolOpenCode = toolDef{
	id: "opencode", name: "OpenCode", needsModel: true, route: "opencode-settings",
	paths: func() []string { return []string{opencodePath()} },
	serverModel: func(data map[string]any) string {
		m := strOf(jsonChild(data, "config")["model"])
		if strings.HasPrefix(m, "proxygo/") {
			return m[len("proxygo/"):]
		}
		return ""
	},
	show: func() (toolConfig, error) {
		cfg, err := readToolJSON(opencodePath())
		if err != nil {
			return toolConfig{}, err
		}
		var p map[string]any
		if prov := jsonChild(cfg, "provider"); prov != nil {
			p = jsonChild(prov, "proxygo")
		}
		var models []toolModel
		if isStr(cfg["model"]) {
			models = append(models, toolModel{"main", strOf(cfg["model"])})
		}
		if agent := jsonChild(cfg, "agent"); agent != nil {
			if ex := jsonChild(agent, "explorer"); ex != nil && isStr(ex["model"]) {
				models = append(models, toolModel{"explorer", strOf(ex["model"])})
			}
		}
		if p != nil {
			if pm := jsonChild(p, "models"); pm != nil && len(pm) > 0 {
				ids := make([]string, 0, len(pm))
				for k := range pm {
					ids = append(ids, k)
				}
				sort.Strings(ids)
				models = append(models, toolModel{"available", strings.Join(ids, ", ")})
			}
		}
		active := strings.HasPrefix(strOf(cfg["model"]), "proxygo/")
		out := toolConfig{Models: models, Active: &active}
		if opts := jsonChild(p, "options"); opts != nil {
			out.BaseURL = strOf(opts["baseURL"])
			out.APIKey = strOf(opts["apiKey"])
		}
		return out, nil
	},
	apply: func(ctx toolCtx) ([]string, error) {
		file := opencodePath()
		cfg, err := readToolJSON(file)
		if err != nil {
			return nil, err
		}
		if cfg == nil {
			cfg = map[string]any{}
		}
		prov := jsonChildOrNew(cfg, "provider")
		p := jsonChild(prov, "proxygo")
		if p == nil {
			p = map[string]any{"npm": "@ai-sdk/openai-compatible", "options": map[string]any{}, "models": map[string]any{}}
			prov["proxygo"] = p
		}
		opts := jsonChildOrNew(p, "options")
		opts["baseURL"] = v1(ctx.BaseURL)
		opts["apiKey"] = ctx.APIKey
		models := jsonChildOrNew(p, "models")
		models[ctx.Model] = map[string]any{
			"name": ctx.Model,
			"modalities": map[string]any{
				"input":  []any{"text", "image"},
				"output": []any{"text"},
			},
		}
		cfg["model"] = "proxygo/" + ctx.Model
		agent := jsonChildOrNew(cfg, "agent")
		agent["explorer"] = map[string]any{
			"description": "Fast explorer subagent for codebase exploration",
			"mode":        "subagent",
			"model":       "proxygo/" + ctx.Model,
		}
		if err := writeToolJSON(file, cfg); err != nil {
			return nil, err
		}
		return []string{file}, nil
	},
	reset: func() ([]string, error) {
		file := opencodePath()
		cfg, err := readToolJSON(file)
		if err != nil {
			return nil, err
		}
		if cfg == nil {
			return nil, nil
		}
		if prov := jsonChild(cfg, "provider"); prov != nil {
			delete(prov, "proxygo")
		}
		if strings.HasPrefix(strOf(cfg["model"]), "proxygo/") {
			delete(cfg, "model")
		}
		if agent := jsonChild(cfg, "agent"); agent != nil {
			if ex := jsonChild(agent, "explorer"); ex != nil && strings.HasPrefix(strOf(ex["model"]), "proxygo/") {
				delete(agent, "explorer")
				if len(agent) == 0 {
					delete(cfg, "agent")
				}
			}
		}
		if err := rewriteToolJSON(file, cfg); err != nil {
			return nil, err
		}
		return []string{file}, nil
	},
}

// ── Factory Droid ───────────────────────────────────────────────────

func droidPath() string { return filepath.Join(homeDir(), ".factory", "settings.json") }

func isDroidProxyGo(m map[string]any) bool {
	return strings.HasPrefix(strOf(m["id"]), "custom:ProxyGo")
}

func droidCustomModels(cfg map[string]any) []map[string]any {
	raw, _ := cfg["customModels"].([]any)
	var out []map[string]any
	for _, e := range raw {
		if m, ok := e.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

var toolDroid = toolDef{
	id: "droid", name: "Factory Droid", needsModel: true, route: "droid-settings",
	paths: func() []string { return []string{droidPath()} },
	serverModel: func(data map[string]any) string {
		for _, m := range droidCustomModels(jsonChild(data, "settings")) {
			if isDroidProxyGo(m) && isStr(m["model"]) {
				return strOf(m["model"])
			}
		}
		return ""
	},
	show: func() (toolConfig, error) {
		cfg, err := readToolJSON(droidPath())
		if err != nil {
			return toolConfig{}, err
		}
		var ours []map[string]any
		for _, m := range droidCustomModels(cfg) {
			if isDroidProxyGo(m) {
				ours = append(ours, m)
			}
		}
		out := toolConfig{}
		if len(ours) > 0 {
			out.BaseURL = strOf(ours[0]["baseUrl"])
			out.APIKey = strOf(ours[0]["apiKey"])
			models := []toolModel{{"main", strOf(ours[0]["model"])}}
			if len(ours) > 1 {
				names := make([]string, len(ours))
				for i, m := range ours {
					names[i] = strOf(m["model"])
				}
				models = append(models, toolModel{"available", strings.Join(names, ", ")})
			}
			out.Models = models
		}
		return out, nil
	},
	apply: func(ctx toolCtx) ([]string, error) {
		file := droidPath()
		cfg, err := readToolJSON(file)
		if err != nil {
			return nil, err
		}
		if cfg == nil {
			cfg = map[string]any{}
		}
		var others []any
		for _, m := range droidCustomModels(cfg) {
			if !isDroidProxyGo(m) {
				others = append(others, m)
			}
		}
		ours := map[string]any{
			"model": ctx.Model, "id": "custom:ProxyGo-0", "index": 0,
			"baseUrl": v1(ctx.BaseURL), "apiKey": ctx.APIKey, "displayName": ctx.Model,
			"maxOutputTokens": 131072, "noImageSupport": false, "provider": "openai",
		}
		all := append([]any{ours}, others...)
		for i, e := range all {
			e.(map[string]any)["index"] = i
		}
		cfg["customModels"] = all
		if err := writeToolJSON(file, cfg); err != nil {
			return nil, err
		}
		return []string{file}, nil
	},
	reset: func() ([]string, error) {
		file := droidPath()
		cfg, err := readToolJSON(file)
		if err != nil {
			return nil, err
		}
		if cfg == nil {
			return nil, nil
		}
		if _, ok := cfg["customModels"]; ok {
			var kept []any
			for _, m := range droidCustomModels(cfg) {
				if !isDroidProxyGo(m) {
					kept = append(kept, m)
				}
			}
			if len(kept) == 0 {
				delete(cfg, "customModels")
			} else {
				cfg["customModels"] = kept
			}
		}
		if err := rewriteToolJSON(file, cfg); err != nil {
			return nil, err
		}
		return []string{file}, nil
	},
}

// ── Crush ───────────────────────────────────────────────────────────

func crushPath() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		base = filepath.Join(homeDir(), ".config")
	}
	return filepath.Join(base, "crush", "crush.json")
}

var toolCrush = toolDef{
	id: "crush", name: "Crush", needsModel: true, route: "crush-settings",
	paths: func() []string { return []string{crushPath()} },
	serverModel: func(data map[string]any) string {
		prov := jsonChild(jsonChild(data, "config"), "providers")
		p := jsonChild(prov, "proxygo")
		models, _ := p["models"].([]any)
		if len(models) > 0 {
			if m, ok := models[0].(map[string]any); ok {
				return strOf(m["id"])
			}
		}
		return ""
	},
	show: func() (toolConfig, error) {
		cfg, err := readToolJSON(crushPath())
		if err != nil {
			return toolConfig{}, err
		}
		p := jsonChild(jsonChild(cfg, "providers"), "proxygo")
		out := toolConfig{}
		if p != nil {
			out.BaseURL = strOf(p["base_url"])
			out.APIKey = strOf(p["api_key"])
			models, _ := p["models"].([]any)
			for _, e := range models {
				if m, ok := e.(map[string]any); ok && isStr(m["id"]) {
					out.Models = []toolModel{{"main", strOf(m["id"])}}
					break
				}
			}
		}
		return out, nil
	},
	apply: func(ctx toolCtx) ([]string, error) {
		file := crushPath()
		cfg, err := readToolJSON(file)
		if err != nil {
			return nil, err
		}
		if cfg == nil {
			cfg = map[string]any{}
		}
		prov := jsonChildOrNew(cfg, "providers")
		prov["proxygo"] = map[string]any{
			"type": "openai-compat", "base_url": v1(ctx.BaseURL), "api_key": ctx.APIKey,
			"models": []any{map[string]any{"id": ctx.Model, "name": ctx.Model, "context_window": 128000}},
		}
		if err := writeToolJSON(file, cfg); err != nil {
			return nil, err
		}
		return []string{file}, nil
	},
	reset: func() ([]string, error) {
		file := crushPath()
		cfg, err := readToolJSON(file)
		if err != nil {
			return nil, err
		}
		if cfg == nil {
			return nil, nil
		}
		prov := jsonChild(cfg, "providers")
		if prov == nil || jsonChild(prov, "proxygo") == nil {
			return nil, nil
		}
		delete(prov, "proxygo")
		if len(prov) == 0 {
			delete(cfg, "providers")
		}
		if err := rewriteToolJSON(file, cfg); err != nil {
			return nil, err
		}
		return []string{file}, nil
	},
}

// ── Kilo Code ───────────────────────────────────────────────────────

func kiloPath() string { return filepath.Join(homeDir(), ".local", "share", "kilo", "auth.json") }

var toolKilo = toolDef{
	id: "kilo", name: "Kilo Code CLI", needsModel: true,
	paths: func() []string { return []string{kiloPath()} },
	show: func() (toolConfig, error) {
		cfg, err := readToolJSON(kiloPath())
		if err != nil {
			return toolConfig{}, err
		}
		a := jsonChild(cfg, "openai-compatible")
		out := toolConfig{}
		if a != nil {
			out.BaseURL = strOf(a["baseUrl"])
			out.APIKey = strOf(a["apiKey"])
			if isStr(a["model"]) {
				out.Models = []toolModel{{"main", strOf(a["model"])}}
			}
		}
		return out, nil
	},
	apply: func(ctx toolCtx) ([]string, error) {
		file := kiloPath()
		cfg, err := readToolJSON(file)
		if err != nil {
			return nil, err
		}
		if cfg == nil {
			cfg = map[string]any{}
		}
		cfg["openai-compatible"] = map[string]any{
			"type": "api-key", "apiKey": ctx.APIKey, "baseUrl": v1(ctx.BaseURL), "model": ctx.Model,
		}
		if err := writeToolJSON(file, cfg); err != nil {
			return nil, err
		}
		return []string{file}, nil
	},
	reset: func() ([]string, error) {
		file := kiloPath()
		cfg, err := readToolJSON(file)
		if err != nil {
			return nil, err
		}
		if cfg == nil {
			return nil, nil
		}
		delete(cfg, "openai-compatible")
		delete(cfg, "proxygo")
		if err := rewriteToolJSON(file, cfg); err != nil {
			return nil, err
		}
		return []string{file}, nil
	},
}

// ── Cline CLI ───────────────────────────────────────────────────────

func clineStatePath() string { return filepath.Join(homeDir(), ".cline", "data", "globalState.json") }
func clineSecretsPath() string {
	return filepath.Join(homeDir(), ".cline", "data", "secrets.json")
}

var toolCline = toolDef{
	id: "cline", name: "Cline CLI", needsModel: true, route: "cline-settings",
	paths: func() []string { return []string{clineStatePath(), clineSecretsPath()} },
	serverModel: func(data map[string]any) string {
		st := jsonChild(data, "settings")
		if strOf(st["actModeApiProvider"]) == "openai" && isStr(st["openAiModelId"]) {
			return strOf(st["openAiModelId"])
		}
		return ""
	},
	show: func() (toolConfig, error) {
		st, err := readToolJSON(clineStatePath())
		if err != nil {
			return toolConfig{}, err
		}
		secrets, err := readToolJSON(clineSecretsPath())
		if err != nil {
			return toolConfig{}, err
		}
		var models []toolModel
		if isStr(st["openAiModelId"]) {
			models = append(models, toolModel{"act", strOf(st["openAiModelId"])})
		}
		if isStr(st["planModeOpenAiModelId"]) {
			models = append(models, toolModel{"plan", strOf(st["planModeOpenAiModelId"])})
		}
		active := strOf(st["actModeApiProvider"]) == "openai"
		return toolConfig{
			BaseURL: strOf(st["openAiBaseUrl"]),
			APIKey:  strOf(secrets["openAiApiKey"]),
			Models:  models, Active: &active,
		}, nil
	},
	apply: func(ctx toolCtx) ([]string, error) {
		st, err := readToolJSON(clineStatePath())
		if err != nil {
			return nil, err
		}
		if st == nil {
			st = map[string]any{}
		}
		st["actModeApiProvider"] = "openai"
		st["planModeApiProvider"] = "openai"
		st["openAiBaseUrl"] = ctx.BaseURL // Cline expects base WITHOUT /v1
		st["openAiModelId"] = ctx.Model
		st["planModeOpenAiModelId"] = ctx.Model
		if err := writeToolJSON(clineStatePath(), st); err != nil {
			return nil, err
		}
		secrets, err := readToolJSON(clineSecretsPath())
		if err != nil {
			return nil, err
		}
		if secrets == nil {
			secrets = map[string]any{}
		}
		secrets["openAiApiKey"] = ctx.APIKey
		if err := writeToolJSON(clineSecretsPath(), secrets); err != nil {
			return nil, err
		}
		return []string{clineStatePath(), clineSecretsPath()}, nil
	},
	reset: func() ([]string, error) {
		st, err := readToolJSON(clineStatePath())
		if err != nil {
			return nil, err
		}
		if st == nil {
			return nil, nil
		}
		if strOf(st["actModeApiProvider"]) == "openai" {
			delete(st, "openAiBaseUrl")
			delete(st, "openAiModelId")
			delete(st, "planModeOpenAiModelId")
			st["actModeApiProvider"] = "cline"
			st["planModeApiProvider"] = "cline"
		}
		if err := rewriteToolJSON(clineStatePath(), st); err != nil {
			return nil, err
		}
		touched := []string{clineStatePath()}
		secrets, err := readToolJSON(clineSecretsPath())
		if err != nil {
			return nil, err
		}
		if secrets != nil {
			delete(secrets, "openAiApiKey")
			if err := rewriteToolJSON(clineSecretsPath(), secrets); err != nil {
				return nil, err
			}
			touched = append(touched, clineSecretsPath())
		}
		return touched, nil
	},
}

// ── Pi ──────────────────────────────────────────────────────────────

func piPath() string {
	agent := filepath.Join(homeDir(), ".pi", "agent", "models.json")
	root := filepath.Join(homeDir(), ".pi", "models.json")
	if _, err := os.Stat(agent); os.IsNotExist(err) {
		if _, err := os.Stat(root); err == nil {
			return root
		}
	}
	return agent
}

var toolPi = toolDef{
	id: "pi", name: "Pi", needsModel: true, route: "pi-settings",
	paths: func() []string { return []string{piPath()} },
	serverModel: func(data map[string]any) string {
		p := jsonChild(jsonChild(jsonChild(data, "config"), "providers"), "proxygo")
		models, _ := p["models"].([]any)
		if len(models) == 0 {
			return ""
		}
		switch m := models[0].(type) {
		case string:
			return m
		case map[string]any:
			return strOf(m["id"])
		}
		return ""
	},
	show: func() (toolConfig, error) {
		cfg, err := readToolJSON(piPath())
		if err != nil {
			return toolConfig{}, err
		}
		p := jsonChild(jsonChild(cfg, "providers"), "proxygo")
		out := toolConfig{}
		if p != nil {
			out.BaseURL = strOf(p["baseUrl"])
			out.APIKey = strOf(p["apiKey"])
			var ids []string
			models, _ := p["models"].([]any)
			for _, e := range models {
				switch m := e.(type) {
				case string:
					ids = append(ids, m)
				case map[string]any:
					if isStr(m["id"]) {
						ids = append(ids, strOf(m["id"]))
					}
				}
			}
			if len(ids) > 0 {
				out.Models = []toolModel{{"main", ids[0]}}
				if len(ids) > 1 {
					out.Models = append(out.Models, toolModel{"available", strings.Join(ids, ", ")})
				}
			}
		}
		return out, nil
	},
	apply: func(ctx toolCtx) ([]string, error) {
		file := piPath()
		cfg, err := readToolJSON(file)
		if err != nil {
			return nil, err
		}
		if cfg == nil {
			cfg = map[string]any{}
		}
		prov := jsonChildOrNew(cfg, "providers")
		p := jsonChildOrNew(prov, "proxygo")
		p["baseUrl"] = v1(ctx.BaseURL)
		p["apiKey"] = ctx.APIKey
		p["api"] = "openai-completions"
		p["models"] = []any{map[string]any{"id": ctx.Model, "name": ctx.Model, "contextWindow": 128000, "maxTokens": 16384}}
		if err := writeToolJSON(file, cfg); err != nil {
			return nil, err
		}
		return []string{file}, nil
	},
	reset: func() ([]string, error) {
		file := piPath()
		cfg, err := readToolJSON(file)
		if err != nil {
			return nil, err
		}
		if cfg == nil {
			return nil, nil
		}
		prov := jsonChild(cfg, "providers")
		if prov == nil || jsonChild(prov, "proxygo") == nil {
			return nil, nil
		}
		delete(prov, "proxygo")
		if len(prov) == 0 {
			delete(cfg, "providers")
		}
		if err := rewriteToolJSON(file, cfg); err != nil {
			return nil, err
		}
		return []string{file}, nil
	},
}

// ── Oh My Pi (YAML text ops) ────────────────────────────────────────

func ompPath() string { return filepath.Join(homeDir(), ".omp", "agent", "models.yml") }

var toolOMP = toolDef{
	id: "omp", name: "Oh My Pi", needsModel: false,
	paths: func() []string { return []string{ompPath()} },
	show: func() (toolConfig, error) {
		raw, err := os.ReadFile(ompPath())
		if err != nil {
			if os.IsNotExist(err) {
				return toolConfig{}, nil
			}
			return toolConfig{}, err
		}
		vals := ompReadProxyGo(string(raw))
		out := toolConfig{BaseURL: vals["baseUrl"], APIKey: vals["apiKey"]}
		if vals["discovery.type"] == "proxy" {
			out.Models = []toolModel{{"main", "(all server models, via discovery)"}}
		}
		return out, nil
	},
	apply: func(ctx toolCtx) ([]string, error) {
		file := ompPath()
		raw, _ := os.ReadFile(file)
		next := ompApplyProxyGo(string(raw), ctx)
		if err := writeToolFile(file, []byte(next)); err != nil {
			return nil, err
		}
		return []string{file}, nil
	},
	reset: func() ([]string, error) {
		file := ompPath()
		raw, err := os.ReadFile(file)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, nil
			}
			return nil, err
		}
		next, changed := ompRemoveProxyGo(string(raw))
		if !changed {
			return nil, nil
		}
		if err := rewriteToolFile(file, []byte(next)); err != nil {
			return nil, err
		}
		return []string{file}, nil
	},
}

// ── registry ────────────────────────────────────────────────────────

var toolList = []toolDef{toolClaude, toolCodex, toolOpenCode, toolDroid, toolCrush, toolKilo, toolCline, toolPi, toolOMP}

var toolIDs = func() []string {
	ids := make([]string, len(toolList))
	for i, t := range toolList {
		ids[i] = t.id
	}
	return ids
}()

var toolAliases = map[string]string{
	"claude-code": "claude", "claudecode": "claude", "factory": "droid",
	"kilocode": "kilo", "pi-coding-agent": "pi", "oh-my-pi": "omp",
}

// resolveTools ports resolveTools from connectTools.js.
func resolveTools(list []string) ([]toolDef, error) {
	seen := map[string]bool{}
	for _, raw := range list {
		id := strings.ToLower(strings.TrimSpace(raw))
		if id == "" {
			continue
		}
		if id == "all" {
			for _, t := range toolIDs {
				seen[t] = true
			}
			continue
		}
		if real, ok := toolAliases[id]; ok {
			id = real
		}
		found := false
		for _, t := range toolIDs {
			if t == id {
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("unknown tool %q. Supported: %s, all", raw, strings.Join(toolIDs, ", "))
		}
		seen[id] = true
	}
	var out []toolDef
	for _, t := range toolList {
		if seen[t.id] {
			out = append(out, t)
		}
	}
	return out, nil
}

func toolByID(id string) (toolDef, bool) {
	for _, t := range toolList {
		if t.id == id {
			return t, true
		}
	}
	return toolDef{}, false
}
