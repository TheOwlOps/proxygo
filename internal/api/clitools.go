package api

// RegisterCLITools — port of src/app/api/cli-tools/* (28 route files +
// resolveApiKey.js + hermes-settings/hermesProfiles.js + hermesYaml.js).
//
// These routes read/write the EXTERNAL tools' own config files on the
// user's machine (~/.claude, ~/.codex, ~/.config/opencode, ...). All
// read-modify-write semantics, per-OS paths and response shapes mirror the
// JS routes. JSON files are edited as map[string]any (JS object key order
// is not preserved on rewrite — same trade-off as the rest of the port).
//
// Parent wiring still needed (documented at the bottom of this file):
//   - Mitm* hook vars → internal/mitm (Team H)
//   - GrokContextWindow hook → internal/modelcatalog capabilities (Team K)

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // sqlite driver for the omp agent.db best-effort write
	"proxygo/internal/db"
)

// ---------- shared helpers ----------

var ctIsWin = runtime.GOOS == "windows"

func ctHome() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return os.Getenv("HOME")
	}
	return h
}

// ctLookPath mirrors the JS `which`/`where` exec checks (Windows gets
// %APPDATA%\npm prepended to PATH, like the JS routes do).
func ctLookPath(name string) bool {
	var cmd *exec.Cmd
	if ctIsWin {
		cmd = exec.Command("where", name)
		env := os.Environ()
		appData := os.Getenv("APPDATA")
		for i, e := range env {
			if strings.HasPrefix(strings.ToUpper(e), "PATH=") {
				env[i] = "PATH=" + filepath.Join(appData, "npm") + ";" + e[len("PATH="):]
			}
		}
		cmd.Env = env
	} else {
		cmd = exec.Command("which", name)
	}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run() == nil
}

func ctFileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

var ctTrailingCommaRe = regexp.MustCompile(`,(\s*[}\]])`)

// ctParseJSONC parses JSON tolerating trailing commas (the JS routes all
// strip `,}` / `,]` before JSON.parse).
func ctParseJSONC(content string) (any, error) {
	stripped := ctTrailingCommaRe.ReplaceAllString(content, "$1")
	var v any
	err := json.Unmarshal([]byte(stripped), &v)
	return v, err
}

func ctReadJSONAny(p string) (any, error) {
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	return ctParseJSONC(string(raw))
}

// ctReadJSONObjTol reads a JSON object file tolerantly: any error
// (missing, unparseable) → nil (the JS readJson/readSettings pattern).
func ctReadJSONObjTol(p string) map[string]any {
	v, err := ctReadJSONAny(p)
	if err != nil {
		return nil
	}
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return nil
}

// ctReadJSONObjStrict returns (obj, existed, err): err only for a file
// that exists but does not parse — several JS POST/DELETE handlers throw
// on parse errors but treat ENOENT as "start fresh".
func ctReadJSONObjStrict(p string) (map[string]any, bool, error) {
	raw, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	var probe any
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, true, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, true, err
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, true, nil
}

// ctWriteJSON writes v as JSON.stringify(v, null, 2) (no trailing newline,
// no HTML escaping).
func ctWriteJSON(p string, v any) error {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(strings.TrimRight(buf.String(), "\n")), 0o644)
}

func ctErrObj(w http.ResponseWriter, status int, msg string) {
	WriteJSON(w, status, map[string]any{"error": map[string]any{"message": msg}})
}

func ctNormalizeV1(base string) string {
	if strings.HasSuffix(base, "/v1") {
		return base
	}
	return base + "/v1"
}

func ctStrSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := []string{}
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func ctMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return nil
}

// ctBodyStrict mirrors `await request.json()` inside a JS try block:
// malformed or empty JSON is an error.
func ctBodyStrict(r *http.Request) (map[string]any, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, fmt.Errorf("empty body")
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = map[string]any{}
	}
	return out, nil
}

// ctBodyLenient mirrors `await request.json().catch(() => ({}))`.
func ctBodyLenient(r *http.Request) map[string]any {
	body, err := ReadBodyJSON(r)
	if err != nil || body == nil {
		return map[string]any{}
	}
	return body
}

// resolveCliApiKey ports cli-tools/resolveApiKey.js: caller key first
// (never the "sk_proxygo" placeholder), else the first active dashboard
// API key, else "".
func resolveCliApiKey(deps Deps, caller string) string {
	if t := strings.TrimSpace(caller); t != "" && t != "sk_proxygo" {
		return t
	}
	if deps.Store != nil {
		if keys, err := deps.Store.GetAPIKeys(); err == nil {
			for _, k := range keys {
				if active, _ := k["isActive"].(bool); active {
					return Str(k, "key")
				}
			}
		}
	}
	return ""
}

// ---------- TOML subset (confbox parseTOML/stringifyTOML replacement) ----------
//
// Supports what the cli-tools routes actually meet in codex/jcode/forge/
// codewhale config.toml files: root scalars, [dotted.section] tables,
// string/number/bool values, arrays and inline tables. Comments are
// dropped on rewrite — exactly what the JS routes do (they parse with
// confbox and stringify the whole document back). Unparseable values are
// kept verbatim as tomlRaw and re-emitted untouched.

type tomlRaw string

type tomlKV struct {
	key string
	val any
}

type tomlSection struct {
	name string
	kvs  []tomlKV
}

type tomlDoc struct {
	root     []tomlKV
	sections []*tomlSection
}

func (d *tomlDoc) section(name string) *tomlSection {
	for _, s := range d.sections {
		if s.name == name {
			return s
		}
	}
	s := &tomlSection{name: name}
	d.sections = append(d.sections, s)
	return s
}

func (d *tomlDoc) findSection(name string) *tomlSection {
	for _, s := range d.sections {
		if s.name == name {
			return s
		}
	}
	return nil
}

func tomlGetKV(kvs []tomlKV, key string) (any, bool) {
	for _, kv := range kvs {
		if kv.key == key {
			return kv.val, true
		}
	}
	return nil, false
}

func tomlSetKV(kvs []tomlKV, key string, val any) []tomlKV {
	for i, kv := range kvs {
		if kv.key == key {
			kvs[i].val = val
			return kvs
		}
	}
	return append(kvs, tomlKV{key, val})
}

func tomlDelKV(kvs []tomlKV, key string) []tomlKV {
	out := kvs[:0]
	for _, kv := range kvs {
		if kv.key != key {
			out = append(out, kv)
		}
	}
	return out
}

// tomlSetNested mirrors setNestedSection(parsed, "a.b.c", value): the
// dotted path is ROOT key + section path — "model_providers.proxygo"
// means root table model_providers → [model_providers.proxygo].
func (d *tomlDoc) tomlSetNested(dotted string, val any) {
	parts := strings.Split(dotted, ".")
	if len(parts) == 1 {
		d.root = tomlSetKV(d.root, parts[0], val)
		return
	}
	sec := d.section(strings.Join(parts[:len(parts)-1], "."))
	sec.kvs = tomlSetKV(sec.kvs, parts[len(parts)-1], val)
}

func (d *tomlDoc) tomlDeleteNested(dotted string) {
	parts := strings.Split(dotted, ".")
	if len(parts) == 1 {
		d.root = tomlDelKV(d.root, parts[0])
		return
	}
	secName := strings.Join(parts[:len(parts)-1], ".")
	if sec := d.findSection(secName); sec != nil {
		sec.kvs = tomlDelKV(sec.kvs, parts[len(parts)-1])
		if len(sec.kvs) == 0 {
			out := d.sections[:0]
			for _, s := range d.sections {
				if s.name != secName {
					out = append(out, s)
				}
			}
			d.sections = out
		}
	}
}

// toMap exports the document as nested maps (what parseTOML returns to
// the JS routes and what GET handlers serialise back to JSON).
func (d *tomlDoc) toMap() map[string]any {
	out := map[string]any{}
	for _, kv := range d.root {
		out[kv.key] = tomlValToAny(kv.val)
	}
	for _, s := range d.sections {
		parts := strings.Split(s.name, ".")
		cur := out
		for _, p := range parts[:len(parts)-1] {
			next, ok := cur[p].(map[string]any)
			if !ok {
				next = map[string]any{}
				cur[p] = next
			}
			cur = next
		}
		leaf := map[string]any{}
		for _, kv := range s.kvs {
			leaf[kv.key] = tomlValToAny(kv.val)
		}
		cur[parts[len(parts)-1]] = leaf
	}
	return out
}

func tomlValToAny(v any) any {
	switch t := v.(type) {
	case tomlRaw:
		return string(t)
	default:
		return v
	}
}

// tomlFromMap builds a doc from a nested map (insertion order = sorted
// keys; only used where JS builds objects itself, e.g. forge `openai`).
func tomlDocFromMap(m map[string]any, sectionName string) *tomlDoc {
	d := &tomlDoc{}
	sec := d.section(sectionName)
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sec.kvs = append(sec.kvs, tomlKV{k, m[k]})
	}
	return d
}

func parseTOMLDoc(content string) (*tomlDoc, error) {
	d := &tomlDoc{}
	cur := &d.root
	lines := strings.Split(content, "\n")
	i := 0
	for i < len(lines) {
		line := strings.TrimSpace(strings.TrimSuffix(lines[i], "\r"))
		i++
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[[") && strings.HasSuffix(line, "]]") {
			// Array-of-tables: kept as a section whose body stays raw.
			name := strings.TrimSpace(line[2 : len(line)-2])
			sec := &tomlSection{name: "[[" + name + "]]"}
			d.sections = append(d.sections, sec)
			cur = &sec.kvs
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			sec := d.section(strings.TrimSpace(line[1 : len(line)-1]))
			cur = &sec.kvs
			continue
		}
		eq := tomlFindEq(line)
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		rawVal := strings.TrimSpace(line[eq+1:])
		// Multi-line basic strings.
		if strings.HasPrefix(rawVal, `"""`) && !strings.HasSuffix(rawVal[3:], `"""`) {
			var sb strings.Builder
			sb.WriteString(rawVal)
			for i < len(lines) {
				sb.WriteString("\n" + lines[i])
				if strings.Contains(lines[i], `"""`) {
					i++
					break
				}
				i++
			}
			rawVal = sb.String()
		}
		val, err := tomlParseValue(rawVal)
		if err != nil {
			val = tomlRaw(rawVal)
		}
		*cur = tomlSetKV(*cur, key, val)
	}
	return d, nil
}

func tomlFindEq(line string) int {
	inStr := byte(0)
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inStr != 0 {
			if c == inStr && (inStr == '\'' || line[i-1] != '\\') {
				inStr = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			inStr = c
			continue
		}
		if c == '=' {
			return i
		}
	}
	return -1
}

func tomlParseValue(s string) (any, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty value")
	}
	switch {
	case strings.HasPrefix(s, `"""`) && strings.HasSuffix(s, `"""`) && len(s) >= 6:
		return s[3 : len(s)-3], nil
	case strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`) && len(s) >= 2:
		var out string
		if err := json.Unmarshal([]byte(s), &out); err != nil {
			return nil, err
		}
		return out, nil
	case strings.HasPrefix(s, `'`) && strings.HasSuffix(s, `'`) && len(s) >= 2:
		return s[1 : len(s)-1], nil
	case s == "true":
		return true, nil
	case s == "false":
		return false, nil
	case strings.HasPrefix(s, "["):
		// Array: split top-level commas.
		if !strings.HasSuffix(s, "]") {
			return nil, fmt.Errorf("unterminated array")
		}
		inner := strings.TrimSpace(s[1 : len(s)-1])
		if inner == "" {
			return []any{}, nil
		}
		parts := tomlSplitTop(inner)
		out := []any{}
		for _, p := range parts {
			v, err := tomlParseValue(p)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case strings.HasPrefix(s, "{"):
		if !strings.HasSuffix(s, "}") {
			return nil, fmt.Errorf("unterminated inline table")
		}
		inner := strings.TrimSpace(s[1 : len(s)-1])
		m := map[string]any{}
		if inner == "" {
			return m, nil
		}
		for _, p := range tomlSplitTop(inner) {
			eq := tomlFindEq(p)
			if eq < 0 {
				return nil, fmt.Errorf("bad inline entry")
			}
			v, err := tomlParseValue(strings.TrimSpace(p[eq+1:]))
			if err != nil {
				return nil, err
			}
			m[strings.TrimSpace(p[:eq])] = v
		}
		return m, nil
	default:
		if n, err := strconv.ParseFloat(strings.ReplaceAll(s, "_", ""), 64); err == nil {
			return n, nil
		}
		return nil, fmt.Errorf("unsupported value")
	}
}

func tomlSplitTop(s string) []string {
	var out []string
	depth := 0
	inStr := byte(0)
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inStr != 0 {
			if c == inStr && s[i-1] != '\\' {
				inStr = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			inStr = c
		case '[', '{':
			depth++
		case ']', '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	out = append(out, strings.TrimSpace(s[start:]))
	return out
}

var tomlBareKeyRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func tomlKey(k string) string {
	if tomlBareKeyRe.MatchString(k) {
		return k
	}
	b, _ := json.Marshal(k)
	return string(b)
}

func tomlValueStr(v any) string {
	switch t := v.(type) {
	case tomlRaw:
		return string(t)
	case string:
		b, _ := json.Marshal(t)
		return string(b)
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case []any:
		parts := make([]string, len(t))
		for i, e := range t {
			parts[i] = tomlValueStr(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(t))
		for _, k := range keys {
			parts = append(parts, tomlKey(k)+" = "+tomlValueStr(t[k]))
		}
		return "{ " + strings.Join(parts, ", ") + " }"
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

func (d *tomlDoc) stringify() string {
	var sb strings.Builder
	writeKVs := func(kvs []tomlKV) {
		for _, kv := range kvs {
			sb.WriteString(tomlKey(kv.key) + " = " + tomlValueStr(kv.val) + "\n")
		}
	}
	writeKVs(d.root)
	for _, s := range d.sections {
		if len(s.kvs) == 0 && !strings.HasPrefix(s.name, "[[") {
			continue
		}
		if sb.Len() > 0 {
			sb.WriteString("\n")
		}
		if strings.HasPrefix(s.name, "[[") {
			sb.WriteString(s.name + "\n")
		} else {
			sb.WriteString("[" + s.name + "]\n")
		}
		writeKVs(s.kvs)
	}
	return sb.String()
}

// ---------- claude-settings (~/.claude/settings.json + ~/.claude.json) ----------

func ctClaudeSettingsPath() string { return filepath.Join(ctHome(), ".claude", "settings.json") }
func ctClaudeJSONPath() string     { return filepath.Join(ctHome(), ".claude.json") }

func ctReadClaudeJSON() map[string]any { return ctReadJSONObjTol(ctClaudeJSONPath()) }

func ctWriteClaudeJSONMcp(mcpServers map[string]any) error {
	filePath := ctClaudeJSONPath()
	data := map[string]any{}
	raw, err := os.ReadFile(filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	} else if err := json.Unmarshal(raw, &data); err != nil {
		return err
	}
	if data == nil {
		data = map[string]any{}
	}
	if len(mcpServers) > 0 {
		merged := ctMap(data["mcpServers"])
		if merged == nil {
			merged = map[string]any{}
		}
		for k, v := range mcpServers {
			merged[k] = v
		}
		data["mcpServers"] = merged
	} else if existing := ctMap(data["mcpServers"]); existing != nil {
		delete(existing, "exa")
		if len(existing) == 0 {
			delete(data, "mcpServers")
		} else {
			data["mcpServers"] = existing
		}
	}
	return ctWriteJSON(filePath, data)
}

func ctClaudeGET(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		installed := ctLookPath("claude") || ctFileExists(ctClaudeSettingsPath())
		if !installed {
			WriteJSON(w, 200, map[string]any{"installed": false, "settings": nil, "message": "Claude CLI is not installed"})
			return
		}
		settings := ctReadJSONObjTol(ctClaudeSettingsPath())
		hasProxyGo := false
		if env := ctMap(settings["env"]); env != nil {
			_, hasProxyGo = env["ANTHROPIC_BASE_URL"]
		}
		claudeJSON := ctReadClaudeJSON()
		exa := false
		if cj := ctMap(claudeJSON["mcpServers"]); cj != nil {
			_, exa = cj["exa"]
		}
		WriteJSON(w, 200, map[string]any{
			"installed": true, "settings": settings, "hasProxyGo": hasProxyGo,
			"exaMcpEnabled": exa, "settingsPath": ctClaudeSettingsPath(),
		})
	}
}

func ctClaudePOST(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ctBodyStrict(r)
		if err != nil {
			Err(w, 500, "Failed to update claude settings")
			return
		}
		env, ok := body["env"].(map[string]any)
		if !ok {
			Err(w, 400, "Invalid env object")
			return
		}
		settingsPath := ctClaudeSettingsPath()
		if err := os.MkdirAll(filepath.Dir(settingsPath), 0o755); err != nil {
			Err(w, 500, "Failed to update claude settings")
			return
		}
		current := map[string]any{}
		if raw, err := os.ReadFile(settingsPath); err == nil {
			if err := json.Unmarshal(raw, &current); err != nil {
				Err(w, 500, "Failed to update claude settings")
				return
			}
			if current == nil {
				current = map[string]any{}
			}
		} else if !os.IsNotExist(err) {
			Err(w, 500, "Failed to update claude settings")
			return
		}
		if v := Str(env, "ANTHROPIC_BASE_URL"); v != "" {
			env["ANTHROPIC_BASE_URL"] = ctNormalizeV1(v)
		}
		curEnv := ctMap(current["env"])
		if curEnv != nil {
			if _, has := curEnv["ANTHROPIC_AUTH_TOKEN"]; has {
				delete(env, "ANTHROPIC_AUTH_TOKEN")
			}
		}
		mergedEnv := map[string]any{}
		for k, v := range curEnv {
			mergedEnv[k] = v
		}
		for k, v := range env {
			mergedEnv[k] = v
		}
		current["hasCompletedOnboarding"] = true
		current["env"] = mergedEnv
		if v, present := body["autoCompactWindow"]; present && v != nil && v != "" && v != false {
			mergedEnv["CLAUDE_CODE_AUTO_COMPACT_WINDOW"] = fmt.Sprint(v)
			if f, ok := v.(float64); ok {
				mergedEnv["CLAUDE_CODE_AUTO_COMPACT_WINDOW"] = strconv.FormatFloat(f, 'f', -1, 64)
			}
		} else {
			delete(mergedEnv, "CLAUDE_CODE_AUTO_COMPACT_WINDOW")
		}
		if err := ctWriteJSON(settingsPath, current); err != nil {
			Err(w, 500, "Failed to update claude settings")
			return
		}
		// Exa MCP toggle → ~/.claude.json (DEFAULT_PLUGINS exa entry).
		exaEnabled, _ := body["exaMcpEnabled"].(bool)
		var mcp map[string]any
		if exaEnabled {
			mcp = map[string]any{"exa": map[string]any{"type": "http", "url": "https://mcp.exa.ai/mcp"}}
		}
		if err := ctWriteClaudeJSONMcp(mcp); err != nil {
			Err(w, 500, "Failed to update claude settings")
			return
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": "Settings updated successfully"})
	}
}

var ctClaudeResetEnvKeys = []string{
	"ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_DEFAULT_OPUS_MODEL",
	"ANTHROPIC_DEFAULT_SONNET_MODEL", "ANTHROPIC_DEFAULT_HAIKU_MODEL",
	"API_TIMEOUT_MS", "CLAUDE_CODE_AUTO_COMPACT_WINDOW",
}

func ctClaudeDELETE(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settingsPath := ctClaudeSettingsPath()
		raw, err := os.ReadFile(settingsPath)
		if err != nil {
			if os.IsNotExist(err) {
				WriteJSON(w, 200, map[string]any{"success": true, "message": "No settings file to reset"})
				return
			}
			Err(w, 500, "Failed to reset claude settings")
			return
		}
		current := map[string]any{}
		if err := json.Unmarshal(raw, &current); err != nil {
			Err(w, 500, "Failed to reset claude settings")
			return
		}
		if env := ctMap(current["env"]); env != nil {
			for _, k := range ctClaudeResetEnvKeys {
				delete(env, k)
			}
			if len(env) == 0 {
				delete(current, "env")
			} else {
				current["env"] = env
			}
		}
		if err := ctWriteClaudeJSONMcp(nil); err != nil {
			Err(w, 500, "Failed to reset claude settings")
			return
		}
		if err := ctWriteJSON(settingsPath, current); err != nil {
			Err(w, 500, "Failed to reset claude settings")
			return
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": "Settings reset successfully"})
	}
}

// ---------- codex-settings (~/.codex/config.toml) ----------

func ctCodexDir() string        { return filepath.Join(ctHome(), ".codex") }
func ctCodexConfigPath() string { return filepath.Join(ctCodexDir(), "config.toml") }
func ctCodexAuthPath() string   { return filepath.Join(ctCodexDir(), "auth.json") }

func ctCodexGET(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		installed := ctLookPath("codex") || ctFileExists(ctCodexConfigPath())
		if !installed {
			WriteJSON(w, 200, map[string]any{"installed": false, "config": nil, "message": "Codex CLI is not installed"})
			return
		}
		var config any
		if raw, err := os.ReadFile(ctCodexConfigPath()); err == nil {
			config = string(raw)
		}
		hasProxyGo := false
		if s, ok := config.(string); ok {
			hasProxyGo = strings.Contains(s, `model_provider = "proxygo"`) || strings.Contains(s, "[model_providers.proxygo]")
		}
		WriteJSON(w, 200, map[string]any{
			"installed": true, "config": config, "hasProxyGo": hasProxyGo, "configPath": ctCodexConfigPath(),
		})
	}
}

func ctReadCodexDoc() (*tomlDoc, error) {
	raw, err := os.ReadFile(ctCodexConfigPath())
	if err != nil {
		return &tomlDoc{}, err
	}
	return parseTOMLDoc(string(raw))
}

func ctCodexPOST(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ctBodyStrict(r)
		if err != nil {
			Err(w, 500, "Failed to update codex settings")
			return
		}
		baseUrl, apiKey, model := Str(body, "baseUrl"), Str(body, "apiKey"), Str(body, "model")
		if baseUrl == "" || apiKey == "" || model == "" {
			Err(w, 400, "baseUrl, apiKey and model are required")
			return
		}
		if err := os.MkdirAll(ctCodexDir(), 0o755); err != nil {
			Err(w, 500, "Failed to update codex settings")
			return
		}
		doc, _ := ctReadCodexDoc()
		if doc == nil {
			doc = &tomlDoc{}
		}
		doc.root = tomlSetKV(doc.root, "model", model)
		doc.root = tomlSetKV(doc.root, "model_provider", "proxygo")
		sec := doc.section("model_providers.proxygo")
		sec.kvs = []tomlKV{
			{"name", "ProxyGo"},
			{"base_url", ctNormalizeV1(baseUrl)},
			{"wire_api", "responses"},
			{"http_headers", map[string]any{"Authorization": "Bearer " + apiKey}},
		}
		doc.tomlDeleteNested("agents.subagent")
		sub := Str(body, "subagentModel")
		if sub == "" {
			sub = model
		}
		doc.tomlSetNested("agents.default_subagent_model", sub)
		if err := os.WriteFile(ctCodexConfigPath(), []byte(doc.stringify()), 0o644); err != nil {
			Err(w, 500, "Failed to update codex settings")
			return
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": "Codex settings applied successfully!", "configPath": ctCodexConfigPath()})
	}
}

func ctCodexDELETE(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, err := os.ReadFile(ctCodexConfigPath())
		if err != nil {
			if os.IsNotExist(err) {
				WriteJSON(w, 200, map[string]any{"success": true, "message": "No config file to reset"})
				return
			}
			Err(w, 500, "Failed to reset codex settings")
			return
		}
		doc, perr := parseTOMLDoc(string(raw))
		if perr != nil {
			Err(w, 500, "Failed to reset codex settings")
			return
		}
		if v, ok := tomlGetKV(doc.root, "model_provider"); ok && v == "proxygo" {
			doc.root = tomlDelKV(doc.root, "model")
			doc.root = tomlDelKV(doc.root, "model_provider")
		}
		doc.tomlDeleteNested("model_providers.proxygo")
		doc.tomlDeleteNested("agents.default_subagent_model")
		doc.tomlDeleteNested("agents.subagent")
		if err := os.WriteFile(ctCodexConfigPath(), []byte(doc.stringify()), 0o644); err != nil {
			Err(w, 500, "Failed to reset codex settings")
			return
		}
		// Remove OPENAI_API_KEY / auth_mode from auth.json.
		if rawAuth, err := os.ReadFile(ctCodexAuthPath()); err == nil {
			var authData map[string]any
			if json.Unmarshal(rawAuth, &authData) == nil && authData != nil {
				delete(authData, "OPENAI_API_KEY")
				delete(authData, "auth_mode")
				if len(authData) == 0 {
					_ = os.Remove(ctCodexAuthPath())
				} else {
					_ = ctWriteJSON(ctCodexAuthPath(), authData)
				}
			}
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": "ProxyGo settings removed successfully"})
	}
}

// ---------- codex-profiles (~/.codex/<name>.config.toml) ----------

var ctProfileNameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func ctValidProfileName(name string) bool {
	return ctProfileNameRe.MatchString(name) && len(name) <= 64 && strings.ToLower(name) != "config"
}

func ctValidModelName(model string) bool {
	return strings.TrimSpace(model) != "" && len(model) <= 256 && !strings.ContainsAny(model, "\r\n\"")
}

// JS used a backreference (["'])...\1 — RE2 has none, so both quote
// styles are alternatives; group 1 = double-quoted, group 2 = single.
var ctProfileModelRe = regexp.MustCompile(`(?m)^\s*model\s*=\s*(?:"([^"\n]+)"|'([^'\n]+)')`)

func ctCodexProfilesGET(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entries, err := os.ReadDir(ctCodexDir())
		if err != nil {
			if os.IsNotExist(err) {
				WriteJSON(w, 200, map[string]any{"profiles": []any{}})
				return
			}
			Err(w, 500, "Failed to read profiles")
			return
		}
		profiles := []any{}
		for _, e := range entries {
			file := e.Name()
			if !strings.HasSuffix(file, ".config.toml") || file == "config.toml" {
				continue
			}
			name := strings.TrimSuffix(file, ".config.toml")
			model := ""
			if raw, err := os.ReadFile(filepath.Join(ctCodexDir(), file)); err == nil {
				if m := ctProfileModelRe.FindSubmatch(raw); m != nil {
					model = string(m[1])
					if model == "" {
						model = string(m[2])
					}
				}
			}
			profiles = append(profiles, map[string]any{"name": name, "model": model, "command": "codex -p " + name})
		}
		sort.Slice(profiles, func(i, j int) bool {
			return profiles[i].(map[string]any)["name"].(string) < profiles[j].(map[string]any)["name"].(string)
		})
		WriteJSON(w, 200, map[string]any{"profiles": profiles})
	}
}

func ctCodexProfilesPOST(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ctBodyStrict(r)
		if err != nil {
			Err(w, 500, "Failed to save profile")
			return
		}
		cleanName := strings.ToLower(strings.TrimSpace(Str(body, "name")))
		if !ctValidProfileName(cleanName) {
			Err(w, 400, "Profile name can only contain alphanumeric characters, dashes, underscores and cannot be 'config'")
			return
		}
		cleanModel := strings.TrimSpace(Str(body, "model"))
		if !ctValidModelName(cleanModel) {
			Err(w, 400, "Invalid model name")
			return
		}
		if err := os.MkdirAll(ctCodexDir(), 0o755); err != nil {
			Err(w, 500, "Failed to save profile")
			return
		}
		content := "# codex -p " + cleanName + "\nmodel = \"" + cleanModel + "\"\nmodel_provider = \"proxygo\"\n"
		if err := os.WriteFile(filepath.Join(ctCodexDir(), cleanName+".config.toml"), []byte(content), 0o644); err != nil {
			Err(w, 500, "Failed to save profile")
			return
		}
		WriteJSON(w, 200, map[string]any{
			"success": true,
			"profile": map[string]any{"name": cleanName, "model": cleanModel, "command": "codex -p " + cleanName},
		})
	}
}

func ctCodexProfilesDELETE(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ctBodyStrict(r)
		if err != nil {
			Err(w, 500, "Failed to delete profile")
			return
		}
		cleanName := strings.ToLower(strings.TrimSpace(Str(body, "name")))
		if !ctValidProfileName(cleanName) {
			Err(w, 400, "Invalid profile name")
			return
		}
		err = os.Remove(filepath.Join(ctCodexDir(), cleanName+".config.toml"))
		if err != nil {
			if os.IsNotExist(err) {
				Err(w, 404, "Profile not found")
				return
			}
			Err(w, 500, "Failed to delete profile")
			return
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": "Profile " + cleanName + " deleted"})
	}
}

// ---------- copilot-settings (VS Code chatLanguageModels.json) ----------

func ctCopilotConfigPath() string {
	home := ctHome()
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("APPDATA")
		if base == "" {
			base = home
		}
		return filepath.Join(base, "Code", "User", "chatLanguageModels.json")
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Code", "User", "chatLanguageModels.json")
	default:
		return filepath.Join(home, ".config", "Code", "User", "chatLanguageModels.json")
	}
}

func ctCopilotRead() []any {
	v, err := ctReadJSONAny(ctCopilotConfigPath())
	if err != nil {
		return nil
	}
	if arr, ok := v.([]any); ok {
		return arr
	}
	return nil
}

func ctCopilotEntry(config []any) map[string]any {
	for _, e := range config {
		if m := ctMap(e); m != nil && m["name"] == "ProxyGo" {
			return m
		}
	}
	return nil
}

func ctCopilotGET(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		config := ctCopilotRead()
		entry := ctCopilotEntry(config)
		var currentModel, currentURL any
		if entry != nil {
			if models := ctSlice(entry["models"]); len(models) > 0 {
				if m0 := ctMap(models[0]); m0 != nil {
					currentModel = m0["id"]
					currentURL = m0["url"]
				}
			}
		}
		var configVal any
		if config != nil {
			configVal = config
		}
		WriteJSON(w, 200, map[string]any{
			"installed": true, "config": configVal, "hasProxyGo": entry != nil,
			"configPath": ctCopilotConfigPath(), "currentModel": currentModel, "currentUrl": currentURL,
		})
	}
}

func ctSlice(v any) []any {
	if arr, ok := v.([]any); ok {
		return arr
	}
	return nil
}

func ctCopilotPOST(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ctBodyStrict(r)
		if err != nil {
			Err(w, 500, "Failed to update copilot settings")
			return
		}
		baseUrl := Str(body, "baseUrl")
		models := ctSlice(body["models"])
		if baseUrl == "" || len(models) == 0 {
			Err(w, 400, "baseUrl and models are required")
			return
		}
		configPath := ctCopilotConfigPath()
		if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
			Err(w, 500, "Failed to update copilot settings")
			return
		}
		config := []any{}
		if raw, err := os.ReadFile(configPath); err == nil {
			var parsed any
			if json.Unmarshal(raw, &parsed) == nil {
				if arr, ok := parsed.([]any); ok {
					config = arr
				}
			}
		}
		endpointURL := baseUrl + "/chat/completions#models.ai.azure.com"
		keyToUse := resolveCliApiKey(deps, Str(body, "apiKey"))
		modelEntries := []any{}
		for _, m := range models {
			id, _ := m.(string)
			modelEntries = append(modelEntries, map[string]any{
				"id": id, "name": id, "url": endpointURL, "toolCalling": true, "vision": false,
				"maxInputTokens": 128000, "maxOutputTokens": 16000,
			})
		}
		newEntry := map[string]any{
			"name": "ProxyGo", "vendor": "azure", "apiKey": keyToUse, "models": modelEntries,
		}
		replaced := false
		for i, e := range config {
			if m := ctMap(e); m != nil && m["name"] == "ProxyGo" {
				config[i] = newEntry
				replaced = true
				break
			}
		}
		if !replaced {
			config = append(config, newEntry)
		}
		if err := ctWriteJSON(configPath, config); err != nil {
			Err(w, 500, "Failed to update copilot settings")
			return
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": "Copilot settings applied! Reload VS Code to take effect.", "configPath": configPath})
	}
}

func ctCopilotDELETE(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		configPath := ctCopilotConfigPath()
		raw, err := os.ReadFile(configPath)
		if err != nil {
			if os.IsNotExist(err) {
				WriteJSON(w, 200, map[string]any{"success": true, "message": "No config file to reset"})
				return
			}
			Err(w, 500, "Failed to reset copilot settings")
			return
		}
		config := []any{}
		var parsed any
		if json.Unmarshal(raw, &parsed) == nil {
			if arr, ok := parsed.([]any); ok {
				config = arr
			}
		}
		out := []any{}
		for _, e := range config {
			if m := ctMap(e); m != nil && m["name"] == "ProxyGo" {
				continue
			}
			out = append(out, e)
		}
		if err := ctWriteJSON(configPath, out); err != nil {
			Err(w, 500, "Failed to reset copilot settings")
			return
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": "ProxyGo removed from Copilot config"})
	}
}

// ---------- cline-settings (~/.cline/data) ----------

func ctClineDataDir() string         { return filepath.Join(ctHome(), ".cline", "data") }
func ctClineGlobalStatePath() string { return filepath.Join(ctClineDataDir(), "globalState.json") }
func ctClineSecretsPath() string     { return filepath.Join(ctClineDataDir(), "secrets.json") }

func ctClineHasProxyGo(gs map[string]any) bool {
	if gs == nil {
		return false
	}
	isOpenAI := gs["actModeApiProvider"] == "openai" || gs["planModeApiProvider"] == "openai"
	base := Str(gs, "openAiBaseUrl")
	return isOpenAI && (strings.Contains(base, "localhost") || strings.Contains(base, "127.0.0.1") || strings.Contains(base, "proxygo"))
}

func ctClineGET(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		installed := ctLookPath("cline") || ctFileExists(ctClineGlobalStatePath())
		if !installed {
			WriteJSON(w, 200, map[string]any{"installed": false, "settings": nil, "message": "Cline CLI is not installed"})
			return
		}
		gs := ctReadJSONObjTol(ctClineGlobalStatePath())
		settings := map[string]any{}
		if gs != nil {
			for _, k := range []string{"actModeApiProvider", "planModeApiProvider", "openAiBaseUrl", "openAiModelId"} {
				if v, ok := gs[k]; ok {
					settings[k] = v
				}
			}
		}
		WriteJSON(w, 200, map[string]any{
			"installed": true, "settings": settings, "hasProxyGo": ctClineHasProxyGo(gs),
			"globalStatePath": ctClineGlobalStatePath(),
		})
	}
}

func ctClinePOST(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ctBodyStrict(r)
		if err != nil {
			Err(w, 500, "Failed to update cline settings")
			return
		}
		baseUrl, apiKey, model := Str(body, "baseUrl"), Str(body, "apiKey"), Str(body, "model")
		if baseUrl == "" || apiKey == "" || model == "" {
			Err(w, 400, "baseUrl, apiKey and model are required")
			return
		}
		if err := os.MkdirAll(ctClineDataDir(), 0o755); err != nil {
			Err(w, 500, "Failed to update cline settings")
			return
		}
		normalized := strings.TrimSuffix(baseUrl, "/v1")
		gs := ctReadJSONObjTol(ctClineGlobalStatePath())
		if gs == nil {
			gs = map[string]any{}
		}
		gs["actModeApiProvider"] = "openai"
		gs["planModeApiProvider"] = "openai"
		gs["openAiBaseUrl"] = normalized
		gs["openAiModelId"] = model
		gs["planModeOpenAiModelId"] = model
		if err := ctWriteJSON(ctClineGlobalStatePath(), gs); err != nil {
			Err(w, 500, "Failed to update cline settings")
			return
		}
		secrets := ctReadJSONObjTol(ctClineSecretsPath())
		if secrets == nil {
			secrets = map[string]any{}
		}
		secrets["openAiApiKey"] = apiKey
		if err := ctWriteJSON(ctClineSecretsPath(), secrets); err != nil {
			Err(w, 500, "Failed to update cline settings")
			return
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": "Cline settings applied successfully!", "globalStatePath": ctClineGlobalStatePath()})
	}
}

func ctClineDELETE(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		gs := ctReadJSONObjTol(ctClineGlobalStatePath())
		if gs == nil {
			WriteJSON(w, 200, map[string]any{"success": true, "message": "No settings file to reset"})
			return
		}
		if gs["actModeApiProvider"] == "openai" {
			delete(gs, "openAiBaseUrl")
			delete(gs, "openAiModelId")
			delete(gs, "planModeOpenAiModelId")
			gs["actModeApiProvider"] = "cline"
			gs["planModeApiProvider"] = "cline"
		}
		if err := ctWriteJSON(ctClineGlobalStatePath(), gs); err != nil {
			Err(w, 500, "Failed to reset cline settings")
			return
		}
		secrets := ctReadJSONObjTol(ctClineSecretsPath())
		if secrets == nil {
			secrets = map[string]any{}
		}
		delete(secrets, "openAiApiKey")
		if err := ctWriteJSON(ctClineSecretsPath(), secrets); err != nil {
			Err(w, 500, "Failed to reset cline settings")
			return
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": "ProxyGo settings removed from Cline"})
	}
}

// ---------- kilo-settings (~/.local/share/kilo/auth.json) ----------

func ctKiloDataDir() string  { return filepath.Join(ctHome(), ".local", "share", "kilo") }
func ctKiloAuthPath() string { return filepath.Join(ctKiloDataDir(), "auth.json") }
func ctKiloVscodePath() string {
	return filepath.Join(ctHome(), ".config", "Code", "User", "settings.json")
}

func ctKiloHasProxyGo(auth map[string]any) bool {
	if auth == nil {
		return false
	}
	entry := ctMap(auth["openai-compatible"])
	if entry == nil {
		entry = ctMap(auth["proxygo"])
	}
	if entry == nil {
		return false
	}
	base := Str(entry, "baseUrl")
	if base == "" {
		base = Str(entry, "baseURL")
	}
	return strings.Contains(base, "localhost") || strings.Contains(base, "127.0.0.1") || strings.Contains(base, "proxygo")
}

func ctKiloGET(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		installed := ctLookPath("kilo") || ctFileExists(ctKiloAuthPath())
		if !installed {
			WriteJSON(w, 200, map[string]any{"installed": false, "settings": nil, "message": "Kilo Code CLI is not installed"})
			return
		}
		auth := ctReadJSONObjTol(ctKiloAuthPath())
		keys := []any{}
		if auth != nil {
			names := make([]string, 0, len(auth))
			for k := range auth {
				names = append(names, k)
			}
			sort.Strings(names)
			for _, n := range names {
				keys = append(keys, n)
			}
		}
		WriteJSON(w, 200, map[string]any{
			"installed": true, "settings": map[string]any{"auth": keys},
			"hasProxyGo": ctKiloHasProxyGo(auth), "authPath": ctKiloAuthPath(),
		})
	}
}

func ctKiloPOST(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ctBodyStrict(r)
		if err != nil {
			Err(w, 500, "Failed to update kilo settings")
			return
		}
		baseUrl, apiKey, model := Str(body, "baseUrl"), Str(body, "apiKey"), Str(body, "model")
		if baseUrl == "" || apiKey == "" || model == "" {
			Err(w, 400, "baseUrl, apiKey and model are required")
			return
		}
		if err := os.MkdirAll(ctKiloDataDir(), 0o755); err != nil {
			Err(w, 500, "Failed to update kilo settings")
			return
		}
		normalized := ctNormalizeV1(baseUrl)
		auth := ctReadJSONObjTol(ctKiloAuthPath())
		if auth == nil {
			auth = map[string]any{}
		}
		auth["openai-compatible"] = map[string]any{
			"type": "api-key", "apiKey": apiKey, "baseUrl": normalized, "model": model,
		}
		if err := ctWriteJSON(ctKiloAuthPath(), auth); err != nil {
			Err(w, 500, "Failed to update kilo settings")
			return
		}
		// Best-effort VS Code extension settings.
		vscode := ctReadJSONObjTol(ctKiloVscodePath())
		if vscode == nil {
			vscode = map[string]any{}
		}
		vscode["kilocode.customProvider"] = map[string]any{"name": "ProxyGo", "baseURL": normalized, "apiKey": apiKey}
		vscode["kilocode.defaultModel"] = model
		_ = ctWriteJSON(ctKiloVscodePath(), vscode)
		WriteJSON(w, 200, map[string]any{"success": true, "message": "Kilo Code settings applied successfully!", "authPath": ctKiloAuthPath()})
	}
}

func ctKiloDELETE(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := ctReadJSONObjTol(ctKiloAuthPath())
		if auth == nil {
			WriteJSON(w, 200, map[string]any{"success": true, "message": "No settings file to reset"})
			return
		}
		delete(auth, "openai-compatible")
		delete(auth, "proxygo")
		if err := ctWriteJSON(ctKiloAuthPath(), auth); err != nil {
			Err(w, 500, "Failed to reset kilo settings")
			return
		}
		if vscode := ctReadJSONObjTol(ctKiloVscodePath()); vscode != nil {
			delete(vscode, "kilocode.customProvider")
			delete(vscode, "kilocode.defaultModel")
			_ = ctWriteJSON(ctKiloVscodePath(), vscode)
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": "ProxyGo settings removed from Kilo Code"})
	}
}

// ---------- opencode-settings (~/.config/opencode/opencode.json) ----------

func ctOpencodeConfigDir() string  { return filepath.Join(ctHome(), ".config", "opencode") }
func ctOpencodeConfigPath() string { return filepath.Join(ctOpencodeConfigDir(), "opencode.json") }

func ctOpencodeRead() map[string]any { return ctReadJSONObjTol(ctOpencodeConfigPath()) }

func ctOpencodeGET(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		installed := ctLookPath("opencode") || ctFileExists(ctOpencodeConfigPath())
		if !installed {
			WriteJSON(w, 200, map[string]any{"installed": false, "config": nil, "message": "OpenCode CLI is not installed"})
			return
		}
		config := ctOpencodeRead()
		var providerConfig map[string]any
		if prov := ctMap(config["provider"]); prov != nil {
			providerConfig = ctMap(prov["proxygo"])
		}
		modelIDs := []string{}
		if models := ctMap(providerConfig["models"]); models != nil {
			for k := range models {
				modelIDs = append(modelIDs, k)
			}
			sort.Strings(modelIDs)
		}
		var activeModel any
		if m := Str(config, "model"); strings.HasPrefix(m, "proxygo/") {
			activeModel = strings.TrimPrefix(m, "proxygo/")
		}
		var baseURL any
		if opts := ctMap(providerConfig["options"]); opts != nil {
			baseURL = opts["baseURL"]
		}
		modelsAny := make([]any, len(modelIDs))
		for i, id := range modelIDs {
			modelsAny[i] = id
		}
		WriteJSON(w, 200, map[string]any{
			"installed": true, "config": config, "hasProxyGo": providerConfig != nil,
			"configPath": ctOpencodeConfigPath(),
			"opencode":   map[string]any{"models": modelsAny, "activeModel": activeModel, "baseURL": baseURL},
		})
	}
}

// ctOpencodeModelsArray accepts `models` (array) or legacy `model` (string).
func ctOpencodeModelsArray(body map[string]any) []string {
	if arr := ctSlice(body["models"]); arr != nil {
		out := []string{}
		for _, m := range arr {
			if s, ok := m.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	if s, ok := body["model"].(string); ok {
		return []string{s}
	}
	return []string{}
}

func ctOpencodePOST(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ctBodyStrict(r)
		if err != nil {
			Err(w, 500, "Failed to apply settings")
			return
		}
		baseUrl := Str(body, "baseUrl")
		modelsArray := ctOpencodeModelsArray(body)
		if baseUrl == "" || len(modelsArray) == 0 {
			Err(w, 400, "baseUrl and at least one model are required")
			return
		}
		if err := os.MkdirAll(ctOpencodeConfigDir(), 0o755); err != nil {
			Err(w, 500, "Failed to apply settings")
			return
		}
		config, _, _ := ctReadJSONObjStrict(ctOpencodeConfigPath())
		if config == nil {
			config = map[string]any{}
		}
		normalized := ctNormalizeV1(baseUrl)
		keyToUse := resolveCliApiKey(deps, Str(body, "apiKey"))
		effectiveSub := Str(body, "subagentModel")
		if effectiveSub == "" {
			effectiveSub = modelsArray[0]
		}
		providers := ctMap(config["provider"])
		if providers == nil {
			providers = map[string]any{}
		}
		config["provider"] = providers
		existing := ctMap(providers["proxygo"])
		if existing == nil {
			existing = map[string]any{"npm": "@ai-sdk/openai-compatible", "options": map[string]any{}, "models": map[string]any{}}
		}
		opts := ctMap(existing["options"])
		if opts == nil {
			opts = map[string]any{}
		}
		opts["baseURL"] = normalized
		opts["apiKey"] = keyToUse
		existing["options"] = opts
		models := ctMap(existing["models"])
		if models == nil {
			models = map[string]any{}
		}
		for _, m := range modelsArray {
			if m == "" {
				continue
			}
			models[m] = map[string]any{
				"name":       m,
				"modalities": map[string]any{"input": []any{"text", "image"}, "output": []any{"text"}},
			}
		}
		existing["models"] = models
		providers["proxygo"] = existing
		if v, present := body["activeModel"]; present {
			if s, ok := v.(string); ok && s == "" {
				config["model"] = ""
			} else if ok {
				config["model"] = "proxygo/" + s
			} else {
				config["model"] = "proxygo/" + modelsArray[0]
			}
		} else {
			config["model"] = "proxygo/" + modelsArray[0]
		}
		agent := ctMap(config["agent"])
		if agent == nil {
			agent = map[string]any{}
		}
		config["agent"] = agent
		agent["explorer"] = map[string]any{
			"description": "Fast explorer subagent for codebase exploration",
			"mode":        "subagent",
			"model":       "proxygo/" + effectiveSub,
		}
		if err := ctWriteJSON(ctOpencodeConfigPath(), config); err != nil {
			Err(w, 500, "Failed to apply settings")
			return
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": "OpenCode settings applied successfully!", "configPath": ctOpencodeConfigPath()})
	}
}

func ctOpencodePATCH(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ctBodyStrict(r)
		if err != nil {
			Err(w, 500, "Failed to patch settings")
			return
		}
		config, existed, rerr := ctReadJSONObjStrict(ctOpencodeConfigPath())
		if rerr != nil {
			Err(w, 500, "Failed to patch settings")
			return
		}
		if !existed {
			WriteJSON(w, 200, map[string]any{"success": true, "message": "No config file found"})
			return
		}
		if clear, _ := body["clearActiveModel"].(bool); clear {
			if m := Str(config, "model"); strings.HasPrefix(m, "proxygo/") {
				config["model"] = ""
			}
		}
		if err := ctWriteJSON(ctOpencodeConfigPath(), config); err != nil {
			Err(w, 500, "Failed to patch settings")
			return
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": "Settings updated"})
	}
}

func ctOpencodeDELETE(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		modelToRemove := r.URL.Query().Get("model")
		config, existed, rerr := ctReadJSONObjStrict(ctOpencodeConfigPath())
		if rerr != nil {
			Err(w, 500, "Failed to reset opencode settings")
			return
		}
		if !existed {
			WriteJSON(w, 200, map[string]any{"success": true, "message": "No config file to reset"})
			return
		}
		providers := ctMap(config["provider"])
		var routerProv map[string]any
		if providers != nil {
			routerProv = ctMap(providers["proxygo"])
		}
		if modelToRemove != "" && routerProv != nil {
			if models := ctMap(routerProv["models"]); models != nil {
				delete(models, modelToRemove)
				if len(models) == 0 {
					delete(providers, "proxygo")
					if m := Str(config, "model"); strings.HasPrefix(m, "proxygo/") {
						delete(config, "model")
					}
				} else if Str(config, "model") == "proxygo/"+modelToRemove {
					remaining := make([]string, 0, len(models))
					for k := range models {
						remaining = append(remaining, k)
					}
					sort.Strings(remaining)
					config["model"] = "proxygo/" + remaining[0]
				}
			}
		} else {
			if providers != nil {
				delete(providers, "proxygo")
			}
			if m := Str(config, "model"); strings.HasPrefix(m, "proxygo/") {
				delete(config, "model")
			}
		}
		if agent := ctMap(config["agent"]); agent != nil {
			if explorer := ctMap(agent["explorer"]); explorer != nil {
				if m := Str(explorer, "model"); strings.HasPrefix(m, "proxygo/") {
					delete(agent, "explorer")
					if len(agent) == 0 {
						delete(config, "agent")
					}
				}
			}
		}
		if err := ctWriteJSON(ctOpencodeConfigPath(), config); err != nil {
			Err(w, 500, "Failed to reset opencode settings")
			return
		}
		msg := "ProxyGo settings removed from OpenCode"
		if modelToRemove != "" {
			msg = "Model \"" + modelToRemove + "\" removed"
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": msg})
	}
}

// ---------- openclaw-settings (~/.openclaw/openclaw.json) ----------

func ctOpenclawDir() string  { return filepath.Join(ctHome(), ".openclaw") }
func ctOpenclawPath() string { return filepath.Join(ctOpenclawDir(), "openclaw.json") }

func ctResolveAgentModel(m any) string {
	switch t := m.(type) {
	case string:
		return t
	case map[string]any:
		return Str(t, "primary")
	}
	return ""
}

func ctOpenclawReadAgentModel(agentDir string) any {
	if agentDir == "" {
		return nil
	}
	data := ctReadJSONObjTol(filepath.Join(agentDir, "models.json"))
	if data == nil {
		return nil
	}
	providers := ctMap(data["providers"])
	rp := ctMap(providers["proxygo"])
	models := ctSlice(rp["models"])
	if len(models) == 0 {
		return nil
	}
	if m0 := ctMap(models[0]); m0 != nil {
		return m0["id"]
	}
	return nil
}

func ctOpenclawHasProxyGo(settings map[string]any) bool {
	if settings == nil {
		return false
	}
	models := ctMap(settings["models"])
	providers := ctMap(models["providers"])
	_, ok := providers["proxygo"]
	return ok
}

func ctOpenclawGET(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		installed := ctLookPath("openclaw") || ctFileExists(ctOpenclawPath())
		if !installed {
			WriteJSON(w, 200, map[string]any{"installed": false, "settings": nil, "message": "Open Claw CLI is not installed"})
			return
		}
		settings := ctReadJSONObjTol(ctOpenclawPath())
		agents := []any{}
		var list []any
		if settings != nil {
			if a := ctMap(settings["agents"]); a != nil {
				list = ctSlice(a["list"])
			}
		}
		for _, item := range list {
			agent := ctMap(item)
			if agent == nil {
				agents = append(agents, item)
				continue
			}
			enriched := map[string]any{}
			for k, v := range agent {
				enriched[k] = v
			}
			enriched["model"] = ctResolveAgentModel(agent["model"])
			enriched["currentModel"] = ctOpenclawReadAgentModel(Str(agent, "agentDir"))
			agents = append(agents, enriched)
		}
		WriteJSON(w, 200, map[string]any{
			"installed": true, "settings": settings, "agents": agents,
			"hasProxyGo": ctOpenclawHasProxyGo(settings), "settingsPath": ctOpenclawPath(),
		})
	}
}

func ctOpenclawWriteAgentModels(agentDir, model, baseUrl string, apiKey any) {
	if agentDir == "" {
		return
	}
	_ = os.MkdirAll(agentDir, 0o755)
	modelsPath := filepath.Join(agentDir, "models.json")
	existing := ctReadJSONObjTol(modelsPath)
	if existing == nil {
		existing = map[string]any{}
	}
	providers := ctMap(existing["providers"])
	if providers == nil {
		providers = map[string]any{}
	}
	existing["providers"] = providers
	name := model
	if idx := strings.LastIndex(model, "/"); idx >= 0 {
		name = model[idx+1:]
	}
	if name == "" {
		name = model
	}
	providers["proxygo"] = map[string]any{
		"baseUrl": baseUrl, "apiKey": apiKey, "api": "openai-completions",
		"models": []any{map[string]any{"id": model, "name": name}},
	}
	_ = ctWriteJSON(modelsPath, existing)
}

func ctOpenclawPOST(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ctBodyStrict(r)
		if err != nil {
			Err(w, 500, "Failed to update openclaw settings")
			return
		}
		baseUrl, model := Str(body, "baseUrl"), Str(body, "model")
		if baseUrl == "" || model == "" {
			Err(w, 400, "baseUrl and model are required")
			return
		}
		var apiKey any = body["apiKey"]
		agentModels := ctMap(body["agentModels"])
		if agentModels == nil {
			agentModels = map[string]any{}
		}
		if err := os.MkdirAll(ctOpenclawDir(), 0o755); err != nil {
			Err(w, 500, "Failed to update openclaw settings")
			return
		}
		settings, _, _ := ctReadJSONObjStrict(ctOpenclawPath())
		if settings == nil {
			settings = map[string]any{}
		}
		agents := ctMap(settings["agents"])
		if agents == nil {
			agents = map[string]any{}
		}
		settings["agents"] = agents
		defaults := ctMap(agents["defaults"])
		if defaults == nil {
			defaults = map[string]any{}
		}
		agents["defaults"] = defaults
		defModel := ctMap(defaults["model"])
		if defModel == nil {
			defModel = map[string]any{}
		}
		defaults["model"] = defModel
		defModels := ctMap(defaults["models"])
		if defModels == nil {
			defModels = map[string]any{}
		}
		defaults["models"] = defModels
		modelsCfg := ctMap(settings["models"])
		if modelsCfg == nil {
			modelsCfg = map[string]any{}
		}
		settings["models"] = modelsCfg
		providers := ctMap(modelsCfg["providers"])
		if providers == nil {
			providers = map[string]any{}
		}
		modelsCfg["providers"] = providers

		normalized := ctNormalizeV1(baseUrl)
		fullModelID := "proxygo/" + model
		for k := range defModels {
			if strings.HasPrefix(k, "proxygo/") {
				delete(defModels, k)
			}
		}
		defModel["primary"] = fullModelID
		allIDs := []string{model}
		seen := map[string]bool{model: true}
		for _, v := range agentModels {
			if s, ok := v.(string); ok && s != "" && !seen[s] {
				seen[s] = true
				allIDs = append(allIDs, s)
			}
		}
		for _, m := range allIDs {
			defModels["proxygo/"+m] = map[string]any{}
		}
		// Strip proxygo model from agents that have one, then re-apply overrides.
		applyList := func(list []any) []any {
			out := []any{}
			for _, item := range list {
				agent := ctMap(item)
				if agent == nil {
					out = append(out, item)
					continue
				}
				if strings.HasPrefix(ctResolveAgentModel(agent["model"]), "proxygo/") {
					na := map[string]any{}
					for k, v := range agent {
						if k != "model" {
							na[k] = v
						}
					}
					agent = na
				}
				out = append(out, agent)
			}
			return out
		}
		if list := ctSlice(agents["list"]); list != nil {
			agents["list"] = applyList(list)
		}
		modelEntries := []any{}
		for _, m := range allIDs {
			name := m
			if idx := strings.LastIndex(m, "/"); idx >= 0 {
				name = m[idx+1:]
			}
			if name == "" {
				name = m
			}
			modelEntries = append(modelEntries, map[string]any{"id": m, "name": name})
		}
		providers["proxygo"] = map[string]any{
			"baseUrl": normalized, "apiKey": apiKey, "api": "openai-completions", "models": modelEntries,
		}
		if list := ctSlice(agents["list"]); list != nil {
			newList := []any{}
			for _, item := range list {
				agent := ctMap(item)
				if agent == nil {
					newList = append(newList, item)
					continue
				}
				if am, ok := agentModels[Str(agent, "id")].(string); ok && am != "" {
					na := map[string]any{}
					for k, v := range agent {
						na[k] = v
					}
					na["model"] = "proxygo/" + am
					agent = na
				}
				newList = append(newList, agent)
				writeModel := model
				if am, ok := agentModels[Str(agent, "id")].(string); ok && am != "" {
					writeModel = am
				}
				if dir := Str(agent, "agentDir"); dir != "" {
					ctOpenclawWriteAgentModels(dir, writeModel, normalized, apiKey)
				}
			}
			agents["list"] = newList
		}
		if err := ctWriteJSON(ctOpenclawPath(), settings); err != nil {
			Err(w, 500, "Failed to update openclaw settings")
			return
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": "Open Claw settings applied successfully!", "settingsPath": ctOpenclawPath()})
	}
}

func ctOpenclawDELETE(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, err := os.ReadFile(ctOpenclawPath())
		if err != nil {
			if os.IsNotExist(err) {
				WriteJSON(w, 200, map[string]any{"success": true, "message": "No settings file to reset"})
				return
			}
			Err(w, 500, "Failed to reset openclaw settings")
			return
		}
		var settings map[string]any
		if err := json.Unmarshal(raw, &settings); err != nil {
			Err(w, 500, "Failed to reset openclaw settings")
			return
		}
		if settings == nil {
			settings = map[string]any{}
		}
		if modelsCfg := ctMap(settings["models"]); modelsCfg != nil {
			if providers := ctMap(modelsCfg["providers"]); providers != nil {
				delete(providers, "proxygo")
				if len(providers) == 0 {
					delete(modelsCfg, "providers")
				}
			}
		}
		if agents := ctMap(settings["agents"]); agents != nil {
			if defaults := ctMap(agents["defaults"]); defaults != nil {
				if dm := ctMap(defaults["models"]); dm != nil {
					for k := range dm {
						if strings.HasPrefix(k, "proxygo/") {
							delete(dm, k)
						}
					}
					if len(dm) == 0 {
						delete(defaults, "models")
					}
				}
				if defModel := ctMap(defaults["model"]); defModel != nil {
					if p := Str(defModel, "primary"); strings.HasPrefix(p, "proxygo/") {
						delete(defModel, "primary")
					}
				}
			}
		}
		if err := ctWriteJSON(ctOpenclawPath(), settings); err != nil {
			Err(w, 500, "Failed to reset openclaw settings")
			return
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": "ProxyGo settings removed successfully"})
	}
}

// ---------- droid-settings (~/.factory/settings.json) ----------

func ctDroidDir() string  { return filepath.Join(ctHome(), ".factory") }
func ctDroidPath() string { return filepath.Join(ctDroidDir(), "settings.json") }

func ctDroidCustomModels(settings map[string]any) []any {
	if settings == nil {
		return nil
	}
	return ctSlice(settings["customModels"])
}

func ctDroidIs9(m any) bool {
	mm := ctMap(m)
	return mm != nil && strings.HasPrefix(Str(mm, "id"), "custom:ProxyGo")
}

func ctDroidHasProxyGo(settings map[string]any) bool {
	for _, m := range ctDroidCustomModels(settings) {
		if ctDroidIs9(m) {
			return true
		}
	}
	return false
}

func ctDroidGET(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		installed := ctLookPath("droid") || ctFileExists(ctDroidPath())
		if !installed {
			WriteJSON(w, 200, map[string]any{"installed": false, "settings": nil, "message": "Factory Droid CLI is not installed"})
			return
		}
		settings := ctReadJSONObjTol(ctDroidPath())
		WriteJSON(w, 200, map[string]any{
			"installed": true, "settings": settings, "hasProxyGo": ctDroidHasProxyGo(settings), "settingsPath": ctDroidPath(),
		})
	}
}

func ctDroidPOST(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ctBodyStrict(r)
		if err != nil {
			Err(w, 500, "Failed to update droid settings")
			return
		}
		baseUrl := Str(body, "baseUrl")
		modelsArray := ctOpencodeModelsArray(body)
		if baseUrl == "" || len(modelsArray) == 0 {
			Err(w, 400, "baseUrl and at least one model are required")
			return
		}
		if err := os.MkdirAll(ctDroidDir(), 0o755); err != nil {
			Err(w, 500, "Failed to update droid settings")
			return
		}
		settings, _, _ := ctReadJSONObjStrict(ctDroidPath())
		if settings == nil {
			settings = map[string]any{}
		}
		kept := []any{}
		for _, m := range ctDroidCustomModels(settings) {
			if !ctDroidIs9(m) {
				kept = append(kept, m)
			}
		}
		normalized := ctNormalizeV1(baseUrl)
		keyToUse := Str(body, "apiKey")
		if keyToUse == "" {
			keyToUse = "your_api_key"
		}
		defaultIndex := 0
		if av, present := body["activeModel"]; present {
			if s, ok := av.(string); ok {
				if s == "" {
					defaultIndex = -1
				} else {
					defaultIndex = 0
					for i, m := range modelsArray {
						if m == s {
							defaultIndex = i
							break
						}
					}
				}
			}
		}
		entries := []any{}
		for i, m := range modelsArray {
			if m == "" {
				continue
			}
			entries = append(entries, map[string]any{
				"model": m, "id": "custom:ProxyGo-" + strconv.Itoa(i), "index": i,
				"baseUrl": normalized, "apiKey": keyToUse, "displayName": m,
				"maxOutputTokens": 131072, "noImageSupport": false, "provider": "openai",
			})
		}
		customModels := append(kept, entries...)
		if defaultIndex >= 0 && defaultIndex < len(customModels) {
			def := customModels[defaultIndex]
			rest := append([]any{}, customModels[:defaultIndex]...)
			rest = append(rest, customModels[defaultIndex+1:]...)
			customModels = append([]any{def}, rest...)
			for i, m := range customModels {
				if mm := ctMap(m); mm != nil {
					mm["index"] = i
				}
			}
		}
		settings["customModels"] = customModels
		if err := ctWriteJSON(ctDroidPath(), settings); err != nil {
			Err(w, 500, "Failed to update droid settings")
			return
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": "Factory Droid settings applied successfully!", "settingsPath": ctDroidPath()})
	}
}

func ctDroidDELETE(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, err := os.ReadFile(ctDroidPath())
		if err != nil {
			if os.IsNotExist(err) {
				WriteJSON(w, 200, map[string]any{"success": true, "message": "No settings file to reset"})
				return
			}
			Err(w, 500, "Failed to reset droid settings")
			return
		}
		var settings map[string]any
		if err := json.Unmarshal(raw, &settings); err != nil {
			Err(w, 500, "Failed to reset droid settings")
			return
		}
		if settings == nil {
			settings = map[string]any{}
		}
		if cms := ctDroidCustomModels(settings); cms != nil {
			kept := []any{}
			for _, m := range cms {
				if !ctDroidIs9(m) {
					kept = append(kept, m)
				}
			}
			if len(kept) == 0 {
				delete(settings, "customModels")
			} else {
				settings["customModels"] = kept
			}
		}
		if err := ctWriteJSON(ctDroidPath(), settings); err != nil {
			Err(w, 500, "Failed to reset droid settings")
			return
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": "ProxyGo settings removed successfully"})
	}
}

// ---------- jcode-settings (~/.jcode/config.toml + XDG env file) ----------

func ctJcodeDir() string  { return filepath.Join(ctHome(), ".jcode") }
func ctJcodePath() string { return filepath.Join(ctJcodeDir(), "config.toml") }
func ctJcodeEnvPath() string {
	configDir := os.Getenv("XDG_CONFIG_HOME")
	if configDir == "" {
		configDir = filepath.Join(ctHome(), ".config")
	}
	return filepath.Join(configDir, "jcode", "provider-proxygo.env")
}

func ctJcodeReadConfig() *tomlDoc {
	raw, err := os.ReadFile(ctJcodePath())
	if err != nil {
		d, _ := parseTOMLDoc("")
		if s := d.findSection("providers"); s == nil {
			d.sections = append(d.sections, &tomlSection{name: "providers"})
		}
		return d
	}
	d, err := parseTOMLDoc(string(raw))
	if err != nil {
		return &tomlDoc{}
	}
	return d
}

func ctJcodeHasProxyGo(d *tomlDoc) bool {
	m := d.toMap()
	providers := ctMap(m["providers"])
	if providers == nil {
		return false
	}
	if _, ok := providers["proxygo"]; ok {
		return true
	}
	for _, v := range providers {
		if pm := ctMap(v); pm != nil && strings.Contains(Str(pm, "base_url"), "localhost:20128") {
			return true
		}
	}
	return false
}

func ctJcodeReadEnv() map[string]string {
	out := map[string]string{}
	raw, err := os.ReadFile(ctJcodeEnvPath())
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		eq := strings.Index(trimmed, "=")
		if eq > 0 {
			key := strings.TrimSpace(trimmed[:eq])
			value := strings.TrimSpace(trimmed[eq+1:])
			if len(value) >= 2 && (value[0] == '"' && value[len(value)-1] == '"' || value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
			out[key] = value
		}
	}
	return out
}

func ctJcodeWriteEnv(env map[string]string) error {
	var sb strings.Builder
	sb.WriteString("# jcode provider environment variables\n")
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sb.WriteString(k + "=\"" + env[k] + "\"\n")
	}
	return os.WriteFile(ctJcodeEnvPath(), []byte(sb.String()), 0o644)
}

func ctJcodeGET(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		installed := ctLookPath("jcode") || ctFileExists(ctJcodeDir())
		if !installed {
			WriteJSON(w, 200, map[string]any{
				"installed": false,
				"message":   "jcode not installed. Install via: curl -fsSL https://raw.githubusercontent.com/1jehuang/jcode/master/scripts/install.sh | bash",
			})
			return
		}
		config := ctJcodeReadConfig()
		WriteJSON(w, 200, map[string]any{
			"installed": true, "config": config.toMap(), "hasProxyGo": ctJcodeHasProxyGo(config), "configPath": ctJcodePath(),
		})
	}
}

func ctJcodePOST(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ctBodyStrict(r)
		if err != nil {
			Err(w, 500, err.Error())
			return
		}
		baseUrl, apiKey := Str(body, "baseUrl"), Str(body, "apiKey")
		if baseUrl == "" || apiKey == "" {
			Err(w, 400, "baseUrl and apiKey are required")
			return
		}
		normalized := ctNormalizeV1(baseUrl)
		config := ctJcodeReadConfig()
		sec := config.section("providers.proxygo")
		defModel := "cc/claude-opus-4-7"
		if models := ctSlice(body["models"]); len(models) > 0 {
			if s, ok := models[0].(string); ok && s != "" {
				defModel = s
			}
		}
		sec.kvs = []tomlKV{
			{"type", "openai-compatible"},
			{"base_url", normalized},
			{"auth", "bearer"},
			{"api_key_env", "JCODE_PROXYGO_API_KEY"},
			{"env_file", "provider-proxygo.env"},
			{"default_model", defModel},
			{"requires_api_key", true},
		}
		if err := os.MkdirAll(ctJcodeDir(), 0o755); err != nil {
			Err(w, 500, err.Error())
			return
		}
		if err := os.WriteFile(ctJcodePath(), []byte(config.stringify()), 0o644); err != nil {
			Err(w, 500, err.Error())
			return
		}
		envPath := ctJcodeEnvPath()
		if err := os.MkdirAll(filepath.Dir(envPath), 0o755); err != nil {
			Err(w, 500, err.Error())
			return
		}
		env := ctJcodeReadEnv()
		env["JCODE_PROXYGO_API_KEY"] = apiKey
		if err := ctJcodeWriteEnv(env); err != nil {
			Err(w, 500, err.Error())
			return
		}
		WriteJSON(w, 200, map[string]any{
			"success": true, "message": "jcode configured successfully. Use: jcode --provider-profile proxygo", "configPath": ctJcodePath(),
		})
	}
}

func ctJcodeDELETE(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		config := ctJcodeReadConfig()
		m := config.toMap()
		if ctMap(m["providers"]) == nil {
			WriteJSON(w, 200, map[string]any{"success": true, "message": "No configuration to remove"})
			return
		}
		// delete config.providers["proxygo"] → section providers.proxygo
		out := config.sections[:0]
		for _, s := range config.sections {
			if s.name != "providers.proxygo" {
				out = append(out, s)
			}
		}
		config.sections = out
		if err := os.WriteFile(ctJcodePath(), []byte(config.stringify()), 0o644); err != nil {
			Err(w, 500, err.Error())
			return
		}
		env := ctJcodeReadEnv()
		delete(env, "JCODE_PROXYGO_API_KEY")
		if err := ctJcodeWriteEnv(env); err != nil {
			Err(w, 500, err.Error())
			return
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": "proxygo configuration removed from jcode"})
	}
}

// ---------- pi-settings (~/.pi/agent/models.json) ----------

func ctPiAgentPath() string { return filepath.Join(ctHome(), ".pi", "agent", "models.json") }
func ctPiRootPath() string  { return filepath.Join(ctHome(), ".pi", "models.json") }

func ctPiResolvePath() string {
	if ctFileExists(ctPiAgentPath()) {
		return ctPiAgentPath()
	}
	if ctFileExists(ctPiRootPath()) {
		return ctPiRootPath()
	}
	return ctPiAgentPath()
}

func ctPiHasProxyGo(settings map[string]any) bool {
	if settings == nil {
		return false
	}
	providers := ctMap(settings["providers"])
	if providers == nil {
		return false
	}
	if p := ctMap(providers["proxygo"]); p != nil && Str(p, "baseUrl") != "" {
		return true
	}
	for _, v := range providers {
		if pm := ctMap(v); pm != nil && strings.Contains(Str(pm, "baseUrl"), "20128") {
			return true
		}
	}
	return false
}

func ctPiGET(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		installed := ctLookPath("pi") || ctFileExists(ctPiAgentPath()) || ctFileExists(ctPiRootPath())
		if !installed {
			WriteJSON(w, 200, map[string]any{"installed": false, "config": nil, "message": "Pi CLI is not installed"})
			return
		}
		config := ctReadJSONObjTol(ctPiResolvePath())
		WriteJSON(w, 200, map[string]any{
			"installed": true, "config": config, "hasProxyGo": ctPiHasProxyGo(config), "configPath": ctPiResolvePath(),
		})
	}
}

// ctErrObjMsg writes pi/crush/forge-style {"error":{"message":...}} errors.
func ctPiPOST(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
		if err != nil {
			ctErrObj(w, 400, "Invalid JSON body")
			return
		}
		var body map[string]any
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &body); err != nil {
				ctErrObj(w, 400, "Invalid JSON body")
				return
			}
		}
		if body == nil {
			body = map[string]any{}
		}
		baseUrl := Str(body, "baseUrl")
		if baseUrl == "" {
			ctErrObj(w, 400, "baseUrl is required")
			return
		}
		configPath := ctPiResolvePath()
		if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
			ctErrObj(w, 500, err.Error())
			return
		}
		existing := map[string]any{}
		if rawCfg, err := os.ReadFile(configPath); err == nil {
			_ = json.Unmarshal(rawCfg, &existing)
			if existing == nil {
				existing = map[string]any{}
			}
		}
		providers := ctMap(existing["providers"])
		if providers == nil {
			providers = map[string]any{}
		}
		existing["providers"] = providers
		existingProvider := ctMap(providers["proxygo"])
		normalized := ctNormalizeV1(baseUrl)
		modelList := []any{}
		if models := ctSlice(body["models"]); len(models) > 0 {
			for _, m := range models {
				if s, ok := m.(string); ok {
					modelList = append(modelList, map[string]any{"id": s, "name": s, "contextWindow": 128000, "maxTokens": 16384})
				} else if mm := ctMap(m); mm != nil {
					id := Str(mm, "id")
					if id == "" {
						id = "provider/model-id"
					}
					name := Str(mm, "name")
					if name == "" {
						name = id
					}
					cw := mm["contextWindow"]
					if cw == nil {
						cw = 128000
					}
					mt := mm["maxTokens"]
					if mt == nil {
						mt = 16384
					}
					modelList = append(modelList, map[string]any{"id": id, "name": name, "contextWindow": cw, "maxTokens": mt})
				}
			}
		} else {
			modelID := Str(body, "model")
			if modelID == "" {
				modelID = "provider/model-id"
			}
			modelList = append(modelList, map[string]any{"id": modelID, "name": modelID, "contextWindow": 128000, "maxTokens": 16384})
		}
		api := "openai-completions"
		if existingProvider != nil && Str(existingProvider, "api") != "" {
			api = Str(existingProvider, "api")
		}
		newProv := map[string]any{}
		for k, v := range existingProvider {
			newProv[k] = v
		}
		newProv["baseUrl"] = normalized
		newProv["apiKey"] = resolveCliApiKey(deps, Str(body, "apiKey"))
		newProv["api"] = api
		newProv["models"] = modelList
		providers["proxygo"] = newProv
		if err := ctWriteJSON(configPath, existing); err != nil {
			ctErrObj(w, 500, err.Error())
			return
		}
		WriteJSON(w, 200, map[string]any{
			"success": true, "message": "Pi settings applied! Use /model in Pi to select the ProxyGo model.", "configPath": configPath,
		})
	}
}

func ctPiDELETE(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		configPath := ctPiResolvePath()
		raw, err := os.ReadFile(configPath)
		if err != nil {
			WriteJSON(w, 200, map[string]any{"success": true, "message": "No config file to reset"})
			return
		}
		var existing map[string]any
		if err := json.Unmarshal(raw, &existing); err != nil || existing == nil {
			WriteJSON(w, 200, map[string]any{"success": true, "message": "No config file to reset"})
			return
		}
		if providers := ctMap(existing["providers"]); providers != nil {
			if _, ok := providers["proxygo"]; ok {
				delete(providers, "proxygo")
				if len(providers) == 0 {
					delete(existing, "providers")
				}
				if err := ctWriteJSON(configPath, existing); err != nil {
					ctErrObj(w, 500, err.Error())
					return
				}
			}
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": "ProxyGo removed from Pi"})
	}
}

// ---------- generic {error:{message}} body helper (pi/crush/forge/smelt/codewhale/omp style) ----------

// ctBodyErrStyle parses the request JSON the way those routes do:
// invalid JSON → 400 {"error":{"message":"Invalid JSON body"}}.
func ctBodyErrStyle(w http.ResponseWriter, r *http.Request) (map[string]any, bool) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		ctErrObj(w, 400, "Invalid JSON body")
		return nil, false
	}
	var body map[string]any
	if len(strings.TrimSpace(string(raw))) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			ctErrObj(w, 400, "Invalid JSON body")
			return nil, false
		}
	}
	if body == nil {
		body = map[string]any{}
	}
	return body, true
}

// ---------- crush-settings (XDG_CONFIG_HOME/crush/crush.json) ----------

func ctCrushConfigPath() string {
	configDir := os.Getenv("XDG_CONFIG_HOME")
	if configDir == "" {
		configDir = filepath.Join(ctHome(), ".config")
	}
	return filepath.Join(configDir, "crush", "crush.json")
}

func ctCrushHasProxyGo(settings map[string]any) bool {
	if settings == nil {
		return false
	}
	providers := ctMap(settings["providers"])
	if providers == nil {
		return false
	}
	if p := ctMap(providers["proxygo"]); p != nil && Str(p, "base_url") != "" {
		return true
	}
	for _, v := range providers {
		if pm := ctMap(v); pm != nil && strings.Contains(Str(pm, "base_url"), "20128") {
			return true
		}
	}
	return false
}

func ctCrushGET(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		installed := ctLookPath("crush") || ctFileExists(ctCrushConfigPath())
		if !installed {
			WriteJSON(w, 200, map[string]any{"installed": false, "config": nil, "message": "Crush CLI is not installed"})
			return
		}
		config := ctReadJSONObjTol(ctCrushConfigPath())
		WriteJSON(w, 200, map[string]any{
			"installed": true, "config": config, "hasProxyGo": ctCrushHasProxyGo(config), "configPath": ctCrushConfigPath(),
		})
	}
}

func ctCrushPOST(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := ctBodyErrStyle(w, r)
		if !ok {
			return
		}
		baseUrl := Str(body, "baseUrl")
		if baseUrl == "" {
			ctErrObj(w, 400, "baseUrl is required")
			return
		}
		configPath := ctCrushConfigPath()
		if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
			ctErrObj(w, 500, err.Error())
			return
		}
		existing := map[string]any{}
		if raw, err := os.ReadFile(configPath); err == nil {
			_ = json.Unmarshal(raw, &existing)
			if existing == nil {
				existing = map[string]any{}
			}
		}
		providers := ctMap(existing["providers"])
		if providers == nil {
			providers = map[string]any{}
		}
		existing["providers"] = providers
		modelID := Str(body, "model")
		if modelID == "" {
			modelID = "provider/model-id"
		}
		providers["proxygo"] = map[string]any{
			"type": "openai-compat", "base_url": ctNormalizeV1(baseUrl),
			"api_key": resolveCliApiKey(deps, Str(body, "apiKey")),
			"models":  []any{map[string]any{"id": modelID, "name": modelID, "context_window": 128000}},
		}
		if err := ctWriteJSON(configPath, existing); err != nil {
			ctErrObj(w, 500, err.Error())
			return
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": "Crush settings applied successfully!", "configPath": configPath})
	}
}

func ctCrushDELETE(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		configPath := ctCrushConfigPath()
		raw, err := os.ReadFile(configPath)
		if err != nil {
			WriteJSON(w, 200, map[string]any{"success": true, "message": "No config file to reset"})
			return
		}
		var existing map[string]any
		if err := json.Unmarshal(raw, &existing); err != nil || existing == nil {
			WriteJSON(w, 200, map[string]any{"success": true, "message": "No config file to reset"})
			return
		}
		if providers := ctMap(existing["providers"]); providers != nil {
			if _, ok := providers["proxygo"]; ok {
				delete(providers, "proxygo")
				if len(providers) == 0 {
					delete(existing, "providers")
				}
				if err := ctWriteJSON(configPath, existing); err != nil {
					ctErrObj(w, 500, err.Error())
					return
				}
			}
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": "ProxyGo removed from Crush"})
	}
}

// ---------- deepseek-tui-settings (~/.deepseek/config.toml, text-level) ----------

func ctDeepseekDir() string  { return filepath.Join(ctHome(), ".deepseek") }
func ctDeepseekPath() string { return filepath.Join(ctDeepseekDir(), "config.toml") }

// ctDeepseekParseToml ports the route's own simple parser (quoted values
// keyed flat; sections kept under their literal dotted name).
func ctDeepseekParseToml(content string) map[string]any {
	result := map[string]any{}
	current := result
	keyRe := regexp.MustCompile(`^(\w+)\s*=\s*"([^"]*)"$`)
	unqRe := regexp.MustCompile(`^(\w+)\s*=\s*(.+)$`)
	secRe := regexp.MustCompile(`^\[([^\]]+)\]$`)
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if m := secRe.FindStringSubmatch(trimmed); m != nil {
			sec := map[string]any{}
			result[m[1]] = sec
			current = sec
			continue
		}
		if m := keyRe.FindStringSubmatch(trimmed); m != nil {
			current[m[1]] = m[2]
			continue
		}
		if m := unqRe.FindStringSubmatch(trimmed); m != nil {
			current[m[1]] = strings.TrimSpace(m[2])
		}
	}
	return result
}

func ctDeepseekHasProxyGo(config map[string]any) bool {
	if config == nil || config["provider"] != "openai" {
		return false
	}
	sec := ctMap(config["providers.openai"])
	if sec == nil || Str(sec, "base_url") == "" {
		return false
	}
	return regexp.MustCompile(`localhost|127\.0\.0\.1|0\.0\.0\.0`).MatchString(Str(sec, "base_url"))
}

func ctDeepseekGET(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		installed := ctLookPath("deepseek") || ctFileExists(ctDeepseekPath())
		if !installed {
			WriteJSON(w, 200, map[string]any{"installed": false, "settings": nil, "message": "DeepSeek TUI is not installed"})
			return
		}
		toml := ""
		if raw, err := os.ReadFile(ctDeepseekPath()); err == nil {
			toml = string(raw)
		}
		config := ctDeepseekParseToml(toml)
		WriteJSON(w, 200, map[string]any{
			"installed": true, "settings": config, "hasProxyGo": ctDeepseekHasProxyGo(config), "configPath": ctDeepseekPath(),
		})
	}
}

func ctDeepseekPOST(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ctBodyStrict(r)
		if err != nil {
			Err(w, 500, "Failed to update deepseek-tui settings")
			return
		}
		baseUrl, model := Str(body, "baseUrl"), Str(body, "model")
		if baseUrl == "" || model == "" {
			Err(w, 400, "baseUrl and model are required")
			return
		}
		if err := os.MkdirAll(ctDeepseekDir(), 0o755); err != nil {
			Err(w, 500, "Failed to update deepseek-tui settings")
			return
		}
		key := resolveCliApiKey(deps, Str(body, "apiKey"))
		content := "provider = \"openai\"\n\n[providers.openai]\nbase_url = \"" + ctNormalizeV1(baseUrl) + "\"\napi_key = \"" + key + "\"\nmodel = \"" + model + "\"\n"
		if err := os.WriteFile(ctDeepseekPath(), []byte(content), 0o644); err != nil {
			Err(w, 500, "Failed to update deepseek-tui settings")
			return
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": "DeepSeek TUI settings applied successfully!", "configPath": ctDeepseekPath()})
	}
}

func ctDeepseekDELETE(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !ctFileExists(ctDeepseekPath()) {
			WriteJSON(w, 200, map[string]any{"success": true, "message": "No config file to reset"})
			return
		}
		if err := os.WriteFile(ctDeepseekPath(), []byte("provider = \"deepseek\"\n"), 0o644); err != nil {
			Err(w, 500, "Failed to reset deepseek-tui settings")
			return
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": "proxygo config reset to DeepSeek defaults"})
	}
}

// ---------- omp-settings (~/.omp/agent/models.yml, text-level) ----------

func ctOmpDir() string        { return filepath.Join(ctHome(), ".omp", "agent") }
func ctOmpDbPath() string     { return filepath.Join(ctOmpDir(), "agent.db") }
func ctOmpModelsPath() string { return filepath.Join(ctOmpDir(), "models.yml") }

var ctOmpBlockRe = regexp.MustCompile(`(?s)\s*proxygo:.*?(?:\n\s*\w+:|\z)`)

func ctOmpRemoveBlock(content string) string {
	// JS: /\s*proxygo:[\s\S]*?(?=\n\s*\w+:|$)/g — emulate with a scanner:
	// find each "proxygo:" at a word position preceded by whitespace/newline,
	// cut until the next "\n<spaces><word>:" or EOF.
	for {
		idx := -1
		search := 0
		for search < len(content) {
			j := strings.Index(content[search:], "proxygo:")
			if j < 0 {
				break
			}
			pos := search + j
			// must be preceded by start, newline or spaces back to newline
			k := pos - 1
			for k >= 0 && (content[k] == ' ' || content[k] == '\t') {
				k--
			}
			if k < 0 || content[k] == '\n' {
				idx = pos
				break
			}
			search = pos + 1
		}
		if idx < 0 {
			return content
		}
		// start of removal includes preceding whitespace run (JS \s*).
		start := idx
		for start > 0 && (content[start-1] == ' ' || content[start-1] == '\t' || content[start-1] == '\n' || content[start-1] == '\r') {
			start--
		}
		// end: next \n\s*\w+: after idx
		end := len(content)
		rest := content[idx+len("proxygo:"):]
		re := regexp.MustCompile(`\n[ \t]*\w+:`)
		if loc := re.FindStringIndex(rest); loc != nil {
			end = idx + len("proxygo:") + loc[0]
		}
		content = content[:start] + content[end:]
	}
}

func ctOmpGET(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		installed := ctLookPath("omp") || ctFileExists(ctOmpDbPath()) || ctFileExists(ctOmpModelsPath())
		if !installed {
			WriteJSON(w, 200, map[string]any{"installed": false, "config": nil, "message": "Oh My Pi is not installed"})
			return
		}
		yml := ""
		if raw, err := os.ReadFile(ctOmpModelsPath()); err == nil {
			yml = string(raw)
		}
		hasProxyGo := yml != "" && (strings.Contains(yml, "proxygo:") || strings.Contains(yml, "localhost:20128"))
		WriteJSON(w, 200, map[string]any{"installed": true, "hasProxyGo": hasProxyGo, "configPath": ctOmpModelsPath()})
	}
}

func ctOmpBuildBlock(baseUrl, apiKey string) string {
	return "  proxygo:\n    baseUrl: " + ctNormalizeV1(baseUrl) + "\n    apiKey: " + apiKey + "\n    api: openai-completions\n    authHeader: true\n    disableStrictTools: true\n    discovery:\n      type: proxy"
}

func ctOmpPOST(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := ctBodyErrStyle(w, r)
		if !ok {
			return
		}
		baseUrl := Str(body, "baseUrl")
		if baseUrl == "" {
			ctErrObj(w, 400, "baseUrl is required")
			return
		}
		resolvedKey := resolveCliApiKey(deps, Str(body, "apiKey"))
		if err := os.MkdirAll(ctOmpDir(), 0o755); err != nil {
			ctErrObj(w, 500, err.Error())
			return
		}
		yml := ""
		if raw, err := os.ReadFile(ctOmpModelsPath()); err == nil {
			yml = string(raw)
		}
		block := ctOmpBuildBlock(baseUrl, resolvedKey)
		yml = ctOmpRemoveBlock(yml)
		switch {
		case strings.TrimSpace(yml) == "":
			yml = "providers:\n" + block + "\n"
		case strings.Contains(yml, "providers:"):
			yml = strings.Replace(yml, "providers:", "providers:\n"+block, 1)
		default:
			yml = strings.TrimSpace(yml) + "\n\nproviders:\n" + block + "\n"
		}
		if err := os.WriteFile(ctOmpModelsPath(), []byte(yml), 0o644); err != nil {
			ctErrObj(w, 500, err.Error())
			return
		}
		ctOmpUpdateDB(resolvedKey, baseUrl)
		WriteJSON(w, 200, map[string]any{
			"success":    true,
			"message":    "Oh My Pi settings applied! Run 'omp' and all ProxyGo models appear under proxygo in /model.",
			"configPath": ctOmpModelsPath(),
		})
	}
}

// ctOmpUpdateDB is the best-effort agent.db credential write (JS does it
// only when a sqlite driver is present; the Go build always has the
// modernc driver via internal/db, so it runs when agent.db exists).
func ctOmpUpdateDB(apiKey, baseUrl string) {
	dbPath := ctOmpDbPath()
	if !ctFileExists(dbPath) {
		return
	}
	sqlDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return
	}
	defer sqlDB.Close()
	now := time.Now().Unix()
	data, _ := json.Marshal(map[string]any{"apiKey": apiKey, "baseUrl": baseUrl})
	_, _ = sqlDB.Exec("DELETE FROM auth_credentials WHERE provider = ?", "proxygo")
	_, _ = sqlDB.Exec("INSERT INTO auth_credentials (provider, credential_type, data, disabled_cause, identity_key, created_at, updated_at) VALUES (?, ?, ?, NULL, NULL, ?, ?)",
		"proxygo", "api_key", string(data), now, now)
}

func ctOmpDELETE(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		yml := ""
		if raw, err := os.ReadFile(ctOmpModelsPath()); err == nil {
			yml = string(raw)
		}
		yml = ctOmpRemoveBlock(yml)
		if strings.TrimSpace(yml) == "providers:" {
			_ = os.Remove(ctOmpModelsPath())
		} else {
			if err := os.WriteFile(ctOmpModelsPath(), []byte(yml), 0o644); err != nil {
				ctErrObj(w, 500, err.Error())
				return
			}
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": "ProxyGo removed from Oh My Pi"})
	}
}

// ---------- forge / codewhale (header comment + TOML [openai]) ----------

func ctTomlToolGET(deps Deps, tool, display, cmd string, dirFn, pathFn func() string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		installed := ctLookPath(cmd) || ctFileExists(pathFn())
		if !installed {
			WriteJSON(w, 200, map[string]any{"installed": false, "config": nil, "message": display + " CLI is not installed"})
			return
		}
		var content string
		if raw, err := os.ReadFile(pathFn()); err == nil {
			content = string(raw)
		}
		var config any
		if content != "" {
			if doc, err := parseTOMLDoc(content); err == nil {
				config = doc.toMap()
			}
		}
		hasProxyGo := strings.Contains(content, "managed by ProxyGo") || strings.Contains(content, "localhost:20128")
		WriteJSON(w, 200, map[string]any{"installed": true, "config": config, "hasProxyGo": hasProxyGo, "configPath": pathFn()})
	}
}

func ctTomlToolPOST(deps Deps, header string, dirFn, pathFn func() string, withAPIKey bool, appliedMsg string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := ctBodyErrStyle(w, r)
		if !ok {
			return
		}
		baseUrl := Str(body, "baseUrl")
		if baseUrl == "" {
			ctErrObj(w, 400, "baseUrl is required")
			return
		}
		configPath := pathFn()
		if err := os.MkdirAll(dirFn(), 0o755); err != nil {
			ctErrObj(w, 500, err.Error())
			return
		}
		doc := &tomlDoc{}
		if raw, err := os.ReadFile(configPath); err == nil {
			if parsed, err := parseTOMLDoc(string(raw)); err == nil {
				doc = parsed
			}
		}
		key := resolveCliApiKey(deps, Str(body, "apiKey"))
		model := Str(body, "model")
		if model == "" {
			model = "provider/model-id"
		}
		sec := doc.section("openai")
		if withAPIKey { // forge: api_key first
			sec.kvs = []tomlKV{{"api_key", key}, {"base_url", ctNormalizeV1(baseUrl)}, {"model", model}}
		} else { // codewhale: base_url first
			sec.kvs = []tomlKV{{"base_url", ctNormalizeV1(baseUrl)}, {"api_key", key}, {"model", model}}
		}
		content := header + doc.stringify()
		if err := os.WriteFile(configPath, []byte(content), 0o644); err != nil {
			ctErrObj(w, 500, err.Error())
			return
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": appliedMsg, "configPath": configPath})
	}
}

func ctTomlToolDELETE(deps Deps, pathFn func() string, removedMsg string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		configPath := pathFn()
		raw, err := os.ReadFile(configPath)
		if err != nil {
			WriteJSON(w, 200, map[string]any{"success": true, "message": "No config file to reset"})
			return
		}
		doc, perr := parseTOMLDoc(string(raw))
		if perr != nil {
			WriteJSON(w, 200, map[string]any{"success": true, "message": "No config file to reset"})
			return
		}
		out := doc.sections[:0]
		for _, s := range doc.sections {
			if s.name != "openai" {
				out = append(out, s)
			}
		}
		doc.sections = out
		if len(doc.root) == 0 && len(doc.sections) == 0 {
			_ = os.Remove(configPath)
		} else {
			if err := os.WriteFile(configPath, []byte(doc.stringify()), 0o644); err != nil {
				ctErrObj(w, 500, err.Error())
				return
			}
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": removedMsg})
	}
}

func ctForgeGET(deps Deps) http.HandlerFunc {
	return ctTomlToolGET(deps, "forge", "ForgeCode", "forge", ctForgeDir, ctForgePath)
}
func ctForgePOST(deps Deps) http.HandlerFunc {
	return ctTomlToolPOST(deps, "# Forge config — managed by ProxyGo\n\n", ctForgeDir, ctForgePath, true, "ForgeCode settings applied successfully!")
}
func ctForgeDELETE(deps Deps) http.HandlerFunc {
	return ctTomlToolDELETE(deps, ctForgePath, "ProxyGo removed from ForgeCode")
}
func ctCodewhaleGET(deps Deps) http.HandlerFunc {
	return ctTomlToolGET(deps, "codewhale", "CodeWhale", "codewhale", ctCodewhaleDir, ctCodewhalePath)
}
func ctCodewhalePOST(deps Deps) http.HandlerFunc {
	return ctTomlToolPOST(deps, "# CodeWhale config — managed by ProxyGo\n\n", ctCodewhaleDir, ctCodewhalePath, false, "CodeWhale settings applied successfully!")
}
func ctCodewhaleDELETE(deps Deps) http.HandlerFunc {
	return ctTomlToolDELETE(deps, ctCodewhalePath, "ProxyGo removed from CodeWhale")
}

func ctForgeDir() string      { return filepath.Join(ctHome(), ".forge") }
func ctForgePath() string     { return filepath.Join(ctForgeDir(), "config.toml") }
func ctCodewhaleDir() string  { return filepath.Join(ctHome(), ".codewhale") }
func ctCodewhalePath() string { return filepath.Join(ctCodewhaleDir(), "config.toml") }
func ctSmeltPath() string     { return filepath.Join(ctHome(), ".smelt", "config.json") }

// ---------- smelt-settings (~/.smelt/config.json) ----------

func ctSmeltHasProxyGo(settings map[string]any) bool {
	if settings == nil {
		return false
	}
	if settings["_managedBy"] == "proxygo" {
		return true
	}
	base := Str(settings, "baseUrl")
	return base != "" && strings.Contains(base, "20128")
}

func ctSmeltGET(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		installed := ctLookPath("smelt") || ctFileExists(ctSmeltPath())
		if !installed {
			WriteJSON(w, 200, map[string]any{"installed": false, "config": nil, "message": "Smelt CLI is not installed"})
			return
		}
		config := ctReadJSONObjTol(ctSmeltPath())
		WriteJSON(w, 200, map[string]any{
			"installed": true, "config": config, "hasProxyGo": ctSmeltHasProxyGo(config), "configPath": ctSmeltPath(),
		})
	}
}

func ctSmeltPOST(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := ctBodyErrStyle(w, r)
		if !ok {
			return
		}
		baseUrl := Str(body, "baseUrl")
		if baseUrl == "" {
			ctErrObj(w, 400, "baseUrl is required")
			return
		}
		configPath := ctSmeltPath()
		if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
			ctErrObj(w, 500, err.Error())
			return
		}
		existing := map[string]any{}
		if raw, err := os.ReadFile(configPath); err == nil {
			_ = json.Unmarshal(raw, &existing)
			if existing == nil {
				existing = map[string]any{}
			}
		}
		model := Str(body, "model")
		if model == "" {
			model = Str(existing, "model")
		}
		if model == "" {
			model = "provider/model-id"
		}
		existing["baseUrl"] = ctNormalizeV1(baseUrl)
		existing["apiKey"] = resolveCliApiKey(deps, Str(body, "apiKey"))
		existing["model"] = model
		existing["_managedBy"] = "proxygo"
		if err := ctWriteJSON(configPath, existing); err != nil {
			ctErrObj(w, 500, err.Error())
			return
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": "Smelt settings applied successfully!", "configPath": configPath})
	}
}

func ctSmeltDELETE(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		configPath := ctSmeltPath()
		raw, err := os.ReadFile(configPath)
		if err != nil {
			WriteJSON(w, 200, map[string]any{"success": true, "message": "No config file to reset"})
			return
		}
		var existing map[string]any
		if err := json.Unmarshal(raw, &existing); err != nil || existing == nil {
			WriteJSON(w, 200, map[string]any{"success": true, "message": "No config file to reset"})
			return
		}
		delete(existing, "baseUrl")
		delete(existing, "apiKey")
		delete(existing, "model")
		delete(existing, "_managedBy")
		if len(existing) == 0 {
			_ = os.Remove(configPath)
		} else if err := ctWriteJSON(configPath, existing); err != nil {
			ctErrObj(w, 500, err.Error())
			return
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": "Smelt ProxyGo settings removed"})
	}
}

// ---------- devin-settings (detection only) ----------

func ctDevinCandidates() []string {
	home := ctHome()
	if ctIsWin {
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData == "" {
			localAppData = filepath.Join(home, "AppData", "Local")
		}
		return []string{
			filepath.Join(localAppData, "devin", "cli", "bin", "devin.exe"),
			filepath.Join(home, ".local", "bin", "devin.exe"),
			filepath.Join(home, "scoop", "shims", "devin.exe"),
			filepath.Join(localAppData, "Programs", "devin", "devin.exe"),
		}
	}
	return []string{
		filepath.Join(home, ".local", "share", "devin", "bin", "devin"),
		filepath.Join(home, ".devin", "bin", "devin"),
		filepath.Join(home, ".local", "bin", "devin"),
		"/opt/homebrew/bin/devin",
		"/usr/local/bin/devin",
		"/usr/bin/devin",
	}
}

func ctDevinGET(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		installed := false
		source := ""
		if ctLookPath("devin") {
			installed, source = true, "path"
		} else {
			for _, c := range ctDevinCandidates() {
				if ctFileExists(c) {
					installed, source = true, c
					break
				}
			}
		}
		if !installed {
			WriteJSON(w, 200, map[string]any{
				"installed":  false,
				"message":    "Devin CLI is not installed. Install it from https://cli.devin.ai and run `devin auth login`.",
				"installUrl": "https://cli.devin.ai",
			})
			return
		}
		var version any
		cmd := exec.Command("devin", "--version")
		if out, err := cmd.Output(); err == nil {
			first := strings.Split(strings.TrimSpace(string(out)), "\n")[0]
			if first != "" {
				version = first
			}
		}
		WriteJSON(w, 200, map[string]any{
			"installed": true, "source": source, "version": version,
			"message": "Devin CLI detected. Make sure `devin auth login` has been run.",
		})
	}
}

// ---------- grok-build-settings (~/.grok/config.toml; port of src/lib/grokBuildConfig.js) ----------

func ctGrokDir() string  { return filepath.Join(ctHome(), ".grok") }
func ctGrokPath() string { return filepath.Join(ctGrokDir(), "config.toml") }

var ctGrokSubagentTypes = []string{"general-purpose", "explore", "plan"}

const ctGrokMainSlot = "proxygo"
const ctGrokBuiltinDefault = "grok-build"
const ctGrokUnsetSentinel = "__proxygo_unset__"

// GrokContextWindow resolves a model's context window when the caller
// gives no explicit value. JS uses getCapabilitiesForModel (Team K's
// catalog): default capabilities carry contextWindow 200000. Parent may
// rebind this var to internal/modelcatalog for exact per-model values.
var GrokContextWindow = func(provider, modelID string) float64 { return 200000 }

func ctGrokSlotForType(t string) string { return ctGrokMainSlot + "-" + t }

// grokSectionSpan finds [section] and returns (headerStart, bodyStart,
// bodyEnd, found). Body runs until the next line starting with '[' —
// equivalent to the JS sectionRegExp (which uses a tempered lookahead).
func grokSectionSpan(toml, section string) (int, int, int, bool) {
	header := "[" + section + "]"
	idx := 0
	for idx <= len(toml) {
		lineEnd := strings.IndexByte(toml[idx:], '\n')
		var line string
		var next int
		if lineEnd < 0 {
			line = toml[idx:]
			next = len(toml) + 1
		} else {
			line = toml[idx : idx+lineEnd]
			next = idx + lineEnd + 1
		}
		trimmed := strings.TrimRight(line, " \t\r")
		if trimmed == header {
			bodyStart := next
			if bodyStart > len(toml) {
				bodyStart = len(toml)
			}
			bodyEnd := len(toml)
			scan := bodyStart
			for scan < len(toml) {
				le := strings.IndexByte(toml[scan:], '\n')
				var l string
				var nx int
				if le < 0 {
					l = toml[scan:]
					nx = len(toml) + 1
				} else {
					l = toml[scan : scan+le]
					nx = scan + le + 1
				}
				if strings.HasPrefix(strings.TrimRight(l, "\r"), "[") {
					bodyEnd = scan
					break
				}
				scan = nx
			}
			return idx, bodyStart, bodyEnd, true
		}
		if next > len(toml) {
			break
		}
		idx = next
	}
	return 0, 0, 0, false
}

func grokGetSectionField(toml, section, key string) (string, bool) {
	_, bs, be, found := grokSectionSpan(toml, section)
	if !found {
		return "", false
	}
	re := regexp.MustCompile(`(?m)^[ \t]*` + regexp.QuoteMeta(key) + `[ \t]*=[ \t]*"([^"]*)"`)
	m := re.FindStringSubmatch(toml[bs:be])
	if m == nil {
		return "", false
	}
	return m[1], true
}

func grokGetSectionNumber(toml, section, key string) (float64, bool) {
	_, bs, be, found := grokSectionSpan(toml, section)
	if !found {
		return 0, false
	}
	re := regexp.MustCompile(`(?m)^[ \t]*` + regexp.QuoteMeta(key) + `[ \t]*=[ \t]*([0-9]+(?:\.[0-9]+)?)`)
	m := re.FindStringSubmatch(toml[bs:be])
	if m == nil {
		return 0, false
	}
	n, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func grokTomlString(v string) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func grokSetSectionField(toml, section, key, value string) string {
	line := key + " = " + grokTomlString(value)
	hs, bs, be, found := grokSectionSpan(toml, section)
	if !found {
		prefix := toml
		if len(prefix) > 0 && !strings.HasSuffix(prefix, "\n") {
			prefix += "\n"
		}
		return prefix + "\n[" + section + "]\n" + line + "\n"
	}
	body := toml[bs:be]
	re := regexp.MustCompile(`(?m)^[ \t]*` + regexp.QuoteMeta(key) + `[ \t]*=[ \t]*"[^"]*"`)
	var nextBody string
	if re.MatchString(body) {
		nextBody = re.ReplaceAllString(body, line)
	} else {
		nextBody = line + "\n" + body
	}
	return toml[:hs] + "[" + section + "]\n" + nextBody + toml[be:]
}

func grokDeleteSectionField(toml, section, key string) string {
	hs, bs, be, found := grokSectionSpan(toml, section)
	if !found {
		return toml
	}
	body := toml[bs:be]
	re := regexp.MustCompile(`(?m)^[ \t]*` + regexp.QuoteMeta(key) + `[ \t]*=[^\r\n]*\r?\n?`)
	nextBody := re.ReplaceAllString(body, "")
	if strings.TrimSpace(nextBody) == "" {
		out := toml[:hs] + toml[be:]
		return regexp.MustCompile(`\n{3,}`).ReplaceAllString(out, "\n\n")
	}
	return toml[:hs] + "[" + section + "]\n" + nextBody + toml[be:]
}

func grokParseModelSection(toml, slot string) map[string]any {
	_, bs, be, found := grokSectionSpan(toml, "model."+slot)
	if !found {
		return nil
	}
	body := toml[bs:be]
	get := func(k string) any {
		if v, ok := grokGetSectionField(toml, "model."+slot, k); ok {
			return v
		}
		return nil
	}
	var cw any
	if n, ok := grokGetSectionNumber(toml, "model."+slot, "context_window"); ok && n > 0 {
		cw = n
	}
	return map[string]any{
		"model": get("model"), "base_url": get("base_url"), "name": get("name"),
		"api_key": get("api_key"), "api_backend": get("api_backend"),
		"context_window": cw, "raw": body,
	}
}

func grokBuildModelSection(slot, model, baseUrl, apiKey string, contextWindow float64, hasCW bool, name string) string {
	lines := []string{
		"[model." + slot + "]",
		"model = " + grokTomlString(model),
		"base_url = " + grokTomlString(baseUrl),
		"name = " + grokTomlString(name),
		"description = " + grokTomlString("Routed via ProxyGo gateway"),
		`api_backend = "chat_completions"`,
	}
	if apiKey != "" {
		lines = append(lines, "api_key = "+grokTomlString(apiKey))
	}
	if hasCW && contextWindow > 0 {
		lines = append(lines, "context_window = "+strconv.FormatInt(int64(contextWindow), 10))
	}
	return strings.Join(lines, "\n") + "\n"
}

func grokUpsertModelSection(toml, section string) string {
	slot := strings.TrimPrefix(section, "")
	_ = slot
	// extract slot name from first line "[model.<slot>]"
	first := strings.SplitN(section, "\n", 2)[0]
	name := strings.TrimSuffix(strings.TrimPrefix(first, "[model."), "]")
	hs, _, be, found := grokSectionSpan(toml, "model."+name)
	if found {
		return toml[:hs] + section + toml[be:]
	}
	prefix := toml
	if len(prefix) > 0 && !strings.HasSuffix(prefix, "\n") {
		prefix += "\n"
	}
	return prefix + "\n" + section
}

func grokRemoveModelSection(toml, slot string) string {
	hs, _, be, found := grokSectionSpan(toml, "model."+slot)
	if !found {
		return regexp.MustCompile(`\n{3,}`).ReplaceAllString(toml, "\n\n")
	}
	out := toml[:hs] + toml[be:]
	return regexp.MustCompile(`\n{3,}`).ReplaceAllString(out, "\n\n")
}

func grokInsertMarker(toml, marker string) string {
	hs, _, _, found := grokSectionSpan(toml, "model."+ctGrokMainSlot)
	if found {
		return toml[:hs] + marker + toml[hs:]
	}
	prefix := toml
	if len(prefix) > 0 && !strings.HasSuffix(prefix, "\n") {
		prefix += "\n"
	}
	return prefix + marker
}

var ctGrokPrevDefaultRe = regexp.MustCompile(`(?m)^# proxygo-prev-default = "([^"]*)"[ \t]*\r?\n?`)

func grokPrevSubagentRe(t string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^# proxygo-prev-subagent-` + regexp.QuoteMeta(t) + ` = "([^"]*)"[ \t]*\r?\n?`)
}

func grokRememberPreviousDefault(toml string) string {
	if ctGrokPrevDefaultRe.MatchString(toml) {
		return toml
	}
	current, ok := grokGetSectionField(toml, "models", "default")
	if !ok || current == "" || current == ctGrokMainSlot {
		return toml
	}
	return grokInsertMarker(toml, "# proxygo-prev-default = "+grokTomlString(current)+"\n")
}

func grokRestorePreviousDefault(toml string) string {
	previous := ctGrokBuiltinDefault
	if m := ctGrokPrevDefaultRe.FindStringSubmatch(toml); m != nil {
		previous = m[1]
	}
	next := ctGrokPrevDefaultRe.ReplaceAllString(toml, "")
	if cur, ok := grokGetSectionField(next, "models", "default"); ok && cur == ctGrokMainSlot {
		next = grokSetSectionField(next, "models", "default", previous)
	}
	return next
}

func grokRememberPreviousSubagent(toml, t string) string {
	re := grokPrevSubagentRe(t)
	if re.MatchString(toml) {
		return toml
	}
	previous := ctGrokUnsetSentinel
	if cur, ok := grokGetSectionField(toml, "subagents.models", t); ok {
		previous = cur
	}
	return grokInsertMarker(toml, "# proxygo-prev-subagent-"+t+" = "+grokTomlString(previous)+"\n")
}

func grokRestorePreviousSubagent(toml, t string) string {
	re := grokPrevSubagentRe(t)
	previous := ctGrokUnsetSentinel
	if m := re.FindStringSubmatch(toml); m != nil {
		previous = m[1]
	}
	next := re.ReplaceAllString(toml, "")
	if cur, _ := grokGetSectionField(next, "subagents.models", t); cur != ctGrokSlotForType(t) {
		return next
	}
	if previous == ctGrokUnsetSentinel {
		return grokDeleteSectionField(next, "subagents.models", t)
	}
	return grokSetSectionField(next, "subagents.models", t, previous)
}

func grokParseConfig(toml string) map[string]any {
	subModels := map[string]any{}
	subMappings := map[string]any{}
	for _, t := range ctGrokSubagentTypes {
		mapping, _ := grokGetSectionField(toml, "subagents.models", t)
		var mappingVal any
		if mapping != "" {
			mappingVal = mapping
		}
		subMappings[t] = mappingVal
		if mapping == ctGrokSlotForType(t) {
			subModels[t] = grokParseModelSection(toml, mapping)
		} else {
			subModels[t] = nil
		}
	}
	var def any
	if d, ok := grokGetSectionField(toml, "models", "default"); ok {
		def = d
	}
	return map[string]any{
		"model":            grokParseModelSection(toml, ctGrokMainSlot),
		"default":          def,
		"subagentModels":   subModels,
		"subagentMappings": subMappings,
	}
}

type ctGrokSubSel struct {
	Model         string
	ContextWindow float64
	HasCW         bool
}

func grokApplyConfig(toml string, baseUrl, apiKey, model string, contextWindow float64, hasCW bool, subagents map[string]ctGrokSubSel, hasSubagents bool) string {
	next := grokRememberPreviousDefault(toml)
	next = grokUpsertModelSection(next, grokBuildModelSection(ctGrokMainSlot, model, baseUrl, apiKey, contextWindow, hasCW, "ProxyGo"))
	next = grokSetSectionField(next, "models", "default", ctGrokMainSlot)
	if hasSubagents {
		for _, t := range ctGrokSubagentTypes {
			sel, ok := subagents[t]
			slot := ctGrokSlotForType(t)
			if ok && sel.Model != "" {
				next = grokRememberPreviousSubagent(next, t)
				next = grokUpsertModelSection(next, grokBuildModelSection(slot, sel.Model, baseUrl, apiKey, sel.ContextWindow, sel.HasCW, "ProxyGo "+t))
				next = grokSetSectionField(next, "subagents.models", t, slot)
			} else {
				next = grokRestorePreviousSubagent(next, t)
				next = grokRemoveModelSection(next, slot)
			}
		}
	}
	return next
}

func grokResetConfig(toml string) string {
	next := toml
	for _, t := range ctGrokSubagentTypes {
		next = grokRestorePreviousSubagent(next, t)
		next = grokRemoveModelSection(next, ctGrokSlotForType(t))
	}
	next = grokRemoveModelSection(next, ctGrokMainSlot)
	next = grokRestorePreviousDefault(next)
	return regexp.MustCompile(`\n{3,}`).ReplaceAllString(next, "\n\n")
}

func ctGrokNormalizeCW(value any, model string) float64 {
	if f, ok := value.(float64); ok && f > 0 {
		return float64(int64(f))
	}
	provider := ""
	modelID := model
	if slash := strings.Index(model, "/"); slash > 0 {
		provider = model[:slash]
		modelID = model[slash+1:]
	}
	return GrokContextWindow(provider, modelID)
}

func ctGrokGET(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		installed := ctLookPath("grok") || ctFileExists(filepath.Join(ctGrokDir(), "bin", "grok")) || ctFileExists(ctGrokPath())
		if !installed {
			WriteJSON(w, 200, map[string]any{"installed": false, "settings": nil, "message": "Grok Build is not installed"})
			return
		}
		toml := ""
		if raw, err := os.ReadFile(ctGrokPath()); err == nil {
			toml = string(raw)
		}
		settings := grokParseConfig(toml)
		hasProxyGo := false
		if m := ctMap(settings["model"]); m != nil && Str(m, "base_url") != "" {
			hasProxyGo = true
		}
		WriteJSON(w, 200, map[string]any{
			"installed": true, "settings": settings, "hasProxyGo": hasProxyGo, "configPath": ctGrokPath(),
		})
	}
}

func ctGrokPOST(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ctBodyStrict(r)
		if err != nil {
			Err(w, 500, "Failed to update grok-build settings")
			return
		}
		baseUrl := Str(body, "baseUrl")
		selectedModel := strings.TrimSpace(Str(body, "model"))
		if baseUrl == "" || selectedModel == "" {
			Err(w, 400, "baseUrl and model are required")
			return
		}
		if err := os.MkdirAll(ctGrokDir(), 0o755); err != nil {
			Err(w, 500, "Failed to update grok-build settings")
			return
		}
		toml := ""
		if raw, err := os.ReadFile(ctGrokPath()); err == nil {
			toml = string(raw)
		}
		// normalizeSubagentModels: undefined → untouched; non-object → {}.
		hasSub := false
		subSels := map[string]ctGrokSubSel{}
		if rawSub, present := body["subagentModels"]; present {
			hasSub = true
			if subMap := ctMap(rawSub); subMap != nil {
				for _, t := range ctGrokSubagentTypes {
					entry := subMap[t]
					var model string
					var cwVal any
					switch e := entry.(type) {
					case string:
						model = strings.TrimSpace(e)
					case map[string]any:
						model = strings.TrimSpace(Str(e, "model"))
						cwVal = e["contextWindow"]
					}
					if model == "" {
						continue
					}
					subSels[t] = ctGrokSubSel{Model: model, ContextWindow: ctGrokNormalizeCW(cwVal, model), HasCW: true}
				}
			}
		}
		cw := ctGrokNormalizeCW(body["contextWindow"], selectedModel)
		out := grokApplyConfig(toml, ctNormalizeV1(baseUrl), resolveCliApiKey(deps, Str(body, "apiKey")), selectedModel, cw, true, subSels, hasSub)
		if err := os.WriteFile(ctGrokPath(), []byte(out), 0o644); err != nil {
			Err(w, 500, "Failed to update grok-build settings")
			return
		}
		WriteJSON(w, 200, map[string]any{
			"success": true, "message": "Grok Build settings applied successfully!",
			"configPath": ctGrokPath(), "modelSlot": "proxygo",
		})
	}
}

func ctGrokDELETE(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, err := os.ReadFile(ctGrokPath())
		if err != nil {
			if os.IsNotExist(err) {
				WriteJSON(w, 200, map[string]any{"success": true, "message": "No config file to reset"})
				return
			}
			Err(w, 500, "Failed to reset grok-build settings")
			return
		}
		if err := os.WriteFile(ctGrokPath(), []byte(grokResetConfig(string(raw))), 0o644); err != nil {
			Err(w, 500, "Failed to reset grok-build settings")
			return
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": "proxygo model slots removed from Grok Build"})
	}
}

// ---------- hermes (port of hermesYaml.js + hermesProfiles.js) ----------

var (
	hermesModelBlockRe   = regexp.MustCompile(`(?m)^model:[ \t]*\r?\n((?:[ \t]+.*\r?\n?|[ \t]*\r?\n)*)`)
	hermesModelScalarRe  = regexp.MustCompile(`(?m)^model:[ \t]*[^\r\n]*\r?\n?`)
	hermesDelegationRe   = regexp.MustCompile(`(?m)^delegation:[ \t]*\r?\n((?:[ \t]+.*\r?\n?|[ \t]*\r?\n)*)`)
	hermesAuxBlockRe     = regexp.MustCompile(`(?m)^auxiliary:[ \t]*\r?\n((?:(?:[ \t]+.*\r?\n?)|(?:[ \t]*\r?\n))*)`)
	hermesSttBlockRe     = regexp.MustCompile(`(?m)^stt:[ \t]*\r?\n((?:[ \t]+.*\r?\n?|[ \t]*\r?\n)*)`)
	hermesAuxSubRe       = regexp.MustCompile(`(?m)^  ([A-Za-z0-9_]+):[ \t]*\r?\n((?:(?:[ \t]{4,}.*\r?\n?)|(?:[ \t]*\r?\n))*)`)
	hermesLeadingBlankRe = regexp.MustCompile(`^\n+`)
)

func hermesAuxRoleRe(role string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^  ` + regexp.QuoteMeta(role) + `:[ \t]*\r?\n(?:(?:[ \t]{4,}.*\r?\n?)|(?:[ \t]*\r?\n))*`)
}

func hermesBuildModelBlock(model, baseUrl string) string {
	return "model:\n  default: \"" + model + "\"\n  provider: \"custom\"\n  base_url: \"" + baseUrl + "\"\n  api_key: ${OPENAI_API_KEY}\n"
}
func hermesBuildDelegationBlock(model, baseUrl string) string {
	return "delegation:\n  model: \"" + model + "\"\n  provider: \"custom\"\n  base_url: \"" + baseUrl + "\"\n  api_key: ${OPENAI_API_KEY}\n"
}
func hermesBuildAuxRoleBlock(role, model, baseUrl string) string {
	return "  " + role + ":\n    provider: \"custom\"\n    model: \"" + model + "\"\n    base_url: \"" + baseUrl + "\"\n    api_key: ${OPENAI_API_KEY}\n"
}

func hermesKVGetter(body string) func(string) any {
	return func(key string) any {
		re := regexp.MustCompile(`(?m)^[ \t]+` + regexp.QuoteMeta(key) + `:[ \t]*["']?([^"'\r\n]+)["']?`)
		m := re.FindStringSubmatch(body)
		if m == nil {
			return nil
		}
		return strings.TrimSpace(m[1])
	}
}

func hermesParseModelBlock(yaml string) map[string]any {
	m := hermesModelBlockRe.FindStringSubmatch(yaml)
	if m == nil {
		return nil
	}
	get := hermesKVGetter(m[1])
	return map[string]any{"default": get("default"), "provider": get("provider"), "base_url": get("base_url"), "api_key": get("api_key")}
}

func hermesParseDelegationBlock(yaml string) map[string]any {
	m := hermesDelegationRe.FindStringSubmatch(yaml)
	if m == nil {
		return nil
	}
	get := hermesKVGetter(m[1])
	return map[string]any{"model": get("model"), "provider": get("provider"), "base_url": get("base_url")}
}

func hermesParseAuxRoles(yaml string) map[string]any {
	roles := map[string]any{}
	m := hermesAuxBlockRe.FindStringSubmatch(yaml)
	if m == nil {
		return roles
	}
	for _, sm := range hermesAuxSubRe.FindAllStringSubmatch(m[1], -1) {
		get := hermesKVGetter(sm[2])
		roles[sm[1]] = map[string]any{"model": get("model"), "provider": get("provider"), "base_url": get("base_url")}
	}
	return roles
}

func hermesUpsertModelBlock(yaml, newBlock string) string {
	if hermesModelBlockRe.MatchString(yaml) {
		return hermesModelBlockRe.ReplaceAllString(yaml, newBlock)
	}
	if hermesModelScalarRe.MatchString(yaml) {
		return hermesModelScalarRe.ReplaceAllString(yaml, newBlock)
	}
	if len(yaml) > 0 {
		return newBlock + "\n" + yaml
	}
	return newBlock
}

func hermesUpsertDelegationBlock(yaml, newBlock string) string {
	if hermesDelegationRe.MatchString(yaml) {
		return hermesDelegationRe.ReplaceAllString(yaml, newBlock)
	}
	if strings.HasSuffix(yaml, "\n") || yaml == "" {
		return yaml + newBlock
	}
	return yaml + "\n" + newBlock
}

func hermesRemoveDelegationBlock(yaml string) string {
	return hermesDelegationRe.ReplaceAllString(yaml, "")
}

func hermesUpsertAuxRole(yaml, role, roleBlock string) string {
	m := hermesAuxBlockRe.FindStringSubmatchIndex(yaml)
	if m == nil {
		block := "auxiliary:\n" + roleBlock
		if strings.HasSuffix(yaml, "\n") || yaml == "" {
			return yaml + block
		}
		return yaml + "\n" + block
	}
	body := yaml[m[2]:m[3]]
	re := hermesAuxRoleRe(role)
	var newBody string
	if re.MatchString(body) {
		newBody = re.ReplaceAllString(body, roleBlock)
	} else {
		newBody = body + roleBlock
	}
	return yaml[:m[0]] + "auxiliary:\n" + newBody + yaml[m[1]:]
}

func hermesRemoveAuxRole(yaml, role string) string {
	m := hermesAuxBlockRe.FindStringSubmatchIndex(yaml)
	if m == nil {
		return yaml
	}
	body := yaml[m[2]:m[3]]
	newBody := hermesAuxRoleRe(role).ReplaceAllString(body, "")
	if strings.TrimSpace(newBody) == "" {
		return yaml[:m[0]] + yaml[m[1]:]
	}
	return yaml[:m[0]] + "auxiliary:\n" + newBody + yaml[m[1]:]
}

func hermesRemoveModelBlock(yaml string) string {
	if hermesModelBlockRe.MatchString(yaml) {
		return hermesLeadingBlankRe.ReplaceAllString(hermesModelBlockRe.ReplaceAllString(yaml, ""), "")
	}
	if hermesModelScalarRe.MatchString(yaml) {
		return hermesLeadingBlankRe.ReplaceAllString(hermesModelScalarRe.ReplaceAllString(yaml, ""), "")
	}
	return yaml
}

func hermesUpsertEnvVar(envText, key, value string) string {
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(key) + `=.*$`)
	line := key + "=" + value
	if re.MatchString(envText) {
		return re.ReplaceAllString(envText, line)
	}
	if len(envText) > 0 && !strings.HasSuffix(envText, "\n") {
		return envText + "\n" + line + "\n"
	}
	return envText + line + "\n"
}

func hermesHasProxyGo(cfg map[string]any) bool {
	if cfg == nil || Str(cfg, "base_url") == "" {
		return false
	}
	return cfg["provider"] == "custom" && regexp.MustCompile(`localhost|127\.0\.0\.1|0\.0\.0\.0`).MatchString(Str(cfg, "base_url"))
}

func hermesIsCustom(cfg map[string]any) bool {
	return cfg != nil && cfg["provider"] == "custom"
}

const hermesSttAPIKeyRef = "${OPENAI_API_KEY}"

func hermesSttSubRe(name string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^  ` + regexp.QuoteMeta(name) + `:[ \t]*\r?\n((?:(?:[ \t]{4,}.*\r?\n?)|(?:[ \t]*\r?\n))*)`)
}

func hermesStripYamlQuotes(v string) string {
	v = strings.TrimLeft(v, " \t")
	v = strings.TrimRight(v, " \t")
	if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
		v = v[1 : len(v)-1]
	}
	return strings.TrimSpace(v)
}

func hermesParseSttBlock(yaml string) map[string]any {
	m := hermesSttBlockRe.FindStringSubmatch(yaml)
	if m == nil {
		return nil
	}
	direct := map[string]any{}
	openai := map[string]any{}
	current := ""
	for _, line := range strings.Split(m[1], "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.HasPrefix(line, "  ") && len(line) > 2 && line[2] != ' ' && line[2] != '\t' {
			kv := regexp.MustCompile(`^  ([A-Za-z0-9_]+):[ \t]*(.*)$`).FindStringSubmatch(line)
			current = ""
			if kv != nil {
				if kv[2] != "" {
					direct[kv[1]] = hermesStripYamlQuotes(kv[2])
				} else {
					current = kv[1]
				}
			}
		} else if current == "openai" && regexp.MustCompile(`^ {4,}\S`).MatchString(line) {
			kv := regexp.MustCompile(`^ {4,}([A-Za-z0-9_]+):[ \t]*(.*)$`).FindStringSubmatch(line)
			if kv != nil && kv[2] != "" {
				openai[kv[1]] = hermesStripYamlQuotes(kv[2])
			}
		}
	}
	get := func(m map[string]any, k string) any {
		if v, ok := m[k]; ok {
			return v
		}
		return nil
	}
	return map[string]any{
		"enabled": get(direct, "enabled"), "provider": get(direct, "provider"),
		"model": get(openai, "model"), "base_url": get(openai, "base_url"), "api_key": get(openai, "api_key"),
	}
}

func hermesIsProxyGoStt(cfg map[string]any) bool {
	return cfg != nil && cfg["provider"] == "openai" && Str(cfg, "base_url") != "" && cfg["api_key"] == hermesSttAPIKeyRef
}

func hermesBuildSttBlock(model, baseUrl string) string {
	return "stt:\n  enabled: true\n  provider: \"openai\"\n  openai:\n    model: \"" + model + "\"\n    base_url: \"" + baseUrl + "\"\n    api_key: " + hermesSttAPIKeyRef + "\n"
}

func hermesUpsertSttDirect(body, key, value string) string {
	re := regexp.MustCompile(`(?m)^  ` + regexp.QuoteMeta(key) + `:[^\r\n]*`)
	if re.MatchString(body) {
		return re.ReplaceAllString(body, "  "+key+": "+value)
	}
	head := "  " + key + ": " + value + "\n"
	if len(body) > 0 && !strings.HasSuffix(body, "\n") {
		return body + "\n" + head
	}
	return body + head
}

func hermesUpsertSttOpenai(body, key, value string) string {
	subRe := hermesSttSubRe("openai")
	loc := subRe.FindStringSubmatchIndex(body)
	if loc == nil {
		block := "  openai:\n    " + key + ": " + value + "\n"
		if len(body) > 0 && !strings.HasSuffix(body, "\n") {
			return body + "\n" + block
		}
		return body + block
	}
	subBody := body[loc[2]:loc[3]]
	re := regexp.MustCompile(`(?m)^ {4}` + regexp.QuoteMeta(key) + `:[^\r\n]*`)
	var newSub string
	if re.MatchString(subBody) {
		newSub = re.ReplaceAllString(subBody, "    "+key+": "+value)
	} else if strings.HasSuffix(subBody, "\n") || subBody == "" {
		newSub = subBody + "    " + key + ": " + value + "\n"
	} else {
		newSub = subBody + "\n    " + key + ": " + value + "\n"
	}
	return body[:loc[0]] + "  openai:\n" + newSub + body[loc[1]:]
}

func hermesUpsertSttProxyGo(yaml, model, baseUrl string) string {
	m := hermesSttBlockRe.FindStringSubmatchIndex(yaml)
	if m == nil {
		prefix := yaml
		if prefix != "" && !strings.HasSuffix(prefix, "\n") {
			prefix += "\n"
		}
		return prefix + hermesBuildSttBlock(model, baseUrl)
	}
	body := yaml[m[2]:m[3]]
	body = hermesUpsertSttDirect(body, "enabled", "true")
	body = hermesUpsertSttDirect(body, "provider", "\"openai\"")
	body = hermesUpsertSttOpenai(body, "model", "\""+model+"\"")
	body = hermesUpsertSttOpenai(body, "base_url", "\""+baseUrl+"\"")
	body = hermesUpsertSttOpenai(body, "api_key", hermesSttAPIKeyRef)
	return yaml[:m[0]] + "stt:\n" + body + yaml[m[1]:]
}

func hermesRemoveSttProxyGo(yaml string) string {
	m := hermesSttBlockRe.FindStringSubmatchIndex(yaml)
	if m == nil {
		return yaml
	}
	body := yaml[m[2]:m[3]]
	body = regexp.MustCompile(`(?m)^  enabled:[ \t]*["']?true["']?[ \t]*\r?\n?`).ReplaceAllString(body, "")
	body = regexp.MustCompile(`(?m)^  provider:[ \t]*["']?openai["']?[ \t]*\r?\n?`).ReplaceAllString(body, "")
	subRe := hermesSttSubRe("openai")
	if loc := subRe.FindStringSubmatchIndex(body); loc != nil {
		subBody := body[loc[2]:loc[3]]
		for _, key := range []string{"model", "base_url", "api_key"} {
			subBody = regexp.MustCompile(`(?m)^ {4}`+key+`:[^\r\n]*\r?\n?`).ReplaceAllString(subBody, "")
		}
		if strings.TrimSpace(subBody) == "" {
			body = body[:loc[0]] + body[loc[1]:]
		} else {
			body = body[:loc[0]] + "  openai:\n" + subBody + body[loc[1]:]
		}
	}
	if strings.TrimSpace(body) == "" {
		return hermesLeadingBlankRe.ReplaceAllString(yaml[:m[0]]+yaml[m[1]:], "")
	}
	return yaml[:m[0]] + "stt:\n" + body + yaml[m[1]:]
}

// ----- hermesProfiles -----

var hermesProfileNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

var hermesIdentityFiles = []string{"config.yaml", ".env", "SOUL.md", "profile.yaml", "auth.json", "state.db"}

func hermesRoot() string { return filepath.Join(ctHome(), ".hermes") }

type hermesHome struct {
	Name       string
	Dir        string
	ConfigPath string
	EnvPath    string
	IsDefault  bool
}

func hermesValidProfileName(name string) bool {
	return hermesProfileNameRe.MatchString(name) && strings.ToLower(name) != "default"
}

func hermesResolveHome(profile string) (hermesHome, error) {
	base := hermesRoot()
	name := strings.TrimSpace(profile)
	if name == "" || name == "default" {
		return hermesHome{Name: "default", Dir: base, ConfigPath: filepath.Join(base, "config.yaml"), EnvPath: filepath.Join(base, ".env"), IsDefault: true}, nil
	}
	if !hermesValidProfileName(name) {
		return hermesHome{}, fmt.Errorf("Invalid Hermes profile name (letters, digits, - and _ only, max 64 chars)")
	}
	profilesRoot, _ := filepath.Abs(filepath.Join(base, "profiles"))
	dir, _ := filepath.Abs(filepath.Join(profilesRoot, name))
	if dir != profilesRoot && !strings.HasPrefix(dir, profilesRoot+string(filepath.Separator)) {
		return hermesHome{}, fmt.Errorf("Invalid Hermes profile path")
	}
	return hermesHome{Name: name, Dir: dir, ConfigPath: filepath.Join(dir, "config.yaml"), EnvPath: filepath.Join(dir, ".env"), IsDefault: false}, nil
}

func hermesDirExists(dir string) bool {
	st, err := os.Stat(dir)
	return err == nil && st.IsDir()
}

func hermesIsProfileHome(dir string) bool {
	for _, f := range hermesIdentityFiles {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			return true
		}
	}
	return false
}

func hermesReadText(p string) (string, error) {
	raw, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return string(raw), nil
}

func hermesParseDisplayName(yaml string) any {
	m := regexp.MustCompile(`(?m)^display_name:[ \t]*["']?([^"'\r\n]+)["']?`).FindStringSubmatch(yaml)
	if m == nil {
		return nil
	}
	return strings.TrimSpace(m[1])
}

func hermesBuildEntry(name, dir string, isDefault bool) map[string]any {
	yaml, _ := hermesReadText(filepath.Join(dir, "config.yaml"))
	model := hermesParseModelBlock(yaml)
	delegation := hermesParseDelegationBlock(yaml)
	auxiliary := hermesParseAuxRoles(yaml)
	profileYaml, _ := hermesReadText(filepath.Join(dir, "profile.yaml"))
	hasProxyGo := hermesHasProxyGo(model) || hermesHasProxyGo(delegation)
	if !hasProxyGo {
		for _, v := range auxiliary {
			if hermesHasProxyGo(ctMap(v)) {
				hasProxyGo = true
				break
			}
		}
	}
	var modelName, baseUrl any
	if model != nil {
		modelName = model["default"]
		baseUrl = model["base_url"]
	}
	command := "hermes"
	var alias any
	if !isDefault {
		command = "hermes -p " + name
		alias = name
	}
	return map[string]any{
		"name": name, "dir": dir, "isDefault": isDefault,
		"displayName": hermesParseDisplayName(profileYaml),
		"command":     command, "alias": alias,
		"model": modelName, "baseUrl": baseUrl, "hasProxyGo": hasProxyGo,
	}
}

func hermesListProfiles() ([]any, error) {
	base := hermesRoot()
	entries := []any{hermesBuildEntry("default", base, true)}
	dirents, err := os.ReadDir(filepath.Join(base, "profiles"))
	if err != nil {
		if os.IsNotExist(err) {
			return entries, nil
		}
		return nil, err
	}
	names := []string{}
	for _, d := range dirents {
		if d.IsDir() && hermesValidProfileName(d.Name()) {
			names = append(names, d.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		dir := filepath.Join(base, "profiles", name)
		if !hermesIsProfileHome(dir) {
			continue
		}
		entries = append(entries, hermesBuildEntry(name, dir, false))
	}
	return entries, nil
}

func ctHermesProfilesGET(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		profiles, err := hermesListProfiles()
		if err != nil {
			Err(w, 500, "Failed to list hermes profiles")
			return
		}
		WriteJSON(w, 200, map[string]any{"profiles": profiles})
	}
}

// ----- hermes-settings route -----

func ctHermesInstalled() bool {
	if ctLookPath("hermes") {
		return true
	}
	home, err := hermesResolveHome("")
	return err == nil && ctFileExists(home.ConfigPath)
}

func hermesReadConfigYaml(home hermesHome) (string, error) { return hermesReadText(home.ConfigPath) }

func hermesWriteHomeConfig(home hermesHome, yaml string) error {
	if home.IsDefault {
		if err := os.MkdirAll(home.Dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(home.ConfigPath, []byte(yaml), 0o644)
}

func hermesWriteHomeEnv(home hermesHome, apiKey string) error {
	if apiKey == "" {
		return nil
	}
	if home.IsDefault {
		if err := os.MkdirAll(home.Dir, 0o755); err != nil {
			return err
		}
	}
	envText, err := hermesReadText(home.EnvPath)
	if err != nil {
		return err
	}
	return os.WriteFile(home.EnvPath, []byte(hermesUpsertEnvVar(envText, "OPENAI_API_KEY", apiKey)), 0o644)
}

func ctHermesTruthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true" || t == "1"
	}
	return false
}

func ctHermesGET(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !ctHermesInstalled() {
			WriteJSON(w, 200, map[string]any{"installed": false, "settings": nil, "message": "Hermes Agent is not installed"})
			return
		}
		home, err := hermesResolveHome(r.URL.Query().Get("profile"))
		if err != nil {
			Err(w, 400, err.Error())
			return
		}
		if !home.IsDefault && !hermesDirExists(home.Dir) {
			Err(w, 404, "Hermes profile \""+home.Name+"\" not found")
			return
		}
		yaml, err := hermesReadConfigYaml(home)
		if err != nil {
			Err(w, 500, "Failed to check hermes settings")
			return
		}
		model := hermesParseModelBlock(yaml)
		delegation := hermesParseDelegationBlock(yaml)
		auxiliary := hermesParseAuxRoles(yaml)
		stt := hermesParseSttBlock(yaml)
		hasProxyGo := hermesHasProxyGo(model) || hermesHasProxyGo(delegation)
		if !hasProxyGo {
			for _, v := range auxiliary {
				if hermesHasProxyGo(ctMap(v)) {
					hasProxyGo = true
					break
				}
			}
		}
		WriteJSON(w, 200, map[string]any{
			"installed":  true,
			"profile":    map[string]any{"name": home.Name, "dir": home.Dir, "isDefault": home.IsDefault},
			"settings":   map[string]any{"model": model, "delegation": delegation, "auxiliary": auxiliary, "stt": stt},
			"hasProxyGo": hasProxyGo, "hasProxyGoStt": hermesIsProxyGoStt(stt),
			"configPath": home.ConfigPath,
		})
	}
}

func ctHermesApplyToAll(deps Deps, w http.ResponseWriter, normalizedBaseUrl, apiKey string, model any) {
	profiles, err := hermesListProfiles()
	if err != nil {
		Err(w, 500, "Failed to update hermes settings")
		return
	}
	results := []any{}
	for _, p := range profiles {
		pm := ctMap(p)
		name := Str(pm, "name")
		home, herr := hermesResolveHome(name)
		if herr != nil {
			results = append(results, map[string]any{"profile": name, "status": "failed", "reason": herr.Error()})
			continue
		}
		func() {
			yaml, err := hermesReadConfigYaml(home)
			if err != nil {
				results = append(results, map[string]any{"profile": name, "status": "failed", "reason": err.Error()})
				return
			}
			main := hermesParseModelBlock(yaml)
			switch {
			case main != nil && Str(main, "default") != "" && hermesIsCustom(main):
				yaml = hermesUpsertModelBlock(yaml, hermesBuildModelBlock(Str(main, "default"), normalizedBaseUrl))
				if delegation := hermesParseDelegationBlock(yaml); delegation != nil && Str(delegation, "model") != "" && hermesIsCustom(delegation) {
					yaml = hermesUpsertDelegationBlock(yaml, hermesBuildDelegationBlock(Str(delegation, "model"), normalizedBaseUrl))
				}
				for role, cfgAny := range hermesParseAuxRoles(yaml) {
					cfg := ctMap(cfgAny)
					if cfg != nil && Str(cfg, "model") != "" && hermesIsCustom(cfg) {
						yaml = hermesUpsertAuxRole(yaml, role, hermesBuildAuxRoleBlock(role, Str(cfg, "model"), normalizedBaseUrl))
					}
				}
				if err := hermesWriteHomeConfig(home, yaml); err != nil {
					results = append(results, map[string]any{"profile": name, "status": "failed", "reason": err.Error()})
					return
				}
				_ = hermesWriteHomeEnv(home, apiKey)
				results = append(results, map[string]any{"profile": name, "status": "updated", "model": main["default"]})
			case main != nil && Str(main, "default") != "":
				provider := Str(main, "provider")
				if provider == "" {
					provider = "unknown"
				}
				results = append(results, map[string]any{
					"profile": name, "status": "skipped",
					"reason": "main model uses provider \"" + provider + "\" — configure this profile individually",
				})
			case model != nil && model.(string) != "":
				yaml = hermesUpsertModelBlock(yaml, hermesBuildModelBlock(model.(string), normalizedBaseUrl))
				if err := hermesWriteHomeConfig(home, yaml); err != nil {
					results = append(results, map[string]any{"profile": name, "status": "failed", "reason": err.Error()})
					return
				}
				_ = hermesWriteHomeEnv(home, apiKey)
				results = append(results, map[string]any{"profile": name, "status": "updated", "model": model})
			default:
				results = append(results, map[string]any{"profile": name, "status": "skipped", "reason": "no main model configured"})
			}
		}()
	}
	updated := 0
	for _, res := range results {
		if ctMap(res)["status"] == "updated" {
			updated++
		}
	}
	WriteJSON(w, 200, map[string]any{
		"success": updated > 0, "bulk": true, "results": results,
		"updated": updated, "skipped": len(results) - updated,
		"message": "Updated endpoint on " + strconv.Itoa(updated) + " profile(s)",
	})
}

type ctHermesSelection struct {
	Role  string
	Model string
}

func ctHermesPOST(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, 500, "Failed to update hermes settings")
			return
		}
		baseUrl := Str(body, "baseUrl")
		apiKey := Str(body, "apiKey")
		var sel []ctHermesSelection
		if arr := ctSlice(body["selections"]); arr != nil {
			valid := []ctHermesSelection{}
			anyValid := false
			for _, s := range arr {
				sm := ctMap(s)
				if sm != nil && Str(sm, "role") != "" && Str(sm, "model") != "" {
					valid = append(valid, ctHermesSelection{Str(sm, "role"), Str(sm, "model")})
					anyValid = true
				}
			}
			if anyValid {
				sel = valid
			}
		}
		if sel == nil {
			if m := Str(body, "model"); m != "" {
				sel = []ctHermesSelection{{"default", m}}
			} else {
				sel = []ctHermesSelection{}
			}
		}
		var defaultSel *ctHermesSelection
		for i := range sel {
			if sel[i].Role == "default" {
				defaultSel = &sel[i]
				break
			}
		}
		audio := ctMap(body["audio"])
		if baseUrl == "" || (defaultSel == nil && audio == nil) {
			Err(w, 400, "baseUrl and model are required")
			return
		}
		audioEnabled := false
		audioModel := ""
		if audio != nil {
			audioEnabled = ctHermesTruthy(audio["enabled"])
			audioModel = strings.TrimSpace(Str(audio, "model"))
		}
		if audioEnabled && audioModel == "" {
			Err(w, 400, "audio.model is required when enabling audio transcription")
			return
		}
		normalized := ctNormalizeV1(baseUrl)
		applyAll := false
		if v, present := body["applyToAll"]; present {
			applyAll = ctHermesTruthy(v)
		} else {
			applyAll = ctHermesTruthy(r.URL.Query().Get("applyToAll"))
		}
		if applyAll {
			var modelArg any
			if defaultSel != nil {
				modelArg = defaultSel.Model
			}
			ctHermesApplyToAll(deps, w, normalized, apiKey, modelArg)
			return
		}
		profile := Str(body, "profile")
		if _, present := body["profile"]; !present {
			profile = r.URL.Query().Get("profile")
		}
		home, herr := hermesResolveHome(profile)
		if herr != nil {
			Err(w, 400, herr.Error())
			return
		}
		if !home.IsDefault && !hermesDirExists(home.Dir) {
			Err(w, 404, "Hermes profile \""+home.Name+"\" not found")
			return
		}
		newYaml, err := hermesReadConfigYaml(home)
		if err != nil {
			Err(w, 500, "Failed to update hermes settings")
			return
		}
		for _, s := range sel {
			switch s.Role {
			case "default":
				newYaml = hermesUpsertModelBlock(newYaml, hermesBuildModelBlock(s.Model, normalized))
			case "delegation":
				newYaml = hermesUpsertDelegationBlock(newYaml, hermesBuildDelegationBlock(s.Model, normalized))
			default:
				newYaml = hermesUpsertAuxRole(newYaml, s.Role, hermesBuildAuxRoleBlock(s.Role, s.Model, normalized))
			}
		}
		if audio != nil {
			if audioEnabled {
				newYaml = hermesUpsertSttProxyGo(newYaml, audioModel, normalized)
			} else if hermesIsProxyGoStt(hermesParseSttBlock(newYaml)) {
				newYaml = hermesRemoveSttProxyGo(newYaml)
			}
		}
		if err := hermesWriteHomeConfig(home, newYaml); err != nil {
			Err(w, 500, "Failed to update hermes settings")
			return
		}
		if err := hermesWriteHomeEnv(home, apiKey); err != nil {
			Err(w, 500, "Failed to update hermes settings")
			return
		}
		msg := "Hermes settings applied successfully!"
		if !home.IsDefault {
			msg = "Hermes settings applied to profile \"" + home.Name + "\"!"
		}
		WriteJSON(w, 200, map[string]any{
			"success": true, "message": msg,
			"profile":    map[string]any{"name": home.Name, "dir": home.Dir, "isDefault": home.IsDefault},
			"sttProxyGo": hermesIsProxyGoStt(hermesParseSttBlock(newYaml)),
			"configPath": home.ConfigPath,
		})
	}
}

func ctHermesDELETE(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if parsed, err := ReadBodyJSON(r); err == nil {
			body = parsed
		}
		profile := ""
		if body != nil {
			profile = Str(body, "profile")
		}
		if profile == "" {
			profile = r.URL.Query().Get("profile")
		}
		home, herr := hermesResolveHome(profile)
		if herr != nil {
			Err(w, 400, herr.Error())
			return
		}
		if !home.IsDefault && !hermesDirExists(home.Dir) {
			Err(w, 404, "Hermes profile \""+home.Name+"\" not found")
			return
		}
		raw, err := os.ReadFile(home.ConfigPath)
		if err != nil {
			if os.IsNotExist(err) {
				WriteJSON(w, 200, map[string]any{"success": true, "profile": home.Name, "message": "No config file to reset"})
				return
			}
			Err(w, 500, "Failed to reset hermes settings")
			return
		}
		yaml := string(raw)
		removed := map[string]any{"model": false, "delegation": false, "auxiliary": []any{}, "stt": false}
		kept := []any{}
		if main := hermesParseModelBlock(yaml); main != nil {
			if hermesIsCustom(main) {
				yaml = hermesRemoveModelBlock(yaml)
				removed["model"] = true
			} else {
				kept = append(kept, "model")
			}
		}
		if delegation := hermesParseDelegationBlock(yaml); delegation != nil {
			if hermesIsCustom(delegation) {
				yaml = hermesRemoveDelegationBlock(yaml)
				removed["delegation"] = true
			} else {
				kept = append(kept, "delegation")
			}
		}
		removedAux := []any{}
		for role, cfgAny := range hermesParseAuxRoles(yaml) {
			if hermesIsCustom(ctMap(cfgAny)) {
				yaml = hermesRemoveAuxRole(yaml, role)
				removedAux = append(removedAux, role)
			}
		}
		removed["auxiliary"] = removedAux
		if sttCfg := hermesParseSttBlock(yaml); sttCfg != nil {
			if hermesIsProxyGoStt(sttCfg) {
				yaml = hermesRemoveSttProxyGo(yaml)
				removed["stt"] = true
				if hermesParseSttBlock(yaml) != nil {
					kept = append(kept, "stt")
				}
			} else {
				kept = append(kept, "stt")
			}
		}
		yaml = hermesLeadingBlankRe.ReplaceAllString(yaml, "")
		if err := hermesWriteHomeConfig(home, yaml); err != nil {
			Err(w, 500, "Failed to reset hermes settings")
			return
		}
		scope := ""
		if !home.IsDefault {
			scope = " in profile \"" + home.Name + "\""
		}
		WriteJSON(w, 200, map[string]any{
			"success": true, "profile": home.Name, "removed": removed, "kept": kept,
			"message": "proxygo model blocks removed" + scope,
		})
	}
}

// ---------- cowork-settings + machine id / CLI token ----------

const ctAppPort = 20128 // src/shared/constants/config.js appPort

func ctDataDir() string { return db.DataDir() }

func ctReadPersistedMachineID() string {
	raw, err := os.ReadFile(filepath.Join(ctDataDir(), "machine-id"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func ctOSMachineID() string {
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
		if err == nil {
			if m := regexp.MustCompile(`"IOPlatformUUID"\s*=\s*"([^"]+)"`).FindSubmatch(out); m != nil {
				return string(m[1])
			}
		}
	case "windows":
		out, err := exec.Command("reg", "query", `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid").Output()
		if err == nil {
			if m := regexp.MustCompile(`MachineGuid\s+REG_SZ\s+([^\r\n]+)`).FindSubmatch(out); m != nil {
				return strings.TrimSpace(string(m[1]))
			}
		}
	default:
		for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
			if raw, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(raw)) != "" {
				return strings.TrimSpace(string(raw))
			}
		}
	}
	return ""
}

func ctRandomUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// ctRawMachineID mirrors getRawMachineId: process.env.MACHINE_ID,
// else persisted $DATA_DIR/machine-id, else OS id (persisted), else a
// random UUID (persisted).
func ctRawMachineID() string {
	if v := os.Getenv("MACHINE_ID"); v != "" {
		return v
	}
	if persisted := ctReadPersistedMachineID(); persisted != "" {
		return persisted
	}
	id := ctOSMachineID()
	if id == "" {
		id = ctRandomUUID()
	}
	_ = os.MkdirAll(ctDataDir(), 0o755)
	_ = os.WriteFile(filepath.Join(ctDataDir(), "machine-id"), []byte(id), 0o600)
	return id
}

func ctReadOrCreateCliSecret() string {
	p := filepath.Join(ctDataDir(), "auth", "cli-secret")
	if raw, err := os.ReadFile(p); err == nil && len(raw) >= 16 {
		return strings.TrimSpace(string(raw))
	}
	var b [32]byte
	_, _ = rand.Read(b[:])
	secret := hex.EncodeToString(b[:])
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	_ = os.WriteFile(p, []byte(secret), 0o600)
	return secret
}

// ctCliToken mirrors getCliToken: sha256(machineId + salt + secret)[:16].
func ctCliToken() string {
	sum := sha256.Sum256([]byte(ctRawMachineID() + "9r-cli-auth" + ctReadOrCreateCliSecret()))
	return hex.EncodeToString(sum[:])[:16]
}

func ctCoworkRoots() []string {
	home := ctHome()
	switch runtime.GOOS {
	case "darwin":
		base := filepath.Join(home, "Library", "Application Support")
		return []string{filepath.Join(base, "Claude-3p"), filepath.Join(base, "Claude")}
	case "windows":
		local := os.Getenv("LOCALAPPDATA")
		if local == "" {
			local = filepath.Join(home, "AppData", "Local")
		}
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			appdata = filepath.Join(home, "AppData", "Roaming")
		}
		return []string{
			filepath.Join(local, "Claude-3p"), filepath.Join(appdata, "Claude-3p"),
			filepath.Join(local, "Claude"), filepath.Join(appdata, "Claude"),
		}
	default:
		return []string{filepath.Join(home, ".config", "Claude-3p"), filepath.Join(home, ".config", "Claude")}
	}
}

func ctCoworkFindRoot() (string, bool) {
	for _, root := range ctCoworkRoots() {
		if _, err := os.Stat(filepath.Join(root, "configLibrary")); err == nil {
			return root, true
		}
	}
	return "", false
}

var ctCoworkDefaultPlugins = []map[string]any{
	{"name": "exa", "displayName": "Exa (Search + Fetch)", "url": "https://mcp.exa.ai/mcp", "transport": "http", "oauth": false,
		"description": "Web search and content fetching via Exa", "homepage": "https://exa.ai",
		"toolNames": []any{"web_search_exa", "web_fetch_exa"}},
	{"name": "tavily", "displayName": "Tavily (Search + Extract)", "url": "https://mcp.tavily.com/mcp/", "transport": "http", "oauth": true,
		"description": "Web search, extract and research via Tavily", "homepage": "https://tavily.com",
		"toolNames": []any{"tavily_search", "tavily_extract", "tavily_research", "tavily_crawl"}},
}

var ctCoworkLocalStdioPlugins = []map[string]any{
	{"name": "browsermcp", "displayName": "Browser MCP (Local npx)", "description": "Control a local Chrome via MCP (npx @browsermcp/mcp)", "homepage": "https://browsermcp.io"},
}

func ctCoworkLocalStdioAsAny() []any {
	out := []any{}
	for _, p := range ctCoworkLocalStdioPlugins {
		out = append(out, p)
	}
	return out
}

func ctCoworkDefaultPluginsAsAny() []any {
	out := []any{}
	for _, p := range ctCoworkDefaultPlugins {
		out = append(out, p)
	}
	return out
}

var ctCoworkSecurityRelax = map[string]any{
	"coworkEgressAllowedHosts":               []any{"*"},
	"coworkWebSearchEnabled":                 true,
	"disableDeploymentModeChooser":           true,
	"inferenceProvider":                      "gateway",
	"isClaudeCodeForCoworkEnabled":           true,
	"isDesktopExtensionEnabled":              false,
	"isDesktopExtensionSignatureRequired":    false,
	"isLocalDevMcpEnabled":                   true,
	"isMcpbDirectoryAutoEnabled":             true,
	"claudeCodeDisableTerminalAuth":          true,
	"managedMcpServersEnabled":               true,
	"managedRemoteMcpServersOnly":            false,
	"musterDeploymentManagementEnabled":      false,
	"organizationPluginsEnabled":             false,
	"organizationPluginsSuppressed":          false,
	"organizationPluginsSupported":           false,
	"organizationPluginsSupportedExceptTool": true,
	"pluginsEnabled":                         true,
	"remoteMcpServersEnabled":                true,
	"strictEgressAllowedHostsModelEnforced":  false,
	"toolElicitationEnabled":                 true,
	"inferenceCredentialHelperEnabled":       false,
	"telemetryEnabled":                       false,
	"ccdTelemetryEnabled":                    false,
	"coworkSentryEnabled":                    false,
}

// buildManagedMcpServers port (coworkPlugins.js)
func ctCoworkBuildManaged(plugins []any, localPlugins []any) []any {
	seen := map[string]bool{}
	out := []any{}
	emitFull := func(name string, entry map[string]any) {
		if name == "" {
			return
		}
		norm := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(name)), " ", "-")
		if seen[norm] {
			return
		}
		seen[norm] = true
		toolNames, _ := entry["toolNames"].([]any)
		tools := []any{}
		for _, t := range toolNames {
			ts, _ := t.(string)
			if ts == "" {
				continue
			}
			tools = append(tools, map[string]any{"name": ts, "action": "allow"})
			tools = append(tools, map[string]any{"name": norm + "-" + ts, "action": "allow"})
		}
		entry["toolPolicy"] = tools
		entry["name"] = norm
		out = append(out, entry)
	}
	for _, p := range plugins {
		pm := ctMap(p)
		url := Str(pm, "url")
		if Str(pm, "name") == "" || url == "" {
			continue
		}
		transport := Str(pm, "transport")
		if transport == "" {
			if regexp.MustCompile(`/sse(\b|/)`).MatchString(url) {
				transport = "sse"
			} else {
				transport = "http"
			}
		}
		emitFull(Str(pm, "name"), map[string]any{"url": url, "transport": transport, "headers": pm["headers"], "toolNames": pm["toolNames"]})
	}
	for _, p := range localPlugins {
		pm := ctMap(p)
		if Str(pm, "name") == "" {
			continue
		}
		emitFull(Str(pm, "name"), map[string]any{"type": "stdio", "command": pm["command"], "args": pm["args"], "env": pm["env"], "toolNames": pm["toolNames"]})
	}
	return out
}

func ctCoworkGET(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		root, installed := ctCoworkFindRoot()
		if !installed {
			WriteJSON(w, 200, map[string]any{"installed": false, "config": nil, "message": "Cowork (Claude Desktop) is not installed"})
			return
		}
		libraryDir := filepath.Join(root, "configLibrary")
		meta := ctReadJSONObjTol(filepath.Join(libraryDir, "_meta.json"))
		appliedId := ""
		if meta != nil {
			appliedId = Str(meta, "appliedId")
		}
		var config map[string]any
		configPath := ""
		if appliedId != "" {
			configPath = filepath.Join(libraryDir, appliedId+".json")
			config = ctReadJSONObjTol(configPath)
		}
		plugins := []any{}
		localPlugins := []any{}
		customPlugins := []any{}
		var models []any
		var baseUrl any
		var provider any
		if config != nil {
			if managed, ok := config["managedMcpServers"].([]any); ok {
				defaultByURL := map[string]map[string]any{}
				for _, p := range ctCoworkDefaultPlugins {
					defaultByURL[Str(p, "url")] = p
				}
				for _, entryAny := range managed {
					entry := ctMap(entryAny)
					if entry == nil {
						continue
					}
					url := Str(entry, "url")
					if url == "" {
						localPlugins = append(localPlugins, entry)
						continue
					}
					if def, ok := defaultByURL[url]; ok {
						plugins = append(plugins, map[string]any{
							"name": def["name"], "displayName": def["displayName"], "url": def["url"],
							"transport": entry["transport"], "oauth": def["oauth"], "description": def["description"],
							"homepage": def["homepage"], "toolNames": def["toolNames"],
						})
					} else {
						plugins = append(plugins, entry)
						customPlugins = append(customPlugins, entry)
					}
				}
			}
			if im, ok := config["inferenceModels"].([]any); ok {
				models = im
			}
			baseUrl = config["inferenceGatewayBaseUrl"]
			provider = config["inferenceProvider"]
		}
		WriteJSON(w, 200, map[string]any{
			"installed": true, "config": config,
			"hasProxyGo": config != nil && config["inferenceProvider"] == "gateway" && Str(config, "inferenceGatewayBaseUrl") != "",
			"configPath": configPath,
			"cowork": map[string]any{
				"appliedId": appliedId, "baseUrl": baseUrl, "models": models, "provider": provider,
				"plugins": plugins, "localPlugins": localPlugins, "customPlugins": customPlugins,
			},
			"defaultPlugins": ctCoworkDefaultPluginsAsAny(), "localStdioPlugins": ctCoworkLocalStdioAsAny(),
		})
	}
}

func ctCoworkPOST(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, 500, "Failed to update cowork settings")
			return
		}
		baseUrl := Str(body, "baseUrl")
		if baseUrl == "" {
			Err(w, 400, "baseUrl is required")
			return
		}
		models := ctSlice(body["models"])
		if models == nil {
			models = []any{}
		}
		if len(models) == 0 {
			Err(w, 400, "At least one model is required")
			return
		}
		root, _ := ctCoworkFindRoot()
		if root == "" {
			roots := ctCoworkRoots()
			root = roots[0]
		}
		libraryDir := filepath.Join(root, "configLibrary")
		if err := os.MkdirAll(libraryDir, 0o755); err != nil {
			Err(w, 500, "Failed to update cowork settings")
			return
		}
		metaPath := filepath.Join(libraryDir, "_meta.json")
		meta := ctReadJSONObjTol(metaPath)
		if meta == nil {
			meta = map[string]any{"entries": []any{}}
		}
		appliedId := Str(meta, "appliedId")
		if appliedId == "" {
			appliedId = ctRandomUUID()
			meta["appliedId"] = appliedId
		}
		if _, ok := meta["entries"]; !ok {
			meta["entries"] = []any{}
		}
		entries, _ := meta["entries"].([]any)
		name := Str(body, "profileName")
		if name == "" {
			name = "ProxyGo"
		}
		foundEntry := false
		for _, e := range entries {
			if Str(ctMap(e), "id") == appliedId {
				foundEntry = true
			}
		}
		if !foundEntry {
			meta["entries"] = append(entries, map[string]any{"id": appliedId, "name": name})
		}
		if err := ctWriteJSON(metaPath, meta); err != nil {
			Err(w, 500, "Failed to update cowork settings")
			return
		}
		// selected plugin names
		selected := map[string]bool{}
		if sel, present := body["selectedPlugins"]; present {
			for _, n := range ctSlice(sel) {
				if s, ok := n.(string); ok {
					selected[s] = true
				}
			}
		} else {
			for _, p := range ctCoworkDefaultPlugins {
				selected[Str(p, "name")] = true
			}
		}
		chosenDefaults := []any{}
		for _, p := range ctCoworkDefaultPlugins {
			if selected[Str(p, "name")] {
				chosenDefaults = append(chosenDefaults, p)
			}
		}
		customSeen := map[string]bool{}
		customs := chosenDefaults
		for _, p := range ctSlice(body["customPlugins"]) {
			pm := ctMap(p)
			url := Str(pm, "url")
			if pm == nil || Str(pm, "name") == "" || url == "" {
				continue
			}
			isDefault := false
			for _, d := range ctCoworkDefaultPlugins {
				if Str(d, "url") == url {
					isDefault = true
				}
			}
			if isDefault || customSeen[url] {
				continue
			}
			customSeen[url] = true
			customs = append(customs, pm)
		}
		// local bridge plugins → local SSE entries w/ CLI token header
		selectedLocal := map[string]bool{}
		if sel, present := body["selectedLocalPlugins"]; present {
			for _, n := range ctSlice(sel) {
				if s, ok := n.(string); ok {
					selectedLocal[s] = true
				}
			}
		} else {
			selectedLocal["browsermcp"] = true
		}
		localBridge := []any{}
		for _, p := range ctSlice(body["localBridgePlugins"]) {
			pm := ctMap(p)
			if pm == nil {
				continue
			}
			name := Str(pm, "name")
			if name == "" || !selectedLocal[name] {
				continue
			}
			localBridge = append(localBridge, map[string]any{
				"name": name, "url": "http://localhost:" + strconv.Itoa(ctAppPort) + "/api/mcp/" + name + "/sse",
				"transport": "sse", "type": "local-bridge", "toolNames": pm["toolNames"],
			})
		}
		resolvedBase := ctNormalizeV1(baseUrl)
		managedAll := ctCoworkBuildManaged(append(customs, localBridge...), nil)
		cliToken := ctCliToken()
		for _, e := range managedAll {
			em := ctMap(e)
			url := Str(em, "url")
			if strings.Contains(url, "/api/mcp/") && (strings.Contains(url, "localhost") || strings.Contains(url, "127.0.0.1")) {
				headers := ctMap(em["headers"])
				if headers == nil {
					headers = map[string]any{}
				}
				headers["x-9r-cli-token"] = cliToken
				em["headers"] = headers
			}
		}
		// Cowork whitelists field names; drop toolNames (JS strips them).
		for _, e := range managedAll {
			delete(ctMap(e), "toolNames")
		}
		config := map[string]any{}
		for k, v := range ctCoworkSecurityRelax {
			config[k] = v
		}
		config["inferenceProvider"] = "gateway"
		config["inferenceGatewayBaseUrl"] = resolvedBase
		config["inferenceGatewayApiKey"] = resolveCliApiKey(deps, Str(body, "apiKey"))
		inferenceModels := []any{}
		for _, m := range models {
			s, _ := m.(string)
			inferenceModels = append(inferenceModels, map[string]any{"name": s, "labelOverride": "ProxyGo · " + s, "supports1m": true})
		}
		config["inferenceModels"] = inferenceModels
		if len(managedAll) > 0 {
			config["managedMcpServers"] = managedAll
		}
		configPath := filepath.Join(libraryDir, appliedId+".json")
		if err := ctWriteJSON(configPath, config); err != nil {
			Err(w, 500, "Failed to update cowork settings")
			return
		}
		// bootstrap 1p desktop config (deploymentMode 3p)
		desktopPath := filepath.Join(root, "claude_desktop_config.json")
		desktop := ctReadJSONObjTol(desktopPath)
		if desktop == nil {
			desktop = map[string]any{}
		}
		desktop["deploymentMode"] = "3p"
		_ = ctWriteJSON(desktopPath, desktop)
		innerPath := filepath.Join(root, "config.json")
		inner := ctReadJSONObjTol(innerPath)
		if inner == nil {
			inner = map[string]any{}
		}
		if _, exists := inner["operonSkipMcpApprovals"]; !exists {
			inner["operonSkipMcpApprovals"] = true
			_ = ctWriteJSON(innerPath, inner)
		}
		// Legacy cleanup: 1p stdio entries that are now managed.
		removeNames := map[string]bool{}
		for _, e := range managedAll {
			em := ctMap(e)
			if em["type"] == "stdio" {
				removeNames[Str(em, "name")] = true
			}
		}
		if len(removeNames) > 0 {
			servers := ctMap(desktop["mcpServers"])
			if servers != nil {
				for n := range removeNames {
					delete(servers, n)
				}
				desktop["mcpServers"] = servers
				_ = ctWriteJSON(desktopPath, desktop)
			}
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": "Cowork settings applied! Restart Claude Desktop to take effect.", "configPath": configPath})
	}
}

func ctCoworkDELETE(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		root, _ := ctCoworkFindRoot()
		if root == "" {
			roots := ctCoworkRoots()
			root = roots[0]
		}
		libraryDir := filepath.Join(root, "configLibrary")
		meta := ctReadJSONObjTol(filepath.Join(libraryDir, "_meta.json"))
		appliedId := ""
		if meta != nil {
			appliedId = Str(meta, "appliedId")
		}
		if appliedId == "" {
			WriteJSON(w, 200, map[string]any{"success": true, "message": "Nothing to reset"})
			return
		}
		if err := ctWriteJSON(filepath.Join(libraryDir, appliedId+".json"), map[string]any{}); err != nil {
			Err(w, 500, "Failed to reset cowork settings")
			return
		}
		WriteJSON(w, 200, map[string]any{"success": true, "message": "Cowork settings cleared. Restart Claude Desktop to take effect."})
	}
}

// ---------- cowork-mcp-registry (Anthropic remote registry proxy + cache) ----------

var (
	ctRegistryMu    sync.Mutex
	ctRegistryCache struct {
		servers []any
		at      time.Time
	}
	ctRegistryKeys = map[string]bool{
		"requiredHeaders": true, "requiredSecrets": true, "tools": true,
		"headers": true, "secrets": true, "env": true,
	}
)

func ctRegistryMungeServer(srv map[string]any) map[string]any {
	if srv == nil {
		return nil
	}
	remotes, _ := srv["remotes"].([]any)
	if len(remotes) == 0 {
		return nil
	}
	remote := ctMap(remotes[0])
	if remote == nil {
		return nil
	}
	url := Str(remote, "url")
	if url == "" {
		return nil
	}
	required := false
	for key := range srv {
		if ctRegistryKeys[key] {
			required = true
		}
	}
	return map[string]any{
		"name": srv["name"], "label": srv["title"], "url": url,
		"transport": remote["type"], "description": srv["description"],
		"homepage": srv["repository"], "oauth": required,
		"requiresAuthKey": nil, "toolNames": nil, "source": "anthropic-registry",
	}
}

func ctFetchRegistry() ([]any, error) {
	visibility := "visibility=commercial,gsuite,gsuite-google"
	base := "https://api.anthropic.com/mcp-registry/v0/servers?limit=500&" + visibility
	seen := map[string]bool{}
	out := []any{}
	url := base
	for page := 0; page < 20 && url != ""; page++ {
		client := &http.Client{Timeout: 15 * time.Second}
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("registry upstream %d", resp.StatusCode)
		}
		var data map[string]any
		if err := json.Unmarshal(raw, &data); err != nil {
			return nil, err
		}
		servers, _ := data["servers"].([]any)
		for _, srvAny := range servers {
			srv := ctMap(srvAny)
			if srv == nil || srv["isDirectConnect"] != true {
				continue
			}
			munged := ctRegistryMungeServer(srv)
			if munged == nil {
				continue
			}
			u := Str(munged, "url")
			if seen[u] {
				continue
			}
			seen[u] = true
			out = append(out, munged)
		}
		next := ""
		if md := ctMap(data["metadata"]); md != nil {
			next = Str(md, "nextCursor")
		}
		if next != "" && len(servers) > 0 {
			url = base + "&cursor=" + urlQueryEscape(next)
		} else {
			url = ""
		}
	}
	return out, nil
}

func urlQueryEscape(s string) string {
	return strings.NewReplacer(" ", "%20", "+", "%2B", "/", "%2F", "=", "%3D").Replace(s)
}

func ctRegistryGET(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		refresh := r.URL.Query().Get("refresh") == "1"
		ctRegistryMu.Lock()
		cachedServers := ctRegistryCache.servers
		cachedAt := ctRegistryCache.at
		ctRegistryMu.Unlock()
		if !refresh && cachedServers != nil && time.Since(cachedAt) < time.Hour {
			WriteJSON(w, 200, map[string]any{"cached": true, "servers": cachedServers, "total": len(cachedServers)})
			return
		}
		servers, err := ctFetchRegistry()
		if err != nil {
			WriteJSON(w, 500, map[string]any{"error": "Failed to fetch MCP registry", "servers": []any{}, "total": 0})
			return
		}
		ctRegistryMu.Lock()
		ctRegistryCache.servers = servers
		ctRegistryCache.at = time.Now()
		ctRegistryMu.Unlock()
		WriteJSON(w, 200, map[string]any{"cached": false, "servers": servers, "total": len(servers)})
	}
}

// ---------- cowork-mcp-tools (JSON-RPC tools/list probe + SSRF guard) ----------

// ctAssertPublicURL mirrors layer-1 of src/shared/utils/ssrfGuard.js
// (scheme http(s) only, blocked hostnames, private/link-local/CGNAT v4,
// ULA + loopback v6). Used to block cloud-metadata/private targets when
// the request is NOT local.
func ctAssertPublicURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("URL not allowed")
	}
	hostname := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if hostname == "" || hostname == "localhost" || hostname == "ip6-localhost" || hostname == "ip6-loopback" ||
		strings.HasSuffix(hostname, ".internal") || strings.HasSuffix(hostname, ".local") || strings.HasSuffix(hostname, ".localhost") {
		return fmt.Errorf("URL not allowed")
	}
	host := hostname
	if strings.HasPrefix(host, "::ffff:") {
		host = strings.TrimPrefix(host, "::ffff:")
	}
	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			a, b := ip4[0], ip4[1]
			if a == 0 || a == 10 || a == 127 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) ||
				(a == 169 && b == 254) || (a == 100 && b >= 64 && b <= 127) {
				return fmt.Errorf("URL not allowed")
			}
		} else {
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				return fmt.Errorf("URL not allowed")
			}
			// fc00::/7 ULA
			if len(ip) == 16 && (ip[0]&0xfe) == 0xfc {
				return fmt.Errorf("URL not allowed")
			}
		}
	}
	return nil
}

func ctMcpProbe(rawURL string, headers map[string]string) (tools []any, requiresAuth bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	client := &http.Client{}
	post := func(payload map[string]any) (*http.Response, []byte, error) {
		b, _ := json.Marshal(payload)
		req, err := http.NewRequestWithContext(ctx, "POST", rawURL, bytes.NewReader(b))
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		return resp, raw, err
	}
	initResp, initRaw, err := post(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05", "capabilities": map[string]any{},
			"clientInfo": map[string]any{"name": "proxygo", "version": "1"},
		},
	})
	if err != nil {
		return nil, false, err
	}
	if initResp.StatusCode == 401 || initResp.StatusCode == 403 {
		return nil, true, nil
	}
	var sessionID string
	if ct := initResp.Header.Get("Content-Type"); strings.Contains(ct, "text/event-stream") {
		for _, line := range strings.Split(string(initRaw), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "data:") {
				continue
			}
			var d map[string]any
			if json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "data:"))), &d) == nil {
				if idf, ok := d["id"].(float64); ok && idf == 1 {
					if res := ctMap(d["result"]); res != nil {
						if sid := Str(res, "sessionId"); sid != "" {
							sessionID = sid
						}
					}
				}
			}
		}
	} else {
		var d map[string]any
		if json.Unmarshal(initRaw, &d) == nil {
			if res := ctMap(d["result"]); res != nil {
				sessionID = Str(res, "sessionId")
			}
		}
	}
	if sessionID != "" {
		headers["Mcp-Session-Id"] = sessionID
	}
	_, _, _ = post(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	toolsResp, toolsRaw, err := post(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": map[string]any{}})
	if err != nil {
		return nil, false, err
	}
	if toolsResp.StatusCode == 401 || toolsResp.StatusCode == 403 {
		return nil, true, nil
	}
	extract := func(d map[string]any) []any {
		if res := ctMap(d["result"]); res != nil {
			if t, ok := res["tools"].([]any); ok {
				return t
			}
		}
		return nil
	}
	if ct := toolsResp.Header.Get("Content-Type"); strings.Contains(ct, "text/event-stream") {
		for _, line := range strings.Split(string(toolsRaw), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "data:") {
				continue
			}
			var d map[string]any
			if json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "data:"))), &d) == nil {
				if idf, ok := d["id"].(float64); ok && idf == 2 {
					return extract(d), false, nil
				}
			}
		}
		return nil, false, fmt.Errorf("no tools/list response in SSE stream")
	}
	var d map[string]any
	if err := json.Unmarshal(toolsRaw, &d); err != nil {
		return nil, false, err
	}
	return extract(d), false, nil
}

func ctMcpToolsPOST(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, 400, "url is required")
			return
		}
		rawURL := Str(body, "url")
		if rawURL == "" {
			Err(w, 400, "url is required")
			return
		}
		headers := map[string]string{}
		if hm, present := body["headers"]; present {
			for k, v := range ctMap(hm) {
				if s, ok := v.(string); ok {
					headers[k] = s
				}
			}
		}
		if !IsLocalRequest(r) {
			if err := ctAssertPublicURL(rawURL); err != nil {
				Err(w, 400, "URL not allowed")
				return
			}
		}
		tools, requiresAuth, err := ctMcpProbe(rawURL, headers)
		if requiresAuth {
			WriteJSON(w, 200, map[string]any{"requiresAuth": true, "tools": []any{}})
			return
		}
		if err != nil {
			msg := err.Error()
			if idx := strings.Index(msg, ":"); idx > 0 && len(msg) > 120 {
				msg = msg[:120]
			}
			WriteJSON(w, 200, map[string]any{"error": "Probe failed: " + msg, "tools": []any{}})
			return
		}
		if tools == nil {
			tools = []any{}
		}
		WriteJSON(w, 200, map[string]any{"requiresAuth": false, "tools": tools})
	}
}

// ---------- antigravity-mitm (delegates to internal/mitm via hooks) ----------
//
// internal/mitm is ported by Team H in parallel. Until the parent wires
// these package-level hooks to the real implementation, they stay nil
// and the routes answer exactly like the JS code does when the MITM
// module reports "not running" (status) or fails to start (500).
//
// Parent wiring contract (signatures mirror the JS functions in
// src/lib/mitm/server.js + cert.js + dns.js + password.js):
//
//	MitmGetStatus() MitmStatus
//	MitmStartServer(apiKey, sudoPassword string, forceKillPort443 bool) error
//	    — error text "PORT_443_BUSY: <owner>" maps to 409 {code:"PORT_443_BUSY", portOwner}
//	MitmStopServer(sudoPassword string) error
//	MitmEnableToolDNS(tool, sudoPassword string) error
//	MitmDisableToolDNS(tool, sudoPassword string) error
//	MitmTrustCert(sudoPassword string) error
//	MitmGetCachedPassword() (string, bool)
//	MitmSetCachedPassword(pw string)
//	MitmLoadEncryptedPassword() string        // "" when none stored
//	MitmIsSudoPasswordRequired() bool
//	MitmWriteAliasForTool(tool string, mappings map[string]any) error
//	    — optional: when nil, the route performs the local aliases.json
//	      merge-write itself (atomic tmp+rename), mirroring JS.

type MitmStatus struct {
	Running           bool
	PID               int
	CertExists        bool
	CertTrusted       bool
	DNSStatus         map[string]bool
	HasCachedPassword bool
}

var (
	MitmGetStatus              func() MitmStatus
	MitmStartServer            func(apiKey, sudoPassword string, forceKillPort443 bool) error
	MitmStopServer             func(sudoPassword string) error
	MitmEnableToolDNS          func(tool, sudoPassword string) error
	MitmDisableToolDNS         func(tool, sudoPassword string) error
	MitmTrustCert              func(sudoPassword string) error
	MitmGetCachedPassword      func() (string, bool)
	MitmSetCachedPassword      func(pw string)
	MitmLoadEncryptedPassword  func() string
	MitmIsSudoPasswordRequired func() bool
	MitmWriteAliasForTool      func(tool string, mappings map[string]any) error
)

func ctMitmStatus() MitmStatus {
	if MitmGetStatus == nil {
		return MitmStatus{DNSStatus: map[string]bool{}}
	}
	st := MitmGetStatus()
	if st.DNSStatus == nil {
		st.DNSStatus = map[string]bool{}
	}
	return st
}

func ctMitmIsAdmin() bool {
	if runtime.GOOS == "windows" {
		return exec.Command("net", "session").Run() == nil
	}
	return os.Geteuid() == 0
}

func ctMitmCachedPasswordFallback() string {
	if MitmGetCachedPassword != nil {
		if pw, ok := MitmGetCachedPassword(); ok && pw != "" {
			return pw
		}
	}
	if MitmLoadEncryptedPassword != nil {
		return MitmLoadEncryptedPassword()
	}
	return ""
}

func ctMitmGET(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st := ctMitmStatus()
		routerBase := "http://localhost:20128"
		if deps.Store != nil {
			if settings, err := deps.Store.GetSettings(); err == nil {
				if v := Str(settings, "mitmRouterBaseUrl"); v != "" {
					routerBase = v
				}
			}
		}
		dns := map[string]any{}
		for k, v := range st.DNSStatus {
			dns[k] = v
		}
		isWin := runtime.GOOS == "windows"
		needsSudo := false
		if MitmIsSudoPasswordRequired != nil {
			needsSudo = MitmIsSudoPasswordRequired()
		} else {
			needsSudo = !isWin && os.Getenv("SUDO_USER") == "" && !ctMitmIsAdmin()
		}
		hasCached := st.HasCachedPassword
		if !hasCached && MitmGetCachedPassword != nil {
			_, hasCached = MitmGetCachedPassword()
		}
		if !hasCached && MitmLoadEncryptedPassword != nil && MitmLoadEncryptedPassword() != "" {
			hasCached = true
		}
		WriteJSON(w, 200, map[string]any{
			"running": st.Running, "pid": st.PID, "certExists": st.CertExists,
			"certTrusted": st.CertTrusted, "dnsStatus": dns,
			"hasCachedPassword": hasCached, "isWin": isWin,
			"needsSudoPassword": needsSudo, "isAdmin": ctMitmIsAdmin(),
			"mitmRouterBaseUrl": routerBase,
		})
	}
}

func ctMitmPOST(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := ReadBodyJSON(r)
		apiKey := Str(body, "apiKey")
		sudoPassword := Str(body, "sudoPassword")
		forceKill := ctHermesTruthy(body["forceKillPort443"])
		mitmRouterBaseUrl := Str(body, "mitmRouterBaseUrl")
		if apiKey == "" && sudoPassword == "" {
			Err(w, 400, "apiKey is required")
			return
		}
		if sudoPassword == "" {
			sudoPassword = ctMitmCachedPasswordFallback()
		}
		isWin := runtime.GOOS == "windows"
		needsSudo := !isWin && os.Getenv("SUDO_USER") == "" && !ctMitmIsAdmin()
		if needsSudo && sudoPassword == "" {
			Err(w, 403, "Sudo password is required")
			return
		}
		if mitmRouterBaseUrl != "" && deps.Store != nil {
			normalized := strings.TrimSuffix(strings.TrimSpace(mitmRouterBaseUrl), "/")
			if normalized != "" {
				settings, _ := deps.Store.GetSettings()
				if settings == nil {
					settings = map[string]any{}
				}
				settings["mitmRouterBaseUrl"] = normalized
				_, _ = deps.Store.UpdateSettings(settings)
			}
		}
		if MitmStartServer == nil {
			Err(w, 500, "MITM module not available")
			return
		}
		if err := MitmStartServer(apiKey, sudoPassword, forceKill); err != nil {
			msg := err.Error()
			if strings.HasPrefix(msg, "PORT_443_BUSY") {
				owner := strings.TrimSpace(strings.TrimPrefix(msg, "PORT_443_BUSY:"))
				if owner == msg || owner == "PORT_443_BUSY" {
					owner = ""
					if idx := strings.Index(msg, ":"); idx >= 0 {
						owner = strings.TrimSpace(msg[idx+1:])
					}
				}
				var ownerVal any
				if owner != "" {
					ownerVal = owner
				}
				WriteJSON(w, 409, map[string]any{
					"error":     "Port 443 is already in use by another process. Stop it (e.g. XAMPP / IIS / another proxy) or kill it to continue.",
					"code":      "PORT_443_BUSY",
					"portOwner": ownerVal,
				})
				return
			}
			Err(w, 500, msg)
			return
		}
		if sudoPassword != "" {
			if MitmSetCachedPassword != nil {
				MitmSetCachedPassword(sudoPassword)
			}
		}
		st := ctMitmStatus()
		WriteJSON(w, 200, map[string]any{"success": true, "running": st.Running, "pid": st.PID})
	}
}

func ctMitmDELETE(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if parsed, err := ReadBodyJSON(r); err == nil {
			body = parsed
		}
		sudoPassword := ""
		if body != nil {
			sudoPassword = Str(body, "sudoPassword")
		}
		if sudoPassword == "" {
			sudoPassword = r.URL.Query().Get("sudoPassword")
		}
		if sudoPassword == "" {
			sudoPassword = ctMitmCachedPasswordFallback()
		}
		if MitmStopServer == nil {
			Err(w, 500, "MITM module not available")
			return
		}
		if err := MitmStopServer(sudoPassword); err != nil {
			Err(w, 500, err.Error())
			return
		}
		WriteJSON(w, 200, map[string]any{"success": true, "running": false})
	}
}

func ctMitmPATCH(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := ReadBodyJSON(r)
		action := Str(body, "action")
		tool := Str(body, "tool")
		sudoPassword := Str(body, "sudoPassword")
		if sudoPassword == "" {
			sudoPassword = ctMitmCachedPasswordFallback()
		}
		fail := func(err error) {
			Err(w, 500, err.Error())
		}
		switch action {
		case "enable":
			if MitmEnableToolDNS == nil {
				Err(w, 500, "MITM module not available")
				return
			}
			if err := MitmEnableToolDNS(tool, sudoPassword); err != nil {
				fail(err)
				return
			}
			WriteJSON(w, 200, map[string]any{"success": true, "tool": tool, "enabled": true})
		case "disable":
			if MitmDisableToolDNS == nil {
				Err(w, 500, "MITM module not available")
				return
			}
			if err := MitmDisableToolDNS(tool, sudoPassword); err != nil {
				fail(err)
				return
			}
			WriteJSON(w, 200, map[string]any{"success": true, "tool": tool, "enabled": false})
		case "trust-cert":
			if MitmTrustCert == nil {
				Err(w, 500, "MITM module not available")
				return
			}
			if err := MitmTrustCert(sudoPassword); err != nil {
				fail(err)
				return
			}
			WriteJSON(w, 200, map[string]any{"success": true, "certTrusted": true})
		default:
			Err(w, 400, "Invalid action")
		}
	}
}

// ----- antigravity-mitm/alias (fully local: db + aliases.json) -----

func ctMitmAliasLocalWrite(tool string, mappings map[string]any) error {
	dir := filepath.Join(ctDataDir(), "mitm")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, "aliases.json")
	existing := map[string]any{}
	if data, err := os.ReadFile(path); err == nil {
		var parsed map[string]any
		if json.Unmarshal(data, &parsed) == nil && parsed != nil {
			existing = parsed
		}
	}
	existing[tool] = mappings
	tmp := path + ".tmp"
	if err := ctWriteJSON(tmp, existing); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func ctMitmAliasGET(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tool := r.URL.Query().Get("tool")
		var aliases any = map[string]any{}
		if deps.Store != nil {
			if rec, err := deps.Store.GetMitmAlias(tool); err == nil && rec != nil {
				aliases = rec
			}
		}
		WriteJSON(w, 200, map[string]any{"aliases": aliases})
	}
}

func ctMitmAliasPUT(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, 400, "tool and mappings are required")
			return
		}
		tool := Str(body, "tool")
		mappings := ctMap(body["mappings"])
		if tool == "" || mappings == nil {
			Err(w, 400, "tool and mappings are required")
			return
		}
		st := ctMitmStatus()
		if !st.DNSStatus[tool] {
			Err(w, 403, "Enable MITM for "+tool+" first (DNS must be active) before saving model aliases.")
			return
		}
		filtered := map[string]any{}
		for orig, aliasAny := range mappings {
			alias := Str(map[string]any{"v": aliasAny}, "v")
			if alias != "" {
				filtered[orig] = alias
			}
		}
		if deps.Store != nil {
			if err := deps.Store.SetMitmAliasAll(tool, filtered); err != nil {
				Err(w, 500, err.Error())
				return
			}
		}
		writeErr := error(nil)
		if MitmWriteAliasForTool != nil {
			writeErr = MitmWriteAliasForTool(tool, filtered)
		} else {
			writeErr = ctMitmAliasLocalWrite(tool, filtered)
		}
		if writeErr != nil {
			Err(w, 500, writeErr.Error())
			return
		}
		WriteJSON(w, 200, map[string]any{"success": true, "aliases": filtered})
	}
}

// ---------- all-statuses ----------

func ctAllStatusesGET(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tools := []struct {
			name string
			get  func(Deps) http.HandlerFunc
		}{
			{"claude", ctClaudeGET}, {"codex", ctCodexGET}, {"opencode", ctOpencodeGET},
			{"droid", ctDroidGET}, {"openclaw", ctOpenclawGET}, {"hermes", ctHermesGET},
			{"cowork", ctCoworkGET}, {"cline", ctClineGET}, {"kilo", ctKiloGET},
			{"deepseek-tui", ctDeepseekGET}, {"jcode", ctJcodeGET}, {"grok-build", ctGrokGET},
			{"devin", ctDevinGET}, {"pi", ctPiGET}, {"omp", ctOmpGET},
			{"crush", ctCrushGET}, {"forge", ctForgeGET}, {"smelt", ctSmeltGET},
			{"codewhale", ctCodewhaleGET},
		}
		out := map[string]any{}
		for _, t := range tools {
			func() {
				defer func() { _ = recover() }()
				rec := httptest.NewRecorder()
				req := httptest.NewRequest("GET", "/api/cli-tools/x", nil)
				t.get(deps)(rec, req)
				var v any
				if json.Unmarshal(rec.Body.Bytes(), &v) == nil {
					out[t.name] = v
				} else {
					out[t.name] = nil
				}
			}()
			if _, ok := out[t.name]; !ok {
				out[t.name] = nil
			}
		}
		WriteJSON(w, 200, out)
	}
}

// ---------- registration ----------

// RegisterCLITools wires every /api/cli-tools/* route (Phase 2 contract).
func RegisterCLITools(mux *http.ServeMux, deps Deps) {
	reg := func(pattern string, h func(Deps) http.HandlerFunc) {
		mux.Handle(pattern, Wrap(deps, h(deps)))
	}
	reg("GET /api/cli-tools/all-statuses", ctAllStatusesGET)

	reg("GET /api/cli-tools/antigravity-mitm", ctMitmGET)
	reg("POST /api/cli-tools/antigravity-mitm", ctMitmPOST)
	reg("DELETE /api/cli-tools/antigravity-mitm", ctMitmDELETE)
	reg("PATCH /api/cli-tools/antigravity-mitm", ctMitmPATCH)
	reg("GET /api/cli-tools/antigravity-mitm/alias", ctMitmAliasGET)
	reg("PUT /api/cli-tools/antigravity-mitm/alias", ctMitmAliasPUT)

	reg("GET /api/cli-tools/claude-settings", ctClaudeGET)
	reg("POST /api/cli-tools/claude-settings", ctClaudePOST)
	reg("DELETE /api/cli-tools/claude-settings", ctClaudeDELETE)

	reg("GET /api/cli-tools/cline-settings", ctClineGET)
	reg("POST /api/cli-tools/cline-settings", ctClinePOST)
	reg("DELETE /api/cli-tools/cline-settings", ctClineDELETE)

	reg("GET /api/cli-tools/codewhale-settings", ctCodewhaleGET)
	reg("POST /api/cli-tools/codewhale-settings", ctCodewhalePOST)
	reg("DELETE /api/cli-tools/codewhale-settings", ctCodewhaleDELETE)

	reg("GET /api/cli-tools/codex-profiles", ctCodexProfilesGET)
	reg("POST /api/cli-tools/codex-profiles", ctCodexProfilesPOST)
	reg("DELETE /api/cli-tools/codex-profiles", ctCodexProfilesDELETE)

	reg("GET /api/cli-tools/codex-settings", ctCodexGET)
	reg("POST /api/cli-tools/codex-settings", ctCodexPOST)
	reg("DELETE /api/cli-tools/codex-settings", ctCodexDELETE)

	reg("GET /api/cli-tools/copilot-settings", ctCopilotGET)
	reg("POST /api/cli-tools/copilot-settings", ctCopilotPOST)
	reg("DELETE /api/cli-tools/copilot-settings", ctCopilotDELETE)

	reg("GET /api/cli-tools/cowork-mcp-registry", ctRegistryGET)
	reg("POST /api/cli-tools/cowork-mcp-tools", ctMcpToolsPOST)
	reg("GET /api/cli-tools/cowork-settings", ctCoworkGET)
	reg("POST /api/cli-tools/cowork-settings", ctCoworkPOST)
	reg("DELETE /api/cli-tools/cowork-settings", ctCoworkDELETE)

	reg("GET /api/cli-tools/crush-settings", ctCrushGET)
	reg("POST /api/cli-tools/crush-settings", ctCrushPOST)
	reg("DELETE /api/cli-tools/crush-settings", ctCrushDELETE)

	reg("GET /api/cli-tools/deepseek-tui-settings", ctDeepseekGET)
	reg("POST /api/cli-tools/deepseek-tui-settings", ctDeepseekPOST)
	reg("DELETE /api/cli-tools/deepseek-tui-settings", ctDeepseekDELETE)

	reg("GET /api/cli-tools/devin-settings", ctDevinGET)

	reg("GET /api/cli-tools/droid-settings", ctDroidGET)
	reg("POST /api/cli-tools/droid-settings", ctDroidPOST)
	reg("DELETE /api/cli-tools/droid-settings", ctDroidDELETE)

	reg("GET /api/cli-tools/forge-settings", ctForgeGET)
	reg("POST /api/cli-tools/forge-settings", ctForgePOST)
	reg("DELETE /api/cli-tools/forge-settings", ctForgeDELETE)

	reg("GET /api/cli-tools/grok-build-settings", ctGrokGET)
	reg("POST /api/cli-tools/grok-build-settings", ctGrokPOST)
	reg("DELETE /api/cli-tools/grok-build-settings", ctGrokDELETE)

	reg("GET /api/cli-tools/hermes-profiles", ctHermesProfilesGET)
	reg("GET /api/cli-tools/hermes-settings", ctHermesGET)
	reg("POST /api/cli-tools/hermes-settings", ctHermesPOST)
	reg("DELETE /api/cli-tools/hermes-settings", ctHermesDELETE)

	reg("GET /api/cli-tools/jcode-settings", ctJcodeGET)
	reg("POST /api/cli-tools/jcode-settings", ctJcodePOST)
	reg("DELETE /api/cli-tools/jcode-settings", ctJcodeDELETE)

	reg("GET /api/cli-tools/kilo-settings", ctKiloGET)
	reg("POST /api/cli-tools/kilo-settings", ctKiloPOST)
	reg("DELETE /api/cli-tools/kilo-settings", ctKiloDELETE)

	reg("GET /api/cli-tools/omp-settings", ctOmpGET)
	reg("POST /api/cli-tools/omp-settings", ctOmpPOST)
	reg("DELETE /api/cli-tools/omp-settings", ctOmpDELETE)

	reg("GET /api/cli-tools/openclaw-settings", ctOpenclawGET)
	reg("POST /api/cli-tools/openclaw-settings", ctOpenclawPOST)
	reg("DELETE /api/cli-tools/openclaw-settings", ctOpenclawDELETE)

	reg("GET /api/cli-tools/opencode-settings", ctOpencodeGET)
	reg("POST /api/cli-tools/opencode-settings", ctOpencodePOST)
	reg("PATCH /api/cli-tools/opencode-settings", ctOpencodePATCH)
	reg("DELETE /api/cli-tools/opencode-settings", ctOpencodeDELETE)

	reg("GET /api/cli-tools/pi-settings", ctPiGET)
	reg("POST /api/cli-tools/pi-settings", ctPiPOST)
	reg("DELETE /api/cli-tools/pi-settings", ctPiDELETE)

	reg("GET /api/cli-tools/smelt-settings", ctSmeltGET)
	reg("POST /api/cli-tools/smelt-settings", ctSmeltPOST)
	reg("DELETE /api/cli-tools/smelt-settings", ctSmeltDELETE)
}
