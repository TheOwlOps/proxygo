package executors

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// DevinCLIExecutor ports open-sse/executors/devin-cli.js: completions are
// routed through the official Devin CLI binary via the Agent Client Protocol
// (ACP) — JSON-RPC 2.0 over the subprocess's stdio — NOT over HTTP.
//
// Flow (devin-cli.js): spawn `devin acp` → initialize → session/new (model +
// cwd + mcpServers) → session/prompt → session/update notifications are
// re-emitted as OpenAI chat.completion.chunk SSE (agent_message_chunk = reply
// text; a call into the client-tools MCP bridge becomes an OpenAI tool_call
// and ends the turn with finish_reason "tool_calls") → the turn ends on
// _cognition.ai/agent_stopped, a stop update, or process exit.
//
// Auth: noAuth — the subprocess inherits the parent environment and uses the
// credentials stored by `devin auth login`. Nothing is taken from Credential.
//
// The Base hooks below only mirror the JS buildUrl/buildHeaders/
// transformRequest surface; Execute is fully bespoke (no HTTP call is made),
// so Base.Execute is never used for this provider.
//
// Live-unverified: acceptance by a real `devin acp` binary (no Devin account
// / binary in this environment) — the protocol is ported 1:1 and exercised
// against a fake ACP subprocess in devin_test.go.
type DevinCLIExecutor struct{ *Base }

// NewDevinCLIExecutor builds the devin-cli executor.
func NewDevinCLIExecutor() *DevinCLIExecutor {
	d := &DevinCLIExecutor{}
	d.Base = &Base{ProviderID: "devin-cli", Hooks: Hooks{
		BuildURL: func(b *Base, req *Request, urlIndex int) (string, error) {
			return "devin://acp/stdio", nil
		},
		BuildHeaders: func(b *Base, req *Request, url string) (map[string]string, error) {
			return map[string]string{}, nil
		},
		TransformBody: func(b *Base, req *Request) (map[string]any, error) {
			return nil, nil // JS transformRequest() returns null
		},
	}}
	return d
}

// devinURL is the pseudo-URL reported in every ExecResult (JS: buildUrl()).
const devinURL = "devin://acp/stdio"

// --- Binary discovery (resolveDevinBin) ---

// devinResolveBin ports resolveDevinBin: CLI_DEVIN_BIN env → known
// installer locations → bare name (PATH lookup at spawn time).
func devinResolveBin() string {
	if envBin := strings.TrimSpace(os.Getenv("CLI_DEVIN_BIN")); envBin != "" {
		return envBin
	}
	home, _ := os.UserHomeDir()
	var candidates []string
	if runtime.GOOS == "windows" {
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData == "" {
			localAppData = filepath.Join(home, "AppData", "Local")
		}
		candidates = []string{
			filepath.Join(localAppData, "devin", "cli", "bin", "devin.exe"),
			filepath.Join(home, ".local", "bin", "devin.exe"),
			filepath.Join(home, "scoop", "shims", "devin.exe"),
			filepath.Join(localAppData, "Programs", "devin", "devin.exe"),
		}
	} else {
		candidates = []string{
			filepath.Join(home, ".local", "share", "devin", "bin", "devin"),
			filepath.Join(home, ".devin", "bin", "devin"),
			filepath.Join(home, ".local", "bin", "devin"),
			"/opt/homebrew/bin/devin",
			"/usr/local/bin/devin",
			"/usr/bin/devin",
		}
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	if runtime.GOOS == "windows" {
		return "devin.exe"
	}
	return "devin"
}

// --- Client-tools → MCP bridge ---

const devinMCPToolPrefix = "mcp_"

func devinToMCPToolName(name string) string {
	if strings.HasPrefix(name, devinMCPToolPrefix) {
		return name
	}
	return devinMCPToolPrefix + name
}

func devinFromMCPToolName(name string) string {
	return strings.TrimPrefix(name, devinMCPToolPrefix)
}

// devinClientToolsMCPScript is the JS CLIENT_TOOLS_MCP_SCRIPT, verbatim: a
// Node stdio MCP server exposing the client's tools to devin, seeded with
// prior tool results (DEVIN_MCP_RESULTS).
const devinClientToolsMCPScript = `
import readline from "node:readline";
const TOOLS = JSON.parse(process.env.DEVIN_MCP_TOOLS || "[]");
const RESULTS = JSON.parse(process.env.DEVIN_MCP_RESULTS || "{}");
const rl = readline.createInterface({ input: process.stdin });
function send(o){ process.stdout.write(JSON.stringify(o) + "\n"); }
rl.on("line", (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m.method === "initialize") {
    send({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: "2024-11-05", capabilities: { tools: {} }, serverInfo: { name: "clientTools", version: "1.0" } } });
  } else if (m.method === "tools/list") {
    send({ jsonrpc: "2.0", id: m.id, result: { tools: TOOLS } });
  } else if (m.method === "tools/call") {
    const name = m.params?.name || "";
    const seeded = RESULTS[name];
    const text = seeded !== undefined
      ? String(seeded)
      : "(awaiting client tool_result)";
    process.stderr.write("[client-tools] tool_call name=" + name + " seeded=" + (seeded !== undefined) + "\n");
    send({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text }] } });
  }
});
`

// devinEnsureClientToolsScript ports ensureClientToolsScript: always
// rewrite so script upgrades land without a process restart.
func devinEnsureClientToolsScript() string {
	scriptPath := filepath.Join(os.TempDir(), "9router-devin-client-tools.mjs")
	_ = os.WriteFile(scriptPath, []byte(strings.TrimLeft(devinClientToolsMCPScript, "\n")), 0o644)
	return scriptPath
}

// devinMCPServer is one entry of the throwaway devin config's mcpServers map
// ({command, args, env} — the devin/DEVIN_MCP_SERVERS shape).
type devinMCPServer struct {
	Command string            `json:"command"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	// Raw preserves user-supplied DEVIN_MCP_SERVERS entries verbatim when
	// they don't fit the typed shape.
	Raw map[string]any `json:"-"`
}

func (s devinMCPServer) MarshalJSON() ([]byte, error) {
	if s.Raw != nil {
		return json.Marshal(s.Raw)
	}
	type alias devinMCPServer
	return json.Marshal(alias(s))
}

// devinBuildClientToolsMCP ports buildClientToolsMcp: map OpenAI tools to
// MCP declarations (mcp_-prefixed names) + the stdio server entry, or nil
// when there are no usable tools. nodePath is the Node binary used as the
// MCP server command (JS: process.execPath — the node running 9router; the
// Go port has no node parent, so it resolves `node` from PATH).
func devinBuildClientToolsMCP(tools []any, resultMap map[string]string) *devinMCPServer {
	var mcpTools []map[string]any
	for _, t := range tools {
		if t == nil {
			continue
		}
		tm, _ := t.(map[string]any)
		if tm == nil {
			continue
		}
		f, _ := tm["function"].(map[string]any)
		if f == nil {
			f = tm
		}
		name := getStr(f, "name")
		if name == "" {
			continue
		}
		schema := f["parameters"]
		if schema == nil {
			schema = f["input_schema"]
		}
		if schema == nil {
			schema = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		mcpTools = append(mcpTools, map[string]any{
			"name":        devinToMCPToolName(name),
			"description": getStr(f, "description"),
			"inputSchema": schema,
		})
	}
	if len(mcpTools) == 0 {
		return nil
	}
	env := map[string]string{}
	toolsJSON, _ := json.Marshal(mcpTools)
	env["DEVIN_MCP_TOOLS"] = string(toolsJSON)
	if len(resultMap) > 0 {
		resultsJSON, _ := json.Marshal(resultMap)
		env["DEVIN_MCP_RESULTS"] = string(resultsJSON)
	}
	nodePath, err := exec.LookPath("node")
	if err != nil {
		nodePath = "node"
	}
	return &devinMCPServer{
		Command: nodePath,
		Args:    []string{devinEnsureClientToolsScript()},
		Env:     env,
	}
}

// devinStringify ports JSON.stringify(content ?? "") for non-string content
// (nil renders as the JSON string `""`, matching JS JSON.stringify("")).
func devinStringify(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if v == nil {
		raw, _ := json.Marshal("")
		return string(raw)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(raw)
}

// devinIDString renders an id-ish JSON value (string or number) as a string.
func devinIDString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		return fmt.Sprintf("%v", t)
	}
	return ""
}

// devinExtractClientToolResults ports extractClientToolResults: tool_result
// content keyed by MCP tool name, walking assistant tool_calls/tool_use and
// role=tool / tool_result blocks.
func devinExtractClientToolResults(messages []any) map[string]string {
	idToMCPName := map[string]string{}
	results := map[string]string{}
	for _, raw := range messages {
		m, _ := raw.(map[string]any)
		if m == nil {
			continue
		}
		if m["role"] == "assistant" {
			if tcs, ok := m["tool_calls"].([]any); ok {
				for _, traw := range tcs {
					tc, _ := traw.(map[string]any)
					if tc == nil {
						continue
					}
					name := ""
					if fn, _ := tc["function"].(map[string]any); fn != nil {
						name = getStr(fn, "name")
					}
					if name == "" {
						name = getStr(tc, "name")
					}
					if id := devinIDString(tc["id"]); id != "" && name != "" {
						idToMCPName[id] = devinToMCPToolName(name)
					}
				}
			}
			if parts, ok := m["content"].([]any); ok {
				for _, praw := range parts {
					p, _ := praw.(map[string]any)
					if p != nil && p["type"] == "tool_use" && devinIDString(p["id"]) != "" && getStr(p, "name") != "" {
						idToMCPName[devinIDString(p["id"])] = devinToMCPToolName(getStr(p, "name"))
					}
				}
			}
		}
		if m["role"] == "tool" && devinIDString(m["tool_call_id"]) != "" {
			if mcpName, ok := idToMCPName[devinIDString(m["tool_call_id"])]; ok {
				results[mcpName] = devinStringify(m["content"])
			}
		}
		if m["role"] == "user" {
			if parts, ok := m["content"].([]any); ok {
				for _, praw := range parts {
					p, _ := praw.(map[string]any)
					if p == nil || p["type"] != "tool_result" {
						continue
					}
					if mcpName, ok := idToMCPName[devinIDString(p["tool_use_id"])]; ok {
						results[mcpName] = devinStringify(p["content"])
					}
				}
			}
		}
	}
	return results
}

// --- Workspace cwd resolution (resolveWorkspaceCwd) ---

var devinCwdTagRe = regexp.MustCompile(`(?i)<cwd>\s*([^<]+?)\s*</cwd>`)

func devinResolveWorkspaceCwd(body map[string]any) string {
	var candidates []string
	push := func(v any) {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			candidates = append(candidates, strings.TrimSpace(s))
		}
	}
	if body != nil {
		push(body["cwd"])
		push(body["working_directory"])
		push(body["workdir"])
		push(body["workspace"])
		if meta, _ := body["metadata"].(map[string]any); meta != nil {
			push(meta["cwd"])
			push(meta["working_directory"])
		}
	}
	scanText := func(text any) {
		s, ok := text.(string)
		if !ok {
			return
		}
		for _, m := range devinCwdTagRe.FindAllStringSubmatch(s, -1) {
			candidates = append(candidates, strings.TrimSpace(m[1]))
		}
	}
	scanMessages := func(msgs any) {
		arr, _ := msgs.([]any)
		for _, raw := range arr {
			scanText(raw) // Responses API input items may be bare strings
			msg, _ := raw.(map[string]any)
			if msg == nil {
				continue
			}
			scanText(msg["content"])
			if parts, ok := msg["content"].([]any); ok {
				for _, praw := range parts {
					scanText(praw)
					if p, _ := praw.(map[string]any); p != nil {
						scanText(p["text"])
						scanText(p["input_text"])
						scanText(p["content"])
					}
				}
			}
			if msg["type"] == "message" {
				if parts, ok := msg["content"].([]any); ok {
					for _, praw := range parts {
						if p, _ := praw.(map[string]any); p != nil {
							if t := getStr(p, "text"); t != "" {
								scanText(t)
							} else {
								scanText(getStr(p, "input_text"))
							}
						}
					}
				}
			}
		}
	}
	if body != nil {
		scanMessages(body["messages"])
		scanMessages(body["input"])
	}
	for _, c := range candidates {
		if filepath.IsAbs(c) {
			if info, err := os.Stat(c); err == nil && info.IsDir() {
				return c
			}
		}
	}
	return os.TempDir()
}

// --- Prompt builder (buildPromptText) ---

// devinBuildPromptText ports buildPromptText: the whole conversation is
// inlined into one prompt, including prior tool_calls / tool_results so the
// agent can continue after a client round-trip.
func devinBuildPromptText(messages []any) string {
	var lines []string
	for _, raw := range messages {
		m, _ := raw.(map[string]any)
		if m == nil {
			continue
		}
		role, _ := m["role"].(string)
		if role == "" {
			role = "user"
		}
		text := ""
		switch content := m["content"].(type) {
		case string:
			text = content
		case []any:
			for _, praw := range content {
				p, _ := praw.(map[string]any)
				if p == nil {
					continue
				}
				switch p["type"] {
				case "text":
					text += getStr(p, "text")
				case "tool_use":
					inputJSON, _ := json.Marshal(devinOrEmptyObject(p["input"]))
					text += fmt.Sprintf("\n[Tool call %s id=%s]\n%s\n", getStr(p, "name"), devinIDString(p["id"]), string(inputJSON))
				case "tool_result":
					text += fmt.Sprintf("\n[Tool result id=%s]\n%s\n", devinIDString(p["tool_use_id"]), devinStringify(p["content"]))
				}
			}
		}
		if role == "assistant" {
			if tcs, ok := m["tool_calls"].([]any); ok && len(tcs) > 0 {
				var parts []string
				for _, traw := range tcs {
					tc, _ := traw.(map[string]any)
					if tc == nil {
						continue
					}
					name := "tool"
					var args any
					if fn, _ := tc["function"].(map[string]any); fn != nil {
						if n := getStr(fn, "name"); n != "" {
							name = n
						}
						args = fn["arguments"]
					}
					if getStr(tc, "name") != "" && name == "tool" {
						name = getStr(tc, "name")
					}
					if args == nil {
						args = tc["arguments"]
					}
					argStr, _ := args.(string)
					if argStr == "" {
						raw, _ := json.Marshal(devinOrEmptyObject(args))
						argStr = string(raw)
					}
					parts = append(parts, fmt.Sprintf("[Tool call %s id=%s]\n%s", name, devinIDString(tc["id"]), argStr))
				}
				var joined []string
				if text != "" {
					joined = append(joined, text)
				}
				joined = append(joined, parts...)
				text = strings.Join(joined, "\n\n")
			}
		}
		if role == "tool" {
			text = fmt.Sprintf("[Tool result id=%s]\n%s", devinIDString(m["tool_call_id"]), devinStringify(m["content"]))
		}
		if strings.TrimSpace(text) == "" {
			continue
		}
		switch role {
		case "system":
			lines = append(lines, "[System]\n"+text)
		case "assistant":
			lines = append(lines, "[Assistant]\n"+text)
		case "tool":
			lines = append(lines, "[Tool]\n"+text)
		default:
			lines = append(lines, "[User]\n"+text)
		}
	}
	if len(lines) == 0 {
		return "(empty)"
	}
	return strings.Join(lines, "\n\n")
}

func devinOrEmptyObject(v any) any {
	if v == nil {
		return map[string]any{}
	}
	return v
}

// devinExtractResultText ports extractResultText (final session/prompt
// result shapes).
func devinExtractResultText(result map[string]any) string {
	if result == nil {
		return ""
	}
	if s := getStr(result, "content"); s != "" {
		return s
	}
	if s := getStr(result, "text"); s != "" {
		return s
	}
	if msg, _ := result["message"].(map[string]any); msg != nil {
		if s := getStr(msg, "content"); s != "" {
			return s
		}
	}
	if msgs, ok := result["messages"].([]any); ok {
		var parts []string
		for _, raw := range msgs {
			m, _ := raw.(map[string]any)
			if m != nil && m["role"] == "assistant" {
				parts = append(parts, getStr(m, "content"))
			}
		}
		return strings.Join(parts, "\n")
	}
	return ""
}

// --- Execute: ACP subprocess session ---

// Execute runs one ACP session against the devin subprocess and returns a
// 200 text/event-stream response of OpenAI chunks (JS execute()).
func (d *DevinCLIExecutor) Execute(ctx context.Context, p *ProviderInfo, cred Credential, body []byte) (*ExecResult, error) {
	bodyMap := BodyMap(body)
	if bodyMap == nil {
		bodyMap = map[string]any{}
	}
	model := ModelOf(bodyMap)
	var messages []any
	if arr, ok := bodyMap["messages"].([]any); ok {
		messages = arr
	} else if arr, ok := bodyMap["input"].([]any); ok {
		messages = arr
	}
	promptText := devinBuildPromptText(messages)
	workspaceCwd := devinResolveWorkspaceCwd(bodyMap)
	devinBin := devinResolveBin()

	// MCP servers: DEVIN_MCP_SERVERS env (devin config format) + body.tools
	// exposed as the "clientTools" MCP server.
	mcpServers := map[string]devinMCPServer{}
	if mcpJSON := strings.TrimSpace(os.Getenv("DEVIN_MCP_SERVERS")); mcpJSON != "" {
		var parsed map[string]map[string]any
		if err := json.Unmarshal([]byte(mcpJSON), &parsed); err == nil {
			for k, v := range parsed {
				mcpServers[k] = devinMCPServer{Raw: v}
			}
		}
	}
	var clientTools []any
	if arr, ok := bodyMap["tools"].([]any); ok {
		for _, t := range arr {
			if t != nil {
				clientTools = append(clientTools, t)
			}
		}
	}
	clientToolResults := devinExtractClientToolResults(messages)
	clientToolsMCP := devinBuildClientToolsMCP(clientTools, clientToolResults)
	hasClientTools := clientToolsMCP != nil
	if clientToolsMCP != nil {
		mcpServers["clientTools"] = *clientToolsMCP
	}

	// Throwaway XDG_CONFIG_HOME holding devin/config.json so the agent
	// auto-connects the MCP servers (cleaned up when the turn finishes).
	var mcpConfigDir string
	if len(mcpServers) > 0 {
		if dir, err := os.MkdirTemp("", "devin-mcp-"); err == nil {
			cfgDir := filepath.Join(dir, "devin")
			if err := os.MkdirAll(cfgDir, 0o755); err == nil {
				cfgJSON, _ := json.Marshal(map[string]any{"mcpServers": mcpServers})
				if err := os.WriteFile(filepath.Join(cfgDir, "config.json"), cfgJSON, 0o644); err == nil {
					mcpConfigDir = dir
				}
			}
			if mcpConfigDir == "" {
				os.RemoveAll(dir)
			}
		}
	}
	cleanupMCP := func() {
		if mcpConfigDir != "" {
			os.RemoveAll(mcpConfigDir)
			mcpConfigDir = ""
		}
	}

	transformed, _ := json.Marshal(map[string]any{
		"model":             model,
		"cwd":               workspaceCwd,
		"clientTools":       devinToolNames(clientTools),
		"clientToolResults": devinMapKeys(clientToolResults),
		"mcpServers":        devinMCPKeys(mcpServers),
		"promptLength":      len(messages),
	})
	result := &ExecResult{URL: devinURL, Headers: map[string]string{}, TransformedBody: transformed}

	// Child environment: inherit the parent env (devin resolves its stored
	// CLI credentials from it). Do NOT inject any API key — this provider is
	// noAuth and a bogus key overrides stored creds in devin.
	env := os.Environ()
	env = devinSetEnv(env, "DEVIN_PERMISSION_MODE", firstNonEmpty(os.Getenv("DEVIN_PERMISSION_MODE"), "bypass"))
	if mcpConfigDir != "" {
		env = devinSetEnv(env, "XDG_CONFIG_HOME", mcpConfigDir)
	}
	acpArgs := []string{"acp"}
	if agentType := strings.TrimSpace(os.Getenv("CLI_DEVIN_AGENT_TYPE")); agentType != "" {
		acpArgs = append(acpArgs, "--agent-type", agentType)
	}

	cmd := exec.Command(devinBin, acpArgs...)
	cmd.Dir = workspaceCwd
	cmd.Env = env
	// NOTE: the JS spawns with shell:true on Windows (devin.exe resolution);
	// Go's exec has no shell mode — on Windows the binary is expected to be
	// resolvable directly (installer .exe path from devinResolveBin).
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		cleanupMCP()
		return nil, err
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		cleanupMCP()
		return nil, err
	}
	cmd.Stderr = io.Discard // JS only debug-logs stderr

	pr, pw := io.Pipe()
	result.Response = &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header: http.Header{
			"Content-Type":  []string{"text/event-stream"},
			"Cache-Control": []string{"no-cache"},
			"Connection":    []string{"keep-alive"},
		},
		Body: pr,
	}

	if err := cmd.Start(); err != nil {
		// JS child "error" event: an SSE error chunk + [DONE], still HTTP 200.
		cleanupMCP()
		msg := "Devin CLI spawn error: " + err.Error()
		if os.IsNotExist(err) || strings.Contains(err.Error(), "no such file") || strings.Contains(err.Error(), "not found") {
			msg = fmt.Sprintf("Devin CLI not found: %s. Install via https://cli.devin.ai or set CLI_DEVIN_BIN env var.", devinBin)
		}
		errChunk, _ := json.Marshal(map[string]any{"error": map[string]any{
			"message": msg, "type": "devin_cli_error", "code": "spawn_failed",
		}})
		payload := "data: " + string(errChunk) + "\n\ndata: [DONE]\n\n"
		result.Response.Body = io.NopCloser(strings.NewReader(payload))
		return result, nil
	}

	sess := &devinSession{
		cmd:        cmd,
		stdin:      stdinPipe,
		model:      model,
		promptText: promptText,
		cwd:        workspaceCwd,
		hasTools:   hasClientTools,
		out:        pw,
		// JS responseId/created are fixed at session start.
		responseID: fmt.Sprintf("chatcmpl-devin-%d", time.Now().UnixMilli()),
		created:    time.Now().Unix(),
		cleanup:    cleanupMCP,
		done:       make(chan struct{}),
	}
	// Caller abort kills the subprocess (JS signal → SIGTERM).
	go func() {
		select {
		case <-ctx.Done():
			sess.kill("SIGTERM")
		case <-sess.done:
		}
	}()
	go sess.run(stdoutPipe)
	return result, nil
}

func devinToolNames(tools []any) []string {
	var names []string
	for _, t := range tools {
		tm, _ := t.(map[string]any)
		if tm == nil {
			continue
		}
		name := ""
		if fn, _ := tm["function"].(map[string]any); fn != nil {
			name = getStr(fn, "name")
		}
		if name == "" {
			name = getStr(tm, "name")
		}
		if name != "" {
			names = append(names, name)
		}
	}
	if names == nil {
		names = []string{}
	}
	return names
}

func devinMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	if keys == nil {
		keys = []string{}
	}
	return keys
}

func devinMCPKeys(m map[string]devinMCPServer) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	if keys == nil {
		keys = []string{}
	}
	return keys
}

// devinSetEnv sets or replaces one key in an os.Environ()-style slice.
func devinSetEnv(env []string, key, value string) []string {
	prefix := key + "="
	for i, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

// devinSession is the per-request ACP state machine (the JS ReadableStream
// start() closure). All fields are touched only from run()'s goroutine,
// except kill state guarded by mu.
type devinSession struct {
	cmd        *exec.Cmd
	stdin      io.WriteCloser
	model      string
	promptText string
	cwd        string
	hasTools   bool
	out        *io.PipeWriter
	responseID string
	created    int64
	cleanup    func()

	done chan struct{}

	mu         sync.Mutex
	killed     bool
	stdinDone  bool
	idCounter  int
	sessionID  string
	initDone   bool
	sessDone   bool
	promptSent bool

	roleEmitted    bool
	totalText      string
	finished       bool
	toolUseEmitted bool
	pendingTools   map[string]string // toolCallId → original tool name
}

func (s *devinSession) kill(_ string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.killed && s.cmd.Process != nil {
		s.killed = true
		_ = s.cmd.Process.Kill()
	}
}

// run is the stdout NDJSON reader + state machine (JS child.stdout handler).
func (s *devinSession) run(stdout io.Reader) {
	defer close(s.done)
	defer func() {
		// Reap the child whenever the session ends.
		go func() { _ = s.cmd.Wait() }()
	}()
	s.pendingTools = map[string]string{}

	// Send initialize.
	s.sendRPC("initialize", map[string]any{
		"protocolVersion": "0.3",
		"clientInfo":      map[string]any{"name": "9router", "version": "1.0"},
		"capabilities":    map[string]any{},
	})

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var msg map[string]any
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			continue // ignore non-JSON lines (banner text, etc.)
		}
		if s.handleMessage(msg) {
			return
		}
		if s.finished {
			return
		}
	}
	// EOF on stdout (child exited): JS child "close" handler finishes the
	// turn (an error message is only synthesised for a non-zero exit with
	// nothing emitted; here stdout EOF without a prior finish completes
	// normally — the kill-after-finish path has already run by then).
	if !s.finished {
		s.finish(nil, "stop")
	}
}

// handleMessage processes one ACP message; returns true when the read loop
// should stop (JS `return` inside the data handler after finish()).
func (s *devinSession) handleMessage(msg map[string]any) bool {
	_, hasResult := msg["result"]
	_, hasMethod := msg["method"]

	// Initialize response → session/new.
	if !s.initDone && hasResult && !hasMethod {
		s.initDone = true
		params := map[string]any{
			"cwd":        s.cwd,
			"mcpServers": []any{},
		}
		if s.model != "" {
			params["model"] = s.model
		}
		s.sendRPC("session/new", params)
		return false
	}

	// session/new response → session/prompt.
	if s.initDone && !s.sessDone && hasResult && !hasMethod {
		res, _ := msg["result"].(map[string]any)
		s.sessionID = getStr(res, "sessionId")
		if s.sessionID == "" {
			s.finish(fmt.Errorf("Devin ACP: session/new returned no sessionId"), "stop")
			return true
		}
		s.sessDone = true
		s.promptSent = true
		s.sendRPC("session/prompt", map[string]any{
			"sessionId": s.sessionID,
			"prompt":    []any{map[string]any{"type": "text", "text": s.promptText}},
		})
		return false
	}

	// session/prompt response (final result, after streaming).
	if s.sessDone && s.promptSent && hasResult && !hasMethod {
		if !s.roleEmitted {
			res, _ := msg["result"].(map[string]any)
			if content := devinExtractResultText(res); content != "" {
				s.emitDelta(content)
			}
			stopReason := getStr(res, "stopReason")
			if stopReason != "" && stopReason != "cancelled" {
				s.finish(nil, "stop")
				return true
			}
		}
		return false
	}

	method := getStr(msg, "method")

	// Permission requests → auto-approve the first allow option.
	if method == "session/request_permission" {
		if _, hasID := msg["id"]; hasID {
			params, _ := msg["params"].(map[string]any)
			options, _ := params["options"].([]any)
			var allow map[string]any
			for _, oraw := range options {
				o, _ := oraw.(map[string]any)
				if o != nil && strings.Contains(strings.ToLower(getStr(o, "kind")), "allow") {
					allow = o
					break
				}
			}
			if allow == nil && len(options) > 0 {
				allow, _ = options[0].(map[string]any)
			}
			if allow != nil {
				s.writeRaw(map[string]any{
					"jsonrpc": "2.0",
					"id":      msg["id"],
					"result": map[string]any{"outcome": map[string]any{
						"outcome": "selected", "optionId": allow["optionId"],
					}},
				})
			}
		}
		return false
	}

	// Agent stopped notification.
	if method == "_cognition.ai/agent_stopped" || method == "$/agent_stopped" {
		params, _ := msg["params"].(map[string]any)
		if getStr(params, "cause") == "error" {
			errText := firstNonEmpty(getStr(params, "errorMessage"), getStr(params, "message"), getStr(params, "error"), "Devin agent error")
			s.finish(fmt.Errorf("%s", errText), "stop")
		} else {
			s.finish(nil, "stop")
		}
		return true
	}

	// Streaming notifications.
	if method == "session/update" || method == "$/update" {
		params, _ := msg["params"].(map[string]any)
		if params == nil {
			return false
		}
		update, _ := params["update"].(map[string]any)
		if update == nil {
			update = map[string]any{}
		}
		typ := getStr(update, "sessionUpdate")
		if typ == "" {
			typ = getStr(params, "type")
		}
		var contentField any
		if v, present := update["content"]; present {
			contentField = v
		} else {
			contentField = params["content"]
		}
		deltaText := ""
		switch c := contentField.(type) {
		case string:
			deltaText = c
		case map[string]any:
			deltaText = getStr(c, "text")
		}
		if deltaText == "" {
			deltaText = firstNonEmpty(getStr(params, "delta"), getStr(params, "text"))
		}

		// Client-tool bridge (upsert-by-id: title may arrive before rawInput).
		if s.hasTools && !s.toolUseEmitted && (typ == "tool_call" || typ == "tool_call_update") {
			tcID := devinIDString(update["toolCallId"])
			if title := getStr(update, "title"); strings.HasPrefix(title, "Calling mcp_") && devinClientToolsFromRe.MatchString(title) && devinClientToolsTitleRe.MatchString(title) {
				mcpName := devinClientToolsTitleRe.FindStringSubmatch(title)[1]
				if orig := devinFromMCPToolName(mcpName); tcID != "" && orig != "" {
					s.pendingTools[tcID] = orig
				}
			}
			origName := s.pendingTools[tcID]
			if origName != "" {
				if rawInput, present := update["rawInput"]; present && rawInput != nil {
					s.toolUseEmitted = true
					delete(s.pendingTools, tcID)
					callID := tcID
					if callID == "" {
						callID = fmt.Sprintf("call_%d", time.Now().UnixMilli())
					}
					s.emitToolUse(origName, rawInput, callID)
					s.finish(nil, "tool_calls")
					return true
				}
			}
			return false
		}

		switch typ {
		case "agent_message_chunk", "message_delta", "text_delta", "content_delta":
			if deltaText != "" {
				s.emitDelta(deltaText)
			}
		case "agent_thought_chunk":
			// Internal reasoning — not surfaced.
		case "message_stop", "stop", "done":
			s.finish(nil, "stop")
			return true
		case "error":
			errText := firstNonEmpty(getStr(params, "message"), getStr(params, "error"), "Devin ACP error")
			s.finish(fmt.Errorf("%s", errText), "stop")
			return true
		}
		return false
	}

	// Error responses.
	if errObj, _ := msg["error"].(map[string]any); errObj != nil {
		code := int(getFloat(errObj, "code"))
		s.finish(fmt.Errorf("Devin ACP error %d: %s", code, getStr(errObj, "message")), "stop")
		return true
	}
	return false
}

var devinClientToolsTitleRe = regexp.MustCompile(`^Calling (mcp_\S+)\b`)
var devinClientToolsFromRe = regexp.MustCompile(`from clientTools\b`)

func (s *devinSession) sendRPC(method string, params map[string]any) {
	s.idCounter++
	s.writeRaw(map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      s.idCounter,
	})
}

func (s *devinSession) writeRaw(msg map[string]any) {
	s.mu.Lock()
	closed := s.stdinDone
	s.mu.Unlock()
	if closed || s.stdin == nil {
		return
	}
	raw, err := json.Marshal(msg)
	if err != nil {
		return
	}
	_, _ = s.stdin.Write(append(raw, '\n'))
}

// emitDelta emits a content delta as an OpenAI SSE chunk (leading role chunk
// once).
func (s *devinSession) emitDelta(delta string) {
	if !s.roleEmitted {
		s.emitChunk(map[string]any{"role": "assistant", "content": ""}, nil)
		s.roleEmitted = true
	}
	s.totalText += delta
	s.emitChunk(map[string]any{"content": delta}, nil)
}

// emitToolUse emits an OpenAI tool_call delta.
func (s *devinSession) emitToolUse(toolName string, args any, toolCallID string) {
	argsStr, _ := args.(string)
	if argsStr == "" {
		raw, _ := json.Marshal(devinOrEmptyObject(args))
		argsStr = string(raw)
	}
	if !s.roleEmitted {
		s.emitChunk(map[string]any{"role": "assistant", "content": nil}, nil)
		s.roleEmitted = true
	}
	s.emitChunk(map[string]any{
		"tool_calls": []any{map[string]any{
			"index": 0,
			"id":    toolCallID,
			"type":  "function",
			"function": map[string]any{
				"name":      toolName,
				"arguments": argsStr,
			},
		}},
	}, nil)
}

func (s *devinSession) emitChunk(delta map[string]any, finishReason any) {
	chunk := map[string]any{
		"id":      s.responseID,
		"object":  "chat.completion.chunk",
		"created": s.created,
		"model":   s.model,
		"choices": []any{map[string]any{
			"index":         0,
			"delta":         delta,
			"finish_reason": finishReason,
		}},
	}
	raw, _ := json.Marshal(chunk)
	_, _ = io.WriteString(s.out, "data: "+string(raw)+"\n\n")
}

// finish emits the terminal chunk (or an error chunk), [DONE], closes stdin
// and schedules a SIGKILL if the child doesn't exit within 2s (JS finish()).
func (s *devinSession) finish(err error, finishReason string) {
	if s.finished {
		return
	}
	s.finished = true
	if err != nil {
		raw, _ := json.Marshal(map[string]any{"error": map[string]any{
			"message": err.Error(), "type": "devin_cli_error",
		}})
		_, _ = io.WriteString(s.out, "data: "+string(raw)+"\n\n")
	} else {
		chunk := map[string]any{
			"id":      s.responseID,
			"object":  "chat.completion.chunk",
			"created": s.created,
			"model":   s.model,
			"choices": []any{map[string]any{
				"index":         0,
				"delta":         map[string]any{},
				"finish_reason": finishReason,
			}},
			"usage": map[string]any{
				"prompt_tokens":     int(math.Ceil(float64(len(s.promptText)) / 4)),
				"completion_tokens": int(math.Ceil(float64(len(s.totalText)) / 4)),
				"total_tokens":      int(math.Ceil(float64(len(s.promptText)+len(s.totalText)) / 4)),
				"estimated":         true,
			},
		}
		raw, _ := json.Marshal(chunk)
		_, _ = io.WriteString(s.out, "data: "+string(raw)+"\n\n")
	}
	_, _ = io.WriteString(s.out, "data: [DONE]\n\n")

	s.mu.Lock()
	if !s.stdinDone && s.stdin != nil {
		s.stdinDone = true
		_ = s.stdin.Close()
	}
	s.mu.Unlock()

	// Give it 2s to exit cleanly, then SIGKILL.
	go func() {
		time.Sleep(2 * time.Second)
		s.kill("SIGKILL")
	}()

	_ = s.out.Close()
	if s.cleanup != nil {
		s.cleanup()
	}
}
