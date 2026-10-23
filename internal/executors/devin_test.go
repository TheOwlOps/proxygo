package executors

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// devinFakeACPScript is a stand-in `devin` binary implementing just enough
// of the ACP stdio protocol for the integration tests. Behaviour is selected
// with FAKE_DEVIN_MODE (inherited through the child env): "" streams two
// text chunks then agent_stopped; "tools" calls the clientTools MCP bridge;
// "perm" first asks session/request_permission, then streams.
const devinFakeACPScript = `#!/usr/bin/env bash
while IFS= read -r line; do
  case "$line" in
    *'"method":"initialize"'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"0.3"}}'
      ;;
    *'"method":"session/new"'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"sessionId":"sess-1"}}'
      ;;
    *'"method":"session/prompt"'*)
      if [ "$FAKE_DEVIN_MODE" = "tools" ]; then
        printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"update":{"sessionUpdate":"tool_call","toolCallId":"tc1","title":"Calling mcp_get_weather from clientTools"}}}'
        printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"update":{"sessionUpdate":"tool_call_update","toolCallId":"tc1","rawInput":{"city":"Hanoi"}}}}'
      elif [ "$FAKE_DEVIN_MODE" = "perm" ]; then
        printf '%s\n' '{"jsonrpc":"2.0","id":99,"method":"session/request_permission","params":{"options":[{"optionId":"deny1","kind":"deny"},{"optionId":"allow1","kind":"allow_once"}]}}'
        printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"after perm"}}}}'
        printf '%s\n' '{"jsonrpc":"2.0","method":"_cognition.ai/agent_stopped","params":{}}'
      else
        printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"Hello "}}}}'
        printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"world"}}}}'
        printf '%s\n' '{"jsonrpc":"2.0","method":"_cognition.ai/agent_stopped","params":{}}'
      fi
      ;;
  esac
done
`

func devinWriteFakeBin(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "devin")
	if err := os.WriteFile(path, []byte(devinFakeACPScript), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDevinBuildPromptText(t *testing.T) {
	messages := []any{
		map[string]any{"role": "system", "content": "be terse"},
		map[string]any{"role": "user", "content": "hi"},
		map[string]any{"role": "assistant", "content": "done", "tool_calls": []any{
			map[string]any{"id": "c1", "function": map[string]any{"name": "read_file", "arguments": `{"path":"a.go"}`}},
		}},
		map[string]any{"role": "tool", "tool_call_id": "c1", "content": "file body"},
		map[string]any{"role": "user", "content": []any{
			map[string]any{"type": "text", "text": "next"},
			map[string]any{"type": "tool_result", "tool_use_id": "c9", "content": "res"},
		}},
		map[string]any{"role": "user", "content": "   "}, // skipped: empty
	}
	got := devinBuildPromptText(messages)
	for _, want := range []string{
		"[System]\nbe terse",
		"[User]\nhi",
		"[Assistant]\ndone\n\n[Tool call read_file id=c1]\n{\"path\":\"a.go\"}",
		"[Tool]\n[Tool result id=c1]\nfile body",
		"[User]\nnext\n[Tool result id=c9]\nres\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("prompt missing %q\nfull prompt:\n%s", want, got)
		}
	}
	if got := devinBuildPromptText(nil); got != "(empty)" {
		t.Fatalf("empty prompt = %q", got)
	}
}

func TestDevinResolveWorkspaceCwd(t *testing.T) {
	dir := t.TempDir()
	if got := devinResolveWorkspaceCwd(map[string]any{"cwd": dir}); got != dir {
		t.Fatalf("body cwd = %q, want %q", got, dir)
	}
	body := map[string]any{"messages": []any{
		map[string]any{"role": "user", "content": "env <cwd>" + dir + "</cwd> end"},
	}}
	if got := devinResolveWorkspaceCwd(body); got != dir {
		t.Fatalf("<cwd> tag = %q, want %q", got, dir)
	}
	if got := devinResolveWorkspaceCwd(map[string]any{"cwd": "/definitely/not/a/real/dir/proxygo"}); got != os.TempDir() {
		t.Fatalf("fallback = %q, want os.TempDir()", got)
	}
}

func TestDevinExtractResultText(t *testing.T) {
	cases := []struct {
		in   map[string]any
		want string
	}{
		{map[string]any{"content": "a"}, "a"},
		{map[string]any{"text": "b"}, "b"},
		{map[string]any{"message": map[string]any{"content": "c"}}, "c"},
		{map[string]any{"messages": []any{
			map[string]any{"role": "user", "content": "x"},
			map[string]any{"role": "assistant", "content": "d"},
			map[string]any{"role": "assistant", "content": "e"},
		}}, "d\ne"},
		{map[string]any{}, ""},
		{nil, ""},
	}
	for _, tc := range cases {
		if got := devinExtractResultText(tc.in); got != tc.want {
			t.Fatalf("extractResultText(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDevinClientToolsBridgeMapping(t *testing.T) {
	if devinToMCPToolName("get_weather") != "mcp_get_weather" || devinToMCPToolName("mcp_x") != "mcp_x" {
		t.Fatal("toMcpToolName mismatch")
	}
	if devinFromMCPToolName("mcp_get_weather") != "get_weather" || devinFromMCPToolName("plain") != "plain" {
		t.Fatal("fromMcpToolName mismatch")
	}
	tools := []any{
		map[string]any{"type": "function", "function": map[string]any{
			"name": "get_weather", "description": "weather",
			"parameters": map[string]any{"type": "object", "properties": map[string]any{"city": map[string]any{"type": "string"}}},
		}},
		map[string]any{"name": "bare_tool"},
		map[string]any{"type": "function", "function": map[string]any{}}, // no name: skipped
		nil,
	}
	srv := devinBuildClientToolsMCP(tools, map[string]string{"mcp_get_weather": "sunny"})
	if srv == nil {
		t.Fatal("expected MCP server entry")
	}
	var declared []map[string]any
	if err := json.Unmarshal([]byte(srv.Env["DEVIN_MCP_TOOLS"]), &declared); err != nil {
		t.Fatal(err)
	}
	if len(declared) != 2 || declared[0]["name"] != "mcp_get_weather" || declared[1]["name"] != "mcp_bare_tool" {
		t.Fatalf("declared tools = %v", declared)
	}
	if declared[1]["inputSchema"].(map[string]any)["type"] != "object" {
		t.Fatalf("default inputSchema = %v", declared[1]["inputSchema"])
	}
	if !strings.Contains(srv.Env["DEVIN_MCP_RESULTS"], "sunny") {
		t.Fatalf("seeded results env = %q", srv.Env["DEVIN_MCP_RESULTS"])
	}
	if devinBuildClientToolsMCP(nil, nil) != nil {
		t.Fatal("no tools must yield nil MCP server")
	}
}

func TestDevinExtractClientToolResults(t *testing.T) {
	messages := []any{
		map[string]any{"role": "assistant", "tool_calls": []any{
			map[string]any{"id": "c1", "function": map[string]any{"name": "get_weather"}},
		}},
		map[string]any{"role": "tool", "tool_call_id": "c1", "content": "sunny"},
		map[string]any{"role": "assistant", "content": []any{
			map[string]any{"type": "tool_use", "id": "c2", "name": "read_file"},
		}},
		map[string]any{"role": "user", "content": []any{
			map[string]any{"type": "tool_result", "tool_use_id": "c2", "content": []any{map[string]any{"type": "text", "text": "body"}}},
		}},
	}
	results := devinExtractClientToolResults(messages)
	if results["mcp_get_weather"] != "sunny" {
		t.Fatalf("openai tool result = %v", results)
	}
	if !strings.Contains(results["mcp_read_file"], "body") {
		t.Fatalf("claude tool result = %v", results)
	}
}

func TestDevinExecutorStreamsViaFakeACP(t *testing.T) {
	t.Setenv("CLI_DEVIN_BIN", devinWriteFakeBin(t))
	ws := t.TempDir()
	ex := NewDevinCLIExecutor()
	res, err := ex.Execute(context.Background(), &ProviderInfo{ID: "devin-cli"}, Credential{},
		[]byte(`{"model":"swe-1.6","cwd":"`+ws+`","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if res.URL != "devin://acp/stdio" || res.ResponseFormat != "" {
		t.Fatalf("result url/format = %q/%q", res.URL, res.ResponseFormat)
	}
	body := readBody(t, res.Response)
	for _, want := range []string{`"role":"assistant"`, "Hello ", "world", `"finish_reason":"stop"`, `"estimated":true`, "[DONE]"} {
		if !strings.Contains(body, want) {
			t.Fatalf("SSE missing %q\nbody:\n%s", want, body)
		}
	}
	var transformed map[string]any
	if err := json.Unmarshal(res.TransformedBody, &transformed); err != nil {
		t.Fatal(err)
	}
	if transformed["cwd"] != ws || transformed["model"] != "swe-1.6" {
		t.Fatalf("transformedBody = %v", transformed)
	}
}

func TestDevinExecutorClientToolBridge(t *testing.T) {
	t.Setenv("CLI_DEVIN_BIN", devinWriteFakeBin(t))
	t.Setenv("FAKE_DEVIN_MODE", "tools")
	ex := NewDevinCLIExecutor()
	res, err := ex.Execute(context.Background(), &ProviderInfo{ID: "devin-cli"}, Credential{},
		[]byte(`{"model":"swe-1.6","messages":[{"role":"user","content":"weather?"}],"tools":[{"type":"function","function":{"name":"get_weather","parameters":{"type":"object","properties":{}}}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	for _, want := range []string{`"tool_calls"`, `"name":"get_weather"`, `"arguments":"{\"city\":\"Hanoi\"}"`, `"finish_reason":"tool_calls"`, "[DONE]"} {
		if !strings.Contains(body, want) {
			t.Fatalf("tool bridge SSE missing %q\nbody:\n%s", want, body)
		}
	}
	if strings.Contains(body, "mcp_get_weather") {
		t.Fatalf("mcp_ prefix must be stripped in the bridged call:\n%s", body)
	}
}

func TestDevinExecutorPermissionAutoApprove(t *testing.T) {
	t.Setenv("CLI_DEVIN_BIN", devinWriteFakeBin(t))
	t.Setenv("FAKE_DEVIN_MODE", "perm")
	ex := NewDevinCLIExecutor()
	res, err := ex.Execute(context.Background(), &ProviderInfo{ID: "devin-cli"}, Credential{},
		[]byte(`{"model":"swe-1.6","messages":[{"role":"user","content":"run ls"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	if !strings.Contains(body, "after perm") || !strings.Contains(body, `"finish_reason":"stop"`) {
		t.Fatalf("permission flow SSE = %s", body)
	}
}

func TestDevinExecutorSpawnNotFound(t *testing.T) {
	t.Setenv("CLI_DEVIN_BIN", filepath.Join(t.TempDir(), "no-such-devin"))
	ex := NewDevinCLIExecutor()
	res, err := ex.Execute(context.Background(), &ProviderInfo{ID: "devin-cli"}, Credential{},
		[]byte(`{"model":"swe-1.6","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	if !strings.Contains(body, "Devin CLI not found") || !strings.Contains(body, `"code":"spawn_failed"`) || !strings.Contains(body, "[DONE]") {
		t.Fatalf("spawn failure SSE = %s", body)
	}
}
