package rtk

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// dedupPayload is >500 chars of identical log lines: autodetect must
// route it to dedup-log (no colons-for-grep, not path-like).
func dedupPayload() string {
	return strings.Repeat("2024-01-01 INFO worker heartbeat ok status nominal\n", 20)
}

func gitDiffPayload() string {
	// A 130-pair hunk: the per-hunk cap (100 lines) truncates it, which is
	// where the savings come from (a fully-kept diff cannot shrink).
	var b strings.Builder
	b.WriteString("diff --git a/main.go b/main.go\n--- a/main.go\n+++ b/main.go\n@@ -1,130 +1,130 @@\n")
	for i := 1; i <= 130; i++ {
		fmt.Fprintf(&b, "-old line %d with some padding text here\n", i)
		fmt.Fprintf(&b, "+new line %d with some padding text here\n", i)
	}
	return b.String()
}

func toolBody(content string) map[string]any {
	return map[string]any{
		"model":    "test/model",
		"messages": []any{map[string]any{"role": "tool", "content": content}},
	}
}

func toolContent(t *testing.T, body map[string]any) string {
	t.Helper()
	msgs := body["messages"].([]any)
	msg := msgs[0].(map[string]any)
	s, ok := msg["content"].(string)
	if !ok {
		t.Fatalf("content is not a string: %T", msg["content"])
	}
	return s
}

func TestCompressDisabledAndNil(t *testing.T) {
	body := toolBody(dedupPayload())
	if stats := CompressMessages(body, false); stats != nil {
		t.Fatalf("disabled should return nil stats, got %+v", stats)
	}
	if toolContent(t, body) != dedupPayload() {
		t.Fatal("disabled must not touch the body")
	}
	if stats := CompressMessages(nil, true); stats != nil {
		t.Fatalf("nil body should return nil, got %+v", stats)
	}
	if stats := CompressMessages(map[string]any{"model": "x"}, true); stats != nil {
		t.Fatalf("body without messages/input should return nil, got %+v", stats)
	}
}

func TestCompressOpenAIToolGitDiff(t *testing.T) {
	payload := gitDiffPayload()
	body := toolBody(payload)
	stats := CompressMessages(body, true)
	if stats == nil || len(stats.Hits) != 1 {
		t.Fatalf("expected 1 hit, got %+v", stats)
	}
	if stats.Hits[0].Filter != FilterGitDiff || stats.Hits[0].Shape != "openai-tool" {
		t.Fatalf("unexpected hit: %+v", stats.Hits[0])
	}
	out := toolContent(t, body)
	if len(out) >= len(payload) {
		t.Fatalf("output not smaller: %d >= %d", len(out), len(payload))
	}
	if !strings.Contains(out, "\nmain.go") || !strings.Contains(out, "+130 -130") || !strings.Contains(out, "(160 lines truncated)") {
		t.Fatalf("diff summary missing in output:\n%s", out)
	}
	log := FormatRtkLog(stats)
	if !strings.Contains(log, "[RTK] saved") || !strings.Contains(log, "git-diff") {
		t.Fatalf("bad log line: %q", log)
	}
}

func TestCompressGrepShape(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 12; i++ {
		fmt.Fprintf(&b, "src/alpha.go:%d: matched content with padding text\n", i+1)
		fmt.Fprintf(&b, "src/beta.go:%d: matched content with padding text\n", i+1)
	}
	body := map[string]any{"messages": []any{
		map[string]any{"role": "tool", "content": []any{
			map[string]any{"type": "text", "text": b.String()},
		}},
	}}
	stats := CompressMessages(body, true)
	if stats == nil || len(stats.Hits) != 1 || stats.Hits[0].Filter != FilterGrep {
		t.Fatalf("expected grep hit, got %+v", stats)
	}
	part := body["messages"].([]any)[0].(map[string]any)["content"].([]any)[0].(map[string]any)
	out := part["text"].(string)
	if !strings.Contains(out, "24 matches in 2F:") || !strings.Contains(out, "[file] src/alpha.go (12):") || !strings.Contains(out, "  +2\n") {
		t.Fatalf("grep grouping wrong:\n%s", out)
	}
}

func TestCompressFindShape(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 30; i++ {
		fmt.Fprintf(&b, "/home/user/proj/file%02d.txt\n", i)
	}
	body := toolBody(b.String())
	stats := CompressMessages(body, true)
	if stats == nil || len(stats.Hits) != 1 || stats.Hits[0].Filter != FilterFind {
		t.Fatalf("expected find hit, got %+v", stats)
	}
	out := toolContent(t, body)
	if !strings.Contains(out, "30 files in 1 dirs:") || !strings.Contains(out, "/home/user/proj/  (30)") || !strings.Contains(out, "  +20\n") {
		t.Fatalf("find grouping wrong:\n%s", out)
	}
}

func TestCompressLSAndGitStatus(t *testing.T) {
	var ls strings.Builder
	ls.WriteString("total 120\n")
	for i := 0; i < 15; i++ {
		fmt.Fprintf(&ls, "-rw-r--r-- 1 user group 2048 Jan 15 2024 file%02d.go\n", i)
	}
	ls.WriteString("drwxr-xr-x 2 user group 4096 Feb 20 2024 subdir\n")
	body := toolBody(ls.String())
	stats := CompressMessages(body, true)
	if stats == nil || len(stats.Hits) != 1 || stats.Hits[0].Filter != FilterLS {
		t.Fatalf("expected ls hit, got %+v", stats)
	}
	out := toolContent(t, body)
	if !strings.Contains(out, "file00.go  2.0K") || !strings.Contains(out, "subdir/") || !strings.Contains(out, "Summary: 15 files, 1 dirs (15 .go)") {
		t.Fatalf("ls output wrong:\n%s", out)
	}

	var gs strings.Builder
	gs.WriteString("On branch main\nChanges not staged for commit:\n")
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&gs, "\tmodified:   src/file%02d.go\n", i)
	}
	body = toolBody(gs.String())
	stats = CompressMessages(body, true)
	if stats == nil || len(stats.Hits) != 1 || stats.Hits[0].Filter != FilterGitStatus {
		t.Fatalf("expected git-status hit, got %+v", stats)
	}
	out = toolContent(t, body)
	if !strings.Contains(out, "* main") || !strings.Contains(out, "~ Modified: 20 files") || !strings.Contains(out, "... +10 more") {
		t.Fatalf("git-status output wrong:\n%s", out)
	}
}

func TestCompressDedupAndSmartTruncate(t *testing.T) {
	body := toolBody(dedupPayload())
	stats := CompressMessages(body, true)
	if stats == nil || len(stats.Hits) != 1 || stats.Hits[0].Filter != FilterDedupLog {
		t.Fatalf("expected dedup hit, got %+v", stats)
	}
	if out := toolContent(t, body); !strings.Contains(out, "(19 duplicate lines)") {
		t.Fatalf("dedup marker missing:\n%s", out)
	}

	// Smart truncate: <5 non-empty lines but >=250 lines total.
	var lines []string
	lines = append(lines, "first unique line with a fair amount of descriptive text in it ok")
	for i := 0; i < 294; i++ {
		lines = append(lines, "")
	}
	lines = append(lines,
		"second unique line with a fair amount of descriptive text in it ok",
		"third unique line with a fair amount of descriptive text in it ok",
		"fourth unique line with a fair amount of descriptive text in it")
	payload := strings.Join(lines, "\n")
	body = toolBody(payload)
	stats = CompressMessages(body, true)
	if stats == nil || len(stats.Hits) != 1 || stats.Hits[0].Filter != FilterSmartTruncate {
		t.Fatalf("expected smart-truncate hit, got %+v", stats)
	}
	if out := toolContent(t, body); !strings.Contains(out, "lines truncated") || strings.Contains(out, "(file continues)") {
		t.Fatalf("smart-truncate marker wrong:\n%.200s", out)
	}
}

func TestCompressClaudeToolResultAndErrorSkip(t *testing.T) {
	mk := func(isError bool) map[string]any {
		block := map[string]any{"type": "tool_result", "content": dedupPayload()}
		if isError {
			block["is_error"] = true
		}
		return map[string]any{"messages": []any{
			map[string]any{"role": "user", "content": []any{block}},
		}}
	}
	errBody := mk(true)
	CompressMessages(errBody, true)
	block := errBody["messages"].([]any)[0].(map[string]any)["content"].([]any)[0].(map[string]any)
	if block["content"] != dedupPayload() {
		t.Fatal("is_error tool_result must be preserved verbatim")
	}

	okBody := mk(false)
	stats := CompressMessages(okBody, true)
	if stats == nil || len(stats.Hits) != 1 || stats.Hits[0].Shape != "claude-string" {
		t.Fatalf("expected claude-string hit, got %+v", stats)
	}
}

func TestCompressResponsesShape(t *testing.T) {
	body := map[string]any{"input": []any{
		map[string]any{"type": "function_call_output", "output": dedupPayload()},
	}}
	stats := CompressMessages(body, true)
	if stats == nil || len(stats.Hits) != 1 || stats.Hits[0].Shape != "openai-responses-string" {
		t.Fatalf("expected responses hit, got %+v", stats)
	}
}

func TestCompressKiroShapeAndErrorSkip(t *testing.T) {
	mkResult := func(status, text string) map[string]any {
		return map[string]any{"status": status, "content": []any{map[string]any{"text": text}}}
	}
	errRes := mkResult("error", dedupPayload())
	okRes := mkResult("success", dedupPayload())
	body := map[string]any{"conversationState": map[string]any{
		"history": []any{map[string]any{"userInputMessage": map[string]any{
			"userInputMessageContext": map[string]any{"toolResults": []any{errRes, okRes}},
		}}},
	}}
	stats := CompressMessages(body, true)
	if stats == nil || len(stats.Hits) != 1 || stats.Hits[0].Shape != "kiro-tool-result" {
		t.Fatalf("expected one kiro hit, got %+v", stats)
	}
	if errRes["content"].([]any)[0].(map[string]any)["text"] != dedupPayload() {
		t.Fatal("kiro error tool result must be preserved")
	}
	if okRes["content"].([]any)[0].(map[string]any)["text"] == dedupPayload() {
		t.Fatal("kiro success tool result should have been compressed")
	}
}

func TestCompressFailOpenOnWeirdShapes(t *testing.T) {
	body := map[string]any{"messages": []any{
		map[string]any{"role": "tool", "content": 12345},
		map[string]any{"role": "user", "content": "plain"},
		"not-a-map",
		nil,
		map[string]any{"role": "user", "content": []any{
			map[string]any{"type": "tool_result", "content": 999},
			map[string]any{"type": "text", "text": "leave me"},
		}},
	}}
	stats := CompressMessages(body, true) // must not panic
	if stats == nil {
		t.Fatal("expected stats object for a walkable body")
	}
	first := body["messages"].([]any)[0].(map[string]any)
	if first["content"] != 12345 {
		t.Fatal("non-string content must be untouched")
	}
	// Below the min size: untouched.
	small := toolBody("tiny output")
	CompressMessages(small, true)
	if toolContent(t, small) != "tiny output" {
		t.Fatal("small payload must be untouched")
	}
}

func TestGitLogFilterDirect(t *testing.T) {
	input := "commit abc1234def5678\nAuthor: Dev <dev@example.com>\nDate:   Mon Jan 1 00:00:00 2024 +0000\n\n    Fix the thing\n\n    A long body paragraph that should be dropped entirely.\n    Another body line to drop.\n\ncommit 1234567abcdef0\nAuthor: Dev <dev@example.com>\nDate:   Tue Jan 2 00:00:00 2024 +0000\n\n    Second subject line here\n"
	out := GitLog(input)
	if !strings.Contains(out, "Subject: Fix the thing") || !strings.Contains(out, "Subject: Second subject line here") {
		t.Fatalf("subjects missing:\n%s", out)
	}
	if strings.Contains(out, "long body paragraph") {
		t.Fatalf("body should be dropped:\n%s", out)
	}
	if !strings.Contains(out, "Author: Dev <dev@example.com>") {
		t.Fatalf("author missing:\n%s", out)
	}
	oneLine := GitLog("abc1234 first commit subject\n1234567 second commit subject\n")
	if !strings.Contains(oneLine, "first commit subject") || !strings.Contains(oneLine, "second commit subject") {
		t.Fatalf("oneline mode broken:\n%s", oneLine)
	}
}

func TestGitDiffTruncationDirect(t *testing.T) {
	var b strings.Builder
	b.WriteString("diff --git a/big.go b/big.go\n@@ -1,150 +1,150 @@\n")
	for i := 0; i < 150; i++ {
		fmt.Fprintf(&b, "+added line %d\n", i)
	}
	out := GitDiff(b.String())
	if !strings.Contains(out, "(50 lines truncated)") || !strings.Contains(out, "[full diff: rtk git diff --no-compact]") || !strings.Contains(out, "+150 -0") {
		t.Fatalf("hunk truncation wrong:\n%.300s", out)
	}
}

func TestTreeSearchListBuildOutputDirect(t *testing.T) {
	treeOut := Tree("./\n├── src\n│   └── a.go\n└── b.go\n\n2 directories, 3 files\n")
	if strings.Contains(treeOut, "directories, 3 files") || !strings.Contains(treeOut, "a.go") {
		t.Fatalf("tree wrong:\n%s", treeOut)
	}

	var sl strings.Builder
	sl.WriteString("Result of search in '/proj' (total 15 files):\n")
	for i := 0; i < 13; i++ {
		fmt.Fprintf(&sl, "- /proj/src/f%02d.go\n", i)
	}
	sl.WriteString("- /proj/docs/a.md\n- /proj/docs/b.md\n")
	slOut := SearchList(sl.String())
	if !strings.Contains(slOut, "15 files in 2 dirs:") || !strings.Contains(slOut, "/proj/src/ (13):") || !strings.HasSuffix(slOut, "  +3") {
		t.Fatalf("search-list wrong:\n%s", slOut)
	}

	build := "Downloading pkg-a\nCompiling alpha\nCompiling beta\nnpm warn deprecated foo@1.0: old\nnpm warn deprecated bar@2.0: older\nnpm warn deprecated baz@3.0: oldest\nnpm warn deprecated qux@4.0: extra\nnpm ERR! code E404\nadded 42 packages in 3s\n"
	bo := BuildOutput(build)
	for _, want := range []string{"Downloaded 1 packages", "Compiled 2 packages", "npm ERR! code E404", "added 42 packages in 3s", "... +1 more deprecated packages"} {
		if !strings.Contains(bo, want) {
			t.Fatalf("build-output missing %q:\n%s", want, bo)
		}
	}
}

func TestTruncateFiltersDirect(t *testing.T) {
	var lines []string
	for i := 0; i < 300; i++ {
		lines = append(lines, fmt.Sprintf("line %d", i))
	}
	out := SmartTruncate(strings.Join(lines, "\n"))
	if !strings.Contains(out, "... +120 lines truncated") || !strings.Contains(out, "line 0") || !strings.Contains(out, "line 299") {
		t.Fatalf("smart-truncate wrong")
	}
	if SmartTruncate("a\nb") != "a\nb" {
		t.Fatal("smart-truncate must pass through short input")
	}

	var numbered []string
	for i := 1; i <= 300; i++ {
		numbered = append(numbered, fmt.Sprintf("%d|content", i))
	}
	out = ReadNumbered(strings.Join(numbered, "\n"))
	if !strings.Contains(out, "... +120 lines truncated (file continues)") {
		t.Fatalf("read-numbered marker wrong")
	}
}

func TestRegistryAndDetect(t *testing.T) {
	if ResolveFilter("git-diff") == nil || ResolveFilter("nope") != nil {
		t.Fatal("registry lookup broken")
	}
	if reflect.ValueOf(ResolveFilter("rg")).Pointer() != reflect.ValueOf(Grep).Pointer() {
		t.Fatal("alias rg should resolve to grep")
	}
	if reflect.ValueOf(ResolveFilter("fd")).Pointer() != reflect.ValueOf(Find).Pointer() {
		t.Fatal("alias fd should resolve to find")
	}
	if ResolveFilter(FilterBuildOutput) != nil {
		t.Fatal("JS quirk: build-output is autodetect-only, not in resolveFilter registry")
	}
	if len(AllFilters()) != 11 {
		t.Fatalf("expected 11 registered filters, got %d", len(AllFilters()))
	}
	if _, name := AutoDetectFilter("just a short plain sentence"); name != "" {
		t.Fatalf("plain text should not detect a filter, got %s", name)
	}
}
