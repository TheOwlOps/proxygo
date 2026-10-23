package mitm

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// ─── EventStream frame decoding (test-side mirror of the wire format) ──────

type decodedEvent struct {
	eventType   string
	contentType string
	payload     map[string]any
	rawPayload  string
}

func decodeEventStream(t *testing.T, data []byte) []decodedEvent {
	t.Helper()
	var out []decodedEvent
	for len(data) > 0 {
		if len(data) < 16 {
			t.Fatalf("trailing %d bytes", len(data))
		}
		total := int(binary.BigEndian.Uint32(data[0:4]))
		hlen := int(binary.BigEndian.Uint32(data[4:8]))
		if total > len(data) {
			t.Fatalf("frame len %d > remaining %d", total, len(data))
		}
		frame := data[:total]
		if crc32.ChecksumIEEE(frame[0:8]) != binary.BigEndian.Uint32(frame[8:12]) {
			t.Fatal("prelude CRC mismatch")
		}
		if crc32.ChecksumIEEE(frame[:total-4]) != binary.BigEndian.Uint32(frame[total-4:]) {
			t.Fatal("message CRC mismatch")
		}
		headers := map[string]string{}
		hb := frame[12 : 12+hlen]
		for len(hb) > 0 {
			nl := int(hb[0])
			name := string(hb[1 : 1+nl])
			typ := hb[1+nl]
			if typ != 7 {
				t.Fatalf("header %s type %d, want string(7)", name, typ)
			}
			vl := int(binary.BigEndian.Uint16(hb[2+nl : 4+nl]))
			headers[name] = string(hb[4+nl : 4+nl+vl])
			hb = hb[4+nl+vl:]
		}
		ev := decodedEvent{
			eventType:   headers[":event-type"],
			contentType: headers[":content-type"],
			rawPayload:  string(frame[12+hlen : total-4]),
		}
		if err := json.Unmarshal(frame[12+hlen:total-4], &ev.payload); err != nil {
			t.Fatalf("payload not JSON: %v", err)
		}
		out = append(out, ev)
		data = data[total:]
	}
	return out
}

func eventTypes(evs []decodedEvent) []string {
	out := make([]string, len(evs))
	for i, e := range evs {
		out[i] = e.eventType
	}
	return out
}

func TestKiroFrameFormat(t *testing.T) {
	frame := buildEventStreamFrame("assistantResponseEvent",
		kiroContentEvent{Content: "hi", ModelID: "m"}, "")
	evs := decodeEventStream(t, frame)
	if len(evs) != 1 || evs[0].eventType != "assistantResponseEvent" {
		t.Fatalf("events = %+v", evs)
	}
	if evs[0].contentType != "application/json" {
		t.Fatalf("content-type = %q", evs[0].contentType)
	}
	if evs[0].payload["content"] != "hi" || evs[0].payload["modelId"] != "m" {
		t.Fatalf("payload = %v", evs[0].payload)
	}

	init := decodeEventStream(t, buildInitialResponseFrame(""))
	if init[0].eventType != "initial-response" ||
		init[0].contentType != "application/x-amz-json-1.0" {
		t.Fatalf("initial frame = %+v", init[0])
	}
}

func TestKiroExtractThinking(t *testing.T) {
	st := initKiroState("m")
	thinking, text := extractThinking("a <thinking>hidden</thinking> b", st)
	if thinking == nil || *thinking != "hidden" {
		t.Fatalf("thinking = %v", thinking)
	}
	// JS trims before/after and joins with "".
	if text == nil || *text != "ab" {
		t.Fatalf("text = %v", text)
	}

	st2 := initKiroState("m")
	thinking, text = extractThinking("start <thinking>abc", st2)
	if thinking != nil || text == nil || *text != "start" {
		t.Fatalf("partial: thinking=%v text=%v", thinking, text)
	}
	if !st2.inThink || st2.thinkBuf != "<thinking>abc" {
		t.Fatalf("state = %+v", st2)
	}
	thinking, text = extractThinking("def</thinking> tail", st2)
	if thinking == nil || *thinking != "abcdef" {
		t.Fatalf("resumed thinking = %v", thinking)
	}
	if text == nil || *text != "tail" {
		t.Fatalf("resumed text = %v", text)
	}

	st3 := initKiroState("m")
	thinking, text = extractThinking("plain", st3)
	if thinking != nil || text == nil || *text != "plain" {
		t.Fatalf("plain: %v %v", thinking, text)
	}
}

const kiroFixtureBody = `{
  "conversationState": {
    "history": [
      {"userInputMessage": {"content": "hi", "userInputMessageContext": {"tools": [
        {"toolSpecification": {"name": "read", "description": "Read file",
          "inputSchema": {"json": {"type": "object", "properties": {"path": {"type": "string"}}}}}}
      ]}}},
      {"assistantResponseMessage": {"content": "", "toolUses": [
        {"toolUseId": "tu1", "name": "read", "input": {"path": "/tmp/x"}}
      ]}},
      {"userInputMessage": {"content": "", "userInputMessageContext": {"toolResults": [
        {"toolUseId": "tu1", "content": [{"text": "file-body"}]}
      ]}}}
    ],
    "currentMessage": {"userInputMessage": {
      "content": "look",
      "images": [{"format": "png", "source": {"bytes": "QUJD"}}],
      "userInputMessageContext": {}
    }}
  }
}`

func TestKiroCodeWhispererConversion(t *testing.T) {
	var body cwBody
	if err := json.Unmarshal([]byte(kiroFixtureBody), &body); err != nil {
		t.Fatal(err)
	}
	msgs := codeWhispererToMessages(&body)
	if len(msgs) != 4 {
		t.Fatalf("messages = %d: %v", len(msgs), msgs)
	}
	if msgs[0]["role"] != "user" || msgs[0]["content"] != "hi" {
		t.Fatalf("msg0 = %v", msgs[0])
	}
	if msgs[1]["role"] != "assistant" || msgs[1]["content"] != nil {
		t.Fatalf("msg1 = %v", msgs[1])
	}
	calls, _ := msgs[1]["tool_calls"].([]any)
	if len(calls) != 1 {
		t.Fatalf("tool_calls = %v", msgs[1]["tool_calls"])
	}
	call := calls[0].(map[string]any)
	if call["id"] != "tu1" || call["function"].(map[string]any)["arguments"] != `{"path":"/tmp/x"}` {
		t.Fatalf("call = %v", call)
	}
	if msgs[2]["role"] != "tool" || msgs[2]["tool_call_id"] != "tu1" ||
		msgs[2]["content"] != "file-body" {
		t.Fatalf("msg2 = %v", msgs[2])
	}
	parts, _ := msgs[3]["content"].([]any)
	if len(parts) != 2 {
		t.Fatalf("msg3 content = %v", msgs[3]["content"])
	}
	img := parts[1].(map[string]any)
	if img["type"] != "image_url" ||
		img["image_url"].(map[string]any)["url"] != "data:image/png;base64,QUJD" {
		t.Fatalf("image part = %v", img)
	}

	tools := extractTools(&body)
	if len(tools) != 1 {
		t.Fatalf("tools = %v", tools)
	}
	fn := tools[0]["function"].(map[string]any)
	if fn["name"] != "read" || fn["description"] != "Read file" {
		t.Fatalf("tool fn = %v", fn)
	}
	paramsJSON, _ := json.Marshal(fn["parameters"])
	if !strings.Contains(string(paramsJSON), `"path"`) {
		t.Fatalf("parameters = %s", paramsJSON)
	}
}

func parseChunk(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestKiroConvertTextStream(t *testing.T) {
	st := initKiroState("acme/sonnet")

	frames := convertOpenAIToKiro(parseChunk(t,
		`{"model":"acme/sonnet","choices":[{"delta":{"role":"assistant"},"finish_reason":null}]}`), st)
	evs := decodeEventStream(t, bytes.Join(frames, nil))
	if got := eventTypes(evs); len(got) != 1 || got[0] != "initial-response" {
		t.Fatalf("first chunk events = %v", got)
	}

	frames = convertOpenAIToKiro(parseChunk(t,
		`{"choices":[{"delta":{"content":"Hello <thinking>plan</thinking> world"},"finish_reason":null}]}`), st)
	evs = decodeEventStream(t, bytes.Join(frames, nil))
	if got := eventTypes(evs); len(got) != 2 || got[0] != "reasoningContentEvent" ||
		got[1] != "assistantResponseEvent" {
		t.Fatalf("content events = %v", got)
	}
	if evs[0].payload["content"] != "plan" || evs[0].payload["modelId"] != "acme/sonnet" {
		t.Fatalf("reasoning payload = %v", evs[0].payload)
	}
	if evs[1].payload["content"] != "Helloworld" {
		t.Fatalf("assistant payload = %v", evs[1].payload)
	}

	frames = convertOpenAIToKiro(parseChunk(t,
		`{"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5}}`), st)
	evs = decodeEventStream(t, bytes.Join(frames, nil))
	if got := eventTypes(evs); len(got) != 2 || got[0] != "messageStopEvent" || got[1] != "usageEvent" {
		t.Fatalf("finish events = %v", got)
	}
	if evs[1].payload["inputTokens"] != float64(10) || evs[1].payload["outputTokens"] != float64(5) {
		t.Fatalf("usage payload = %v", evs[1].payload)
	}

	if frames := convertOpenAIToKiro(nil, st); frames != nil {
		t.Fatalf("flush after finish = %d frames, want nil", len(frames))
	}
}

func TestKiroConvertToolStream(t *testing.T) {
	st := initKiroState("m")

	frames := convertOpenAIToKiro(parseChunk(t,
		`{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"read","arguments":""}}]},"finish_reason":null}]}`), st)
	evs := decodeEventStream(t, bytes.Join(frames, nil))
	if got := eventTypes(evs); len(got) != 2 || got[0] != "initial-response" || got[1] != "toolUseEvent" {
		t.Fatalf("init events = %v", got)
	}
	if evs[1].payload["name"] != "read" || evs[1].payload["toolUseId"] != "call_1" {
		t.Fatalf("init payload = %v", evs[1].payload)
	}
	if _, has := evs[1].payload["input"]; has {
		t.Fatalf("init frame must not carry input: %v", evs[1].payload)
	}

	frames = convertOpenAIToKiro(parseChunk(t,
		`{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"path\":"}}]},"finish_reason":null}]}`), st)
	evs = decodeEventStream(t, bytes.Join(frames, nil))
	if len(evs) != 1 || evs[0].eventType != "toolUseEvent" ||
		evs[0].payload["input"] != `{"path":` || evs[0].payload["name"] != "read" ||
		evs[0].payload["toolUseId"] != "call_1" {
		t.Fatalf("fragment = %+v", evs)
	}

	frames = convertOpenAIToKiro(parseChunk(t,
		`{"choices":[{"delta":{},"finish_reason":"tool_calls"}]}`), st)
	evs = decodeEventStream(t, bytes.Join(frames, nil))
	if len(evs) != 1 || evs[0].eventType != "toolUseEvent" ||
		evs[0].payload["stop"] != true || evs[0].payload["name"] != "read" {
		t.Fatalf("stop frame = %+v", evs)
	}
}

func kiroBodyWithModel(modelID string) []byte {
	return []byte(`{"conversationState":{"currentMessage":{"userInputMessage":{"content":"hi","modelId":"` +
		modelID + `"}}}}`)
}

func TestKiroMappedModelGating(t *testing.T) {
	InitDBHooks(nil, nil, func(tool string) (map[string]string, bool) {
		if tool == "kiro" {
			return map[string]string{
				"claude-sonnet-4-5": "acme/sonnet",
				"claude-opus":       "acme/opus",
			}, true
		}
		return nil, false
	})
	defer InitDBHooks(nil, nil, nil)

	if got := kiroMappedModel(kiroBodyWithModel("claude-sonnet-4-5")); got != "acme/sonnet" {
		t.Fatalf("exact = %q", got)
	}
	if got := kiroMappedModel(kiroBodyWithModel("claude-sonnet-4-5-20250929")); got != "acme/sonnet" {
		t.Fatalf("prefix = %q", got)
	}
	if got := kiroMappedModel(kiroBodyWithModel("unknown-model")); got != "" {
		t.Fatalf("unmapped = %q, want passthrough", got)
	}
	if got := kiroMappedModel([]byte(`{"foo":1}`)); got != "" {
		t.Fatalf("no conversationState = %q", got)
	}
}

func TestKiroInterceptEndToEnd(t *testing.T) {
	InitDBHooks(nil, nil, func(tool string) (map[string]string, bool) {
		if tool == "kiro" {
			return map[string]string{"kiro-model": "acme/mapped"}, true
		}
		return nil, false
	})
	defer InitDBHooks(nil, nil, nil)

	var routerBody []byte
	router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		routerBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"Hi there\"},\"finish_reason\":null}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2}}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer router.Close()

	s := &mitmServer{base: router.URL}
	reqBody := []byte(`{"conversationState":{"currentMessage":{"userInputMessage":` +
		`{"content":"hello","modelId":"kiro-model"}}}}`)
	req := httptest.NewRequest("POST", "https://runtime.us-east-1.kiro.dev/", bytes.NewReader(reqBody))
	req.Header.Set("X-Amz-Target", "KiroRuntimeService.GenerateAssistantResponse")
	rec := httptest.NewRecorder()
	s.handle(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/vnd.amazon.eventstream" {
		t.Fatalf("content-type = %q", ct)
	}
	evs := decodeEventStream(t, rec.Body.Bytes())
	if got := eventTypes(evs); len(got) != 4 || got[0] != "initial-response" ||
		got[1] != "assistantResponseEvent" || got[2] != "messageStopEvent" || got[3] != "usageEvent" {
		t.Fatalf("events = %v", got)
	}
	if evs[1].payload["content"] != "Hi there" || evs[1].payload["modelId"] != "acme/mapped" {
		t.Fatalf("assistant payload = %v", evs[1].payload)
	}

	var sent map[string]any
	if err := json.Unmarshal(routerBody, &sent); err != nil {
		t.Fatalf("router body: %v", err)
	}
	if sent["model"] != "acme/mapped" || sent["stream"] != true {
		t.Fatalf("router body = %v", sent)
	}
	msgs, _ := sent["messages"].([]any)
	if len(msgs) != 1 || msgs[0].(map[string]any)["content"] != "hello" {
		t.Fatalf("router messages = %v", sent["messages"])
	}
}

func TestKiroInterceptRejectsBinaryBody(t *testing.T) {
	s := &mitmServer{}
	frame := buildEventStreamFrame("assistantResponseEvent", `{"content":"x"}`, "")
	req := httptest.NewRequest("POST", "https://runtime.us-east-1.kiro.dev/", bytes.NewReader(frame))
	rec := httptest.NewRecorder()
	s.interceptKiro(rec, req, frame, "acme/mapped")
	if rec.Code != 500 {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp struct {
		Error struct {
			Handler string `json:"handler"`
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error.Handler != "kiro" || resp.Error.Type != "mitm_error" ||
		!strings.Contains(resp.Error.Message, "Binary EventStream") {
		t.Fatalf("error = %+v", resp.Error)
	}
}

// Anti-loop (server.js): a request carrying x-request-source: local
// originates from 9Router itself and must passthrough, never intercept —
// even when its model would otherwise map.
func TestKiroAntiLoopHeaderPassthrough(t *testing.T) {
	InitDBHooks(nil, nil, func(tool string) (map[string]string, bool) {
		if tool == "kiro" {
			return map[string]string{"kiro-model": "acme/mapped"}, true
		}
		return nil, false
	})
	defer InitDBHooks(nil, nil, nil)

	var routerHits atomic.Int32
	router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		routerHits.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer router.Close()

	s := &mitmServer{base: router.URL}
	reqBody := []byte(`{"conversationState":{"currentMessage":{"userInputMessage":` +
		`{"content":"hello","modelId":"kiro-model"}}}}`)
	req := httptest.NewRequest("POST", "https://runtime.us-east-1.kiro.dev/", bytes.NewReader(reqBody))
	req.Header.Set("X-Amz-Target", "KiroRuntimeService.GenerateAssistantResponse")
	req.Header.Set("x-request-source", "local")
	rec := httptest.NewRecorder()
	s.handle(rec, req)

	if routerHits.Load() != 0 {
		t.Fatalf("router hit %d times; anti-loop request must passthrough", routerHits.Load())
	}
	if rec.Code == 200 && rec.Header().Get("Content-Type") == "application/vnd.amazon.eventstream" {
		t.Fatalf("request was intercepted despite x-request-source: local")
	}
}
