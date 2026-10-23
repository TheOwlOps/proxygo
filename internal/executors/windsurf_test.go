package executors

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func windsurfTestFrame(flag byte, payload []byte) []byte {
	frame := make([]byte, 5+len(payload))
	frame[0] = flag
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)))
	copy(frame[5:], payload)
	return frame
}

func windsurfTestVarintField(fieldNum int, v uint64) []byte {
	return append(windsurfEncodeVarint(uint64(fieldNum<<3|0)), windsurfEncodeVarint(v)...)
}

func windsurfTestContentChunk(text string) []byte {
	return windsurfEncodeField(1, windsurfEncodeString(1, text))
}

func windsurfTestDoneChunk(prompt, completion int) []byte {
	usage := windsurfConcat(windsurfTestVarintField(1, uint64(prompt)), windsurfTestVarintField(2, uint64(completion)))
	return windsurfEncodeField(3, windsurfEncodeField(1, usage))
}

func windsurfTestTrailer(status int, msg string) []byte {
	return windsurfTestFrame(0x80, []byte("grpc-status: "+strconv.Itoa(status)+"\r\ngrpc-message: "+msg))
}

type windsurfCapture struct {
	auth string
	ct   string
	grpc string
	body []byte
}

func windsurfTestServer(t *testing.T, cap *windsurfCapture, respond func(w http.ResponseWriter)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap.auth = r.Header.Get("Authorization")
		cap.ct = r.Header.Get("Content-Type")
		cap.grpc = r.Header.Get("X-Grpc-Web")
		cap.body, _ = io.ReadAll(r.Body)
		respond(w)
	}))
	t.Cleanup(srv.Close)
	old := HTTPClient
	HTTPClient = srv.Client()
	t.Cleanup(func() { HTTPClient = old })
	return srv
}

func TestWindsurfStreamingConversion(t *testing.T) {
	cap := &windsurfCapture{}
	srv := windsurfTestServer(t, cap, func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/grpc-web+proto")
		w.WriteHeader(200)
		w.Write(windsurfTestFrame(0x00, windsurfTestContentChunk("Hello ")))
		w.Write(windsurfTestFrame(0x00, windsurfTestContentChunk("world")))
		w.Write(windsurfTestFrame(0x00, windsurfTestDoneChunk(11, 7)))
		w.Write(windsurfTestTrailer(0, ""))
	})
	ex := NewWindsurfExecutor()
	p := &ProviderInfo{ID: "windsurf", BaseURL: srv.URL}
	res, err := ex.Execute(context.Background(), p, Credential{AccessToken: "sk-ws-test"},
		[]byte(`{"model":"gpt-5.4","stream":true,"messages":[{"role":"user","content":"hello windsurf"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	if res.ResponseFormat != "openai" {
		t.Fatalf("format = %q", res.ResponseFormat)
	}
	if !strings.Contains(body, `"content":"Hello "`) || !strings.Contains(body, `"content":"world"`) {
		t.Fatalf("converted content missing: %q", body)
	}
	if !strings.Contains(body, `"prompt_tokens":11`) || !strings.Contains(body, `"completion_tokens":7`) || !strings.Contains(body, `"total_tokens":18`) {
		t.Fatalf("usage missing: %q", body)
	}
	if !strings.Contains(body, `"finish_reason":"stop"`) || !strings.Contains(body, "[DONE]") {
		t.Fatalf("finish missing: %q", body)
	}
	// Request side: gRPC-web framing + protobuf carrying key/model/message.
	if cap.auth != "Bearer sk-ws-test" || cap.ct != "application/grpc-web+proto" || cap.grpc != "1" {
		t.Fatalf("headers auth=%q ct=%q grpc=%q", cap.auth, cap.ct, cap.grpc)
	}
	if len(cap.body) < 5 || cap.body[0] != 0x00 {
		t.Fatalf("framed body head = %v", cap.body[:5])
	}
	if int(binary.BigEndian.Uint32(cap.body[1:5])) != len(cap.body)-5 {
		t.Fatalf("frame length prefix mismatch: %d vs %d", binary.BigEndian.Uint32(cap.body[1:5]), len(cap.body)-5)
	}
	for _, want := range []string{"sk-ws-test", "gpt-5-4-medium", "windsurf", "hello windsurf", "user"} {
		if !bytes.Contains(cap.body, []byte(want)) {
			t.Fatalf("protobuf payload missing %q", want)
		}
	}
	// TransformedBody is the unframed protobuf (JS behaviour).
	if len(res.TransformedBody) == 0 || res.TransformedBody[0] == 0x00 && len(res.TransformedBody) != len(cap.body)-5 {
		t.Fatalf("transformedBody should be raw protobuf, len=%d", len(res.TransformedBody))
	}
}

func TestWindsurfModelAliases(t *testing.T) {
	cases := map[string]string{
		"claude-sonnet-4.5":  "MODEL_PRIVATE_2",
		"gpt-5.5":            "gpt-5-5-medium",
		"gpt-5.4-mini-high":  "gpt-5-4-mini-high",
		"gemini-3.0-flash":   "MODEL_GOOGLE_GEMINI_3_0_FLASH_HIGH",
		"swe-1.6-fast":       "swe-1-6-fast",
		"some-unknown-model": "some-unknown-model",
	}
	for in, want := range cases {
		if got := windsurfResolveModelID(in); got != want {
			t.Fatalf("alias %q = %q, want %q", in, got, want)
		}
	}
	// Round-trip the request builder + chunk decoder directly.
	payload := windsurfBuildGetChatMessageRequest("k", "m", []windsurfChatMsg{{role: "user", content: "x"}})
	if !bytes.Contains(payload, []byte("m")) || !bytes.Contains(payload, []byte("k")) {
		t.Fatal("request builder missing fields")
	}
	chunk := windsurfDecodeCompletionChunk(windsurfTestContentChunk("abc"))
	if chunk.kind != "content" || chunk.text != "abc" {
		t.Fatalf("decode content = %+v", chunk)
	}
	done := windsurfDecodeCompletionChunk(windsurfTestDoneChunk(3, 4))
	if done.kind != "done" || done.promptTokens != 3 || done.completionTokens != 4 {
		t.Fatalf("decode done = %+v", done)
	}
}

func TestWindsurfTrailerError(t *testing.T) {
	cap := &windsurfCapture{}
	srv := windsurfTestServer(t, cap, func(w http.ResponseWriter) {
		w.WriteHeader(200)
		w.Write(windsurfTestFrame(0x00, windsurfTestContentChunk("partial")))
		w.Write(windsurfTestTrailer(3, "invalid%20argument"))
	})
	ex := NewWindsurfExecutor()
	p := &ProviderInfo{ID: "windsurf", BaseURL: srv.URL}
	res, err := ex.Execute(context.Background(), p, Credential{APIKey: "k"}, []byte(`{"model":"gpt-5","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	if !strings.Contains(body, `"message":"invalid argument"`) || !strings.Contains(body, `"type":"windsurf_error"`) {
		t.Fatalf("trailer error not surfaced: %q", body)
	}
	if strings.Contains(body, `"finish_reason":"stop"`) {
		t.Fatalf("error stream must not emit a stop finish: %q", body)
	}
	if !strings.Contains(body, "[DONE]") {
		t.Fatalf("error stream missing DONE: %q", body)
	}
}

func TestWindsurfUpstreamNon200Passthrough(t *testing.T) {
	cap := &windsurfCapture{}
	srv := windsurfTestServer(t, cap, func(w http.ResponseWriter) {
		w.WriteHeader(500)
		io.WriteString(w, "codeium boom")
	})
	ex := NewWindsurfExecutor()
	p := &ProviderInfo{ID: "windsurf", BaseURL: srv.URL}
	res, err := ex.Execute(context.Background(), p, Credential{APIKey: "k"}, []byte(`{"model":"gpt-5","messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	if res.Response.StatusCode != 500 || body != "codeium boom" {
		t.Fatalf("passthrough = %d %q", res.Response.StatusCode, body)
	}
}
