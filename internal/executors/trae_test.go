package executors

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type traeCapture struct {
	createAuth string
	createBody map[string]any
	eventsAuth string
	replyTo    string
}

const traeTestEventsOK = "event: plan_item\ndata: {\"id\":\"p1\",\"thought\":\"Hello \"}\n\n" +
	"event: plan_item\ndata: {\"id\":\"p1\",\"thought\":\"Hello world\"}\n\n" +
	"event: plan_item\ndata: {\"id\":\"p2\",\"thought\":\"!\"}\n\n" +
	"event: token_usage\ndata: {\"prompt_tokens\":5,\"completion_tokens\":4,\"total_tokens\":9}\n\n" +
	"event: done\ndata: {}\n\n"

func traeTestServer(t *testing.T, cap *traeCapture, createResp, events string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/chat_sessions", func(w http.ResponseWriter, r *http.Request) {
		cap.createAuth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		var decoded map[string]any
		if err := unmarshalJSON(raw, &decoded); err == nil {
			cap.createBody = decoded
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, createResp)
	})
	mux.HandleFunc("/chat_sessions/sess1/events", func(w http.ResponseWriter, r *http.Request) {
		cap.eventsAuth = r.Header.Get("Authorization")
		cap.replyTo = r.URL.Query().Get("reply_to_message_id")
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, events)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	old := HTTPClient
	HTTPClient = srv.Client()
	t.Cleanup(func() { HTTPClient = old })
	return srv
}

func traeInitialMessage(t *testing.T, cap *traeCapture) map[string]any {
	t.Helper()
	im, _ := cap.createBody["initial_message"].(map[string]any)
	if im == nil {
		t.Fatalf("no initial_message in create body: %v", cap.createBody)
	}
	return im
}

func TestTraeStreamingFlow(t *testing.T) {
	cap := &traeCapture{}
	srv := traeTestServer(t, cap, `{"code":0,"data":{"chat_session_id":"sess1","message_id":"msg1"}}`, traeTestEventsOK)
	ex := NewTraeExecutor()
	p := &ProviderInfo{ID: "trae", BaseURL: srv.URL}
	cred := Credential{AccessToken: "jwt-123", Specific: map[string]any{"appLanguage": "vi", "userRegion": "SG", "webId": "web-9"}}
	res, err := ex.Execute(context.Background(), p, cred,
		[]byte(`{"model":"gpt-5.4","stream":true,"messages":[{"role":"system","content":"sys prompt"},{"role":"user","content":"hello trae"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	if res.ResponseFormat != "openai" || res.URL != srv.URL {
		t.Fatalf("format=%q url=%q", res.ResponseFormat, res.URL)
	}
	// Cumulative plan_item thoughts emit only the grown suffix per item.
	if !strings.Contains(body, `"content":"Hello "`) || !strings.Contains(body, `"content":"world"`) || !strings.Contains(body, `"content":"!"`) {
		t.Fatalf("streamed pieces missing: %q", body)
	}
	if !strings.Contains(body, `"prompt_tokens":5`) || !strings.Contains(body, `"total_tokens":9`) {
		t.Fatalf("usage chunk missing: %q", body)
	}
	if !strings.Contains(body, `"finish_reason":"stop"`) || !strings.Contains(body, "[DONE]") {
		t.Fatalf("finish missing: %q", body)
	}
	// Auth + session/event wiring.
	if cap.createAuth != "Cloud-IDE-JWT jwt-123" || cap.eventsAuth != "Cloud-IDE-JWT jwt-123" {
		t.Fatalf("auth create=%q events=%q", cap.createAuth, cap.eventsAuth)
	}
	if cap.replyTo != "msg1" {
		t.Fatalf("reply_to_message_id = %q", cap.replyTo)
	}
	// Create-session body shape.
	if cap.createBody["mode"] != "code" || cap.createBody["env"] != "remote" || cap.createBody["origin"] != "web" {
		t.Fatalf("create body = %v", cap.createBody)
	}
	im := traeInitialMessage(t, cap)
	if im["model_name"] != "gpt-5.4" || im["model_selection_strategy"] != "manual" || im["agent_type"] != "solo_agent_remote" {
		t.Fatalf("initial_message = %v", im)
	}
	query, _ := im["query"].(string)
	if !strings.Contains(query, "[System]\\nsys prompt") || !strings.Contains(query, "hello trae") {
		t.Fatalf("flattened query = %q", query)
	}
	cp, _ := im["common_params"].(string)
	for _, want := range []string{`"app_version":"1.0.0.1229"`, `"web_id":"web-9"`, `"solo_chat_mode":"code"`, `"scope":"marscode-us"`, `"tenant":"marscode"`, `"aiRegion":"US-East"`} {
		if !strings.Contains(cp, want) {
			t.Fatalf("common_params missing %s: %q", want, cp)
		}
	}
}

func TestTraeNonStreamingFlow(t *testing.T) {
	cap := &traeCapture{}
	srv := traeTestServer(t, cap, `{"code":0,"data":{"chat_session_id":"sess1","message_id":"msg1"}}`, traeTestEventsOK)
	ex := NewTraeExecutor()
	p := &ProviderInfo{ID: "trae", BaseURL: srv.URL}
	res, err := ex.Execute(context.Background(), p, Credential{AccessToken: "jwt-1"},
		[]byte(`{"model":"auto","stream":false,"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	if res.Response.StatusCode != 200 {
		t.Fatalf("status = %d body %q", res.Response.StatusCode, body)
	}
	if !strings.Contains(body, `"content":"Hello world!"`) {
		t.Fatalf("assembled content missing: %q", body)
	}
	if !strings.Contains(body, `"prompt_tokens":5`) || !strings.Contains(body, `"total_tokens":9`) {
		t.Fatalf("usage missing: %q", body)
	}
	im := traeInitialMessage(t, cap)
	// "auto" → code mode, auto strategy, empty model_name.
	if im["model_selection_strategy"] != "auto" || im["model_name"] != "" {
		t.Fatalf("auto mode = %v", im)
	}
}

func TestTraeWorkMode(t *testing.T) {
	cap := &traeCapture{}
	srv := traeTestServer(t, cap, `{"code":0,"data":{"chat_session_id":"sess1","message_id":"msg1"}}`, traeTestEventsOK)
	ex := NewTraeExecutor()
	p := &ProviderInfo{ID: "trae", BaseURL: srv.URL}
	res, err := ex.Execute(context.Background(), p, Credential{AccessToken: "jwt-1"},
		[]byte(`{"model":"work","stream":false,"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, res.Response)
	if cap.createBody["mode"] != "work" {
		t.Fatalf("mode = %v", cap.createBody["mode"])
	}
	im := traeInitialMessage(t, cap)
	if im["model_selection_strategy"] != "auto" || im["model_name"] != "" {
		t.Fatalf("work initial_message = %v", im)
	}
	cp, _ := im["common_params"].(string)
	if !strings.Contains(cp, `"solo_chat_mode":"work"`) {
		t.Fatalf("common_params mode = %q", cp)
	}
	// Unit-level mode resolution.
	if m := traeResolveMode("Solo-Work"); m.mode != "work" {
		t.Fatalf("resolveMode solo-work = %+v", m)
	}
	if m := traeResolveMode("gemini-3.1-pro"); m.mode != "code" || m.strategy != "manual" || m.modelName != "gemini-3.1-pro" {
		t.Fatalf("resolveMode manual = %+v", m)
	}
}

func TestTraeCreateSessionError(t *testing.T) {
	cap := &traeCapture{}
	srv := traeTestServer(t, cap, `{"code":7,"message":"nope"}`, traeTestEventsOK)
	ex := NewTraeExecutor()
	p := &ProviderInfo{ID: "trae", BaseURL: srv.URL}
	res, err := ex.Execute(context.Background(), p, Credential{AccessToken: "jwt-1"},
		[]byte(`{"model":"auto","stream":false,"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	if res.Response.StatusCode != 502 || !strings.Contains(body, "Trae create_session:") {
		t.Fatalf("create error = %d %q", res.Response.StatusCode, body)
	}
}

func TestTraeErrorEvent(t *testing.T) {
	cap := &traeCapture{}
	events := "event: error\ndata: {\"code\":\"E1\",\"message\":\"boom\"}\n\n"
	srv := traeTestServer(t, cap, `{"code":0,"data":{"chat_session_id":"sess1","message_id":"msg1"}}`, events)
	ex := NewTraeExecutor()
	p := &ProviderInfo{ID: "trae", BaseURL: srv.URL}
	res, err := ex.Execute(context.Background(), p, Credential{AccessToken: "jwt-1"},
		[]byte(`{"model":"auto","stream":false,"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	if res.Response.StatusCode != 502 || !strings.Contains(body, "trae E1: boom") {
		t.Fatalf("error event = %d %q", res.Response.StatusCode, body)
	}
}
