package executors

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type pplxCapture struct {
	cookie string
	auth   string
	ua     string
	apiVer string
	body   map[string]any
}

func pplxTestServer(t *testing.T, cap *pplxCapture, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap.cookie = r.Header.Get("Cookie")
		cap.auth = r.Header.Get("Authorization")
		cap.ua = r.Header.Get("User-Agent")
		cap.apiVer = r.Header.Get("X-App-ApiVersion")
		raw, _ := io.ReadAll(r.Body)
		var decoded map[string]any
		if err := unmarshalJSON(raw, &decoded); err == nil {
			cap.body = decoded
		}
		if status != 200 {
			w.WriteHeader(status)
			io.WriteString(w, "upstream error")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		io.WriteString(w, "data: {\"backend_uuid\":\"uuid-abc\",\"blocks\":[{\"intended_usage\":\"pro_search_steps\",\"plan_block\":{\"steps\":[{\"step_type\":\"SEARCH_WEB\",\"search_web_content\":{\"queries\":[{\"query\":\"weather today\"}]}}]}},{\"intended_usage\":\"answer_markdown\",\"markdown_block\":{\"chunks\":[\"Hello [1] \"],\"progress\":\"IN_PROGRESS\"}}]}\n\n")
		io.WriteString(w, "data: {\"backend_uuid\":\"uuid-abc\",\"blocks\":[{\"intended_usage\":\"answer_markdown\",\"markdown_block\":{\"chunks\":[\"world\"],\"progress\":\"IN_PROGRESS\"}}]}\n\n")
		io.WriteString(w, "data: {\"backend_uuid\":\"uuid-abc\",\"blocks\":[{\"intended_usage\":\"answer_markdown\",\"markdown_block\":{\"chunks\":[\"Hello world\"],\"progress\":\"DONE\"}}],\"status\":\"COMPLETED\"}\n\n")
	}))
	t.Cleanup(srv.Close)
	old := HTTPClient
	HTTPClient = srv.Client()
	t.Cleanup(func() { HTTPClient = old })
	return srv
}

func pplxParams(t *testing.T, cap *pplxCapture) map[string]any {
	t.Helper()
	params, _ := cap.body["params"].(map[string]any)
	if params == nil {
		t.Fatalf("no params in captured body: %v", cap.body)
	}
	return params
}

func TestPplxNonStreamingCookieAuthAndModelMap(t *testing.T) {
	cap := &pplxCapture{}
	srv := pplxTestServer(t, cap, 200)
	ex := NewPerplexityWebExecutor()
	p := &ProviderInfo{ID: "perplexity-web", BaseURL: srv.URL}
	res, err := ex.Execute(context.Background(), p, Credential{APIKey: "cookie-token-1"},
		[]byte(`{"model":"pplx-sonnet","messages":[{"role":"system","content":"Be brief."},{"role":"user","content":"pplx unique question one"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	if res.Response.StatusCode != 200 || res.ResponseFormat != "openai" {
		t.Fatalf("status=%d format=%q", res.Response.StatusCode, res.ResponseFormat)
	}
	if !strings.Contains(body, `"content":"Hello world"`) {
		t.Fatalf("cleaned non-stream answer missing: %q", body)
	}
	if !strings.Contains(body, `"reasoning_content":"Searching: weather today"`) {
		t.Fatalf("thinking/reasoning missing: %q", body)
	}
	if !strings.Contains(body, `"total_tokens":`) {
		t.Fatalf("usage missing: %q", body)
	}
	// Cookie auth: apiKey becomes the session-token cookie, no Bearer.
	if cap.cookie != "__Secure-next-auth.session-token=cookie-token-1" {
		t.Fatalf("cookie header = %q", cap.cookie)
	}
	if cap.auth != "" {
		t.Fatalf("Authorization must be empty for cookie auth, got %q", cap.auth)
	}
	if cap.apiVer != "2.18" || !strings.Contains(cap.ua, "Chrome/130") {
		t.Fatalf("headers ua=%q ver=%q", cap.ua, cap.apiVer)
	}
	params := pplxParams(t, cap)
	if params["mode"] != "copilot" || params["model_preference"] != "claude46sonnet" {
		t.Fatalf("model map = mode %v pref %v", params["mode"], params["model_preference"])
	}
	if params["version"] != "2.18" || params["is_incognito"] != true || params["last_backend_uuid"] != nil {
		t.Fatalf("params = %v", params)
	}
	queryStr, _ := cap.body["query_str"].(string)
	if !strings.Contains(queryStr, `"instructions":["Be brief."`) || !strings.Contains(queryStr, `"query":"pplx unique question one"`) ||
		!strings.Contains(queryStr, "You have built-in web search.") {
		t.Fatalf("query_str = %q", queryStr)
	}
}

func TestPplxStreamingBearerAuth(t *testing.T) {
	cap := &pplxCapture{}
	srv := pplxTestServer(t, cap, 200)
	ex := NewPerplexityWebExecutor()
	p := &ProviderInfo{ID: "perplexity-web", BaseURL: srv.URL}
	res, err := ex.Execute(context.Background(), p, Credential{AccessToken: "tok-9", APIKey: "cookie-x"},
		[]byte(`{"model":"pplx-auto","stream":true,"messages":[{"role":"user","content":"stream q"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	// AccessToken wins over the cookie (JS order).
	if cap.auth != "Bearer tok-9" || cap.cookie != "" {
		t.Fatalf("auth=%q cookie=%q", cap.auth, cap.cookie)
	}
	params := pplxParams(t, cap)
	if params["mode"] != "concise" || params["model_preference"] != "pplx_pro" {
		t.Fatalf("pplx-auto map = %v / %v", params["mode"], params["model_preference"])
	}
	// JS streaming cleans with strip=false: removing "[1]" from
	// "Hello [1] " leaves both surrounding spaces ("Hello  ").
	if !strings.Contains(body, `"role":"assistant"`) || !strings.Contains(body, `"content":"Hello  "`) ||
		!strings.Contains(body, `"content":"world"`) || !strings.Contains(body, `"reasoning_content":"Searching: weather today`) {
		t.Fatalf("stream chunks missing content: %q", body)
	}
	if strings.Contains(body, "[1]") {
		t.Fatalf("citation markers must be stripped: %q", body)
	}
	if !strings.Contains(body, `"finish_reason":"stop"`) || !strings.Contains(body, "[DONE]") {
		t.Fatalf("stream finish missing: %q", body)
	}
	if ct := res.Response.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("stream content-type = %q", ct)
	}
}

func TestPplxThinkingModelMap(t *testing.T) {
	cap := &pplxCapture{}
	srv := pplxTestServer(t, cap, 200)
	ex := NewPerplexityWebExecutor()
	p := &ProviderInfo{ID: "perplexity-web", BaseURL: srv.URL}
	res, err := ex.Execute(context.Background(), p, Credential{APIKey: "c"},
		[]byte(`{"model":"pplx-opus","thinking":true,"messages":[{"role":"user","content":"think q"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, res.Response)
	params := pplxParams(t, cap)
	if params["model_preference"] != "claude46opusthinking" || params["mode"] != "copilot" {
		t.Fatalf("thinking map = %v / %v", params["mode"], params["model_preference"])
	}
}

func TestPplxSessionFollowUp(t *testing.T) {
	cap := &pplxCapture{}
	srv := pplxTestServer(t, cap, 200)
	ex := NewPerplexityWebExecutor()
	p := &ProviderInfo{ID: "perplexity-web", BaseURL: srv.URL}
	cred := Credential{APIKey: "c"}
	res, err := ex.Execute(context.Background(), p, cred,
		[]byte(`{"model":"pplx-auto","messages":[{"role":"user","content":"followup first question"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, res.Response)

	res2, err := ex.Execute(context.Background(), p, cred,
		[]byte(`{"model":"pplx-auto","messages":[{"role":"user","content":"followup first question"},{"role":"assistant","content":"Hello world"},{"role":"user","content":"second question"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, res2.Response)
	params := pplxParams(t, cap)
	if params["last_backend_uuid"] != "uuid-abc" {
		t.Fatalf("follow-up uuid = %v", params["last_backend_uuid"])
	}
	if cap.body["query_str"] != "second question" {
		t.Fatalf("follow-up query must be the bare current message, got %q", cap.body["query_str"])
	}
}

func TestPplxUpstreamErrorsAndValidation(t *testing.T) {
	cap := &pplxCapture{}
	srv := pplxTestServer(t, cap, 401)
	ex := NewPerplexityWebExecutor()
	p := &ProviderInfo{ID: "perplexity-web", BaseURL: srv.URL}
	res, err := ex.Execute(context.Background(), p, Credential{APIKey: "stale"},
		[]byte(`{"model":"pplx-auto","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	if res.Response.StatusCode != 401 || !strings.Contains(body, "session cookie may be expired") || !strings.Contains(body, `"code":"HTTP_401"`) {
		t.Fatalf("401 mapping = %d %q", res.Response.StatusCode, body)
	}

	// Missing messages → local 400 without any upstream call shape.
	res2, err := ex.Execute(context.Background(), p, Credential{APIKey: "x"}, []byte(`{"model":"pplx-auto"}`))
	if err != nil {
		t.Fatal(err)
	}
	body2 := readBody(t, res2.Response)
	if res2.Response.StatusCode != 400 || !strings.Contains(body2, "Missing or empty messages array") {
		t.Fatalf("validation = %d %q", res2.Response.StatusCode, body2)
	}
}
