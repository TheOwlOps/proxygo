package executors

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// qoderDecodeForTest reverses qoderEncodeBody (inverse alphabet +
// un-rearrange thirds + base64 decode) so tests can assert on the exact
// payload the executor put on the wire.
func qoderDecodeForTest(t *testing.T, encoded string) []byte {
	t.Helper()
	inverse := map[byte]byte{}
	for i := 0; i < 64; i++ {
		inverse[qoderCustomAlphabet[i]] = qoderStdAlphabet[i]
	}
	inverse['$'] = '='
	n := len(encoded)
	a := n / 3
	// encoded = [tail][mid][head]; original = head + mid + tail.
	rearranged := encoded[n-a:] + encoded[a:n-a] + encoded[:a]
	std := make([]byte, n)
	for i := 0; i < n; i++ {
		if v, ok := inverse[rearranged[i]]; ok {
			std[i] = v
		} else {
			std[i] = rearranged[i]
		}
	}
	plain, err := base64.StdEncoding.DecodeString(string(std))
	if err != nil {
		t.Fatalf("decode encoded body: %v", err)
	}
	return plain
}

func TestQoderEncodeBodyVectors(t *testing.T) {
	// Vectors generated from the original JS qoderEncodeBody.
	cases := []struct{ plain, want string }{
		{"hello qoder", "zDxB$Hq&NSWPHFru"},
		{`{"a":1,"b":"x"}`, "n*moKWn%GoK*BMmYKiBM"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := qoderEncodeBody([]byte(tc.plain)); got != tc.want {
			t.Errorf("qoderEncodeBody(%q) = %q, want %q", tc.plain, got, tc.want)
		}
		// Round-trip through the independent decoder.
		if rt := qoderDecodeForTest(t, qoderEncodeBody([]byte(tc.plain))); string(rt) != tc.plain {
			t.Errorf("encode round-trip = %q, want %q", rt, tc.plain)
		}
	}
}

func TestQoderCosyHeadersStructureAndSignature(t *testing.T) {
	body := []byte("hello")
	url := "https://api3.qoder.sh/algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1"
	headers, err := qoderBuildCosyHeaders(body, url, qoderCosyCreds{userID: "u-1", authToken: "dt-abc", machineID: "mid-1"})
	if err != nil {
		t.Fatal(err)
	}
	auth := headers["Authorization"]
	if !strings.HasPrefix(auth, "Bearer COSY.") {
		t.Fatalf("Authorization = %q", auth)
	}
	parts := strings.Split(strings.TrimPrefix(auth, "Bearer COSY."), ".")
	if len(parts) != 2 {
		t.Fatalf("COSY authorization parts = %d", len(parts))
	}
	payloadB64, sig := parts[0], parts[1]
	// Recompute the MD5 signature exactly as the JS does:
	// md5(payloadB64 \n cosyKey \n timestamp \n body \n sigPath).
	sigPath := "/api/v2/service/pro/sse/agent_chat_generation"
	sigInput := payloadB64 + "\n" + headers["Cosy-Key"] + "\n" + headers["Cosy-Date"] + "\n" + string(body) + "\n" + sigPath
	sum := md5.Sum([]byte(sigInput))
	if hex.EncodeToString(sum[:]) != sig {
		t.Fatalf("COSY sig mismatch: header %q, recomputed %q", sig, hex.EncodeToString(sum[:]))
	}
	bodySum := md5.Sum(body)
	if headers["Cosy-Bodyhash"] != hex.EncodeToString(bodySum[:]) {
		t.Fatalf("Cosy-Bodyhash = %q", headers["Cosy-Bodyhash"])
	}
	if headers["Cosy-Bodylength"] != "5" || headers["Cosy-Sigpath"] != sigPath {
		t.Fatalf("body length/sigpath = %q/%q", headers["Cosy-Bodylength"], headers["Cosy-Sigpath"])
	}
	if headers["Cosy-User"] != "u-1" || headers["Cosy-Machineid"] != "mid-1" || headers["Cosy-Machinetoken"] != "mid-1" {
		t.Fatalf("user/machine headers = %q/%q/%q", headers["Cosy-User"], headers["Cosy-Machineid"], headers["Cosy-Machinetoken"])
	}
	if headers["Cosy-Version"] != "1.0.0" || headers["Cosy-Clienttype"] != "5" || headers["Login-Version"] != "v2" ||
		headers["Cosy-Machineos"] != "x86_64_windows" || headers["Cosy-Data-Policy"] != "disagree" {
		t.Fatalf("fingerprint headers wrong: %v", headers)
	}
	// Payload envelope decodes and carries the AES-encrypted user info.
	payloadRaw, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["version"] != "v1" || payload["cosyVersion"] != "1.0.0" || payload["info"] == "" || payload["requestId"] == "" {
		t.Fatalf("COSY payload = %v", payload)
	}
	// The RSA-wrapped AES key is one 1024-bit RSA block.
	keyRaw, err := base64.StdEncoding.DecodeString(headers["Cosy-Key"])
	if err != nil || len(keyRaw) != 128 {
		t.Fatalf("Cosy-Key decoded len = %d, err %v; want 128-byte RSA block", len(keyRaw), err)
	}
	// Missing userId / token are hard errors in the JS.
	if _, err := qoderBuildCosyHeaders(body, url, qoderCosyCreds{authToken: "x"}); err == nil {
		t.Fatal("expected error for empty userId")
	}
	if _, err := qoderBuildCosyHeaders(body, url, qoderCosyCreds{userID: "x"}); err == nil {
		t.Fatal("expected error for empty authToken")
	}
}

func TestQoderNormalizeMessages(t *testing.T) {
	in := []any{
		map[string]any{"role": "system", "content": "S1"},
		map[string]any{"role": "user", "content": []any{
			map[string]any{"type": "text", "text": "a"},
			map[string]any{"type": "text", "text": "b"},
		}},
		map[string]any{"role": "assistant", "content": "ok"},
		map[string]any{"role": "user", "content": []any{
			map[string]any{"type": "text", "text": "look "},
			map[string]any{"type": "image_url", "image_url": map[string]any{"url": "https://x/y.png"}},
		}},
		map[string]any{"role": "user", "content": []any{
			map[string]any{"type": "image", "source": map[string]any{"type": "base64", "media_type": "image/jpeg", "data": "QUJD"}},
		}},
	}
	out, systemText := qoderNormalizeMessages(in)
	if systemText != "S1" {
		t.Fatalf("systemText = %q", systemText)
	}
	if len(out) != 4 {
		t.Fatalf("normalized messages = %d, want 4 (system hoisted)", len(out))
	}
	if out[0].(map[string]any)["content"] != "a\nb" {
		t.Fatalf("text-only content must flatten: %v", out[0])
	}
	withImage := out[2].(map[string]any)["content"].([]any)
	if len(withImage) != 2 {
		t.Fatalf("image content blocks = %v", withImage)
	}
	if withImage[0].(map[string]any)["text"] != "look " {
		t.Fatalf("leading text block = %v", withImage[0])
	}
	imgBlock := withImage[1].(map[string]any)
	if imgBlock["type"] != "image_url" || imgBlock["image_url"].(map[string]any)["url"] != "https://x/y.png" {
		t.Fatalf("image block = %v", imgBlock)
	}
	claudeImg := out[3].(map[string]any)["content"].([]any)
	if got := claudeImg[0].(map[string]any)["image_url"].(map[string]any)["url"]; got != "data:image/jpeg;base64,QUJD" {
		t.Fatalf("claude image → image_url = %v", got)
	}
}

func TestQoderIsBillingBlock(t *testing.T) {
	cases := []struct {
		inner string
		want  bool
	}{
		{`{"code":110,"message":"daily"}`, true},
		{`{"code":"112"}`, true},
		{`{"code":10605}`, true},
		{`{"code": "10605", "message":"queue"}`, true},
		{`{"pricingUrl":"https://qoder.com/pricing"}`, true},
		{`{"code":500,"message":"oops"}`, false},
		{`quota exhausted`, false},
		{``, false},
	}
	for _, tc := range cases {
		if got := qoderIsBillingBlock(tc.inner); got != tc.want {
			t.Errorf("qoderIsBillingBlock(%q) = %v, want %v", tc.inner, got, tc.want)
		}
	}
}

func TestQoderInferenceBaseSelection(t *testing.T) {
	bases := qoderDefaultBases("intl")
	if got := qoderInferenceBase(Credential{AccessToken: "dt-1"}, "intl", bases); got != "https://api3.qoder.sh" {
		t.Fatalf("device token base = %q, want api3", got)
	}
	if got := qoderInferenceBase(Credential{AccessToken: "jt-1"}, "intl", bases); got != "https://api2.qoder.sh" {
		t.Fatalf("job token base = %q, want api2", got)
	}
	if got := qoderInferenceBase(Credential{APIKey: "pt-1"}, "intl", bases); got != "https://api3.qoder.sh" {
		t.Fatalf("PAT base (pre-exchange) = %q, want api3", got)
	}
	cnBases := qoderDefaultBases("cn")
	if got := qoderInferenceBase(Credential{AccessToken: "jt-1"}, "cn", cnBases); got != "https://gateway.qoder.com.cn" {
		t.Fatalf("cn job token base = %q, want gateway", got)
	}
	// Constructor region derivation (JS: qoder-cn → cn, else intl).
	if e := NewQoderExecutor("qoder"); e.region != "intl" || e.providerID != "qoder" {
		t.Fatalf("qoder executor = %+v", e)
	}
	if e := NewQoderCnExecutor(); e.region != "cn" || e.providerID != "qoder-cn" {
		t.Fatalf("qoder-cn executor = %+v", e)
	}
	if got := NewQoderCnExecutor().qoderBuildURL(&ProviderInfo{ID: "qoder-cn", BaseURL: "https://gateway.qoder.com.cn/algo/api/v2/service/pro/sse/agent_chat_generation"}, Credential{AccessToken: "dt-1"}); got != "https://gateway.qoder.com.cn/algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1" {
		t.Fatalf("cn buildURL = %q", got)
	}
}

// --- end-to-end fixture ---

type qoderFixture struct {
	mu           sync.Mutex
	modelCalls   int
	chatCalls    int
	uploadCalls  int
	modelCosyUsr string
	chatCosyUsr  string
	chatQuery    string
	chatModelKey string
	chatRawBody  []byte
	chatFn       func(w http.ResponseWriter, r *http.Request)
	srv          *httptest.Server
}

const qoderModelListJSON = `{"chat":[{"key":"auto","display_name":"Auto","is_reasoning":false,"max_output_tokens":8192,"max_input_tokens":200000,"source":"system","enable":true}]}`

func newQoderFixture(t *testing.T) *qoderFixture {
	t.Helper()
	qoderClearCachesForTest()
	f := &qoderFixture{}
	mux := http.NewServeMux()
	mux.HandleFunc("/algo/api/v2/model/list", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.modelCalls++
		f.modelCosyUsr = r.Header.Get("Cosy-User")
		f.mu.Unlock()
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer COSY.") {
			t.Errorf("model/list Authorization = %q, want COSY", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, qoderModelListJSON)
	})
	mux.HandleFunc("/algo/api/v2/service/pro/sse/agent_chat_generation", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.chatCalls++
		f.chatCosyUsr = r.Header.Get("Cosy-User")
		f.chatQuery = r.URL.RawQuery
		f.chatModelKey = r.Header.Get("X-Model-Key")
		f.chatRawBody = raw
		fn := f.chatFn
		f.mu.Unlock()
		if fn != nil {
			fn(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"statusCodeValue\":200,\"body\":\"{\\\"id\\\":\\\"c1\\\",\\\"choices\\\":[{\\\"delta\\\":{\\\"content\\\":\\\"ok\\\"}}]}\"}\n")
	})
	mux.HandleFunc("/algo/api/v2/image/upload", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.uploadCalls++
		f.mu.Unlock()
		if !strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data") {
			t.Errorf("upload Content-Type = %q, want multipart", r.Header.Get("Content-Type"))
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"url":"https://oss.example.com/img.png"}`)
	})
	mux.HandleFunc("/api/v1/jobToken/exchange", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var bodyMap map[string]any
		_ = json.Unmarshal(raw, &bodyMap)
		if bodyMap["personal_token"] != "pt-secret" {
			t.Errorf("exchange personal_token = %v", bodyMap["personal_token"])
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"token":"jt-xyz"}`)
	})
	mux.HandleFunc("/api/v1/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer jt-xyz" {
			t.Errorf("userinfo Authorization = %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"user-9"}`)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *qoderFixture) providerInfo(id string) *ProviderInfo {
	return &ProviderInfo{ID: id, BaseURL: f.srv.URL + "/algo/api/v2/service/pro/sse/agent_chat_generation"}
}

func qoderEnvelope(body string) string {
	raw, _ := json.Marshal(map[string]any{"statusCodeValue": 200, "body": body})
	return "data: " + string(raw) + "\n"
}

func TestQoderExecutorEndToEnd(t *testing.T) {
	f := newQoderFixture(t)
	f.chatFn = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, qoderEnvelope(`{"id":"c1","object":"chat.completion.chunk","created":1700000000,"model":"qoder/auto","choices":[{"index":0,"delta":{"role":"assistant","content":"Hello"},"finish_reason":null}]}`))
		io.WriteString(w, qoderEnvelope(`{"id":"c1","object":"chat.completion.chunk","created":1700000000,"model":"qoder/auto","choices":[{"index":0,"delta":{"content":" world","finish_reason":"stop"},"finish_reason":null}]}`))
		io.WriteString(w, qoderEnvelope(`{"id":"c1","object":"chat.completion.chunk","created":1700000000,"model":"qoder/auto","choices":[],"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}}`))
	}
	ex := NewQoderExecutor("qoder")
	cred := Credential{AccessToken: "dt-token", Specific: map[string]any{"userId": "user-1", "machineId": "mid-1"}}
	res, err := ex.Execute(context.Background(), f.providerInfo("qoder"), cred,
		[]byte(`{"model":"auto","messages":[{"role":"system","content":"You are helpful"},{"role":"user","content":"Say hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if res.Response.StatusCode != 200 {
		t.Fatalf("status = %d", res.Response.StatusCode)
	}
	body := readBody(t, res.Response)
	if !strings.Contains(body, "Hello") || !strings.Contains(body, " world") {
		t.Fatalf("unwrapped SSE missing content: %q", body)
	}
	// Usage arrived on a separate choices:[] frame and must be coalesced
	// onto a terminal finish chunk.
	if !strings.Contains(body, `"prompt_tokens":11`) || !strings.Contains(body, `"completion_tokens":7`) {
		t.Fatalf("coalesced usage missing: %q", body)
	}
	if !strings.Contains(body, `"finish_reason":"stop"`) || !strings.HasSuffix(strings.TrimSpace(body), "[DONE]") {
		t.Fatalf("terminal chunk/[DONE] missing: %q", body)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.modelCalls != 1 || f.modelCosyUsr != "user-1" {
		t.Fatalf("model/list calls = %d, cosy user = %q", f.modelCalls, f.modelCosyUsr)
	}
	if f.chatCalls != 1 || f.chatCosyUsr != "user-1" || f.chatModelKey != "auto" {
		t.Fatalf("chat calls = %d, cosy user = %q, model key = %q", f.chatCalls, f.chatCosyUsr, f.chatModelKey)
	}
	if !strings.Contains(f.chatQuery, "Encode=1") || !strings.Contains(f.chatQuery, "FetchKeys=llm_model_result") {
		t.Fatalf("chat query = %q", f.chatQuery)
	}
	// Decode the encoded wire body and assert the Qoder request shape.
	plain := qoderDecodeForTest(t, string(f.chatRawBody))
	var payload map[string]any
	if err := json.Unmarshal(plain, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["system"] != "You are helpful" {
		t.Fatalf("system not hoisted: %v", payload["system"])
	}
	msgs, _ := payload["messages"].([]any)
	if len(msgs) != 1 || msgs[0].(map[string]any)["role"] != "user" {
		t.Fatalf("payload messages = %v (system must be hoisted out)", payload["messages"])
	}
	mc, _ := payload["model_config"].(map[string]any)
	if mc == nil || mc["key"] != "auto" {
		t.Fatalf("model_config = %v", payload["model_config"])
	}
	params, _ := payload["parameters"].(map[string]any)
	if params["max_tokens"] != float64(8192) {
		t.Fatalf("parameters.max_tokens = %v, want model max_output_tokens 8192", params)
	}
	chatCtx, _ := payload["chat_context"].(map[string]any)
	extra, _ := chatCtx["extra"].(map[string]any)
	mirror, _ := extra["modelConfig"].(map[string]any)
	if mirror["key"] != "auto" || extra["originalContent"] != "Say hi" || chatCtx["text"] != "Say hi" {
		t.Fatalf("chat_context = %v", payload["chat_context"])
	}
	biz, _ := payload["business"].(map[string]any)
	if biz["product"] != "cli" || biz["type"] != "agent" {
		t.Fatalf("business = %v", biz)
	}
	if payload["chat_record_id"] != payload["request_set_id"] || len(payload["session_id"].(string)) != 16 {
		t.Fatalf("ids: record %v, set %v, session %v", payload["chat_record_id"], payload["request_set_id"], payload["session_id"])
	}
	// The executor's TransformedBody is the *plain* payload (JS result).
	var transformed map[string]any
	if err := json.Unmarshal(res.TransformedBody, &transformed); err != nil {
		t.Fatal(err)
	}
	if transformed["chat_record_id"] != payload["chat_record_id"] {
		t.Fatalf("TransformedBody mismatch: %v", transformed["chat_record_id"])
	}
}

func TestQoderExecutorBillingFirstFrame(t *testing.T) {
	f := newQoderFixture(t)
	f.chatFn = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		raw, _ := json.Marshal(map[string]any{"statusCodeValue": 403, "body": `{"code":"112","message":"quota exhausted"}`})
		io.WriteString(w, "data: "+string(raw)+"\n")
	}
	ex := NewQoderExecutor("qoder")
	cred := Credential{AccessToken: "dt-token", Specific: map[string]any{"userId": "user-1"}}
	res, err := ex.Execute(context.Background(), f.providerInfo("qoder"), cred,
		[]byte(`{"model":"auto","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	if res.Response.StatusCode != 403 {
		t.Fatalf("billing first frame status = %d, want 403; body %q", res.Response.StatusCode, body)
	}
	if !strings.Contains(body, "quota exhausted") {
		t.Fatalf("billing error body = %q", body)
	}
}

func TestQoderExecutorMidStreamBilling(t *testing.T) {
	f := newQoderFixture(t)
	f.chatFn = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, qoderEnvelope(`{"id":"c1","choices":[{"index":0,"delta":{"content":"partial"},"finish_reason":null}]}`))
		raw, _ := json.Marshal(map[string]any{"statusCodeValue": 403, "body": `{"code":"112","message":"quota exhausted"}`})
		io.WriteString(w, "data: "+string(raw)+"\n")
	}
	ex := NewQoderExecutor("qoder")
	cred := Credential{AccessToken: "dt-token", Specific: map[string]any{"userId": "user-1"}}
	res, err := ex.Execute(context.Background(), f.providerInfo("qoder"), cred,
		[]byte(`{"model":"auto","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	if res.Response.StatusCode != 200 {
		t.Fatalf("mid-stream status = %d (error must ride the stream)", res.Response.StatusCode)
	}
	if !strings.Contains(body, "partial") || !strings.Contains(body, "qoder_billing_block") || !strings.Contains(body, "[DONE]") {
		t.Fatalf("mid-stream billing stream = %q", body)
	}
}

func TestQoderExecutorMissingUserID(t *testing.T) {
	f := newQoderFixture(t)
	ex := NewQoderExecutor("qoder")
	res, err := ex.Execute(context.Background(), f.providerInfo("qoder"),
		Credential{AccessToken: "dt-token"}, []byte(`{"model":"auto","messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	if res.Response.StatusCode != 401 || !strings.Contains(body, "missing userId") {
		t.Fatalf("status = %d body = %q, want 401 missing userId", res.Response.StatusCode, body)
	}
	if f.modelCalls != 0 || f.chatCalls != 0 {
		t.Fatalf("upstream must not be called without userId: model %d chat %d", f.modelCalls, f.chatCalls)
	}
}

func TestQoderExecutorUnknownModel(t *testing.T) {
	f := newQoderFixture(t)
	ex := NewQoderExecutor("qoder")
	cred := Credential{AccessToken: "dt-token", Specific: map[string]any{"userId": "user-1"}}
	res, err := ex.Execute(context.Background(), f.providerInfo("qoder"), cred,
		[]byte(`{"model":"nope","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	var errBody struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &errBody); err != nil {
		t.Fatal(err)
	}
	if res.Response.StatusCode != 400 || errBody.Error.Message != `qoder: model_config for "nope" not yet known (run a model list fetch or check upstream connectivity)` {
		t.Fatalf("status = %d body = %q, want 400 model_config error", res.Response.StatusCode, body)
	}
	if f.modelCalls != 2 {
		t.Fatalf("model/list calls = %d, want 2 (initial + one forced refresh)", f.modelCalls)
	}
	if f.chatCalls != 0 {
		t.Fatalf("chat must not be called for an unknown model")
	}
}

func TestQoderExecutorPATFlow(t *testing.T) {
	f := newQoderFixture(t)
	ex := NewQoderExecutor("qoder")
	cred := Credential{APIKey: "pt-secret"} // no userId, no accessToken
	res, err := ex.Execute(context.Background(), f.providerInfo("qoder"), cred,
		[]byte(`{"model":"auto","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	if res.Response.StatusCode != 200 || !strings.Contains(body, "ok") {
		t.Fatalf("PAT flow status = %d body = %q", res.Response.StatusCode, body)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.modelCosyUsr != "user-9" || f.chatCosyUsr != "user-9" {
		t.Fatalf("COSY user after PAT exchange = model %q chat %q, want user-9 from userinfo", f.modelCosyUsr, f.chatCosyUsr)
	}
}

func TestQoderExecutorImageUploadRewrite(t *testing.T) {
	f := newQoderFixture(t)
	ex := NewQoderExecutor("qoder")
	cred := Credential{AccessToken: "dt-token", Specific: map[string]any{"userId": "user-1", "machineId": "mid-1"}}
	reqBody := `{"model":"auto","messages":[{"role":"user","content":[` +
		`{"type":"text","text":"look"},` +
		`{"type":"image_url","image_url":{"url":"data:image/png;base64,iVBORw0KGgo="}}` +
		`]}]}`
	res, err := ex.Execute(context.Background(), f.providerInfo("qoder"), cred, []byte(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, res.Response)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.uploadCalls != 1 {
		t.Fatalf("upload calls = %d, want 1", f.uploadCalls)
	}
	plain := qoderDecodeForTest(t, string(f.chatRawBody))
	var payload map[string]any
	if err := json.Unmarshal(plain, &payload); err != nil {
		t.Fatal(err)
	}
	msgs, _ := payload["messages"].([]any)
	content, _ := msgs[0].(map[string]any)["content"].([]any)
	if len(content) != 2 {
		t.Fatalf("rewritten content = %v", content)
	}
	img := content[1].(map[string]any)
	if img["type"] != "image_url" || img["image_url"].(map[string]any)["url"] != "https://oss.example.com/img.png" {
		t.Fatalf("image block after upload rewrite = %v, want OSS URL", img)
	}
}

func TestQoderExecutorCnEndToEnd(t *testing.T) {
	f := newQoderFixture(t)
	ex := NewQoderCnExecutor()
	cred := Credential{AccessToken: "dt-token", Specific: map[string]any{"userId": "user-1"}}
	res, err := ex.Execute(context.Background(), f.providerInfo("qoder-cn"), cred,
		[]byte(`{"model":"auto","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res.Response)
	if res.Response.StatusCode != 200 || !strings.Contains(body, "ok") {
		t.Fatalf("cn status = %d body = %q", res.Response.StatusCode, body)
	}
	if !strings.HasPrefix(res.URL, f.srv.URL) {
		t.Fatalf("cn URL = %q", res.URL)
	}
}
