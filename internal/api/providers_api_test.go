package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"proxygo/internal/chatcore"
	"proxygo/internal/db"
	"proxygo/internal/oauthsvc"
)

type pvTestEnv struct {
	store *db.Store
	mux   *http.ServeMux
	token string
}

func pvNewEnv(t *testing.T) *pvTestEnv {
	t.Helper()
	store, err := db.OpenInDir(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	mux := http.NewServeMux()
	RegisterProviders(mux, Deps{Store: store})
	return &pvTestEnv{store: store, mux: mux, token: CreateSessionToken(store)}
}

func (e *pvTestEnv) do(t *testing.T, method, path string, body string) (int, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: e.token})
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	out := map[string]any{}
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
	}
	return rec.Code, out
}

func (e *pvTestEnv) doRaw(t *testing.T, method, path string) (int, http.Header, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: e.token})
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec.Code, rec.Header(), rec.Body.String()
}

// pvStubFetch replaces the outbound HTTP funnel for the duration of a test.
func pvStubFetch(t *testing.T, fn func(req *http.Request) (*http.Response, error)) {
	t.Helper()
	old := pvHTTPDo
	pvHTTPDo = fn
	t.Cleanup(func() { pvHTTPDo = old })
}

func pvHTTPResp(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{},
	}
}

func TestPVProvidersCRUD(t *testing.T) {
	env := pvNewEnv(t)
	code, resp := env.do(t, "POST", "/api/providers", `{"provider":"openai","apiKey":"sk-test","name":"My OpenAI"}`)
	if code != 201 {
		t.Fatalf("create status = %d, resp = %v", code, resp)
	}
	conn, _ := resp["connection"].(map[string]any)
	if conn == nil {
		t.Fatalf("no connection in %v", resp)
	}
	if _, leaked := conn["apiKey"]; leaked {
		t.Fatalf("apiKey leaked in response: %v", conn)
	}
	id, _ := conn["id"].(string)
	if id == "" {
		t.Fatalf("connection has no id: %v", conn)
	}

	code, resp = env.do(t, "GET", "/api/providers", "")
	if code != 200 || len(resp["connections"].([]any)) != 1 {
		t.Fatalf("list: %d %v", code, resp)
	}
	code, resp = env.do(t, "GET", "/api/providers/"+id, "")
	if code != 200 {
		t.Fatalf("get: %d %v", code, resp)
	}
	code, resp = env.do(t, "PUT", "/api/providers/"+id, `{"name":"Renamed","providerSpecificData":{"region":"us"}}`)
	if code != 200 {
		t.Fatalf("put: %d %v", code, resp)
	}
	updated, _ := resp["connection"].(map[string]any)
	if updated["name"] != "Renamed" {
		t.Fatalf("name not updated: %v", updated)
	}
	code, _ = env.do(t, "DELETE", "/api/providers/"+id, "")
	if code != 200 {
		t.Fatalf("delete: %d", code)
	}
	code, _ = env.do(t, "GET", "/api/providers/"+id, "")
	if code != 404 {
		t.Fatalf("get after delete: %d", code)
	}
}

func TestPVProvidersCreateValidation(t *testing.T) {
	env := pvNewEnv(t)
	code, resp := env.do(t, "POST", "/api/providers", `{"provider":"openai","name":"X"}`)
	if code != 400 || resp["error"] != "API Key is required" {
		t.Fatalf("missing key: %d %v", code, resp)
	}
	code, resp = env.do(t, "POST", "/api/providers", `{"provider":"not-a-provider","apiKey":"k","name":"X"}`)
	if code != 400 || resp["error"] != "Invalid provider" {
		t.Fatalf("invalid provider: %d %v", code, resp)
	}
	code, resp = env.do(t, "POST", "/api/providers", `{"provider":"openai","apiKey":"k","name":"X","connectionProxyEnabled":true}`)
	if code != 400 || resp["error"] != "Connection proxy URL is required when connection proxy is enabled" {
		t.Fatalf("proxy validation: %d %v", code, resp)
	}
	// Name conflict -> 409 with the typed shape.
	code, _ = env.do(t, "POST", "/api/providers", `{"provider":"openai","apiKey":"k1","name":"Dup"}`)
	if code != 201 {
		t.Fatalf("first create: %d", code)
	}
	code, resp = env.do(t, "POST", "/api/providers", `{"provider":"openai","apiKey":"k2","name":"Dup"}`)
	if code != 409 || resp["code"] != "PROVIDER_NAME_CONFLICT" || resp["existingName"] != "Dup" {
		t.Fatalf("conflict: %d %v", code, resp)
	}
}

func TestPVNodesLifecycle(t *testing.T) {
	env := pvNewEnv(t)
	code, resp := env.do(t, "POST", "/api/provider-nodes", `{"name":"My Node","prefix":"mine","apiType":"chat","type":"openai-compatible"}`)
	if code != 201 {
		t.Fatalf("create node: %d %v", code, resp)
	}
	node, _ := resp["node"].(map[string]any)
	nodeID, _ := node["id"].(string)
	if !strings.HasPrefix(nodeID, "openai-compatible-chat-") {
		t.Fatalf("node id = %v", nodeID)
	}
	if node["baseUrl"] != "https://api.openai.com/v1" {
		t.Fatalf("default baseUrl = %v", node["baseUrl"])
	}
	code, resp = env.do(t, "POST", "/api/provider-nodes", `{"name":"Bad","prefix":"b","apiType":"nope","type":"openai-compatible"}`)
	if code != 400 || resp["error"] != "Invalid OpenAI compatible API type" {
		t.Fatalf("bad apiType: %d %v", code, resp)
	}
	// Connection against the node, then node PUT must sync its psd.
	code, resp = env.do(t, "POST", "/api/providers", `{"provider":"`+nodeID+`","apiKey":"k","name":"Node Conn"}`)
	if code != 201 {
		t.Fatalf("create node conn: %d %v", code, resp)
	}
	conn, _ := resp["connection"].(map[string]any)
	connID, _ := conn["id"].(string)

	code, resp = env.do(t, "PUT", "/api/provider-nodes/"+nodeID, `{"name":"My Node","prefix":"mine","apiType":"chat","baseUrl":"https://example.com/v1"}`)
	if code != 200 {
		t.Fatalf("put node: %d %v", code, resp)
	}
	stored, err := env.store.GetProviderConnectionByID(connID)
	if err != nil || stored == nil {
		t.Fatalf("conn lookup: %v", err)
	}
	psd, _ := stored["providerSpecificData"].(map[string]any)
	if psd["baseUrl"] != "https://example.com/v1" {
		t.Fatalf("psd not synced: %v", psd)
	}
	code, _ = env.do(t, "DELETE", "/api/provider-nodes/"+nodeID, "")
	if code != 200 {
		t.Fatalf("delete node: %d", code)
	}
	stored, _ = env.store.GetProviderConnectionByID(connID)
	if stored != nil {
		t.Fatalf("connection should be deleted with node")
	}
}

func TestPVCombosAndPresets(t *testing.T) {
	env := pvNewEnv(t)
	code, resp := env.do(t, "POST", "/api/combos", `{"name":"my-combo","models":["openai/gpt-4o"]}`)
	if code != 201 {
		t.Fatalf("create combo: %d %v", code, resp)
	}
	comboID, _ := resp["id"].(string)
	if comboID == "" || resp["name"] != "my-combo" {
		t.Fatalf("combo shape: %v", resp)
	}
	code, resp = env.do(t, "POST", "/api/combos", `{"name":"my-combo","models":[]}`)
	if code != 400 || resp["error"] != "Combo name already exists" {
		t.Fatalf("dup combo: %d %v", code, resp)
	}
	code, resp = env.do(t, "POST", "/api/combos", `{"name":"bad name!","models":[]}`)
	if code != 400 {
		t.Fatalf("bad name: %d %v", code, resp)
	}
	code, resp = env.do(t, "GET", "/api/combos/presets?source=claude", "")
	if code != 200 {
		t.Fatalf("presets get: %d %v", code, resp)
	}
	items, _ := resp["items"].([]any)
	foundSonnet := false
	for _, it := range items {
		m, _ := it.(map[string]any)
		if m["name"] == "sonnet" {
			foundSonnet = true
		}
	}
	if !foundSonnet {
		t.Fatalf("claude presets missing sonnet alias: %v", resp["toCreate"])
	}
	code, resp = env.do(t, "POST", "/api/combos/presets", `{"source":"claude"}`)
	if code != 200 || resp["createdCount"] == float64(0) {
		t.Fatalf("presets post: %d %v", code, resp)
	}
	code, resp = env.do(t, "GET", "/api/combos/presets?source=bogus", "")
	if code != 400 {
		t.Fatalf("bad source: %d", code)
	}
	code, _ = env.do(t, "DELETE", "/api/combos/"+comboID, "")
	if code != 200 {
		t.Fatalf("delete combo: %d", code)
	}
}

func TestPVModelsRoutes(t *testing.T) {
	env := pvNewEnv(t)
	code, resp := env.do(t, "GET", "/api/models", "")
	if code != 200 {
		t.Fatalf("models list: %d", code)
	}
	models, _ := resp["models"].([]any)
	if len(models) < 1000 {
		t.Fatalf("expected 1000+ models, got %d", len(models))
	}
	first, _ := models[0].(map[string]any)
	if first["fullModel"] == "" || first["caps"] == nil {
		t.Fatalf("model entry shape: %v", first)
	}
	// alias via /api/models PUT (stored key = model, JS quirk)
	code, resp = env.do(t, "PUT", "/api/models", `{"model":"openai/gpt-4o","alias":"best"}`)
	if code != 200 || resp["success"] != true {
		t.Fatalf("models put alias: %d %v", code, resp)
	}
	code, resp = env.do(t, "PUT", "/api/models", `{"model":"openai/gpt-4o-mini","alias":"best"}`)
	if code != 400 || resp["error"] != "Alias already in use" {
		t.Fatalf("alias reuse: %d %v", code, resp)
	}
	code, _ = env.do(t, "PUT", "/api/models/alias", `{"alias":"fast","model":"openai/gpt-4o-mini"}`)
	if code != 200 {
		t.Fatalf("alias put: %d", code)
	}
	code, resp = env.do(t, "GET", "/api/models/alias", "")
	aliases, _ := resp["aliases"].(map[string]any)
	if aliases["fast"] != "openai/gpt-4o-mini" {
		t.Fatalf("aliases: %v", aliases)
	}
	code, _ = env.do(t, "DELETE", "/api/models/alias?alias=fast", "")
	if code != 200 {
		t.Fatalf("alias delete: %d", code)
	}

	// custom models: caps sanitized to vision/reasoning only
	code, resp = env.do(t, "POST", "/api/models/custom", `{"providerAlias":"openai","id":"my-model","type":"llm","caps":{"vision":true,"search":true,"bogus":1}}`)
	if code != 200 || resp["success"] != true {
		t.Fatalf("custom create: %d %v", code, resp)
	}
	code, resp = env.do(t, "GET", "/api/models/custom", "")
	custom, _ := resp["models"].([]any)
	if len(custom) != 1 {
		t.Fatalf("custom list: %v", resp)
	}
	caps, _ := custom[0].(map[string]any)["caps"].(map[string]any)
	if caps["vision"] != true {
		t.Fatalf("caps vision lost: %v", caps)
	}
	if _, bad := caps["search"]; bad {
		t.Fatalf("caps search should be stripped: %v", caps)
	}
	code, _ = env.do(t, "DELETE", "/api/models/custom?providerAlias=openai&id=my-model", "")
	if code != 200 {
		t.Fatalf("custom delete: %d", code)
	}

	// disabled models
	code, _ = env.do(t, "POST", "/api/models/disabled", `{"providerAlias":"openai","ids":["gpt-4o"]}`)
	if code != 200 {
		t.Fatalf("disable: %d", code)
	}
	code, resp = env.do(t, "GET", "/api/models/disabled?providerAlias=openai", "")
	ids, _ := resp["ids"].([]any)
	if len(ids) != 1 || ids[0] != "gpt-4o" {
		t.Fatalf("disabled ids: %v", resp)
	}
	code, resp = env.do(t, "GET", "/api/models", "")
	for _, m := range resp["models"].([]any) {
		mm, _ := m.(map[string]any)
		if mm["fullModel"] == "openai/gpt-4o" {
			t.Fatalf("disabled model still listed")
		}
	}
	code, _ = env.do(t, "DELETE", "/api/models/disabled?providerAlias=openai&id=gpt-4o", "")
	if code != 200 {
		t.Fatalf("enable: %d", code)
	}
}

func TestPVAvailability(t *testing.T) {
	env := pvNewEnv(t)
	// Note: the db repo clears modelLock_* when testStatus flips to "active"
	// in the same write (resetHealthStateOnActivation), so seed the lock
	// alongside a non-active status, as the runtime does.
	conn, err := env.store.CreateProviderConnection(db.Record{
		"provider": "openai", "authType": "apikey", "name": "Locked", "apiKey": "k",
		"isActive": true, "testStatus": "error",
	})
	if err != nil {
		t.Fatalf("seed conn: %v", err)
	}
	// Locks are written by the runtime via update (create uses a field
	// whitelist), so set the lock the same way.
	connID, _ := conn["id"].(string)
	if _, err := env.store.UpdateProviderConnection(connID, db.Record{
		"modelLock_gpt-4o": "2999-01-01T00:00:00.000Z",
	}); err != nil {
		t.Fatalf("seed lock: %v", err)
	}
	_ = conn
	code, resp := env.do(t, "GET", "/api/models/availability", "")
	if code != 200 {
		t.Fatalf("availability: %d %v", code, resp)
	}
	entries, _ := resp["models"].([]any)
	if len(entries) != 1 {
		t.Fatalf("expected 1 lock entry: %v", resp)
	}
	entry, _ := entries[0].(map[string]any)
	if entry["model"] != "gpt-4o" || entry["status"] != "cooldown" {
		t.Fatalf("entry: %v", entry)
	}
	code, resp = env.do(t, "POST", "/api/models/availability", `{"action":"clearCooldown","provider":"openai","model":"gpt-4o"}`)
	if code != 200 || resp["ok"] != true {
		t.Fatalf("clear: %d %v", code, resp)
	}
	code, resp = env.do(t, "GET", "/api/models/availability", "")
	if len(resp["models"].([]any)) != 0 {
		t.Fatalf("lock not cleared: %v", resp)
	}
	code, _ = env.do(t, "POST", "/api/models/availability", `{"action":"nope"}`)
	if code != 400 {
		t.Fatalf("bad action: %d", code)
	}
}

func TestPVOverrides(t *testing.T) {
	env := pvNewEnv(t)
	code, resp := env.do(t, "PUT", "/api/providers/openai/overrides", `{"headers":{"X-Custom":"yes"}}`)
	if code != 200 {
		t.Fatalf("put overrides: %d %v", code, resp)
	}
	code, resp = env.do(t, "GET", "/api/providers/openai/overrides", "")
	if code != 200 {
		t.Fatalf("get overrides: %d %v", code, resp)
	}
	headers, _ := resp["headers"].(map[string]any)
	if headers["X-Custom"] != "yes" {
		t.Fatalf("headers: %v", resp)
	}
	code, resp = env.do(t, "PUT", "/api/providers/openai/overrides", `{"headers":{"Authorization":"Bearer x"}}`)
	if code != 400 || resp["error"] != "Header Authorization cannot be overridden" {
		t.Fatalf("blocked header: %d %v", code, resp)
	}
	code, resp = env.do(t, "PUT", "/api/providers/openai/overrides", `{"headers":{"Bad Name":"x"}}`)
	if code != 400 {
		t.Fatalf("bad name: %d %v", code, resp)
	}
	code, _ = env.do(t, "PUT", "/api/providers/openai/overrides", `{"headers":{}}`)
	if code != 200 {
		t.Fatalf("clear overrides: %d", code)
	}
	code, resp = env.do(t, "GET", "/api/providers/openai/overrides", "")
	headers, _ = resp["headers"].(map[string]any)
	if len(headers) != 0 {
		t.Fatalf("overrides not cleared: %v", headers)
	}
}

func TestPVProviderTestWithMockUpstream(t *testing.T) {
	env := pvNewEnv(t)
	status := 200
	pvStubFetch(t, func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Host, "api.openai.com") {
			return pvHTTPResp(status, `{"data":[]}`), nil
		}
		return pvHTTPResp(404, `{}`), nil
	})
	code, resp := env.do(t, "POST", "/api/providers", `{"provider":"openai","apiKey":"sk-x","name":"Mocked"}`)
	if code != 201 {
		t.Fatalf("create: %d %v", code, resp)
	}
	connID, _ := resp["connection"].(map[string]any)["id"].(string)

	code, resp = env.do(t, "POST", "/api/providers/"+connID+"/test", "")
	if code != 200 || resp["valid"] != true {
		t.Fatalf("test ok: %d %v", code, resp)
	}
	stored, _ := env.store.GetProviderConnectionByID(connID)
	if stored["testStatus"] != "active" {
		t.Fatalf("testStatus not persisted: %v", stored["testStatus"])
	}
	status = 401
	code, resp = env.do(t, "POST", "/api/providers/"+connID+"/test", "")
	if code != 200 || resp["valid"] != false || resp["error"] != "Invalid API key" {
		t.Fatalf("test 401: %d %v", code, resp)
	}
	code, _ = env.do(t, "POST", "/api/providers/does-not-exist/test", "")
	if code != 404 {
		t.Fatalf("test missing conn: %d", code)
	}
	// validate endpoint
	code, resp = env.do(t, "POST", "/api/providers/validate", `{"provider":"openai","apiKey":"sk-x"}`)
	if code != 200 || resp["valid"] != false {
		t.Fatalf("validate 401: %d %v", code, resp)
	}
	status = 200
	code, resp = env.do(t, "POST", "/api/providers/validate", `{"provider":"openai","apiKey":"sk-x"}`)
	if code != 200 || resp["valid"] != true {
		t.Fatalf("validate ok: %d %v", code, resp)
	}
	code, resp = env.do(t, "POST", "/api/providers/validate", `{"provider":"openai"}`)
	if code != 400 {
		t.Fatalf("validate missing key: %d %v", code, resp)
	}
	// test-batch
	code, resp = env.do(t, "POST", "/api/providers/test-batch", `{"mode":"bogus"}`)
	if code != 400 {
		t.Fatalf("batch bad mode: %d %v", code, resp)
	}
	code, resp = env.do(t, "POST", "/api/providers/test-batch", `{"mode":"apikey"}`)
	if code != 200 {
		t.Fatalf("batch: %d %v", code, resp)
	}
	summary, _ := resp["summary"].(map[string]any)
	if summary["total"] != float64(1) || summary["passed"] != float64(1) {
		t.Fatalf("batch summary: %v", summary)
	}
}

func TestPVSuggestedAndKilo(t *testing.T) {
	env := pvNewEnv(t)
	pvStubFetch(t, func(req *http.Request) (*http.Response, error) {
		switch {
		case strings.Contains(req.URL.Host, "api.kilo.ai"):
			return pvHTTPResp(200, `{"data":[{"id":"free-1","name":"Free One","isFree":true,"context_length":128000},{"id":"paid-1","name":"Paid","isFree":false}]}`), nil
		default:
			return pvHTTPResp(200, `{"data":[
				{"id":"a/free","name":"A","pricing":{"prompt":"0","completion":"0"},"context_length":300000},
				{"id":"b/small","name":"B","pricing":{"prompt":"0","completion":"0"},"context_length":100000},
				{"id":"c/paid","name":"C","pricing":{"prompt":"1","completion":"0"},"context_length":500000}
			]}`), nil
		}
	})
	code, resp := env.do(t, "GET", "/api/providers/suggested-models?url=https://example.com/models&type=openrouter-free", "")
	if code != 200 {
		t.Fatalf("suggested: %d %v", code, resp)
	}
	data, _ := resp["data"].([]any)
	if len(data) != 1 {
		t.Fatalf("openrouter-free filter: %v", data)
	}
	code, _ = env.do(t, "GET", "/api/providers/suggested-models?url=https://example.com&type=nope", "")
	if code != 400 {
		t.Fatalf("unknown filter: %d", code)
	}
	code, _ = env.do(t, "GET", "/api/providers/suggested-models", "")
	if code != 400 {
		t.Fatalf("missing params: %d", code)
	}
	code, resp = env.do(t, "GET", "/api/providers/kilo/free-models", "")
	if code != 200 || resp["cached"] != false {
		t.Fatalf("kilo first: %d %v", code, resp)
	}
	kiloModels, _ := resp["models"].([]any)
	if len(kiloModels) != 1 {
		t.Fatalf("kilo free filter: %v", kiloModels)
	}
	code, resp = env.do(t, "GET", "/api/providers/kilo/free-models", "")
	if code != 200 || resp["cached"] != true {
		t.Fatalf("kilo cached: %d %v", code, resp)
	}
}

func TestPVTags(t *testing.T) {
	env := pvNewEnv(t)
	code, headers, body := env.doRaw(t, "GET", "/api/tags")
	if code != 200 {
		t.Fatalf("tags: %d", code)
	}
	if headers.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("cors header missing: %v", headers)
	}
	if !strings.Contains(body, "llama3.2") {
		t.Fatalf("tags body: %s", body)
	}
	code, _, _ = env.doRaw(t, "OPTIONS", "/api/tags")
	if code != 200 {
		t.Fatalf("tags options: %d", code)
	}
}

func TestPVProxyPools(t *testing.T) {
	env := pvNewEnv(t)
	code, resp := env.do(t, "POST", "/api/proxy-pools", `{"name":"","proxyUrl":"http://x:8080"}`)
	if code != 400 || resp["error"] != "Name is required" {
		t.Fatalf("pool name validation: %d %v", code, resp)
	}
	code, resp = env.do(t, "POST", "/api/proxy-pools", `{"name":"Pool A","proxyUrl":"http://127.0.0.1:9999","type":"bogus"}`)
	if code != 201 {
		t.Fatalf("pool create: %d %v", code, resp)
	}
	pool, _ := resp["proxyPool"].(map[string]any)
	poolID, _ := pool["id"].(string)
	if pool["type"] != "http" {
		t.Fatalf("pool type normalized: %v", pool["type"])
	}
	// Bind a connection -> delete must 409.
	code, resp = env.do(t, "POST", "/api/providers", `{"provider":"openai","apiKey":"k","name":"Bound","proxyPoolId":"`+poolID+`"}`)
	if code != 201 {
		t.Fatalf("bound conn: %d %v", code, resp)
	}
	code, resp = env.do(t, "GET", "/api/proxy-pools?includeUsage=true", "")
	pools, _ := resp["proxyPools"].([]any)
	if len(pools) != 1 || pools[0].(map[string]any)["boundConnectionCount"] != float64(1) {
		t.Fatalf("usage: %v", resp)
	}
	code, resp = env.do(t, "DELETE", "/api/proxy-pools/"+poolID, "")
	if code != 409 || resp["boundConnectionCount"] != float64(1) {
		t.Fatalf("pool delete blocked: %d %v", code, resp)
	}
	// Test endpoint against a stubbed proxy transport.
	pvStubFetch(t, func(req *http.Request) (*http.Response, error) {
		return pvHTTPResp(200, ""), nil
	})
	oldProxied := pvProxiedDo
	pvProxiedDo = func(string) (func(*http.Request) (*http.Response, error), error) {
		return pvHTTPDo, nil
	}
	t.Cleanup(func() { pvProxiedDo = oldProxied })
	code, resp = env.do(t, "POST", "/api/proxy-pools/"+poolID+"/test", "")
	if code != 200 || resp["ok"] != true {
		t.Fatalf("pool test: %d %v", code, resp)
	}
	stored, _ := env.store.GetProxyPoolByID(poolID)
	if stored["testStatus"] != "active" {
		t.Fatalf("pool testStatus: %v", stored["testStatus"])
	}
	code, resp = env.do(t, "PUT", "/api/proxy-pools/"+poolID, `{"name":"Pool B"}`)
	if code != 200 || resp["proxyPool"].(map[string]any)["name"] != "Pool B" {
		t.Fatalf("pool put: %d %v", code, resp)
	}
	code, _ = env.do(t, "GET", "/api/proxy-pools/nope", "")
	if code != 404 {
		t.Fatalf("pool missing: %d", code)
	}
}

func TestPVProviderModelsEndpoint(t *testing.T) {
	env := pvNewEnv(t)
	pvStubFetch(t, func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Host, "api.openai.com") {
			return pvHTTPResp(200, `{"data":[{"id":"gpt-4o"},{"id":"gpt-4o-mini"}]}`), nil
		}
		return pvHTTPResp(404, `{}`), nil
	})
	code, resp := env.do(t, "POST", "/api/providers", `{"provider":"openai","apiKey":"sk-x","name":"M"}`)
	if code != 201 {
		t.Fatalf("create: %d", code)
	}
	connID, _ := resp["connection"].(map[string]any)["id"].(string)
	code, resp = env.do(t, "GET", "/api/providers/"+connID+"/models", "")
	if code != 200 {
		t.Fatalf("models: %d %v", code, resp)
	}
	models, _ := resp["models"].([]any)
	if len(models) != 2 {
		t.Fatalf("models parsed: %v", models)
	}
	// Unsupported provider -> 400 with the JS message.
	code, resp = env.do(t, "POST", "/api/providers", `{"provider":"ollama-local","name":"Local"}`)
	if code != 201 {
		t.Fatalf("ollama-local create (no key needed): %d %v", code, resp)
	}
}

func TestPVPingAndTestModels(t *testing.T) {
	env := pvNewEnv(t)
	pingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"hi"},"finish_reason":"stop"}]}`))
	}))
	defer pingServer.Close()
	old := pvPingBaseOverride
	pvPingBaseOverride = pingServer.URL
	t.Cleanup(func() { pvPingBaseOverride = old })

	code, resp := env.do(t, "POST", "/api/models/test", `{"model":"deepseek/deepseek-chat","kind":"llm"}`)
	if code != 200 || resp["ok"] != true {
		t.Fatalf("ping llm: %d %v", code, resp)
	}
	code, _ = env.do(t, "POST", "/api/models/test", `{"kind":"llm"}`)
	if code != 400 {
		t.Fatalf("ping missing model: %d", code)
	}
	// test-models over a connection whose provider has a static catalog.
	conn, err := env.store.CreateProviderConnection(db.Record{
		"provider": "deepseek", "authType": "apikey", "name": "DS", "apiKey": "k", "isActive": true,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	code, resp = env.do(t, "POST", "/api/providers/"+conn["id"].(string)+"/test-models", "")
	if code != 200 {
		t.Fatalf("test-models: %d %v", code, resp)
	}
	results, _ := resp["results"].([]any)
	if len(results) == 0 {
		t.Fatalf("test-models results empty")
	}
	for _, r0 := range results {
		m, _ := r0.(map[string]any)
		if m["ok"] != true {
			t.Fatalf("ping result not ok: %v", m)
		}
	}
}

func TestPVNodeValidate(t *testing.T) {
	env := pvNewEnv(t)
	pvStubFetch(t, func(req *http.Request) (*http.Response, error) {
		return pvHTTPResp(200, `{"data":[]}`), nil
	})
	code, resp := env.do(t, "POST", "/api/provider-nodes/validate", `{"baseUrl":"https://example.com/v1","apiKey":"k"}`)
	if code != 200 || resp["valid"] != true {
		t.Fatalf("node validate: %d %v", code, resp)
	}
	code, resp = env.do(t, "POST", "/api/provider-nodes/validate", `{"baseUrl":"https://example.com/v1"}`)
	if code != 400 {
		t.Fatalf("node validate missing key: %d %v", code, resp)
	}
	code, resp = env.do(t, "POST", "/api/provider-nodes/validate", `{"baseUrl":"https://example.com/v1","apiKey":"k","type":"custom-embedding"}`)
	if code != 200 || resp["valid"] != false || resp["error"] != "Model ID required for embedding validation" {
		t.Fatalf("embedding model required: %d %v", code, resp)
	}
}

func TestPVCatalogSyncGet(t *testing.T) {
	env := pvNewEnv(t)
	code, resp := env.do(t, "GET", "/api/models/catalog-sync", "")
	if code != 200 {
		t.Fatalf("catalog-sync: %d %v", code, resp)
	}
	if resp["url"] != "https://models.dev/api.json" || resp["intervalMs"] != float64(86400000) {
		t.Fatalf("catalog-sync state: %v", resp)
	}
	if resp["catalog"] != nil {
		t.Fatalf("catalog should be null without a synced file: %v", resp["catalog"])
	}
	// With the sync engine landed, a POST whose upstream fetch fails still
	// surfaces 503 (lastError || "sync in progress"), like the JS route.
	pvStubFetch(t, func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("network down")
	})
	code, resp = env.do(t, "POST", "/api/models/catalog-sync", "")
	if code != 503 || resp["error"] == nil || resp["error"] == "" {
		t.Fatalf("catalog-sync post with dead upstream: %d %v", code, resp)
	}
}

func TestPVClientEndpoint(t *testing.T) {
	env := pvNewEnv(t)
	code, resp := env.do(t, "GET", "/api/providers/client", "")
	if code != 200 {
		t.Fatalf("client: %d %v", code, resp)
	}
	if _, ok := resp["connections"].([]any); !ok {
		t.Fatalf("client shape: %v", resp)
	}
	pagination, _ := resp["pagination"].(map[string]any)
	if pagination["pageSize"] != float64(20) {
		t.Fatalf("client pagination: %v", pagination)
	}
}

func TestPVCloudflareDeployMocked(t *testing.T) {
	env := pvNewEnv(t)
	pvStubFetch(t, func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == "PUT" && strings.Contains(req.URL.Path, "/workers/scripts/"):
			return pvHTTPResp(200, `{"success":true}`), nil
		case req.Method == "POST" && strings.HasSuffix(req.URL.Path, "/subdomain"):
			return pvHTTPResp(200, `{"success":true}`), nil
		case req.Method == "GET" && strings.HasSuffix(req.URL.Path, "/workers/subdomain"):
			return pvHTTPResp(200, `{"result":{"subdomain":"myacct"}}`), nil
		}
		return pvHTTPResp(404, `{}`), nil
	})
	code, resp := env.do(t, "POST", "/api/proxy-pools/cloudflare-deploy", `{"accountId":"acc1"}`)
	if code != 400 {
		t.Fatalf("cf missing token: %d %v", code, resp)
	}
	code, resp = env.do(t, "POST", "/api/proxy-pools/cloudflare-deploy", `{"accountId":"acc1","apiToken":"tok","projectName":"relay-x"}`)
	if code != 201 {
		t.Fatalf("cf deploy: %d %v", code, resp)
	}
	if resp["deployUrl"] != "https://relay-x.myacct.workers.dev" {
		t.Fatalf("cf deployUrl: %v", resp["deployUrl"])
	}
	pool, _ := resp["proxyPool"].(map[string]any)
	if pool["type"] != "cloudflare" {
		t.Fatalf("cf pool type: %v", pool)
	}
}

// ---------- Team X: providers leftovers ----------

type pvRoundTripFunc func(*http.Request) (*http.Response, error)

func (f pvRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// pvStubOAuthHTTP swaps oauthsvc's upstream client (item 1 delegation
// goes through oauthsvc, not pvHTTPDo).
func pvStubOAuthHTTP(t *testing.T, fn func(req *http.Request) (*http.Response, error)) {
	t.Helper()
	old := oauthsvc.HTTPClient
	oauthsvc.HTTPClient = &http.Client{Transport: pvRoundTripFunc(fn)}
	t.Cleanup(func() { oauthsvc.HTTPClient = old })
}

func TestPVRefreshDelegatedToOAuthSvc(t *testing.T) {
	env := pvNewEnv(t)
	var refreshForm string
	pvStubOAuthHTTP(t, func(req *http.Request) (*http.Response, error) {
		if !strings.Contains(req.URL.Host, "auth.openai.com") {
			return pvHTTPResp(404, `{}`), nil
		}
		body, _ := io.ReadAll(req.Body)
		refreshForm = string(body)
		return pvHTTPResp(200, `{"access_token":"new-at","refresh_token":"new-rt","expires_in":3600,"id_token":"id-tok"}`), nil
	})
	var probeAuth string
	pvStubFetch(t, func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Host, "chatgpt.com") {
			probeAuth = req.Header.Get("Authorization")
			return pvHTTPResp(400, `{}`), nil // codex accepts 400 as reachable
		}
		return pvHTTPResp(404, `{}`), nil
	})
	conn, err := env.store.CreateProviderConnection(db.Record{
		"provider": "codex", "name": "Codex", "accessToken": "old-at",
		"refreshToken": "old-rt", "expiresAt": "2000-01-01T00:00:00.000Z", "isActive": true,
	})
	if err != nil {
		t.Fatalf("seed conn: %v", err)
	}
	connID, _ := conn["id"].(string)
	code, resp := env.do(t, "POST", "/api/providers/"+connID+"/test", "")
	if code != 200 || resp["valid"] != true {
		t.Fatalf("codex test after refresh: %d %v", code, resp)
	}
	if !strings.Contains(refreshForm, "grant_type=refresh_token") || !strings.Contains(refreshForm, "refresh_token=old-rt") {
		t.Fatalf("oauthsvc refresh form: %s", refreshForm)
	}
	if probeAuth != "Bearer new-at" {
		t.Fatalf("probe should use refreshed token, got %q", probeAuth)
	}
	stored, _ := env.store.GetProviderConnectionByID(connID)
	if stored["accessToken"] != "new-at" || stored["refreshToken"] != "new-rt" {
		t.Fatalf("refreshed tokens not persisted: %v", stored)
	}
	if stored["idToken"] != "id-tok" {
		t.Fatalf("idToken not persisted: %v", stored["idToken"])
	}
	// Refresh failure -> JS outcome "Token expired and refresh failed".
	pvStubOAuthHTTP(t, func(req *http.Request) (*http.Response, error) {
		return pvHTTPResp(400, `{"error":"invalid_grant"}`), nil
	})
	conn2, err := env.store.CreateProviderConnection(db.Record{
		"provider": "grok-cli", "name": "Grok", "accessToken": "old-at",
		"refreshToken": "old-rt", "expiresAt": "2000-01-01T00:00:00.000Z", "isActive": true,
	})
	if err != nil {
		t.Fatalf("seed grok-cli conn: %v", err)
	}
	code, resp = env.do(t, "POST", "/api/providers/"+conn2["id"].(string)+"/test", "")
	if code != 200 || resp["valid"] != false || resp["error"] != "Token expired and refresh failed" {
		t.Fatalf("grok-cli failed refresh: %d %v", code, resp)
	}
}

func TestPVBedrockProbe(t *testing.T) {
	env := pvNewEnv(t)
	mode := "ok"
	var gotHost, gotPath, gotAuth string
	pvStubFetch(t, func(req *http.Request) (*http.Response, error) {
		gotHost, gotPath, gotAuth = req.URL.Host, req.URL.Path, req.Header.Get("Authorization")
		switch mode {
		case "ok":
			return pvHTTPResp(200, `{"foundationModels":[]}`), nil
		case "denied":
			r := pvHTTPResp(403, `{"message":"not allowed"}`)
			r.Header.Set("x-amzn-errortype", "AccessDeniedException:abc")
			return r, nil
		case "rejected":
			r := pvHTTPResp(403, `{"message":"bad signature"}`)
			r.Header.Set("x-amzn-errortype", "ValidationException")
			return r, nil
		}
		return pvHTTPResp(500, `{}`), nil
	})
	validate := func(body string) (int, map[string]any) {
		return env.do(t, "POST", "/api/providers/validate", body)
	}
	// Static creds, region from psd -> signed GET on the control plane.
	code, resp := validate(`{"provider":"bedrock","apiKey":"secret","providerSpecificData":{"accessKeyId":"AKID123","region":"eu-west-1"}}`)
	if code != 200 || resp["valid"] != true {
		t.Fatalf("bedrock validate ok: %d %v", code, resp)
	}
	if gotHost != "bedrock.eu-west-1.amazonaws.com" || gotPath != "/foundation-models" {
		t.Fatalf("probe target: %s%s", gotHost, gotPath)
	}
	if !strings.HasPrefix(gotAuth, "AWS4-HMAC-SHA256 Credential=AKID123/") || !strings.Contains(gotAuth, "/eu-west-1/bedrock/aws4_request") {
		t.Fatalf("probe auth header: %s", gotAuth)
	}
	// AccessDeniedException = signature accepted -> valid.
	mode = "denied"
	code, resp = validate(`{"provider":"bedrock","apiKey":"secret","providerSpecificData":{"accessKeyId":"AKID123"}}`)
	if code != 200 || resp["valid"] != true {
		t.Fatalf("bedrock access-denied should be valid: %d %v", code, resp)
	}
	// Other AWS errors surface the JS message shape.
	mode = "rejected"
	code, resp = validate(`{"provider":"bedrock","apiKey":"secret","providerSpecificData":{"accessKeyId":"AKID123"}}`)
	if code != 200 || resp["valid"] != false || resp["error"] != "AWS rejected the credentials (ValidationException): bad signature" {
		t.Fatalf("bedrock rejected: %d %v", code, resp)
	}
	// Incomplete static credentials -> the JS guidance message.
	mode = "ok"
	code, resp = validate(`{"provider":"bedrock","apiKey":"secret"}`)
	if code != 200 || resp["valid"] != false || !strings.Contains(resp["error"].(string), "Bedrock static credentials are incomplete") {
		t.Fatalf("bedrock incomplete: %d %v", code, resp)
	}
	// Test path (connection) uses the same probe through the proxy funnel.
	conn, err := env.store.CreateProviderConnection(db.Record{
		"provider": "bedrock", "authType": "apikey", "name": "BR", "apiKey": "secret",
		"providerSpecificData": map[string]any{"accessKeyId": "AKID123", "region": "us-east-1"},
		"isActive":             true,
	})
	if err != nil {
		t.Fatalf("seed bedrock conn: %v", err)
	}
	code, resp = env.do(t, "POST", "/api/providers/"+conn["id"].(string)+"/test", "")
	if code != 200 || resp["valid"] != true {
		t.Fatalf("bedrock test path: %d %v", code, resp)
	}
	if gotHost != "bedrock.us-east-1.amazonaws.com" {
		t.Fatalf("test path probe host: %s", gotHost)
	}
}

func TestPVVercelRelayRewrite(t *testing.T) {
	env := pvNewEnv(t)
	var gotURL, gotTarget, gotPath, gotMethod, gotBody string
	pvStubFetch(t, func(req *http.Request) (*http.Response, error) {
		gotURL = req.URL.String()
		gotTarget = req.Header.Get("x-relay-target")
		gotPath = req.Header.Get("x-relay-path")
		gotMethod = req.Method
		if req.Body != nil {
			b, _ := io.ReadAll(req.Body)
			gotBody = string(b)
		}
		return pvHTTPResp(200, `{"data":[]}`), nil
	})
	// Direct unit-level check of pvFetchViaProxy's relay mode.
	_, err := pvFetchViaProxy(context.Background(), "https://api.example.com/v1/models?x=1", "POST",
		map[string]string{"Authorization": "Bearer k"}, []byte(`{"a":1}`),
		pvProxyConfig{VercelRelayURL: "https://relay.test/relay"})
	if err != nil {
		t.Fatalf("relay fetch: %v", err)
	}
	if gotURL != "https://relay.test/relay" || gotTarget != "https://api.example.com" ||
		gotPath != "/v1/models?x=1" || gotMethod != "POST" || gotBody != `{"a":1}` {
		t.Fatalf("relay rewrite: url=%s target=%s path=%s method=%s body=%s", gotURL, gotTarget, gotPath, gotMethod, gotBody)
	}
	// End-to-end: vercel-type pool bound to a connection -> the provider
	// test probe is relayed, not proxied.
	code, resp := env.do(t, "POST", "/api/proxy-pools", `{"name":"Relay","proxyUrl":"https://relay.test/relay","type":"vercel"}`)
	if code != 201 {
		t.Fatalf("relay pool create: %d %v", code, resp)
	}
	poolID, _ := resp["proxyPool"].(map[string]any)["id"].(string)
	code, resp = env.do(t, "POST", "/api/providers", `{"provider":"openai","apiKey":"sk-x","name":"Relayed","proxyPoolId":"`+poolID+`"}`)
	if code != 201 {
		t.Fatalf("relayed conn create: %d %v", code, resp)
	}
	connID, _ := resp["connection"].(map[string]any)["id"].(string)
	code, resp = env.do(t, "POST", "/api/providers/"+connID+"/test", "")
	if code != 200 || resp["valid"] != true {
		t.Fatalf("relayed test: %d %v", code, resp)
	}
	if gotURL != "https://relay.test/relay" || gotTarget != "https://api.openai.com" || gotPath != "/v1/models" {
		t.Fatalf("relayed probe: url=%s target=%s path=%s", gotURL, gotTarget, gotPath)
	}
}

func TestPVCatalogSyncPost(t *testing.T) {
	env := pvNewEnv(t)
	dir := t.TempDir()
	t.Setenv("DATA_DIR", dir)
	catalogFixture := `{
		"anthropic": {"models": {
			"claude-opus-4-5-20251101": {"modalities": {"input": ["text", "image", "pdf"]}, "limit": {"context": 500000, "output": 64000}, "reasoning": true}
		}},
		"openai": {"models": {
			"gpt-4o": {"modalities": {"input": ["text", "image"]}, "limit": {"context": 999999, "output": 16384}}
		}}
	}`
	notModified := false
	pvStubFetch(t, func(req *http.Request) (*http.Response, error) {
		if !strings.Contains(req.URL.Host, "models.dev") {
			return pvHTTPResp(404, `{}`), nil
		}
		if notModified {
			if req.Header.Get("If-None-Match") != `"etag-1"` {
				t.Errorf("second sync should send If-None-Match, got %q", req.Header.Get("If-None-Match"))
			}
			return pvHTTPResp(304, ""), nil
		}
		r := pvHTTPResp(200, catalogFixture)
		r.Header.Set("ETag", `"etag-1"`)
		return r, nil
	})
	code, resp := env.do(t, "POST", "/api/models/catalog-sync", "")
	if code != 200 || resp["success"] != true {
		t.Fatalf("sync post: %d %v", code, resp)
	}
	result, _ := resp["result"].(map[string]any)
	if result["status"] != "updated" || result["etag"] != `"etag-1"` {
		t.Fatalf("sync result: %v", result)
	}
	// Merged file: modalities filed under local (claude) + upstream
	// (anthropic) keys; the gpt-4o context delta (>10% vs the tables)
	// lands under providers.openai.
	data, err := os.ReadFile(filepath.Join(dir, "model-catalog.json"))
	if err != nil {
		t.Fatalf("catalog file: %v", err)
	}
	var fileMap map[string]any
	if err := json.Unmarshal(data, &fileMap); err != nil {
		t.Fatalf("catalog file JSON: %v", err)
	}
	if fileMap["v"] != float64(2) {
		t.Fatalf("catalog version: %v", fileMap["v"])
	}
	modelsMap, _ := fileMap["models"].(map[string]any)
	for _, key := range []string{"claude:claude-opus-4-5-20251101", "anthropic:claude-opus-4-5-20251101", "openai:gpt-4o"} {
		declared, _ := modelsMap[key].(map[string]any)
		if declared == nil || declared["vision"] != true {
			t.Fatalf("models[%s] = %v", key, modelsMap[key])
		}
	}
	if declared, _ := modelsMap["claude:claude-opus-4-5-20251101"].(map[string]any); declared["pdf"] != true {
		t.Fatalf("pdf modality missing: %v", declared)
	}
	providersMap, _ := fileMap["providers"].(map[string]any)
	openaiDeltas, _ := providersMap["openai"].(map[string]any)
	gptDelta, _ := openaiDeltas["gpt-4o"].(map[string]any)
	if gptDelta["contextWindow"] != float64(999999) {
		t.Fatalf("gpt-4o delta: %v", gptDelta)
	}
	if _, err := os.Stat(filepath.Join(dir, "model-catalog-raw.json")); err != nil {
		t.Fatalf("raw catalog file: %v", err)
	}
	// GET reflects the real state now.
	code, resp = env.do(t, "GET", "/api/models/catalog-sync", "")
	if code != 200 {
		t.Fatalf("sync get: %d %v", code, resp)
	}
	if resp["etag"] != `"etag-1"` || resp["lastSync"] == nil {
		t.Fatalf("sync state after post: %v", resp)
	}
	catalogSummary, _ := resp["catalog"].(map[string]any)
	if catalogSummary == nil || catalogSummary["models"] != result["models"] {
		t.Fatalf("catalog summary: %v vs result %v", catalogSummary, result)
	}
	// The synced overlay now refines capabilities (openai/gpt-4o context).
	if caps := pvCapabilities("openai", "gpt-4o"); caps["contextWindow"] != float64(999999) {
		t.Fatalf("overlay not applied: %v", caps["contextWindow"])
	}
	// Second run: upstream 304 -> unchanged.
	notModified = true
	code, resp = env.do(t, "POST", "/api/models/catalog-sync", "")
	if code != 200 || resp["result"].(map[string]any)["status"] != "unchanged" {
		t.Fatalf("sync 304: %d %v", code, resp)
	}
}

func TestPVLiveModelResolvers(t *testing.T) {
	env := pvNewEnv(t)
	var qoderAuth, qoderUser string
	pvStubFetch(t, func(req *http.Request) (*http.Response, error) {
		host, path := req.URL.Host, req.URL.Path
		switch {
		case strings.Contains(host, "llm.kimchi.dev"):
			return pvHTTPResp(200, `{"models":[
				{"slug":"kimi-k2","display_name":"Kimi K2","input_modalities":["text","image"],"limits":{"context_window":256000,"max_output_tokens":8192},"provider":"moonshot"},
				{"slug":"claude-x","provider":"anthropic","input_modalities":["text"]}
			]}`), nil
		case strings.Contains(host, "api.cline.bot") && path == "/api/v1/models":
			return pvHTTPResp(200, `{"data":[{"id":"cline-pass/pro-1","name":"Pro 1"},{"id":"z-ai/glm-5","name":"GLM 5"}]}`), nil
		case strings.Contains(host, "api.cline.bot") && strings.Contains(path, "recommended-models"):
			return pvHTTPResp(200, `{"free":[{"id":"cline-free/free-1","name":"Free 1"},{"id":"z-ai/glm-5","name":"GLM 5 dup"}]}`), nil
		case strings.Contains(host, "cli-chat-proxy.grok.com"):
			return pvHTTPResp(200, `{"data":[{"id":"grok-build","display_name":"Grok Build"},{"model_id":"grok-4","context_length":256000}]}`), nil
		case strings.Contains(host, "amazonaws.com"):
			return pvHTTPResp(200, `{"models":[{"modelId":"claude-sonnet","modelName":"Sonnet","rateMultiplier":1.5,"tokenLimits":{"maxInputTokens":128000},"description":"d"}]}`), nil
		case strings.Contains(host, "api3.qoder.sh"):
			qoderAuth = req.Header.Get("Authorization")
			qoderUser = req.Header.Get("Cosy-User")
			return pvHTTPResp(200, `{"chat":[
				{"key":"qmodel","display_name":"QModel","max_input_tokens":200000,"max_output_tokens":8192,"is_vl":true,"is_reasoning":true},
				{"key":"hidden1","enable":false}
			]}`), nil
		case strings.Contains(host, "cloud.zed.dev") && path == "/client/llm_tokens":
			return pvHTTPResp(200, `{"token":"llm-tok"}`), nil
		case strings.Contains(host, "cloud.zed.dev") && path == "/models":
			return pvHTTPResp(200, `{"models":[
				{"id":"m1","display_name":"M1","max_token_count":100000,"supports_tools":true},
				{"id":"m2","is_disabled":true}
			]}`), nil
		}
		return pvHTTPResp(404, `{}`), nil
	})
	mkConn := func(rec db.Record) string {
		t.Helper()
		conn, err := env.store.CreateProviderConnection(rec)
		if err != nil {
			t.Fatalf("seed %v: %v", rec["provider"], err)
		}
		id, _ := conn["id"].(string)
		return id
	}
	modelsOf := func(id string) (map[string]any, []any) {
		t.Helper()
		code, resp := env.do(t, "GET", "/api/providers/"+id+"/models", "")
		if code != 200 {
			t.Fatalf("models for %s: %d %v", id, code, resp)
		}
		models, _ := resp["models"].([]any)
		return resp, models
	}

	// kimchi
	_, models := modelsOf(mkConn(db.Record{"provider": "kimchi", "name": "K", "accessToken": "tok", "isActive": true}))
	if len(models) != 2 {
		t.Fatalf("kimchi models: %v", models)
	}
	m0, _ := models[0].(map[string]any)
	if m0["id"] != "kimi-k2" || m0["kind"] != "imageToText" || m0["contextLength"] != float64(256000) {
		t.Fatalf("kimchi model 0: %v", m0)
	}
	if caps, _ := m0["capabilities"].(map[string]any); caps["vision"] != true {
		t.Fatalf("kimchi caps: %v", caps)
	}
	m1, _ := models[1].(map[string]any)
	if compat, _ := m1["compat"].(map[string]any); compat["cacheControlFormat"] != "anthropic" {
		t.Fatalf("kimchi anthropic compat: %v", m1)
	}

	// cline: full catalog + free tier merged (first writer wins)
	_, models = modelsOf(mkConn(db.Record{"provider": "cline", "name": "C", "accessToken": "tok", "isActive": true}))
	if len(models) != 3 {
		t.Fatalf("cline models (catalog + free tier): %v", models)
	}
	// clinepass: cline-pass/* only
	_, models = modelsOf(mkConn(db.Record{"provider": "clinepass", "name": "CP", "apiKey": "clp_x", "isActive": true}))
	if len(models) != 1 || models[0].(map[string]any)["id"] != "cline-pass/pro-1" {
		t.Fatalf("clinepass models: %v", models)
	}

	// grok-cli: parse + grok-build defaults
	_, models = modelsOf(mkConn(db.Record{"provider": "grok-cli", "name": "G", "accessToken": "tok", "isActive": true}))
	if len(models) != 2 {
		t.Fatalf("grok-cli models: %v", models)
	}
	g0, _ := models[0].(map[string]any)
	if g0["id"] != "grok-build" || g0["contextLength"] != float64(500000) || g0["maxOutputTokens"] != float64(64000) {
		t.Fatalf("grok-build defaults: %v", g0)
	}
	g1, _ := models[1].(map[string]any)
	if g1["id"] != "grok-4" || g1["contextLength"] != float64(256000) {
		t.Fatalf("grok-4: %v", g1)
	}

	// kiro: variant expansion + credit display name
	_, models = modelsOf(mkConn(db.Record{"provider": "kiro", "name": "Ki", "accessToken": "tok", "isActive": true}))
	if len(models) != 4 {
		t.Fatalf("kiro variants: %v", models)
	}
	k0, _ := models[0].(map[string]any)
	if k0["id"] != "claude-sonnet" || k0["name"] != "Kiro Sonnet (1.5x credit)" ||
		k0["contextLength"] != float64(128000) || k0["upstreamModelId"] != "claude-sonnet" {
		t.Fatalf("kiro base variant: %v", k0)
	}
	k3, _ := models[3].(map[string]any)
	if k3["id"] != "claude-sonnet-thinking-agentic" {
		t.Fatalf("kiro variant 3: %v", k3)
	}
	if caps, _ := k3["capabilities"].(map[string]any); caps["thinking"] != true || caps["agentic"] != true {
		t.Fatalf("kiro variant caps: %v", caps)
	}

	// qoder: COSY-signed catalog, provider-prefixed ids, hidden filtered
	_, models = modelsOf(mkConn(db.Record{"provider": "qoder", "name": "Q", "accessToken": "dt-token",
		"providerSpecificData": map[string]any{"userId": "user-1", "machineId": "mach-1"}, "isActive": true}))
	if len(models) != 1 {
		t.Fatalf("qoder models: %v", models)
	}
	q0, _ := models[0].(map[string]any)
	if q0["id"] != "qoder/qmodel" || q0["isVL"] != true || q0["contextLength"] != float64(200000) {
		t.Fatalf("qoder model: %v", q0)
	}
	if !strings.HasPrefix(qoderAuth, "Bearer COSY.") || qoderUser != "user-1" {
		t.Fatalf("qoder cosy headers: auth=%q user=%q", qoderAuth, qoderUser)
	}

	// zed: llm-token flow, disabled filtered, route field mapping
	_, models = modelsOf(mkConn(db.Record{"provider": "zed", "name": "Z", "accessToken": "tok",
		"providerSpecificData": map[string]any{"userId": "u1", "organizationId": "org1"}, "isActive": true}))
	if len(models) != 1 {
		t.Fatalf("zed models: %v", models)
	}
	z0, _ := models[0].(map[string]any)
	if z0["id"] != "m1" || z0["contextLength"] != float64(100000) || z0["supportsTools"] != true {
		t.Fatalf("zed model: %v", z0)
	}

	// cursor without machineId -> live resolver declines -> static fallback
	resp, models := modelsOf(mkConn(db.Record{"provider": "cursor", "name": "Cu", "accessToken": "tok", "isActive": true}))
	if resp["warning"] != "Cursor returned no live models; falling back to static catalog." || len(models) == 0 {
		t.Fatalf("cursor fallback: %v (models %d)", resp["warning"], len(models))
	}
}

func TestPVComboRotationResetWired(t *testing.T) {
	// pvNewEnv leaves Deps.Chat nil; here a zero-value chatcore.Service
	// proves the reset call sites run (ResetComboRotation is nil-safe and
	// state-free on a zero Service — chatcore covers the state itself).
	store, err := db.OpenInDir(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	mux := http.NewServeMux()
	RegisterProviders(mux, Deps{Store: store, Chat: chatcore.NewService(chatcore.Service{})})
	env := &pvTestEnv{store: store, mux: mux, token: CreateSessionToken(store)}
	code, resp := env.do(t, "POST", "/api/combos", `{"name":"rot-combo","models":["openai/gpt-4o"]}`)
	if code != 201 {
		t.Fatalf("create combo: %d %v", code, resp)
	}
	comboID, _ := resp["id"].(string)
	code, resp = env.do(t, "PUT", "/api/combos/"+comboID, `{"name":"rot-combo-2","models":["openai/gpt-4o-mini"]}`)
	if code != 200 || resp["name"] != "rot-combo-2" {
		t.Fatalf("rename combo: %d %v", code, resp)
	}
	code, _ = env.do(t, "DELETE", "/api/combos/"+comboID, "")
	if code != 200 {
		t.Fatalf("delete combo: %d", code)
	}
}

func TestPVQoderValidate(t *testing.T) {
	env := pvNewEnv(t)
	pvStubFetch(t, func(req *http.Request) (*http.Response, error) {
		switch {
		case strings.Contains(req.URL.Host, "openapi.qoder.sh") && strings.Contains(req.URL.Path, "jobToken/exchange"):
			return pvHTTPResp(200, `{"token":"jt-1"}`), nil
		case strings.Contains(req.URL.Host, "openapi.qoder.sh") && strings.Contains(req.URL.Path, "userinfo"):
			return pvHTTPResp(200, `{"id":"user-9"}`), nil
		case strings.Contains(req.URL.Host, "api2.qoder.sh"):
			// Job tokens are served from api2 on intl.
			return pvHTTPResp(200, `{"chat":[{"key":"qmodel","display_name":"QModel"}]}`), nil
		}
		return pvHTTPResp(404, `{}`), nil
	})
	// PAT validate: exchange -> userinfo -> COSY catalog -> valid.
	code, resp := env.do(t, "POST", "/api/providers/validate", `{"provider":"qoder","apiKey":"pt-abc","providerSpecificData":{}}`)
	if code != 200 || resp["valid"] != true {
		t.Fatalf("qoder PAT validate: %d %v", code, resp)
	}
	// Non-PAT apiKey: JS validate passes no accessToken into the resolver,
	// so it resolves no models and reports invalid (JS parity, incl. quirk).
	code, resp = env.do(t, "POST", "/api/providers/validate", `{"provider":"qoder","apiKey":"dt-abc","providerSpecificData":{"userId":"user-1"}}`)
	if code != 200 || resp["valid"] != false {
		t.Fatalf("qoder device-token validate: %d %v", code, resp)
	}
}
