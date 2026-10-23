package api

// Tests for the lot-A usage fetchers (usage_fetch_a.go). All upstream
// traffic is stubbed with httptest servers; endpoints are redirected
// through ufAEndpointOverrides so no real provider is contacted.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"proxygo/internal/db"
)

func ufATOverride(t *testing.T, kv map[string]string) {
	t.Helper()
	type saved struct {
		v  string
		ok bool
	}
	prev := map[string]saved{}
	for k, v := range kv {
		old, ok := ufAEndpointOverrides[k]
		prev[k] = saved{old, ok}
		ufAEndpointOverrides[k] = v
	}
	t.Cleanup(func() {
		for k, s := range prev {
			if s.ok {
				ufAEndpointOverrides[k] = s.v
			} else {
				delete(ufAEndpointOverrides, k)
			}
		}
	})
}

func ufATWriteJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func ufATQuotas(t *testing.T, rec db.Record) db.Record {
	t.Helper()
	q, _ := rec["quotas"].(db.Record)
	if q == nil {
		t.Fatalf("record has no quotas map: %v", rec)
	}
	return q
}

// ---------- GLM ----------

func TestUFAGLMUsage(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		ufATWriteJSON(w, 200, `{"data":{"level":"pro","limits":[
			{"type":"TOKENS_LIMIT","unit":3,"number":5,"percentage":40,"nextResetTime":1893456000000},
			{"type":"TOKENS_LIMIT","unit":6,"percentage":10,"nextResetTime":0},
			{"type":"CREDIT_LIMIT","percentage":25,"nextResetTime":0},
			{"type":"OTHER","percentage":99}
		]}}`)
	}))
	defer srv.Close()
	ufATOverride(t, map[string]string{"glm.url": srv.URL})

	rec, err := ufAGLMUsage(context.Background(), db.Record{
		"provider": "glm", "apiKey": "glm-key",
	}, false)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if gotAuth != "Bearer glm-key" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if rec["plan"] != "Pro" {
		t.Errorf("plan = %v", rec["plan"])
	}
	quotas := ufATQuotas(t, rec)
	session, _ := quotas["Session (5h)"].(db.Record)
	if session == nil || session["used"] != 40.0 || session["remaining"] != 60.0 {
		t.Errorf("session quota = %v", quotas["Session (5h)"])
	}
	if session["resetAt"] != "2030-01-01T00:00:00.000Z" {
		t.Errorf("session resetAt = %v", session["resetAt"])
	}
	if _, ok := quotas["Weekly (7d)"]; !ok {
		t.Errorf("weekly quota missing: %v", quotas)
	}
	if _, ok := quotas["Limit (undefined)"]; !ok {
		t.Errorf("credit limit quota missing: %v", quotas)
	}
	if len(quotas) != 3 {
		t.Errorf("quotas len = %d, want 3 (%v)", len(quotas), quotas)
	}
}

func TestUFAGLMUsageErrors(t *testing.T) {
	srv401 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ufATWriteJSON(w, 401, `{}`)
	}))
	defer srv401.Close()
	srv500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ufATWriteJSON(w, 500, `{}`)
	}))
	defer srv500.Close()
	ufATOverride(t, map[string]string{"glm.url": srv401.URL, "glm-cn.url": srv500.URL})

	rec, _ := ufAGLMUsage(context.Background(), db.Record{"provider": "glm", "apiKey": "k"}, false)
	if rec["message"] != "GLM API key invalid or expired." {
		t.Errorf("401 message = %v", rec["message"])
	}
	// glm-cn falls back to accessToken and uses the CN endpoint.
	rec, _ = ufAGLMUsage(context.Background(), db.Record{"provider": "glm-cn", "accessToken": "tok"}, false)
	if rec["message"] != "GLM quota API error (500)." {
		t.Errorf("500 message = %v", rec["message"])
	}
	rec, _ = ufAGLMUsage(context.Background(), db.Record{"provider": "glm"}, false)
	if rec["message"] != "GLM API key not available." {
		t.Errorf("no-key message = %v", rec["message"])
	}
}

// ---------- Gemini CLI ----------

func TestUFAGeminiUsageWithStoredProject(t *testing.T) {
	var gotProject string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		gotProject, _ = body["project"].(string)
		ufATWriteJSON(w, 200, `{"buckets":[
			{"modelId":"gemini-2.5-pro","remainingFraction":0.25,"resetTime":"2030-01-01T00:00:00Z"},
			{"modelId":"no-fraction","remainingFraction":null},
			{"remainingFraction":0.5}
		]}`)
	}))
	defer srv.Close()
	ufATOverride(t, map[string]string{"gemini-cli.quotaUrl": srv.URL})

	rec, err := ufAGeminiUsage(context.Background(), db.Record{
		"provider":             "gemini-cli",
		"accessToken":          "tok",
		"providerSpecificData": db.Record{"projectId": "proj-1"},
	}, false)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if gotProject != "proj-1" {
		t.Errorf("project sent = %q", gotProject)
	}
	if rec["plan"] != "Free" {
		t.Errorf("plan = %v", rec["plan"])
	}
	quotas := ufATQuotas(t, rec)
	if len(quotas) != 1 {
		t.Fatalf("quotas = %v", quotas)
	}
	q, _ := quotas["gemini-2.5-pro"].(db.Record)
	if q["used"] != 750.0 || q["total"] != 1000.0 || q["remainingPercentage"] != 25.0 {
		t.Errorf("quota = %v", q)
	}
	if q["resetAt"] != "2030-01-01T00:00:00.000Z" {
		t.Errorf("resetAt = %v", q["resetAt"])
	}
}

func TestUFAGeminiUsageProjectLookupAndError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/load", func(w http.ResponseWriter, r *http.Request) {
		ufATWriteJSON(w, 200, `{"cloudaicompanionProject":"proj-9","currentTier":{"name":"Paid"}}`)
	})
	mux.HandleFunc("/quota", func(w http.ResponseWriter, r *http.Request) {
		ufATWriteJSON(w, 500, `{}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ufATOverride(t, map[string]string{
		"gemini-cli.quotaUrl":          srv.URL + "/quota",
		"gemini-cli.loadCodeAssistUrl": srv.URL + "/load",
	})

	rec, _ := ufAGeminiUsage(context.Background(), db.Record{
		"provider": "gemini-cli", "accessToken": "tok",
	}, false)
	if rec["message"] != "Gemini CLI quota error (500)." {
		t.Errorf("message = %v", rec["message"])
	}
	if rec["plan"] != "Paid" {
		t.Errorf("plan from loadCodeAssist = %v", rec["plan"])
	}

	rec, _ = ufAGeminiUsage(context.Background(), db.Record{"provider": "gemini-cli"}, false)
	if rec["message"] != "Gemini CLI access token not available." || rec["plan"] != "Free" {
		t.Errorf("no-token record = %v", rec)
	}
}

// ---------- Antigravity ----------

func TestUFAAntigravityUsage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/load", func(w http.ResponseWriter, r *http.Request) {
		ufATWriteJSON(w, 200, `{"cloudaicompanionProject":"p1","currentTier":{"name":"Pro"},"paidTier":{"id":"paid-tier"}}`)
	})
	mux.HandleFunc("/quota", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Client-Name") != "antigravity" {
			t.Errorf("missing antigravity client header")
		}
		ufATWriteJSON(w, 200, `{"models":{
			"gemini-3.1-pro-high":{"displayName":"Gemini Pro","quotaInfo":{"remainingFraction":0.5,"resetTime":"2030-01-01T00:00:00Z"}},
			"gemini-3.1-pro-low":{"isInternal":true,"quotaInfo":{"remainingFraction":0.5}},
			"some-random-model":{"quotaInfo":{"remainingFraction":0.5}}
		}}`)
	})
	mux.HandleFunc("/summary", func(w http.ResponseWriter, r *http.Request) {
		ufATWriteJSON(w, 200, `{"groups":[
			{"displayName":"Gemini Models","buckets":[{"window":"weekly","remainingFraction":0.8,"resetTime":"2030-01-07T00:00:00Z"}]}
		]}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ufATOverride(t, map[string]string{
		"antigravity.loadProjectApiUrl":  srv.URL + "/load",
		"antigravity.quotaApiUrl":        srv.URL + "/quota",
		"antigravity.quotaSummaryApiUrl": srv.URL + "/summary",
	})

	rec, err := ufAAntigravityUsage(context.Background(), db.Record{
		"provider": "antigravity", "accessToken": "ag-token-1",
	}, false)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if rec["plan"] != "Pro" {
		t.Errorf("plan = %v", rec["plan"])
	}
	if rec["subscriptionInfo"] == nil {
		t.Errorf("subscriptionInfo missing")
	}
	quotas := ufATQuotas(t, rec)
	q, _ := quotas["gemini-3.1-pro-high"].(db.Record)
	if q == nil || q["used"] != 500.0 || q["displayName"] != "Gemini Pro" {
		t.Errorf("model quota = %v", quotas["gemini-3.1-pro-high"])
	}
	if _, ok := quotas["gemini-3.1-pro-low"]; ok {
		t.Errorf("internal model should be filtered")
	}
	if _, ok := quotas["some-random-model"]; ok {
		t.Errorf("non-important model should be filtered")
	}
	weekly, _ := quotas["gemini_weekly"].(db.Record)
	if weekly == nil || weekly["remainingPercentage"] != 80.0 || weekly["displayName"] != "Gemini (Weekly)" {
		t.Errorf("weekly quota = %v", quotas["gemini_weekly"])
	}
}

func TestUFAAntigravityForbidden(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/load", func(w http.ResponseWriter, r *http.Request) {
		ufATWriteJSON(w, 200, `{"currentTier":{"name":"Free"}}`)
	})
	mux.HandleFunc("/quota", func(w http.ResponseWriter, r *http.Request) {
		ufATWriteJSON(w, 403, `{}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ufATOverride(t, map[string]string{
		"antigravity.loadProjectApiUrl": srv.URL + "/load",
		"antigravity.quotaApiUrl":       srv.URL + "/quota",
	})

	rec, _ := ufAAntigravityUsage(context.Background(), db.Record{
		"provider": "antigravity", "accessToken": "ag-token-2",
	}, false)
	if rec["message"] != "Antigravity quota API access forbidden. Chat may still work." {
		t.Errorf("message = %v", rec["message"])
	}
	if len(ufATQuotas(t, rec)) != 0 {
		t.Errorf("quotas should be empty: %v", rec["quotas"])
	}
}

// ---------- Kiro ----------

func TestUFAKiroUsageFallbackChain(t *testing.T) {
	var postBody string
	mux := http.NewServeMux()
	mux.HandleFunc("/getUsageLimits", func(w http.ResponseWriter, r *http.Request) {
		ufATWriteJSON(w, 500, `{"message":"boom"}`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		postBody = string(raw)
		if r.Header.Get("x-amz-target") != "AmazonCodeWhispererService.GetUsageLimits" {
			t.Errorf("missing x-amz-target header")
		}
		ufATWriteJSON(w, 200, `{
			"usageBreakdownList":[{
				"resourceType":"AGENTIC_REQUEST",
				"currentUsageWithPrecision":30,
				"usageLimitWithPrecision":100,
				"freeTrialInfo":{"currentUsageWithPrecision":5,"usageLimitWithPrecision":50,"freeTrialExpiry":"2030-06-01T00:00:00Z"}
			}],
			"nextDateReset":"2030-05-01T00:00:00Z",
			"subscriptionInfo":{"subscriptionTitle":"Kiro Pro"}
		}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ufATOverride(t, map[string]string{"kiro.cwHost": srv.URL, "kiro.qHost": srv.URL})

	rec, err := ufAKiroUsage(context.Background(), db.Record{
		"provider":    "kiro",
		"accessToken": "tok",
	}, false)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if rec["plan"] != "Kiro Pro" {
		t.Errorf("plan = %v", rec["plan"])
	}
	if !strings.Contains(postBody, "AAAACCCCXXXX") {
		t.Errorf("POST body should carry the default Builder ID profileArn: %s", postBody)
	}
	quotas := ufATQuotas(t, rec)
	q, _ := quotas["agentic_request"].(db.Record)
	if q == nil || q["used"] != 30.0 || q["remaining"] != 70.0 || q["resetAt"] != "2030-05-01T00:00:00.000Z" {
		t.Errorf("quota = %v", quotas["agentic_request"])
	}
	ft, _ := quotas["agentic_request_freetrial"].(db.Record)
	if ft == nil || ft["used"] != 5.0 || ft["resetAt"] != "2030-06-01T00:00:00.000Z" {
		t.Errorf("freetrial quota = %v", quotas["agentic_request_freetrial"])
	}
}

func TestUFAKiroUsageAuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ufATWriteJSON(w, 403, `{"message":"denied"}`)
	}))
	defer srv.Close()
	ufATOverride(t, map[string]string{"kiro.cwHost": srv.URL, "kiro.qHost": srv.URL})

	rec, _ := ufAKiroUsage(context.Background(), db.Record{
		"provider":    "kiro",
		"accessToken": "tok",
	}, false)
	if rec["message"] != "Kiro quota API rejected the current token. Chat may still work." {
		t.Errorf("message = %v", rec["message"])
	}
	if len(ufATQuotas(t, rec)) != 0 {
		t.Errorf("quotas should be empty")
	}

	rec, _ = ufAKiroUsage(context.Background(), db.Record{
		"provider":             "kiro",
		"accessToken":          "tok",
		"providerSpecificData": db.Record{"authMethod": "idc"},
	}, false)
	if !strings.Contains(opStr(rec, "message"), "IAM Identity Center") {
		t.Errorf("idc message = %v", rec["message"])
	}
}

// ---------- Qoder ----------

func TestUFAQoderUsagePATExchange(t *testing.T) {
	var quotaAuth string
	mux := http.NewServeMux()
	mux.HandleFunc("/exchange", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		if body["personal_token"] != "pt-secret" {
			t.Errorf("exchange body = %s", raw)
		}
		ufATWriteJSON(w, 200, `{"token":"jt-123","expires_in":3600}`)
	})
	mux.HandleFunc("/quota", func(w http.ResponseWriter, r *http.Request) {
		quotaAuth = r.Header.Get("Authorization")
		ufATWriteJSON(w, 200, `{
			"userQuota":{"total":100,"used":10,"remaining":90,"unit":"credits"},
			"orgResourcePackage":{"total":1000,"used":100,"remaining":900},
			"addOnQuota":{"total":2200,"used":200,"remaining":2000,"detailUrl":"https://qoder.example/usage"},
			"totalUsagePercentage":12.5,
			"isQuotaExceeded":false,
			"expiresAt":253402214400000
		}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ufATOverride(t, map[string]string{
		"qoder.url":         srv.URL + "/quota",
		"qoder.exchangeUrl": srv.URL + "/exchange",
	})

	rec, err := ufAQoderUsage(context.Background(), db.Record{
		"provider": "qoder", "apiKey": "pt-secret",
	}, false)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if quotaAuth != "Bearer jt-123" {
		t.Errorf("quota Authorization = %q, want the exchanged job token", quotaAuth)
	}
	quotas := ufATQuotas(t, rec)
	user, _ := quotas["user"].(db.Record)
	if user == nil || user["total"] != 100.0 || user["used"] != 10.0 || user["unit"] != "credits" {
		t.Errorf("user quota = %v", quotas["user"])
	}
	if user["neverExpires"] != true || user["resetAt"] != nil {
		t.Errorf("sentinel expiry handling = %v", user)
	}
	org, _ := quotas["organization"].(db.Record)
	if org == nil || org["remaining"] != 900.0 {
		t.Errorf("org quota = %v", quotas["organization"])
	}
	addOn, _ := quotas["addOn"].(db.Record)
	if addOn == nil || addOn["total"] != 2200.0 || addOn["detailUrl"] != "https://qoder.example/usage" {
		t.Errorf("addOn quota = %v", quotas["addOn"])
	}
	if rec["totalUsagePercentage"] != 12.5 || rec["expiresAt"] != 253402214400000.0 {
		t.Errorf("siblings = %v / %v", rec["totalUsagePercentage"], rec["expiresAt"])
	}
}

func TestUFAQoderUsageError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ufATWriteJSON(w, 503, `{}`)
	}))
	defer srv.Close()
	ufATOverride(t, map[string]string{"qoder-cn.url": srv.URL})

	rec, _ := ufAQoderUsage(context.Background(), db.Record{
		"provider": "qoder-cn", "accessToken": "tok",
	}, false)
	if rec["message"] != "Qoder connected. Usage fetch returned 503." {
		t.Errorf("message = %v", rec["message"])
	}
	rec, _ = ufAQoderUsage(context.Background(), db.Record{"provider": "qoder-cn"}, false)
	if rec["message"] != "Qoder usage unavailable: no access token" {
		t.Errorf("no-token message = %v", rec["message"])
	}
}

// ---------- iFlow / dispatch ----------

func TestUFAIflowAndDispatch(t *testing.T) {
	rec, err := opFetchUsageForProvider(context.Background(), db.Record{"provider": "iflow"}, false)
	if err != nil {
		t.Fatalf("dispatch err = %v (plugin registration missing?)", err)
	}
	if rec["message"] != "iFlow connected. Usage tracked per request." {
		t.Errorf("message = %v", rec["message"])
	}
}

// ---------- Ollama ----------

func TestUFAOllamaUsage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/usage", func(w http.ResponseWriter, r *http.Request) {
		ufATWriteJSON(w, 200, `{"limits":{"session":{"usage":0.5},"weekly":{"usage":0.25},"monthly":{"usage":0.1}}}`)
	})
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("me method = %s", r.Method)
		}
		ufATWriteJSON(w, 200, `{"Plan":"pro","CreatedAt":"2024-01-15T00:00:00Z"}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ufATOverride(t, map[string]string{
		"ollama.usageUrl": srv.URL + "/api/usage",
		"ollama.meUrl":    srv.URL + "/api/me",
	})

	rec, err := ufAOllamaUsage(context.Background(), db.Record{
		"provider": "ollama", "apiKey": "ollama-key",
	}, false)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if rec["plan"] != "Pro" {
		t.Errorf("plan = %v", rec["plan"])
	}
	quotas := ufATQuotas(t, rec)
	session, _ := quotas["Session (5h)"].(db.Record)
	if session == nil || session["used"] != 50.0 || session["remainingPercentage"] != 50.0 || session["resetAt"] != nil {
		t.Errorf("session quota = %v", quotas["Session (5h)"])
	}
	weekly, _ := quotas["Weekly (7d)"].(db.Record)
	if weekly == nil || weekly["used"] != 25.0 {
		t.Errorf("weekly quota = %v", quotas["Weekly (7d)"])
	}
	monthly, _ := quotas["Monthly"].(db.Record)
	if monthly == nil || monthly["used"] != 10.0 || monthly["resetAt"] != nil {
		t.Errorf("monthly quota (paid plan → no derived reset) = %v", quotas["Monthly"])
	}
}

func TestUFAOllamaUsageError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ufATWriteJSON(w, 401, `{}`)
	}))
	defer srv.Close()
	ufATOverride(t, map[string]string{"ollama.usageUrl": srv.URL})

	rec, _ := ufAOllamaUsage(context.Background(), db.Record{
		"provider": "ollama", "apiKey": "bad",
	}, false)
	if rec["message"] != "Ollama Cloud API key invalid or expired." {
		t.Errorf("message = %v", rec["message"])
	}
	rec, _ = ufAOllamaUsage(context.Background(), db.Record{"provider": "ollama"}, false)
	if rec["message"] != "Ollama Cloud API key not available." {
		t.Errorf("no-key message = %v", rec["message"])
	}
}
