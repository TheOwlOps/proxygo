// usage_fetch_b_test.go — Team U2 tests: every batch-B provider gets at
// least one httptest-simulated upstream parse case. A rewrite transport
// points all upstream hosts at one local server and records the original
// host in X-UFb-Host so the stub can dispatch per provider.
package api

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"9router-go/internal/db"
)

type ufBRewriteTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (t *ufBRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	origHost := clone.URL.Host
	clone.URL.Scheme = t.target.Scheme
	clone.URL.Host = t.target.Host
	clone.Host = ""
	clone.Header = req.Header.Clone()
	clone.Header.Set("X-UFb-Host", origHost)
	return t.base.RoundTrip(clone)
}

// ufBInstallStub swaps opHTTPClient for one that rewrites every request
// to the given test server. Returns a cleanup func.
func ufBInstallStub(t *testing.T, handler http.Handler) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	target, _ := url.Parse(srv.URL)
	prev := opHTTPClient
	opHTTPClient = &http.Client{
		Timeout:   15 * time.Second,
		Transport: &ufBRewriteTransport{target: target, base: http.DefaultTransport},
	}
	t.Cleanup(func() { opHTTPClient = prev })
}

func ufBHostPath(r *http.Request) string {
	return r.Header.Get("X-UFb-Host") + r.URL.Path
}

func ufBJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, body)
}

func ufBQuotas(t *testing.T, rec db.Record) map[string]db.Record {
	t.Helper()
	q, ok := rec["quotas"].(map[string]db.Record)
	if !ok {
		t.Fatalf("record has no quotas map: %#v", rec)
	}
	return q
}

func ufBConn(fields map[string]any) db.Record {
	return db.Record(fields)
}

// ---------- minimax / minimax-cn ----------

func TestUFBMinMaxTokenPlan(t *testing.T) {
	ufBInstallStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer mm-key" {
			w.WriteHeader(401)
			return
		}
		ufBJSON(w, `{"base_resp":{"status_code":0},"model_remains":[
			{"model_name":"MiniMax-M*","current_interval_total_count":200,"current_interval_usage_count":50,
			 "current_weekly_total_count":1000,"current_weekly_usage_count":100,
			 "current_interval_remaining_percent":75,"current_weekly_remaining_percent":90,
			 "remains_time":3600000,"weekly_remains_time":86400000}
		]}`)
	}))
	rec, err := ufBMiniMaxUsage(context.Background(), ufBConn(map[string]any{
		"provider": "minimax", "apiKey": "mm-key",
	}), false)
	if err != nil {
		t.Fatal(err)
	}
	quotas := ufBQuotas(t, rec)
	q5 := quotas["M-series (5h)"]
	if q5 == nil {
		t.Fatalf("missing M-series (5h): %#v", quotas)
	}
	if q5["used"] != 50.0 || q5["total"] != 200.0 || q5["remaining"] != 150.0 {
		t.Errorf("5h quota = %#v", q5)
	}
	if q5["remainingPercentage"] != 75.0 {
		t.Errorf("5h pct = %v, want upstream-provided 75", q5["remainingPercentage"])
	}
	if q5["resetAt"] == nil {
		t.Errorf("5h resetAt should be derived from remains_time")
	}
	q7 := quotas["M-series (7d)"]
	if q7 == nil || q7["used"] != 100.0 || q7["total"] != 1000.0 {
		t.Errorf("7d quota = %#v", q7)
	}
}

func TestUFBMinMaxCnFallbackAndCountMeansRemaining(t *testing.T) {
	var hits int
	ufBInstallStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits == 1 {
			w.WriteHeader(500) // first URL fails -> fallback to second
			return
		}
		// coding_plan/remains: usage_count means REMAINING.
		ufBJSON(w, `{"base_resp":{"status_code":0},"model_remains":[
			{"model_name":"general","current_interval_total_count":100,"current_interval_usage_count":80,
			 "current_weekly_total_count":0,"current_weekly_usage_count":0}
		]}`)
	}))
	rec, err := ufBMiniMaxUsage(context.Background(), ufBConn(map[string]any{
		"provider": "minimax-cn", "apiKey": "mm-cn-key",
	}), false)
	if err != nil {
		t.Fatal(err)
	}
	if hits != 2 {
		t.Fatalf("expected fallback to 2nd URL, hits=%d", hits)
	}
	quotas := ufBQuotas(t, rec)
	q := quotas["M-series (5h)"]
	if q == nil {
		t.Fatalf("quotas: %#v", quotas)
	}
	// count=remaining=80 of 100 -> used=20.
	if q["used"] != 20.0 || q["remaining"] != 80.0 {
		t.Errorf("countMeansRemaining semantics wrong: %#v", q)
	}
}

// ---------- minimax-code ----------

func ufBMiniMaxCodeStub(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/api/user/info":
			ufBJSON(w, `{"data":{"userInfo":{"realUserID":"u-123","userEmail":"dev@example.com"}}}`)
		case "/matrix/api/v1/user/get_user_extra_info":
			ufBJSON(w, `{"workspaces":[{"workspace_type":0,"workspace_id":7,"has_token_plan":true,
				"op_group_id":"grp-1","token_plan_tier":"Pro",
				"op_credit_summary":{"total_remaining_amount":"42.5"}}]}`)
		case "/matrix/api/v1/commerce/get_membership_info":
			ufBJSON(w, `{"has_token_plan":true,"op_group_id":"grp-1","token_plan_tier":"Pro"}`)
		case "/v1/api/openplatform/coding_plan/remains":
			end := time.Now().Add(5 * time.Hour).UnixMilli()
			start := time.Now().Add(-1 * time.Hour).UnixMilli()
			ufBJSON(w, fmt.Sprintf(`{"base_resp":{"status_code":0},"model_remains":[
				{"model_name":"general","current_interval_remaining_percent":80,"current_interval_status":1,
				 "start_time":%d,"end_time":%d,
				 "current_weekly_remaining_percent":50,"current_weekly_status":1,
				 "weekly_start_time":%d,"weekly_end_time":%d}]}`,
				start, end, start, end+7*86400000))
		default:
			w.WriteHeader(404)
		}
	})
}

func TestUFBMinMaxCode(t *testing.T) {
	ufBInstallStub(t, ufBMiniMaxCodeStub(t))
	rec, err := ufBMiniMaxCodeUsage(context.Background(), ufBConn(map[string]any{
		"provider": "minimax-code", "accessToken": "mcode-token",
		"providerSpecificData": map[string]any{},
	}), false)
	if err != nil {
		t.Fatal(err)
	}
	if rec["plan"] != "M Plan Pro" {
		t.Errorf("plan = %v", rec["plan"])
	}
	if rec["user"] != "dev@example.com" {
		t.Errorf("user = %v", rec["user"])
	}
	quotas := ufBQuotas(t, rec)
	credits := quotas["Credits"]
	if credits == nil || credits["total"] != 42.5 || credits["isCreditBalance"] != true {
		t.Errorf("credits = %#v", credits)
	}
	// general bucket, 6h span -> "6 hours" window at 80% remaining.
	win := quotas["6 hours"]
	if win == nil {
		t.Fatalf("windows: %#v", quotas)
	}
	if win["used"] != 20.0 || win["remainingPercentage"] != 80.0 {
		t.Errorf("window = %#v", win)
	}
	if quotas["7 days"] == nil {
		t.Errorf("weekly window missing: %#v", quotas)
	}
}

func TestUFBMinMaxCodeGlobalFree(t *testing.T) {
	ufBInstallStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/matrix/api/v1/user/get_user_extra_info":
			ufBJSON(w, `{"workspaces":[]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	rec, err := ufBMiniMaxCodeUsage(context.Background(), ufBConn(map[string]any{
		"provider": "minimax-code-global", "accessToken": "tok",
		"providerSpecificData": map[string]any{"realUserID": "u-9"},
	}), false)
	if err != nil {
		t.Fatal(err)
	}
	if rec["plan"] != "Free" {
		t.Errorf("plan = %v", rec["plan"])
	}
	quotas := ufBQuotas(t, rec)
	plan := quotas["Plan"]
	if plan == nil || plan["message"] != "No usage data returned" {
		t.Errorf("plan quota = %#v", plan)
	}
}

// ---------- vercel-ai-gateway ----------

func TestUFBVercel(t *testing.T) {
	ufBInstallStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ufBJSON(w, `{"balance":"95.50","total_used":"4.50"}`)
	}))
	rec, err := ufBVercelUsage(context.Background(), ufBConn(map[string]any{
		"provider": "vercel-ai-gateway", "apiKey": "vai-key",
	}), false)
	if err != nil {
		t.Fatal(err)
	}
	if rec["plan"] != "Pay-as-you-go" {
		t.Errorf("plan = %v", rec["plan"])
	}
	quotas := ufBQuotas(t, rec)
	rem := quotas["Remaining (USD)"]
	if rem == nil || rem["total"] != 5.0 || rem["used"] != 95.5 || rem["remaining"] != 95.5 {
		t.Errorf("remaining = %#v", rem)
	}
	// JS deliberately does not clamp: 95.5 / 5 * 100 = 1910.
	if pct, _ := rem["remainingPercentage"].(float64); math.Abs(pct-1910) > 1e-9 {
		t.Errorf("pct = %v", rem["remainingPercentage"])
	}
	used := quotas["Used (USD)"]
	if used == nil || used["used"] != 4.5 || used["unlimited"] != true {
		t.Errorf("used = %#v", used)
	}
}

// ---------- codebuddy ----------

func TestUFBCodebuddyCnRefill(t *testing.T) {
	now := time.Now()
	start := now.Add(-24 * time.Hour).UnixMilli()
	end := now.Add(29 * 24 * time.Hour).UnixMilli()
	deduction := now.Add(365 * 24 * time.Hour).UnixMilli()
	ufBInstallStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		ufBJSON(w, fmt.Sprintf(`{"code":0,"data":{"Response":{"Data":{"Accounts":[
			{"PackageName":"CodeBuddy Pro","CycleCapacitySizePrecise":"500","CycleCapacityUsedPrecise":"100.5",
			 "CycleStartTime":%d,"CycleEndTime":%d,"DeductionEndTime":%d}
		]}}}}`, start, end, deduction))
	}))
	rec, err := ufBCodebuddyUsage(context.Background(), "codebuddy-cn", ufBConn(map[string]any{
		"provider": "codebuddy-cn", "accessToken": "cb-token",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if rec["plan"] != "CodeBuddy Pro" {
		t.Errorf("plan = %v", rec["plan"])
	}
	quotas := ufBQuotas(t, rec)
	m := quotas["Monthly"]
	if m == nil {
		t.Fatalf("quotas: %#v", quotas)
	}
	if m["used"] != 100.5 || m["total"] != 500.0 || m["recurring"] != true {
		t.Errorf("monthly = %#v", m)
	}
}

func TestUFBCodebuddyIntlBonus(t *testing.T) {
	now := time.Now()
	end := now.Add(10 * 24 * time.Hour).UnixMilli()
	ufBInstallStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ufBJSON(w, fmt.Sprintf(`{"code":0,"data":{"Response":{"Data":{"Accounts":[
			{"CapacitySize":200,"CapacityUsed":50,"CycleEndTime":%d,"DeductionEndTime":%d}
		]}}}}`, end, end))
	}))
	rec, err := ufBCodebuddyUsage(context.Background(), "codebuddy-intl", ufBConn(map[string]any{
		"provider": "codebuddy-intl", "apiKey": "cb-key",
	}))
	if err != nil {
		t.Fatal(err)
	}
	quotas := ufBQuotas(t, rec)
	b := quotas["Bonus Pack 1"]
	if b == nil || b["used"] != 50.0 || b["total"] != 200.0 || b["recurring"] != false {
		t.Errorf("bonus = %#v", b)
	}
}

// ---------- grok-cli ----------

func ufBFakeJWT(tier int) string {
	header := "eyJhbGciOiJIUzI1NiJ9"
	payload := fmt.Sprintf(`{"tier":%d}`, tier)
	enc := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return header + "." + enc + ".sig"
}

func TestUFBGrokBilling(t *testing.T) {
	ufBInstallStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/v1/billing"):
			ufBJSON(w, `{"config":{"onDemandCap":{"val":100},"onDemandUsed":{"val":25},
				"billingPeriodEnd":"2026-11-01T00:00:00.000Z","isUnifiedBillingUser":true}}`)
		case strings.Contains(r.URL.Path, "/v1/user"):
			ufBJSON(w, `{"subscriptionTier":"premium"}`)
		default:
			w.WriteHeader(404)
		}
	}))
	rec, err := ufBGrokUsage(context.Background(), ufBConn(map[string]any{
		"provider": "grok-cli", "accessToken": ufBFakeJWT(1),
		"providerSpecificData": map[string]any{},
	}), false)
	if err != nil {
		t.Fatal(err)
	}
	// JWT tier 1 -> SuperGrok wins over the REST plan.
	if rec["plan"] != "SuperGrok" {
		t.Errorf("plan = %v", rec["plan"])
	}
	quotas := ufBQuotas(t, rec)
	od := quotas["On-demand"]
	if od == nil || od["used"] != 25.0 || od["total"] != 100.0 || od["remainingPercentage"] != 75.0 {
		t.Errorf("on-demand = %#v", od)
	}
}

func ufBGrokFrame(ratio float32, resetSeconds int64) []byte {
	// credits info: field1 fixed32 ratio, field5 Timestamp{1: seconds}
	ts := []byte{0x08}
	ts = appendVarint(ts, uint64(resetSeconds))
	info := []byte{0x0D}
	var f32 [4]byte
	binary.LittleEndian.PutUint32(f32[:], math.Float32bits(ratio))
	info = append(info, f32[:]...)
	info = append(info, 0x2A, byte(len(ts)))
	info = append(info, ts...)
	payload := []byte{0x0A, byte(len(info))}
	payload = append(payload, info...)
	frame := []byte{0x00}
	var ln [4]byte
	binary.BigEndian.PutUint32(ln[:], uint32(len(payload)))
	frame = append(frame, ln[:]...)
	frame = append(frame, payload...)
	// trailer frame: grpc-status ok
	trailer := []byte{0x80, 0, 0, 0, 0}
	frame = append(frame, trailer...)
	return frame
}

func appendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v&0x7f)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func TestUFBGrokGrpcFallback(t *testing.T) {
	ufBInstallStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/v1/billing"):
			ufBJSON(w, `{"config":{"isUnifiedBillingUser":true}}`)
		case strings.Contains(r.URL.Path, "/v1/user"):
			ufBJSON(w, `{}`)
		case strings.Contains(r.URL.Path, "GetGrokCreditsConfig"):
			w.Header().Set("Content-Type", "application/grpc-web+proto")
			_, _ = w.Write(ufBGrokFrame(0.35, 1890000000))
		default:
			w.WriteHeader(404)
		}
	}))
	rec, err := ufBGrokUsage(context.Background(), ufBConn(map[string]any{
		"provider": "grok-cli", "accessToken": "not-a-jwt",
		"providerSpecificData": map[string]any{},
	}), false)
	if err != nil {
		t.Fatal(err)
	}
	quotas := ufBQuotas(t, rec)
	ws := quotas["Weekly SuperGrok"]
	if ws == nil || ws["used"] != 35.0 || ws["total"] != 100.0 {
		t.Errorf("weekly supergrok = %#v", ws)
	}
	if ws != nil && ws["resetAt"] == nil {
		t.Errorf("resetAt missing from grpc timestamp")
	}
}

// ---------- kimi ----------

func TestUFBKimi(t *testing.T) {
	ufBInstallStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "kimi-key" {
			w.WriteHeader(401)
			ufBJSON(w, `{"message":"bad key"}`)
			return
		}
		ufBJSON(w, `{"usage":{"limit":1000,"used":250,"remaining":750,"resetTime":"2026-11-01T00:00:00.000Z"},
			"limits":[{"detail":{"limit":100,"remaining":40}}],
			"user":{"membership":{"level":"LEVEL_ADVANCED"}}}`)
	}))
	rec, err := ufBKimiUsage(context.Background(), ufBConn(map[string]any{
		"provider": "kimi", "apiKey": "kimi-key",
	}), false)
	if err != nil {
		t.Fatal(err)
	}
	if rec["plan"] != "Allegro" {
		t.Errorf("plan = %v", rec["plan"])
	}
	quotas := ufBQuotas(t, rec)
	wk := quotas["Weekly"]
	if wk == nil || wk["used"] != 250.0 || wk["remainingPercentage"] != 75.0 {
		t.Errorf("weekly = %#v", wk)
	}
	rl := quotas["Ratelimit"]
	if rl == nil || rl["used"] != 60.0 || rl["total"] != 100.0 {
		t.Errorf("ratelimit = %#v", rl)
	}
}

// ---------- opencode go/zen ----------

func TestUFBOpenCodeGo(t *testing.T) {
	ufBInstallStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ufBJSON(w, `{"usage":{"rolling":{"percent":10,"resetsAt":"2026-10-24T00:00:00.000Z"},
			"weekly":{"percent":50},"monthly":{"percent":"25"}}}`)
	}))
	rec, err := ufBOpenCodeUsage(context.Background(), "opencode-go", "OpenCode Go",
		"OpenCode Go subscription required for this API key.", ufBConn(map[string]any{
			"provider": "opencode-go", "apiKey": "oc-key",
		}))
	if err != nil {
		t.Fatal(err)
	}
	if rec["plan"] != "OpenCode Go" {
		t.Errorf("plan = %v", rec["plan"])
	}
	quotas := ufBQuotas(t, rec)
	if quotas["Rolling"] == nil || quotas["Rolling"]["used"] != 10.0 || quotas["Rolling"]["remainingPercentage"] != 90.0 {
		t.Errorf("rolling = %#v", quotas["Rolling"])
	}
	if quotas["Monthly"] == nil || quotas["Monthly"]["used"] != 25.0 {
		t.Errorf("monthly (string percent) = %#v", quotas["Monthly"])
	}
}

func TestUFBOpenCodeZenForbidden(t *testing.T) {
	ufBInstallStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		ufBJSON(w, `{"error":{"type":"EntitlementError"}}`)
	}))
	rec, err := ufBOpenCodeUsage(context.Background(), "opencode-zen", "OpenCode Zen",
		"OpenCode Zen billing required for this API key.", ufBConn(map[string]any{
			"provider": "opencode-zen", "apiKey": "oc-key",
		}))
	if err != nil {
		t.Fatal(err)
	}
	if rec["message"] != "OpenCode Zen billing required for this API key." {
		t.Errorf("message = %v", rec["message"])
	}
}

// ---------- deepseek ----------

func TestUFBDeepseek(t *testing.T) {
	ufBInstallStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ufBJSON(w, `{"is_available":true,"balance_infos":[
			{"currency":"usd","total_balance":"10.00","granted_balance":"2.00","topped_up_balance":"8.00"}]}`)
	}))
	rec, err := ufBDeepseekUsage(context.Background(), ufBConn(map[string]any{
		"provider": "deepseek", "apiKey": "ds-key",
	}), false)
	if err != nil {
		t.Fatal(err)
	}
	if rec["plan"] != "DeepSeek" {
		t.Errorf("plan = %v", rec["plan"])
	}
	quotas := ufBQuotas(t, rec)
	b := quotas["Balance (USD)"]
	if b == nil || b["total"] != 10.0 || b["currency"] != "USD" || b["isCreditBalance"] != true {
		t.Errorf("balance = %#v", b)
	}
}

// ---------- zed ----------

func TestUFBZed(t *testing.T) {
	ufBInstallStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "user-1 zed-token" {
			w.WriteHeader(401)
			return
		}
		ufBJSON(w, `{"plan":{"plan_v3":"zed_pro",
			"usage":{"edit_predictions":{"used":10,"limit":50},
			         "model_requests":{"used":5,"limit":{"limited":100}}},
			"subscription_period":{"ended_at":"2026-11-15T00:00:00.000Z"}}}`)
	}))
	rec, err := ufBZedUsage(context.Background(), ufBConn(map[string]any{
		"provider": "zed", "accessToken": "zed-token",
		"providerSpecificData": map[string]any{"userId": "user-1"},
	}), false)
	if err != nil {
		t.Fatal(err)
	}
	if rec["plan"] != "Zed Pro" {
		t.Errorf("plan = %v", rec["plan"])
	}
	quotas := ufBQuotas(t, rec)
	ep := quotas["Edit Predictions"]
	if ep == nil || ep["used"] != 10.0 || ep["total"] != 50.0 || ep["remainingPercentage"] != 80.0 {
		t.Errorf("edit predictions = %#v", ep)
	}
	mr := quotas["Hosted Model Requests"]
	if mr == nil || mr["total"] != 100.0 {
		t.Errorf("model requests = %#v", mr)
	}
}

// ---------- xiaomi-mimo ----------

func TestUFBMimoSkFallback(t *testing.T) {
	ufBInstallStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ufBJSON(w, `{"code":0,"data":{"percent":94,"resetDate":"2026-09-16"}}`)
	}))
	rec, err := ufBMimoUsage(context.Background(), ufBConn(map[string]any{
		"provider": "xiaomi-mimo", "accessToken": "sk-mimo",
		"providerSpecificData": map[string]any{},
	}), false)
	if err != nil {
		t.Fatal(err)
	}
	quotas := ufBQuotas(t, rec)
	wk := quotas["Weekly"]
	if wk == nil || wk["used"] != 6.0 || wk["remainingPercentage"] != 94.0 {
		t.Errorf("weekly = %#v", wk)
	}
	if wk != nil && wk["resetAt"] != "2026-09-16T00:00:00.000Z" {
		t.Errorf("resetAt = %v", wk["resetAt"])
	}
}

func TestUFBMimoAccountSession(t *testing.T) {
	ufBInstallStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/pass/serviceLogin"):
			if !strings.Contains(r.Header.Get("Cookie"), "passToken=pt-1") {
				w.WriteHeader(403)
				return
			}
			ufBJSON(w, `&&&START&&&{"code":0,"location":"https://account.xiaomi.com/pass/sts?d=1","ssecurity":"sec123","nonce":987654321}`)
		case strings.Contains(r.URL.Path, "/pass/sts"):
			if r.Header.Get("Cookie") != "" {
				w.WriteHeader(400) // phase 2 must NOT send cookies
				return
			}
			w.Header().Add("Set-Cookie", "serviceToken=svc-tok; Path=/")
			w.WriteHeader(200)
		case strings.Contains(r.URL.Path, "/api/user/usage"):
			if !strings.Contains(r.Header.Get("Cookie"), "serviceToken=svc-tok") {
				w.WriteHeader(401)
				return
			}
			ufBJSON(w, `{"code":0,"data":{"percent":50,"resetAt":1890000000}}`)
		default:
			w.WriteHeader(404)
		}
	}))
	rec, err := ufBMimoUsage(context.Background(), ufBConn(map[string]any{
		"provider": "xiaomi-mimo", "accessToken": "sk-mimo",
		"providerSpecificData": map[string]any{
			"mimoPassToken": "pt-1", "mimoUserId": "u-7", "region": "sgp",
		},
	}), false)
	if err != nil {
		t.Fatal(err)
	}
	quotas := ufBQuotas(t, rec)
	wk := quotas["Weekly"]
	if wk == nil || wk["used"] != 50.0 || wk["remainingPercentage"] != 50.0 {
		t.Errorf("weekly = %#v", wk)
	}
}

// ---------- commandcode ----------

func TestUFBCommandCode(t *testing.T) {
	ufBInstallStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/alpha/whoami"):
			ufBJSON(w, `{"org":{"id":"org-1"}}`)
		case strings.Contains(r.URL.Path, "/alpha/billing/credits"):
			if !strings.Contains(r.URL.RawQuery, "orgId=org-1") {
				w.WriteHeader(400)
				return
			}
			ufBJSON(w, `{"credits":{"monthlyCredits":5,"purchasedCredits":0,"freeCredits":0},
				"windowLimits":{"fiveHour":{"used":1,"cap":10,"resetAt":"2026-10-24T00:00:00.000Z"}}}`)
		case strings.Contains(r.URL.Path, "/alpha/billing/subscriptions"):
			ufBJSON(w, `{"data":{"planId":"individual-pro","currentPeriodEnd":"2026-11-20T00:00:00.000Z"}}`)
		default:
			w.WriteHeader(404)
		}
	}))
	rec, err := ufBCommandCodeUsage(context.Background(), ufBConn(map[string]any{
		"provider": "commandcode", "apiKey": "cc-key",
	}), false)
	if err != nil {
		t.Fatal(err)
	}
	if rec["plan"] != "Pro" {
		t.Errorf("plan = %v", rec["plan"])
	}
	quotas := ufBQuotas(t, rec)
	cr := quotas["Credits"]
	// cap 30 (individual-pro), remaining 5 -> used 25.
	if cr == nil || cr["total"] != 30.0 || cr["used"] != 25.0 || cr["remaining"] != 5.0 {
		t.Errorf("credits = %#v", cr)
	}
	sh := quotas["Session (5h)"]
	if sh == nil || sh["used"] != 1.0 || sh["total"] != 10.0 {
		t.Errorf("session = %#v", sh)
	}
}

// ---------- cursor ----------

func TestUFBCursor(t *testing.T) {
	ufBInstallStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "GetCurrentPeriodUsage"):
			ufBJSON(w, `{"planUsage":{"limit":2000,"includedSpend":500,"remaining":1500,"totalPercentUsed":25},
				"billingCycleEnd":1890000000000}`)
		case strings.Contains(r.URL.Path, "GetPlanInfo"):
			ufBJSON(w, `{"planInfo":{"planName":"Pro"}}`)
		default:
			w.WriteHeader(404)
		}
	}))
	rec, err := ufBCursorUsage(context.Background(), ufBConn(map[string]any{
		"provider": "cursor", "accessToken": "cursor-token",
		"providerSpecificData": map[string]any{},
	}), false)
	if err != nil {
		t.Fatal(err)
	}
	if rec["plan"] != "Cursor Pro" {
		t.Errorf("plan = %v", rec["plan"])
	}
	quotas := ufBQuotas(t, rec)
	p := quotas["Plan (USD)"]
	// 2000c limit = $20, 500c used = $5, percentUsed 25 -> 75% remaining.
	if p == nil || p["total"] != 20.0 || p["used"] != 5.0 || p["remainingPercentage"] != 75.0 {
		t.Errorf("plan usd = %#v", p)
	}
}
