// usage_fetch_b.go — Phase 3 usage fetchers, batch B (Team U2).
//
// Ports of open-sse/services/usage/{minimax,minimaxCodeUsage (services/),
// codebuddy-cn,misc#getVercelAiGatewayUsage,grok-cli+grokCliQuotaFrame,
// kimi,opencode-go,opencode-zen,deepseek,zed,xiaomi-mimo,commandcode,
// cursor}.js, registered as plugins via init() — see ops.go's
// opRegisterUsageFetcher dispatch.
//
// Proxy note: the JS handlers call proxyAwareFetch with the connection's
// proxyOptions. Like the four Phase-2 fetchers in ops.go, this port goes
// through the shared opHTTPClient and does NOT apply per-connection proxy
// options (documented boundary of the Go port's usage path).
//
// Test seam: every request goes through opHTTPClient (swappable in
// tests); the xiaomi phase-2 SSO hop derives a no-redirect client from
// opHTTPClient's Transport at call time.
package api

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"9router-go/internal/db"
	"9router-go/internal/executors"
	"9router-go/internal/providers"
)

func init() {
	opRegisterUsageFetcher("minimax", ufBMiniMaxUsage)
	opRegisterUsageFetcher("minimax-cn", ufBMiniMaxUsage)
	opRegisterUsageFetcher("minimax-code", ufBMiniMaxCodeUsage)
	opRegisterUsageFetcher("minimax-code-global", ufBMiniMaxCodeUsage)
	opRegisterUsageFetcher("vercel-ai-gateway", ufBVercelUsage)
	opRegisterUsageFetcher("codebuddy-cn", func(ctx context.Context, conn db.Record, force bool) (db.Record, error) {
		return ufBCodebuddyUsage(ctx, "codebuddy-cn", conn)
	})
	opRegisterUsageFetcher("codebuddy-intl", func(ctx context.Context, conn db.Record, force bool) (db.Record, error) {
		return ufBCodebuddyUsage(ctx, "codebuddy-intl", conn)
	})
	opRegisterUsageFetcher("grok-cli", ufBGrokUsage)
	opRegisterUsageFetcher("kimi", ufBKimiUsage)
	opRegisterUsageFetcher("opencode-go", func(ctx context.Context, conn db.Record, force bool) (db.Record, error) {
		return ufBOpenCodeUsage(ctx, "opencode-go", "OpenCode Go",
			"OpenCode Go subscription required for this API key.", conn)
	})
	opRegisterUsageFetcher("opencode-zen", func(ctx context.Context, conn db.Record, force bool) (db.Record, error) {
		return ufBOpenCodeUsage(ctx, "opencode-zen", "OpenCode Zen",
			"OpenCode Zen billing required for this API key.", conn)
	})
	opRegisterUsageFetcher("deepseek", ufBDeepseekUsage)
	opRegisterUsageFetcher("zed", ufBZedUsage)
	opRegisterUsageFetcher("xiaomi-mimo", ufBMimoUsage)
	opRegisterUsageFetcher("commandcode", ufBCommandCodeUsage)
	opRegisterUsageFetcher("cursor", ufBCursorUsage)
}

// ---------- shared helpers (ufB prefix; U1 works in usage_fetch_a.go) ----------

// ufBDo performs one HTTP request through the shared client and returns
// the status, raw body and headers (several JS handlers need the raw
// text for error messages / auth heuristics, which opFetchJSON drops).
func ufBDo(ctx context.Context, method, rawURL string, headers map[string]string, body []byte) (int, []byte, http.Header, error) {
	return ufBDoClient(ctx, opHTTPClient, method, rawURL, headers, body)
}

func ufBDoClient(ctx context.Context, client *http.Client, method, rawURL string, headers map[string]string, body []byte) (int, []byte, http.Header, error) {
	var rdr io.Reader
	if body != nil {
		rdr = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rdr)
	if err != nil {
		return 0, nil, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	return resp.StatusCode, raw, resp.Header, nil
}

// ufBJSONMap decodes a JSON object body; nil when not a JSON object.
func ufBJSONMap(raw []byte) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	return m
}

// ufBTruthy mirrors JS truthiness for the shapes these APIs return.
func ufBTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case float64:
		return t != 0 && !math.IsNaN(t)
	}
	return true
}

// ufBFirstNonNil mirrors a JS `a ?? b ?? c` chain.
func ufBFirstNonNil(vals ...any) any {
	for _, v := range vals {
		if v != nil {
			return v
		}
	}
	return nil
}

// ufBNumRaw is JS Number(v) with an explicit finite check (no fallback).
func ufBNumRaw(v any) (float64, bool) {
	f := opFinite(v, math.NaN())
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

// ufBField mirrors `model[snake] ?? model[camel]`.
func ufBField(m map[string]any, snake, camel string) any {
	if m == nil {
		return nil
	}
	if v, ok := m[snake]; ok && v != nil {
		return v
	}
	if v, ok := m[camel]; ok && v != nil {
		return v
	}
	return nil
}

// ufBTitleWords mirrors JS .replace(/\b\w/g, ch => ch.toUpperCase()).
func ufBTitleWords(s string) string {
	isWord := func(r rune) bool {
		return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
	}
	runes := []rune(s)
	for i, r := range runes {
		if isWord(r) && (i == 0 || !isWord(runes[i-1])) {
			runes[i] = unicode.ToUpper(r)
		}
	}
	return string(runes)
}

// ufBResetMs converts a reset value to epoch milliseconds (via the
// shared parseResetTime port), for comparisons/sorting.
func ufBResetMs(v any) (float64, bool) {
	iso := opParseResetTime(v)
	s, ok := iso.(string)
	if !ok || s == "" {
		return 0, false
	}
	t, err := time.Parse("2006-01-02T15:04:05.000Z", s)
	if err != nil {
		return 0, false
	}
	return float64(t.UnixMilli()), true
}

// ufBRegistryHeaders returns registry transport.headers for a provider
// (PROVIDERS[id].headers in the built JS registry).
func ufBRegistryHeaders(providerID string) map[string]string {
	p, ok := providers.Get(providerID)
	if !ok {
		return nil
	}
	hm := opMap(opMap(p.Raw, "transport"), "headers")
	if hm == nil {
		return nil
	}
	out := map[string]string{}
	for k, v := range hm {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

// ---------- minimax / minimax-cn (usage/minimax.js) ----------

var ufBMiniMaxAuthRe = regexp.MustCompile(`(?i)token plan|coding plan|invalid api key|invalid key|unauthorized|inactive`)

func ufBMiniMaxField(m map[string]any, snake, camel string) any { return ufBField(m, snake, camel) }

func ufBMiniMaxModelName(m map[string]any) string {
	s, _ := ufBMiniMaxField(m, "model_name", "modelName").(string)
	return strings.TrimSpace(s)
}

var (
	ufBMinMaxSepRe   = regexp.MustCompile(`[_-]+`)
	ufBMinMaxSpaceRe = regexp.MustCompile(`\s+`)
	ufBWordToRe      = regexp.MustCompile(`\bTo\b`)
	ufBWordTtsRe     = regexp.MustCompile(`\bTts\b`)
	ufBWordHdRe      = regexp.MustCompile(`\bHd\b`)
)

// formatMiniMaxQuotaName ports formatMiniMaxQuotaName.
func ufBMiniMaxQuotaName(m map[string]any) string {
	rawName := ufBMiniMaxModelName(m)
	if rawName == "" {
		return "MiniMax"
	}
	if rawName == "MiniMax-M*" || rawName == "general" {
		return "M-series"
	}
	s := ufBMinMaxSepRe.ReplaceAllString(rawName, " ")
	s = ufBMinMaxSpaceRe.ReplaceAllString(s, " ")
	s = strings.TrimSpace(s)
	s = ufBTitleWords(s)
	s = ufBWordToRe.ReplaceAllString(s, "to")
	s = ufBWordTtsRe.ReplaceAllString(s, "TTS")
	s = ufBWordHdRe.ReplaceAllString(s, "HD")
	return s
}

// ufBMiniMaxPercent ports getMiniMaxProvidedPercent (nil = absent).
func ufBMiniMaxPercent(m map[string]any, snake, camel string) *float64 {
	raw := ufBMiniMaxField(m, snake, camel)
	if raw == nil {
		return nil
	}
	n, ok := ufBNumRaw(raw)
	if !ok {
		return nil
	}
	c := math.Max(0, math.Min(100, n))
	return &c
}

func ufBMiniMaxSessionTotal(m map[string]any) float64 {
	return math.Max(0, opFinite(ufBMiniMaxField(m, "current_interval_total_count", "currentIntervalTotalCount"), 0))
}

func ufBMiniMaxWeeklyTotal(m map[string]any) float64 {
	return math.Max(0, opFinite(ufBMiniMaxField(m, "current_weekly_total_count", "currentWeeklyTotalCount"), 0))
}

func ufBMiniMaxHasQuota(m map[string]any) bool {
	if ufBMiniMaxSessionTotal(m) > 0 || ufBMiniMaxWeeklyTotal(m) > 0 {
		return true
	}
	if ufBMiniMaxPercent(m, "current_interval_remaining_percent", "currentIntervalRemainingPercent") != nil {
		return true
	}
	if ufBMiniMaxPercent(m, "current_weekly_remaining_percent", "currentWeeklyRemainingPercent") != nil {
		return true
	}
	return false
}

func ufBMiniMaxResetAt(m map[string]any, capturedAtMs int64, remainsSnake, remainsCamel, endSnake, endCamel string) any {
	remainsMs := opFinite(ufBMiniMaxField(m, remainsSnake, remainsCamel), 0)
	if remainsMs > 0 {
		return time.UnixMilli(capturedAtMs + int64(remainsMs)).UTC().Format("2006-01-02T15:04:05.000Z")
	}
	return opParseResetTime(ufBMiniMaxField(m, endSnake, endCamel))
}

func ufBMiniMaxProvidedPct(provided *float64, remaining, total float64) float64 {
	if provided != nil {
		return math.Max(0, math.Min(100, *provided))
	}
	if total > 0 {
		return math.Max(0, math.Min(100, (remaining/total)*100))
	}
	return 0
}

// ufBMiniMaxBuildQuota ports buildMiniMaxQuota.
func ufBMiniMaxBuildQuota(total, count float64, resetAt any, countMeansRemaining bool, provided *float64) db.Record {
	safeTotal := math.Max(0, total)
	var used float64
	if countMeansRemaining {
		used = math.Max(safeTotal-count, 0)
	} else {
		used = math.Min(math.Max(0, count), safeTotal)
	}
	remaining := math.Max(safeTotal-used, 0)
	return db.Record{
		"used":                used,
		"total":               safeTotal,
		"remaining":           remaining,
		"remainingPercentage": ufBMiniMaxProvidedPct(provided, remaining, safeTotal),
		"resetAt":             resetAt,
		"unlimited":           false,
	}
}

// ufBMiniMaxAddQuota ports addMiniMaxQuota.
func ufBMiniMaxAddQuota(quotas map[string]db.Record, key string, model map[string]any, total float64,
	countSnake, countCamel, percentSnake, percentCamel string,
	capturedAtMs int64, remainsSnake, remainsCamel, endSnake, endCamel string, countMeansRemaining bool) {
	provided := ufBMiniMaxPercent(model, percentSnake, percentCamel)
	if total <= 0 && provided == nil {
		return
	}
	count := math.Max(0, opFinite(ufBMiniMaxField(model, countSnake, countCamel), 0))
	effectiveTotal, effectiveCount := total, count
	if total <= 0 {
		effectiveTotal = 100
		pct := *provided
		if countMeansRemaining {
			effectiveCount = math.Round(effectiveTotal * (pct / 100))
		} else {
			effectiveCount = math.Round(effectiveTotal * (1 - pct/100))
		}
	}
	quotas[key] = ufBMiniMaxBuildQuota(effectiveTotal, effectiveCount,
		ufBMiniMaxResetAt(model, capturedAtMs, remainsSnake, remainsCamel, endSnake, endCamel),
		countMeansRemaining, provided)
}

// ufBMiniMaxUsage ports getMiniMaxUsage (Token Plan / Coding Plan).
func ufBMiniMaxUsage(ctx context.Context, conn db.Record, force bool) (db.Record, error) {
	apiKey := opStr(conn, "apiKey")
	if apiKey == "" {
		return db.Record{"message": "MiniMax API key not available."}, nil
	}
	provider := opStr(conn, "provider")
	usageUrls := opStrSlice(opProviderUsage(provider), "urls")
	lastErrorMessage := ""

	for index, usageURL := range usageUrls {
		canFallback := index < len(usageUrls)-1
		status, raw, _, ferr := ufBDo(ctx, "GET", usageURL, map[string]string{
			"Authorization": "Bearer " + apiKey,
			"Accept":        "application/json",
			"Content-Type":  "application/json",
		}, nil)
		if ferr != nil {
			lastErrorMessage = ferr.Error()
			if !canFallback {
				break
			}
			continue
		}
		rawText := string(raw)
		payload := ufBJSONMap(raw)
		if payload == nil {
			payload = db.Record{}
		}
		baseResp, _ := ufBFirstNonNil(payload["base_resp"], payload["baseResp"]).(map[string]any)
		apiStatusCode := opFinite(ufBField(baseResp, "status_code", "statusCode"), 0)
		apiStatusMessage := ""
		if s, ok := ufBField(baseResp, "status_msg", "statusMsg").(string); ok {
			apiStatusMessage = strings.TrimSpace(s)
		}
		combined := strings.TrimSpace(apiStatusMessage + " " + rawText)

		if status == 401 || status == 403 || apiStatusCode == 1004 || ufBMiniMaxAuthRe.MatchString(combined) {
			return db.Record{"message": "MiniMax API key invalid or inactive. Use an active Token/Coding Plan key."}, nil
		}
		okStatus := status >= 200 && status < 300
		if !okStatus {
			lastErrorMessage = fmt.Sprintf("MiniMax usage endpoint error (%d)", status)
			if (status == 404 || status == 405 || status >= 500) && canFallback {
				continue
			}
			return db.Record{"message": "MiniMax connected. " + lastErrorMessage}, nil
		}
		if apiStatusCode != 0 {
			msg := apiStatusMessage
			if msg == "" {
				msg = "Upstream quota API error"
			}
			return db.Record{"message": "MiniMax connected. " + msg}, nil
		}

		modelRemains := ufBFirstNonNil(payload["model_remains"], payload["modelRemains"])
		var quotaModels []map[string]any
		if arr, ok := modelRemains.([]any); ok {
			for _, item := range arr {
				if mm, ok := item.(map[string]any); ok && ufBMiniMaxHasQuota(mm) {
					quotaModels = append(quotaModels, mm)
				}
			}
		}
		if len(quotaModels) == 0 {
			return db.Record{"message": "MiniMax connected. No quota data was returned."}, nil
		}

		capturedAtMs := time.Now().UnixMilli()
		countMeansRemaining := strings.Contains(usageURL, "/coding_plan/remains")
		quotas := map[string]db.Record{}
		for _, model := range quotaModels {
			displayName := ufBMiniMaxQuotaName(model)
			ufBMiniMaxAddQuota(quotas, displayName+" (5h)", model, ufBMiniMaxSessionTotal(model),
				"current_interval_usage_count", "currentIntervalUsageCount",
				"current_interval_remaining_percent", "currentIntervalRemainingPercent",
				capturedAtMs, "remains_time", "remainsTime", "end_time", "endTime", countMeansRemaining)
			ufBMiniMaxAddQuota(quotas, displayName+" (7d)", model, ufBMiniMaxWeeklyTotal(model),
				"current_weekly_usage_count", "currentWeeklyUsageCount",
				"current_weekly_remaining_percent", "currentWeeklyRemainingPercent",
				capturedAtMs, "weekly_remains_time", "weeklyRemainsTime", "weekly_end_time", "weeklyEndTime", countMeansRemaining)
		}
		if len(quotas) == 0 {
			return db.Record{"message": "MiniMax connected. Unable to extract quota usage."}, nil
		}
		return db.Record{"quotas": quotas}, nil
	}

	if lastErrorMessage != "" {
		return db.Record{"message": "MiniMax connected. Unable to fetch usage: " + lastErrorMessage}, nil
	}
	return db.Record{"message": "MiniMax connected. Unable to fetch usage."}, nil
}

// ---------- minimax-code / minimax-code-global (services/minimaxCodeUsage.js) ----------

const ufBMiniMaxCodeSignSecret = "I*7Cf%WZ#S&%1RlZJ&C2"

type ufBMiniMaxCodeSite struct {
	agent    string
	platform string
	lang     string
}

var ufBMiniMaxCodeSites = map[string]ufBMiniMaxCodeSite{
	"minimax-code":        {agent: "https://agent.minimaxi.com", platform: "https://www.minimaxi.com", lang: "zh"},
	"minimax-code-global": {agent: "https://agent.minimax.io", platform: "https://platform.minimax.io", lang: "en"},
}

// ufBAccountRefused mirrors the JS AccountRefused error class.
type ufBAccountRefused struct{ msg string }

func (e *ufBAccountRefused) Error() string { return e.msg }

func ufBMd5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ufBEncodeURIComponent mirrors JS encodeURIComponent.
func ufBEncodeURIComponent(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '!' || c == '~' || c == '*' || c == '\'' || c == '(' || c == ')' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// ufBNumStrict mirrors the `num` helper in minimaxCodeUsage.js: only
// actual JSON numbers count (strings do not coerce).
func ufBNumStrict(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return 0, false
		}
		return n, true
	case json.Number:
		f, err := n.Float64()
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, false
		}
		return f, true
	}
	return 0, false
}

// ufBSignedAccountRequest ports signedAccountRequest. body == nil means
// a GET (no JSON body); otherwise a POST with the given JSON body bytes.
// Returns (method, url, headers).
func ufBSignedAccountRequest(site ufBMiniMaxCodeSite, path, access, userID string, body []byte, now time.Time) (string, string, map[string]string) {
	_, tzOffsetSec := now.Zone()
	osName := runtime.GOOS
	if osName == "windows" {
		osName = "win32"
	}
	uid := strings.TrimSpace(userID)
	if uid == "" {
		uid = "0"
	}
	params := [][2]string{
		{"device_platform", "mcode"}, {"biz_id", "3"}, {"app_id", "3001"}, {"version_code", "22201"},
		{"unix", strconv.FormatInt(now.UnixMilli(), 10)}, {"timezone_offset", strconv.Itoa(tzOffsetSec)},
		{"sys_language", site.lang}, {"lang", site.lang}, {"device_id", "0"}, {"os_name", osName},
		{"browser_name", "mcode"}, {"user_id", uid}, {"client", "mcode"},
	}
	var qs strings.Builder
	for i, kv := range params {
		if i > 0 {
			qs.WriteByte('&')
		}
		qs.WriteString(url.QueryEscape(kv[0]) + "=" + url.QueryEscape(kv[1]))
	}
	full := site.agent + path + "?" + qs.String()
	at := path + "?" + qs.String()
	ts := now.Unix() // Math.floor(now/1000); now is ms-precision — Unix() floors for positive values
	nowStr := strconv.FormatInt(now.UnixMilli(), 10)
	var yy, sig string
	if body == nil {
		yy = ufBMd5Hex(ufBEncodeURIComponent(at) + "_{}" + ufBMd5Hex(nowStr) + "ooui")
		sig = ufBMd5Hex(strconv.FormatInt(ts, 10) + ufBMiniMaxCodeSignSecret)
	} else {
		yy = ufBMd5Hex(ufBEncodeURIComponent(at) + "_" + string(body) + ufBMd5Hex(nowStr) + "ooui")
		sig = ufBMd5Hex(strconv.FormatInt(ts, 10) + ufBMiniMaxCodeSignSecret + string(body))
	}
	headers := map[string]string{
		"Accept":        "application/json",
		"Content-Type":  "application/json",
		"User-Agent":    "MiniMaxCode",
		"Authorization": "Bearer " + access,
		"yy":            yy,
		"x-timestamp":   strconv.FormatInt(ts, 10),
		"x-signature":   sig,
	}
	method := "GET"
	if body != nil {
		method = "POST"
	}
	return method, full, headers
}

// ufBMiniMaxCodeAccountCall ports accountCall + checked.
func ufBMiniMaxCodeAccountCall(ctx context.Context, site ufBMiniMaxCodeSite, path, access, userID string, body []byte, what string) (map[string]any, error) {
	method, fullURL, headers := ufBSignedAccountRequest(site, path, access, userID, body, time.Now())
	status, raw, _, err := ufBDo(ctx, method, fullURL, headers, body)
	if err != nil {
		return nil, err
	}
	if status == 401 || status == 403 {
		return nil, &ufBAccountRefused{msg: fmt.Sprintf("%s: the sign-in was refused (HTTP %d)", what, status)}
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("%s: HTTP %d", what, status)
	}
	env := ufBJSONMap(raw)
	if env == nil {
		return nil, fmt.Errorf("%s: not JSON", what)
	}
	// checked()
	if si, ok := env["statusInfo"].(map[string]any); ok {
		if code, isNum := ufBNumStrict(si["code"]); isNum && code != 0 {
			if code == 1000048 {
				return nil, &ufBAccountRefused{msg: fmt.Sprintf("%s: the sign-in was refused", what)}
			}
			msg := "status " + strconv.FormatFloat(code, 'f', -1, 64)
			if s, ok := ufBFirstNonNil(si["message"], si["msg"]).(string); ok && s != "" {
				msg = s
			}
			return nil, fmt.Errorf("%s: %s", what, msg)
		}
	}
	if br, ok := env["base_resp"].(map[string]any); ok {
		if code, isNum := ufBNumStrict(br["status_code"]); isNum && code != 0 {
			msg := "status " + strconv.FormatFloat(code, 'f', -1, 64)
			if s, ok := br["status_msg"].(string); ok && s != "" {
				msg = s
			}
			return nil, fmt.Errorf("%s: %s", what, msg)
		}
	}
	return env, nil
}

func ufBStrTrimmed(m map[string]any, k string) (string, bool) {
	if m == nil {
		return "", false
	}
	s, ok := m[k].(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "", false
	}
	return strings.TrimSpace(s), true
}

// ufBMiniMaxCodeIdentity ports getMiniMaxCodeIdentity.
func ufBMiniMaxCodeIdentity(ctx context.Context, site ufBMiniMaxCodeSite, access string) (map[string]any, error) {
	env, err := ufBMiniMaxCodeAccountCall(ctx, site, "/v1/api/user/info", access, "", nil, "account")
	if err != nil {
		return nil, err
	}
	d, _ := env["data"].(map[string]any)
	var u map[string]any
	for _, cand := range []map[string]any{d, env} {
		if cand == nil {
			continue
		}
		if v, ok := ufBFirstNonNil(cand["userInfo"], cand["user_info"]).(map[string]any); ok {
			u = v
			break
		}
	}
	id, ok := ufBStrTrimmed(u, "realUserID")
	if !ok {
		id, ok = ufBStrTrimmed(u, "real_user_id")
	}
	if !ok {
		return nil, fmt.Errorf("account: no user id in the reply")
	}
	out := map[string]any{"realUserID": id}
	for _, k := range []string{"userEmail", "email", "userMail", "user_email"} {
		if s, ok := ufBStrTrimmed(u, k); ok {
			out["email"] = s
			break
		}
	}
	for _, k := range []string{"name", "userName", "user_name"} {
		if s, ok := ufBStrTrimmed(u, k); ok {
			out["name"] = s
			break
		}
	}
	return out, nil
}

// ufBMiniMaxCodeParseMembership ports parseMembership.
func ufBMiniMaxCodeParseMembership(e map[string]any) map[string]any {
	d, _ := e["data"].(map[string]any)
	pick := func(k string) any { return ufBFirstNonNil(e[k], d[k]) }
	out := map[string]any{}
	if has, ok := pick("has_token_plan").(bool); ok {
		out["hasTokenPlan"] = has
	}
	if s, ok := ufBStrTrimmed(map[string]any{"v": pick("op_group_id")}, "v"); ok {
		out["opGroupId"] = s
	}
	if s, ok := ufBStrTrimmed(map[string]any{"v": pick("token_plan_tier")}, "v"); ok {
		out["tier"] = s
	}
	if ends, ok := ufBNumStrict(pick("token_plan_expires_at")); ok && ends > 0 {
		out["expiresAt"] = ends
	}
	var sum map[string]any
	if v, ok := ufBFirstNonNil(e["op_credit_summary"], d["op_credit_summary"]).(map[string]any); ok {
		sum = v
	}
	bal, balOK := ufBStrTrimmed(sum, "total_remaining_amount")
	if !balOK {
		switch v := pick("opcredit_balance").(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				bal, balOK = strings.TrimSpace(v), true
			}
		case float64:
			bal, balOK = strconv.FormatFloat(v, 'f', -1, 64), true
		}
	}
	if balOK {
		out["balance"] = bal
	}
	return out
}

// ufBMiniMaxCodeMembership ports getMiniMaxCodeMembership.
func ufBMiniMaxCodeMembership(ctx context.Context, site ufBMiniMaxCodeSite, access, userID string) (map[string]any, error) {
	var wsID any
	var wsM map[string]any
	wsFound := false
	env, err := ufBMiniMaxCodeAccountCall(ctx, site, "/matrix/api/v1/user/get_user_extra_info", access, userID, []byte("{}"), "workspace")
	if err != nil {
		var refused *ufBAccountRefused
		if isRefused := errorAsRefused(err, &refused); isRefused {
			return nil, err
		}
		env2, err2 := ufBMiniMaxCodeAccountCall(ctx, site, "/matrix/api/v1/commerce/get_membership_info", access, userID, []byte("{}"), "membership")
		if err2 != nil {
			return nil, err2
		}
		return ufBMiniMaxCodeParseMembership(env2), nil
	}
	var list []any
	if arr, ok := env["workspaces"].([]any); ok {
		list = arr
	} else if d, ok := env["data"].(map[string]any); ok {
		list, _ = d["workspaces"].([]any)
	}
	for _, item := range list {
		w, ok := item.(map[string]any)
		if !ok {
			continue
		}
		wt, isNum := ufBNumStrict(w["workspace_type"])
		if !isNum || wt != 0 {
			continue
		}
		var id any
		if n, isNum := ufBNumStrict(w["workspace_id"]); isNum && n >= 0 {
			id = n
		} else if s, ok := ufBStrTrimmed(w, "workspace_id"); ok {
			id = s
		}
		if id != nil {
			wsID, wsM, wsFound = id, ufBMiniMaxCodeParseMembership(w), true
			break
		}
	}
	if !wsFound {
		return map[string]any{}, nil
	}
	bodyMap := map[string]any{"workspace_id": wsID}
	bodyBytes, _ := json.Marshal(bodyMap)
	env3, err := ufBMiniMaxCodeAccountCall(ctx, site, "/matrix/api/v1/commerce/get_membership_info", access, userID, bodyBytes, "membership")
	if err != nil {
		var refused *ufBAccountRefused
		if errorAsRefused(err, &refused) {
			return nil, err
		}
		return wsM, nil
	}
	m := ufBMiniMaxCodeParseMembership(env3)
	merged := map[string]any{}
	for k, v := range wsM {
		merged[k] = v
	}
	for k, v := range m {
		merged[k] = v
	}
	wsHas, wsHasOK := wsM["hasTokenPlan"].(bool)
	mHas, mHasOK := m["hasTokenPlan"].(bool)
	switch {
	case (wsHasOK && wsHas) || (mHasOK && mHas):
		merged["hasTokenPlan"] = true
	case (wsHasOK && !wsHas) || (mHasOK && !mHas):
		merged["hasTokenPlan"] = false
	default:
		delete(merged, "hasTokenPlan")
	}
	if _, ok := merged["opGroupId"]; !ok {
		if v, ok := wsM["opGroupId"]; ok {
			merged["opGroupId"] = v
		}
	}
	return merged, nil
}

// errorAsRefused is errors.As for ufBAccountRefused (kept local to
// avoid an extra import dance in the membership flow).
func errorAsRefused(err error, target **ufBAccountRefused) bool {
	for err != nil {
		if r, ok := err.(*ufBAccountRefused); ok {
			*target = r
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// ufBMiniMaxCodePlanWindows ports getMiniMaxPlanWindows + parsePlanWindows.
func ufBMiniMaxCodePlanWindows(ctx context.Context, site ufBMiniMaxCodeSite, access, group string) ([]db.Record, error) {
	headers := map[string]string{
		"Accept":        "application/json",
		"Authorization": "Bearer " + access,
	}
	if group != "" {
		headers["X-Group-Id"] = group
	}
	status, raw, _, err := ufBDo(ctx, "GET", site.platform+"/v1/api/openplatform/coding_plan/remains", headers, nil)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("M Plan: HTTP %d", status)
	}
	body := ufBJSONMap(raw)
	return ufBMiniMaxCodeParsePlanWindows(body)
}

func ufBMiniMaxCodeParsePlanWindows(body map[string]any) ([]db.Record, error) {
	br, hasBR := body["base_resp"].(map[string]any)
	if hasBR {
		if code, isNum := ufBNumStrict(br["status_code"]); isNum && code != 0 {
			msg := fmt.Sprintf("MiniMax said %s", strconv.FormatFloat(code, 'f', -1, 64))
			if s, ok := br["status_msg"].(string); ok && s != "" {
				msg = s
			}
			return nil, fmt.Errorf("%s", msg)
		}
	}
	remains, isArr := body["model_remains"].([]any)
	if !hasBR && !isArr {
		return nil, fmt.Errorf("no plan in the reply")
	}
	ms := func(n float64) float64 {
		if n < 1e12 {
			return n * 1000
		}
		return n
	}
	numOf := func(m map[string]any, k string) (float64, bool) {
		return ufBNumStrict(m[k])
	}
	out := []db.Record{}
	for _, item := range remains {
		k, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name := ""
		if s, ok := k["model_name"].(string); ok {
			name = strings.TrimSpace(s)
		}
		iStatus, iStatusOK := numOf(k, "current_interval_status")
		wStatus, wStatusOK := numOf(k, "current_weekly_status")
		iTotal, iTotalOK := numOf(k, "current_interval_total_count")
		wTotal, wTotalOK := numOf(k, "current_weekly_total_count")
		// JS skip rule: both statuses are the number 3 AND both totals
		// are the number 0 (num() is undefined for missing/non-numbers,
		// and zero(undefined) is false).
		if name == "" || (iStatusOK && iStatus == 3 && wStatusOK && wStatus == 3 &&
			iTotalOK && iTotal == 0 && wTotalOK && wTotal == 0) {
			continue
		}
		general := strings.ToLower(name) == "general"
		type win struct {
			left    float64
			hasLeft bool
			status  float64
			start   float64
			end     float64
			week    bool
		}
		wins := []win{}
		for _, spec := range []struct {
			leftKey, statusKey, startKey, endKey string
			week                                 bool
		}{
			{"current_interval_remaining_percent", "current_interval_status", "start_time", "end_time", false},
			{"current_weekly_remaining_percent", "current_weekly_status", "weekly_start_time", "weekly_end_time", true},
		} {
			left, hasLeft := numOf(k, spec.leftKey)
			status, _ := numOf(k, spec.statusKey)
			start, _ := numOf(k, spec.startKey)
			end, _ := numOf(k, spec.endKey)
			wins = append(wins, win{left: left, hasLeft: hasLeft, status: status, start: start, end: end, week: spec.week})
		}
		for _, x := range wins {
			if x.status == 3 || (!x.hasLeft && x.status != 2) {
				continue
			}
			var left float64
			if x.status == 2 {
				left = 0
			} else {
				left = math.Max(0, math.Min(100, x.left))
			}
			var span float64
			if x.start > 0 && x.end > x.start {
				span = ms(x.end) - ms(x.start)
			} else if x.week {
				span = 7 * 86400000
			}
			var label string
			switch {
			case x.week:
				label = "7 days"
			case span > 86400000 && math.Mod(span, 86400000) == 0:
				label = fmt.Sprintf("%d days", int64(span/86400000))
			case span >= 3600000 && math.Mod(span, 3600000) == 0:
				label = fmt.Sprintf("%d hours", int64(span/3600000))
			case span > 0:
				label = fmt.Sprintf("%d minutes", int64(math.Floor(span/60000)))
			default:
				label = "Allowance"
			}
			windowName := label
			if !general {
				r := []rune(name)
				windowName = string(unicode.ToUpper(r[0])) + string(r[1:]) + " · " + label
			}
			var resetAt any
			if x.end > 0 {
				resetAt = time.UnixMilli(int64(ms(x.end))).UTC().Format("2006-01-02T15:04:05.000Z")
			}
			out = append(out, db.Record{
				"name":                windowName,
				"used":                100 - left,
				"total":               float64(100),
				"remaining":           left,
				"remainingPercentage": left,
				"resetAt":             resetAt,
			})
		}
	}
	return out, nil
}

// ufBMiniMaxCodeUsage ports getMiniMaxCodeUsage.
func ufBMiniMaxCodeUsage(ctx context.Context, conn db.Record, force bool) (db.Record, error) {
	provider := opStr(conn, "provider")
	site, siteOK := ufBMiniMaxCodeSites[provider]
	access := opStr(conn, "accessToken")
	if !siteOK || access == "" {
		return db.Record{"message": fmt.Sprintf("Usage API not implemented for %s", provider)}, nil
	}
	psd := opMap(conn, "providerSpecificData")

	rec, err := ufBMiniMaxCodeUsageInner(ctx, site, access, psd)
	if err != nil {
		var refused *ufBAccountRefused
		if errorAsRefused(err, &refused) {
			return db.Record{"message": fmt.Sprintf("MiniMax Code sign-in expired — unauthorized, please re-authorize (%s)", refused.msg)}, nil
		}
		return db.Record{"message": err.Error()}, nil
	}
	return rec, nil
}

func ufBMiniMaxCodeUsageInner(ctx context.Context, site ufBMiniMaxCodeSite, access string, psd map[string]any) (db.Record, error) {
	userID, _ := ufBStrTrimmed(psd, "realUserID")
	var who map[string]any
	if userID == "" {
		var err error
		who, err = ufBMiniMaxCodeIdentity(ctx, site, access)
		if err != nil {
			return nil, err
		}
		userID, _ = who["realUserID"].(string)
	}
	m, err := ufBMiniMaxCodeMembership(ctx, site, access, userID)
	if err != nil {
		return nil, err
	}

	quotas := map[string]db.Record{}
	if balStr, ok := m["balance"].(string); ok {
		n, _ := strconv.ParseFloat(balStr, 64)
		if math.IsNaN(n) || math.IsInf(n, 0) {
			n = 0
		}
		quotas["Credits"] = db.Record{
			"used":            float64(0),
			"total":           n,
			"isCreditBalance": true,
			"currency":        "credits",
		}
	}
	hasTokenPlan, _ := m["hasTokenPlan"].(bool)
	opGroupID, _ := m["opGroupId"].(string)
	if hasTokenPlan && opGroupID != "" {
		windows, werr := ufBMiniMaxCodePlanWindows(ctx, site, access, opGroupID)
		if werr != nil {
			quotas["M Plan windows"] = db.Record{
				"name": "M Plan windows", "used": float64(0), "total": float64(0),
				"resetAt": nil, "message": werr.Error(),
			}
		} else {
			for _, w := range windows {
				name, _ := w["name"].(string)
				quotas[name] = w
			}
		}
	}
	if len(quotas) == 0 {
		msg := "No usage data returned"
		if has, present := m["hasTokenPlan"].(bool); present && !has {
			msg = "Free account (no M Plan)"
		}
		quotas["Plan"] = db.Record{
			"name": "Plan", "used": float64(0), "total": float64(0),
			"resetAt": nil, "message": msg,
		}
	}

	plan := "Free"
	if hasTokenPlan {
		if tier, ok := m["tier"].(string); ok && tier != "" {
			plan = "M Plan " + tier
		} else {
			plan = "M Plan"
		}
	}
	rec := db.Record{"quotas": quotas, "plan": plan}
	if ends, ok := ufBNumRaw(m["expiresAt"]); ok && ends > 0 {
		msVal := ends
		if msVal < 1e12 {
			msVal *= 1000
		}
		rec["planExpiresAt"] = time.UnixMilli(int64(msVal)).UTC().Format("2006-01-02T15:04:05.000Z")
	}
	var user any
	if who != nil {
		if s, ok := who["email"].(string); ok && s != "" {
			user = s
		} else if s, ok := who["name"].(string); ok && s != "" {
			user = s
		}
	}
	if user == nil {
		if s, ok := ufBStrTrimmed(psd, "realUserID"); ok {
			user = s
		} else if userID != "" {
			user = userID
		}
	}
	rec["user"] = user
	return rec, nil
}

// ---------- vercel-ai-gateway (usage/misc.js getVercelAiGatewayUsage) ----------

func ufBVercelUsage(ctx context.Context, conn db.Record, force bool) (db.Record, error) {
	apiKey := opStr(conn, "apiKey")
	if apiKey == "" {
		return db.Record{"message": "Vercel AI Gateway API key not available."}, nil
	}
	creditsURL := opStr(opProviderUsage("vercel-ai-gateway"), "url")
	status, raw, _, err := ufBDo(ctx, "GET", creditsURL, map[string]string{
		"Authorization": "Bearer " + apiKey,
		"Accept":        "application/json",
	}, nil)
	if err != nil {
		return db.Record{"message": "Vercel AI Gateway error: " + err.Error()}, nil
	}
	if status == 401 || status == 403 {
		return db.Record{"message": "Vercel AI Gateway API key invalid or expired."}, nil
	}
	if status < 200 || status >= 300 {
		trimmed := ""
		if len(raw) > 0 {
			text := string(raw)
			if len(text) > 200 {
				text = text[:200]
			}
			trimmed = ": " + text
		}
		return db.Record{"message": fmt.Sprintf("Vercel AI Gateway credits API error (%d)%s", status, trimmed)}, nil
	}
	data := ufBJSONMap(raw)
	if data == nil {
		return db.Record{"message": "Vercel AI Gateway error: response was not JSON"}, nil
	}
	balance := opFinite(data["balance"], 0)
	totalUsed := opFinite(data["total_used"], 0)
	const monthlyCredit = 5.0
	remainingPercentage := (balance / monthlyCredit) * 100

	if balance <= 0 && totalUsed <= 0 {
		return db.Record{
			"plan":    "Pay-as-you-go",
			"message": "Vercel AI Gateway connected. No credit allocation found (BYOK or unfunded account).",
			"quotas":  map[string]db.Record{},
		}, nil
	}
	return db.Record{
		"plan": "Pay-as-you-go",
		"quotas": map[string]db.Record{
			"Used (USD)": {
				"used": totalUsed, "total": float64(0), "remaining": float64(0),
				"remainingPercentage": float64(100), "unlimited": true,
			},
			"Remaining (USD)": {
				"used": balance, "total": monthlyCredit, "remaining": balance,
				"remainingPercentage": remainingPercentage, "unlimited": false,
			},
		},
	}, nil
}

// ---------- codebuddy-cn / codebuddy-intl (usage/codebuddy-cn.js) ----------

// ufBCodebuddyNum ports num(precise, plain): Number(precise ?? plain) or 0.
func ufBCodebuddyNum(precise, plain any) float64 {
	v := ufBFirstNonNil(precise, plain)
	return opFinite(v, 0)
}

// ufBRefillCadence ports refillCadence.
func ufBRefillCadence(acc map[string]any) string {
	startMs, startOK := ufBResetMs(acc["CycleStartTime"])
	endMs, endOK := ufBResetMs(acc["CycleEndTime"])
	if startOK && endOK {
		days := (endMs - startMs) / 86400000
		if days <= 1.5 {
			return "Daily"
		}
		if days <= 10 {
			return "Weekly"
		}
	}
	return "Monthly"
}

func ufBCodebuddyUsage(ctx context.Context, providerID string, conn db.Record) (db.Record, error) {
	token := opStr(conn, "accessToken")
	if token == "" {
		token = opStr(conn, "apiKey")
	}
	if token == "" {
		return db.Record{"message": fmt.Sprintf("CodeBuddy (%s) credential not available.", providerID)}, nil
	}
	headers := ufBRegistryHeaders(providerID)
	if headers == nil {
		headers = map[string]string{}
	}
	headers["Authorization"] = "Bearer " + token
	headers["Content-Type"] = "application/json"
	headers["Accept"] = "application/json"

	status, raw, _, err := ufBDo(ctx, "POST", opStr(opProviderUsage(providerID), "url"), headers, []byte("{}"))
	if err != nil {
		return db.Record{"message": fmt.Sprintf("CodeBuddy (%s) error: %s", providerID, err.Error())}, nil
	}
	if status == 401 || status == 403 {
		return db.Record{"message": "CodeBuddy CN credential invalid or expired."}, nil
	}
	if status < 200 || status >= 300 {
		return db.Record{"message": fmt.Sprintf("CodeBuddy CN quota API error (%d).", status)}, nil
	}
	jsonBody := ufBJSONMap(raw)
	if jsonBody == nil {
		return db.Record{"message": fmt.Sprintf("CodeBuddy (%s) error: response was not JSON", providerID)}, nil
	}
	if code := opFinite(jsonBody["code"], 0); code != 0 {
		msg, _ := jsonBody["msg"].(string)
		if msg == "" {
			msg = "unknown"
		}
		return db.Record{"message": "CodeBuddy CN quota error: " + msg}, nil
	}
	data := opMap(opMap(jsonBody, "data"), "Response")
	data = opMap(data, "Data")
	var accounts []map[string]any
	if arr, ok := data["Accounts"].([]any); ok {
		for _, item := range arr {
			if acc, ok := item.(map[string]any); ok {
				accounts = append(accounts, acc)
			}
		}
	}
	if len(accounts) == 0 {
		return db.Record{"message": "CodeBuddy CN connected. No credit package found."}, nil
	}

	cycleEndMs := func(acc map[string]any) float64 {
		if ms, ok := ufBResetMs(acc["CycleEndTime"]); ok {
			return ms
		}
		return math.Inf(1)
	}
	const refillGapMs = 2 * 24 * 60 * 60 * 1000
	isRefill := func(acc map[string]any) bool {
		ce := cycleEndMs(acc)
		de, deOK := ufBNumRaw(acc["DeductionEndTime"])
		return !math.IsInf(ce, 0) && deOK && de-ce > refillGapMs
	}
	var refills, bonuses []map[string]any
	for _, acc := range accounts {
		if isRefill(acc) {
			refills = append(refills, acc)
		} else {
			bonuses = append(bonuses, acc)
		}
	}
	byExpiry := func(list []map[string]any) {
		sort.SliceStable(list, func(i, j int) bool { return cycleEndMs(list[i]) < cycleEndMs(list[j]) })
	}
	byExpiry(refills)
	byExpiry(bonuses)

	quotas := map[string]db.Record{}
	seenRefill := map[string]int{}
	for _, acc := range refills {
		base := ufBRefillCadence(acc)
		seenRefill[base]++
		name := base
		if seenRefill[base] > 1 {
			name = fmt.Sprintf("%s %d", base, seenRefill[base])
		}
		quotas[name] = db.Record{
			"used":      ufBCodebuddyNum(acc["CycleCapacityUsedPrecise"], acc["CycleCapacityUsed"]),
			"total":     ufBCodebuddyNum(acc["CycleCapacitySizePrecise"], acc["CycleCapacitySize"]),
			"resetAt":   opParseResetTime(acc["CycleEndTime"]),
			"unlimited": false,
			"recurring": true,
		}
	}
	for i, acc := range bonuses {
		quotas[fmt.Sprintf("Bonus Pack %d", i+1)] = db.Record{
			"used":      ufBCodebuddyNum(acc["CapacityUsedPrecise"], acc["CapacityUsed"]),
			"total":     ufBCodebuddyNum(acc["CapacitySizePrecise"], acc["CapacitySize"]),
			"resetAt":   opParseResetTime(acc["CycleEndTime"]),
			"unlimited": false,
			"recurring": false,
		}
	}

	basePkg := accounts[0]
	if len(refills) > 0 {
		basePkg = refills[0]
	}
	plan, _ := basePkg["PackageName"].(string)
	if plan == "" {
		plan, _ = basePkg["SubProductName"].(string)
	}
	if plan == "" {
		plan = "CodeBuddy"
	}
	return db.Record{"plan": plan, "quotas": quotas}, nil
}

// ---------- deepseek (usage/deepseek.js) ----------

func ufBDeepseekUsage(ctx context.Context, conn db.Record, force bool) (db.Record, error) {
	apiKey := opStr(conn, "apiKey")
	if strings.TrimSpace(apiKey) == "" {
		return db.Record{"message": "DeepSeek API key not available. Add a key to view usage."}, nil
	}
	status, raw, _, err := ufBDo(ctx, "GET", "https://api.deepseek.com/user/balance", map[string]string{
		"Authorization": "Bearer " + strings.TrimSpace(apiKey),
		"Content-Type":  "application/json",
		"Accept":        "application/json",
	}, nil)
	if err != nil {
		return db.Record{"message": "DeepSeek error: " + err.Error()}, nil
	}
	if status == 401 || status == 403 {
		return db.Record{"plan": "DeepSeek", "message": "DeepSeek authentication failed. Check the API key."}, nil
	}
	if status < 200 || status >= 300 {
		msg := fmt.Sprintf("DeepSeek balance API error (%d)", status)
		if len(raw) > 0 {
			text := string(raw)
			if len(text) > 120 {
				text = text[:120]
			}
			msg += ": " + text
		}
		return db.Record{"plan": "DeepSeek", "message": msg}, nil
	}
	data := ufBJSONMap(raw)
	if data == nil {
		return db.Record{"message": "DeepSeek balance response was not JSON."}, nil
	}
	type balance struct {
		currency string
		total    float64
		granted  float64
		toppedUp float64
	}
	var balances []balance
	if arr, ok := data["balance_infos"].([]any); ok {
		for _, item := range arr {
			it, ok := item.(map[string]any)
			if !ok {
				continue
			}
			currency := ""
			if s, ok := it["currency"].(string); ok {
				currency = strings.ToUpper(s)
			}
			if currency == "" {
				continue
			}
			balances = append(balances, balance{
				currency: currency,
				total:    opFinite(ufBFirstNonNil(it["total_balance"], it["totalBalance"]), 0),
				granted:  opFinite(ufBFirstNonNil(it["granted_balance"], it["grantedBalance"]), 0),
				toppedUp: opFinite(ufBFirstNonNil(it["topped_up_balance"], it["toppedUpBalance"]), 0),
			})
		}
	}
	if len(balances) == 0 {
		return db.Record{"plan": "DeepSeek", "message": "DeepSeek connected. No balance data returned."}, nil
	}
	isAvailable := data["is_available"] == true || data["isAvailable"] == true
	quotas := map[string]db.Record{}
	for _, b := range balances {
		total := math.Max(0, b.total)
		pct := float64(0)
		if total > 0 {
			pct = 100
		}
		quotas[fmt.Sprintf("Balance (%s)", b.currency)] = db.Record{
			"used":                float64(0),
			"total":               total,
			"remainingPercentage": pct,
			"resetAt":             nil,
			"unlimited":           false,
			"isCreditBalance":     true,
			"currency":            b.currency,
		}
	}
	plan := "DeepSeek"
	if !isAvailable {
		plan = "DeepSeek (Insufficient Balance)"
	}
	return db.Record{"plan": plan, "quotas": quotas}, nil
}

// ---------- opencode-go / opencode-zen (usage/opencode-{go,zen}.js) ----------

var ufBOpenCodePeriods = []struct{ key, name string }{
	{"rolling", "Rolling"}, {"weekly", "Weekly"}, {"monthly", "Monthly"},
}

// ufBParsePercent ports parsePercent (nil = unparseable).
func ufBParsePercent(v any) *float64 {
	if n, ok := ufBNumRaw(v); ok {
		return &n
	}
	return nil
}

func ufBOpenCodeUsage(ctx context.Context, providerID, planLabel, forbiddenSubMsg string, conn db.Record) (db.Record, error) {
	apiKey := opStr(conn, "apiKey")
	if strings.TrimSpace(apiKey) == "" {
		return db.Record{"message": fmt.Sprintf("%s API key not available. Add a key to view usage.", planLabel)}, nil
	}
	status, raw, _, err := ufBDo(ctx, "GET", opStr(opProviderUsage(providerID), "url"), map[string]string{
		"Authorization": "Bearer " + strings.TrimSpace(apiKey),
		"Accept":        "application/json",
	}, nil)
	if err != nil {
		return db.Record{"message": fmt.Sprintf("%s error: %s", planLabel, err.Error())}, nil
	}
	if status == 401 {
		return db.Record{"plan": planLabel, "message": fmt.Sprintf("%s authentication failed. Check the API key.", planLabel)}, nil
	}
	if status == 403 {
		msg := fmt.Sprintf("%s access forbidden for this API key.", planLabel)
		if body := ufBJSONMap(raw); body != nil {
			if opStr(opMap(body, "error"), "type") == "EntitlementError" {
				msg = forbiddenSubMsg
			}
		}
		return db.Record{"plan": planLabel, "message": msg}, nil
	}
	if status < 200 || status >= 300 {
		return db.Record{"plan": planLabel, "message": fmt.Sprintf("%s usage API error (%d).", planLabel, status)}, nil
	}
	data := ufBJSONMap(raw)
	usage, _ := data["usage"].(map[string]any)
	if usage == nil {
		return db.Record{"plan": planLabel, "message": fmt.Sprintf("%s usage response did not contain quota data.", planLabel)}, nil
	}
	quotas := map[string]db.Record{}
	for _, period := range ufBOpenCodePeriods {
		quota, ok := usage[period.key].(map[string]any)
		if !ok {
			continue
		}
		percent := ufBParsePercent(quota["percent"])
		if percent == nil {
			continue
		}
		used := math.Max(0, math.Min(100, opFinite(*percent, 0)))
		quotas[period.name] = db.Record{
			"used":                used,
			"total":               float64(100),
			"remaining":           100 - used,
			"remainingPercentage": 100 - used,
			"resetAt":             opParseResetTime(quota["resetsAt"]),
			"unlimited":           false,
		}
	}
	if len(quotas) == 0 {
		return db.Record{"plan": planLabel, "message": fmt.Sprintf("%s usage response did not contain valid quota data.", planLabel)}, nil
	}
	return db.Record{"plan": planLabel, "quotas": quotas}, nil
}

// ---------- kimi (usage/kimi.js) ----------

var ufBKimiPlanLevels = map[string]string{
	"LEVEL_BASIC":        "Moderato",
	"LEVEL_INTERMEDIATE": "Allegretto",
	"LEVEL_ADVANCED":     "Allegro",
	"LEVEL_STANDARD":     "Vivace",
}

func ufBKimiPlanName(level any) string {
	s, ok := level.(string)
	if !ok || s == "" {
		return ""
	}
	if name, ok := ufBKimiPlanLevels[s]; ok {
		return name
	}
	return strings.ToLower(strings.TrimPrefix(s, "LEVEL_"))
}

// ufBKimiHeaders ports buildKimiHeaders (config/appConstants.js).
func ufBKimiHeaders(deviceID string) map[string]string {
	arch := runtime.GOARCH
	switch arch {
	case "amd64":
		arch = "x64"
	case "386":
		arch = "ia32"
	}
	osName := runtime.GOOS
	deviceModel := osName + " " + arch
	switch osName {
	case "darwin":
		deviceModel = "macOS " + arch
	case "windows":
		deviceModel = "Windows " + arch
	case "linux":
		deviceModel = "Linux " + arch
	}
	deviceName, err := os.Hostname()
	if err != nil || deviceName == "" {
		deviceName = "unknown"
	}
	resolved := strings.TrimSpace(deviceID)
	if resolved == "" {
		resolved = fmt.Sprintf("kimi-%d", time.Now().UnixMilli())
	}
	return map[string]string{
		"X-Msh-Platform":     "9router",
		"X-Msh-Version":      "0.5.104",
		"X-Msh-Device-Name":  deviceName,
		"X-Msh-Device-Model": deviceModel,
		"X-Msh-Device-Id":    resolved,
	}
}

var ufBKimiPermissionRe = regexp.MustCompile(`(?i)permission_denied|do not have permission|subscribe`)

// ufBFormatKimiError ports formatKimiUsageError.
func ufBFormatKimiError(status int, responseText string) string {
	parsed := ufBJSONMap([]byte(responseText))
	var detail0 map[string]any
	if arr, ok := parsed["details"].([]any); ok && len(arr) > 0 {
		detail0, _ = arr[0].(map[string]any)
	}
	var debug map[string]any
	if detail0 != nil {
		debug, _ = detail0["debug"].(map[string]any)
	}
	if debug == nil {
		debug, _ = parsed["debug"].(map[string]any)
	}
	reason := ""
	if debug != nil {
		reason, _ = debug["reason"].(string)
	}
	if reason == "" {
		reason, _ = parsed["reason"].(string)
	}
	localized := ""
	if debug != nil {
		if lm, ok := debug["localizedMessage"].(map[string]any); ok {
			localized, _ = lm["message"].(string)
		}
	}
	if localized == "" && detail0 != nil {
		if lm, ok := detail0["localizedMessage"].(map[string]any); ok {
			localized, _ = lm["message"].(string)
		}
	}
	if localized == "" {
		localized, _ = parsed["message"].(string)
	}

	if status == 401 {
		return "Kimi authentication expired. Please re-authorize."
	}
	if status == 403 {
		code, _ := parsed["code"].(string)
		haystack := code + " " + localized + " " + responseText
		if reason == "REASON_FEATURE_NO_PERMISSION" || ufBKimiPermissionRe.MatchString(haystack) {
			if localized != "" {
				return localized
			}
			return "Kimi connected, but this account has no permission to view usage. Subscribe to Kimi Code to access quota."
		}
	}
	snippet := localized
	if snippet == "" {
		snippet = responseText
	}
	if len(snippet) > 100 {
		snippet = snippet[:100]
	}
	if snippet != "" {
		return fmt.Sprintf("Kimi Coding connected. API Error %d: %s", status, snippet)
	}
	return fmt.Sprintf("Kimi Coding connected. API Error %d", status)
}

// ufBKimiQuota ports makeQuota in kimi.js.
func ufBKimiQuota(used, total float64, remaining *float64, resetAt any) db.Record {
	safeTotal := math.Max(0, opFinite(total, 0))
	safeUsed := math.Max(0, opFinite(used, 0))
	var pct float64
	if safeTotal > 0 && remaining != nil {
		pct = (math.Max(0, *remaining) / safeTotal) * 100
	} else if safeTotal > 0 {
		pct = (math.Max(0, safeTotal-safeUsed) / safeTotal) * 100
	}
	return db.Record{
		"used":                safeUsed,
		"total":               safeTotal,
		"remainingPercentage": pct,
		"resetAt":             resetAt,
		"unlimited":           false,
	}
}

func ufBKimiUsage(ctx context.Context, conn db.Record, force bool) (db.Record, error) {
	accessToken := opStr(conn, "accessToken")
	apiKey := opStr(conn, "apiKey")
	useAPIKey := apiKey != ""
	useOAuth := !useAPIKey && accessToken != ""
	if !useAPIKey && !useOAuth {
		return db.Record{"message": "Kimi access token or API key not available."}, nil
	}
	psd := opMap(conn, "providerSpecificData")
	headers := map[string]string{"Content-Type": "application/json", "Accept": "application/json"}
	if useAPIKey {
		headers["x-api-key"] = apiKey
	} else {
		headers["Authorization"] = "Bearer " + accessToken
		for k, v := range ufBKimiHeaders(opStr(psd, "deviceId")) {
			headers[k] = v
		}
	}
	status, raw, _, err := ufBDo(ctx, "GET", "https://api.kimi.com/coding/v1/usages", headers, nil)
	if err != nil {
		return db.Record{"message": "Kimi Coding connected. Unable to fetch usage: " + err.Error()}, nil
	}
	responseText := string(raw)
	if status < 200 || status >= 300 {
		return db.Record{"plan": "Kimi Coding", "message": ufBFormatKimiError(status, responseText)}, nil
	}
	data := ufBJSONMap(raw)
	if data == nil {
		return db.Record{"plan": "Kimi Coding", "message": "Kimi Coding connected. Invalid JSON response from API."}, nil
	}

	quotas := map[string]db.Record{}
	usageObj, _ := data["usage"].(map[string]any)
	usageLimit := opFinite(ufBFirstNonNil(usageObj["limit"], usageObj["Limit"]), 0)
	usageUsed := opFinite(ufBFirstNonNil(usageObj["used"], usageObj["Used"]), 0)
	var usageRemaining *float64
	if rawRem := ufBFirstNonNil(usageObj["remaining"], usageObj["Remaining"]); rawRem != nil && rawRem != "" {
		if n, ok := ufBNumRaw(rawRem); ok {
			usageRemaining = &n
		} else {
			n := math.NaN()
			usageRemaining = &n
		}
	}
	usageResetTime := ufBFirstNonNil(
		truthyOrNil(usageObj["resetTime"]), truthyOrNil(usageObj["ResetTime"]),
		truthyOrNil(usageObj["reset_at"]), truthyOrNil(usageObj["resetAt"]))
	if usageLimit > 0 {
		var rem *float64
		if usageRemaining != nil && !math.IsNaN(*usageRemaining) {
			rem = usageRemaining
		}
		quotas["Weekly"] = ufBKimiQuota(usageUsed, usageLimit, rem, opParseResetTime(usageResetTime))
	}

	if arr, ok := data["limits"].([]any); ok {
		for _, item := range arr {
			it, ok := item.(map[string]any)
			if !ok {
				continue
			}
			detail, _ := it["detail"].(map[string]any)
			if detail == nil {
				continue
			}
			limit := opFinite(ufBFirstNonNil(detail["limit"], detail["Limit"]), 0)
			remaining, remOK := ufBNumRaw(ufBFirstNonNil(detail["remaining"], detail["Remaining"]))
			resetTime := ufBFirstNonNil(
				truthyOrNil(detail["resetTime"]), truthyOrNil(detail["reset_at"]), truthyOrNil(detail["resetAt"]))
			if limit > 0 {
				rem := math.Max(0, limit)
				if remOK {
					rem = remaining
				}
				remVal := rem
				quotas["Ratelimit"] = ufBKimiQuota(math.Max(0, limit-rem), limit, &remVal, opParseResetTime(resetTime))
			}
		}
	}

	membership := opMap(opMap(data, "user"), "membership")
	planName := ufBKimiPlanName(membership["level"])
	if planName == "" {
		planName = "Kimi Coding"
	}
	if len(quotas) > 0 {
		return db.Record{"plan": planName, "quotas": quotas}, nil
	}
	return db.Record{"plan": planName, "message": "Kimi Coding connected. Usage tracked per request."}, nil
}

// truthyOrNil returns v when JS-truthy, else nil (for `a || b` chains).
func truthyOrNil(v any) any {
	if ufBTruthy(v) {
		return v
	}
	return nil
}

// ---------- grok-cli (usage/grok-cli.js + grokCliQuotaFrame.js) ----------

const (
	ufBGrokCliVersion     = "1.0.44"
	ufBGrokCliUserAgent   = "grok-shell/1.0.44 (linux; x86_64)"
	ufBGrokCliClientID    = "grok-shell"
	ufBGrokGrpcCreditsURL = "https://grok.com/grok_api_v2.GrokBuildBilling/GetGrokCreditsConfig"
)

// ufBGrokUnwrap ports unwrapVal: {val:n} unwrap + toFiniteNumber.
// Returns (value, finite).
func ufBGrokUnwrap(v any) (float64, bool) {
	if m, ok := v.(map[string]any); ok {
		if inner, has := m["val"]; has {
			return ufBNumRaw(inner)
		}
	}
	return ufBNumRaw(v)
}

func ufBGrokFirstUnwrap(vals ...any) (float64, bool) {
	for _, v := range vals {
		if v == nil {
			continue
		}
		return ufBGrokUnwrap(v)
	}
	return 0, false
}

// ufBGrokMakeQuota ports makeQuota in grok-cli.js.
func ufBGrokMakeQuota(used, total float64, resetAt any, unlimited bool) db.Record {
	safeTotal := math.Max(0, opFinite(total, 0))
	safeUsed := math.Max(0, opFinite(used, 0))
	if unlimited || safeTotal == 0 {
		pct := float64(0)
		if unlimited {
			pct = 100
		}
		return db.Record{
			"used": safeUsed, "total": float64(0), "remainingPercentage": pct,
			"resetAt": resetAt, "unlimited": true,
		}
	}
	remaining := math.Max(0, safeTotal-safeUsed)
	return db.Record{
		"used": safeUsed, "total": safeTotal,
		"remainingPercentage": (remaining / safeTotal) * 100,
		"resetAt":             resetAt, "unlimited": false,
	}
}

func ufBGrokSubscriptionTier(user, config map[string]any) string {
	sub, _ := user["subscription"].(map[string]any)
	raw := ufBFirstNonNil(user["subscriptionTier"], user["subscription_tier"],
		sub["tier"], config["subscriptionTier"], config["subscription_tier"])
	if s, ok := raw.(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

var ufBGrokTierSepRe = regexp.MustCompile(`[_-]+`)

func ufBGrokResolvePlan(user, config map[string]any) string {
	tier := ufBGrokSubscriptionTier(user, config)
	if tier != "" {
		s := ufBGrokTierSepRe.ReplaceAllString(tier, " ")
		return ufBTitleWords(s)
	}
	if user["hasGrokCodeAccess"] == true {
		return "Grok Code"
	}
	return "Grok Build"
}

var ufBGrokPlanByTier = map[float64]string{
	0: "Free", 1: "SuperGrok", 2: "X Basic", 3: "X Premium",
	4: "X Premium Plus", 5: "SuperGrok Heavy", 6: "SuperGrok Lite",
}

// ufBGrokPlanFromToken ports planFromAccessToken (display only).
func ufBGrokPlanFromToken(accessToken string) string {
	parts := strings.Split(accessToken, ".")
	if len(parts) < 2 {
		return ""
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// base64url with padding tolerated by JS Buffer; retry padded.
		padded := parts[1]
		for len(padded)%4 != 0 {
			padded += "="
		}
		decoded, err = base64.URLEncoding.DecodeString(padded)
		if err != nil {
			return ""
		}
	}
	payload := ufBJSONMap(decoded)
	if payload == nil {
		return ""
	}
	if tier, ok := ufBNumRaw(payload["tier"]); ok {
		if name, ok := ufBGrokPlanByTier[tier]; ok {
			return name
		}
	}
	return ""
}

type ufBGrokParsed struct {
	plan               string
	quotas             map[string]db.Record
	subscriptionAccess bool
}

// ufBGrokParseBilling ports parseGrokCliBilling.
func ufBGrokParseBilling(billing, user map[string]any) ufBGrokParsed {
	root := billing
	if root == nil {
		root = db.Record{}
	}
	config := root
	if c, ok := root["config"].(map[string]any); ok {
		config = c
	}
	currentPeriod, _ := config["currentPeriod"].(map[string]any)
	periodEnd := ufBFirstNonNil(
		opParseResetTime(config["billingPeriodEnd"]),
		opParseResetTime(config["billing_period_end"]),
		opParseResetTime(currentPeriod["end"]),
		opParseResetTime(ufBFirstNonNil(truthyOrNil(config["resetAt"]), truthyOrNil(config["resetsAt"]), truthyOrNil(config["periodEnd"]))),
		opParseResetTime(root["billingPeriodEnd"]),
		opParseResetTime(root["billing_period_end"]),
		opParseResetTime(ufBFirstNonNil(truthyOrNil(root["resetAt"]), truthyOrNil(root["resetsAt"]), truthyOrNil(root["periodEnd"]))),
	)

	quotas := map[string]db.Record{}
	tier := ufBGrokSubscriptionTier(user, config)
	subscriptionAccess := tier != "" && !regexp.MustCompile(`(?i)^(free|none|null)$`).MatchString(tier)

	monthlyLimit, mlOK := ufBGrokFirstUnwrap(
		ufBFirstNonNil(config["monthlyLimit"], config["monthly_limit"], root["monthlyLimit"], root["monthly_limit"]))
	includedUsed, iuOK := ufBGrokFirstUnwrap(
		ufBFirstNonNil(config["includedUsed"], config["included_used"], root["includedUsed"], root["included_used"]))
	totalUsed, tuOK := ufBGrokFirstUnwrap(
		ufBFirstNonNil(config["totalUsed"], config["total_used"], root["totalUsed"], root["total_used"]))
	if mlOK && monthlyLimit > 0 {
		used := float64(0)
		if iuOK {
			used = includedUsed
		} else if tuOK {
			used = totalUsed
		}
		quotas["Monthly included"] = ufBGrokMakeQuota(used, monthlyLimit, periodEnd, false)
	}

	onDemandCap, capOK := ufBGrokFirstUnwrap(ufBFirstNonNil(config["onDemandCap"], root["onDemandCap"]))
	onDemandUsed, usedOK := ufBGrokFirstUnwrap(ufBFirstNonNil(config["onDemandUsed"], root["onDemandUsed"]))
	if capOK && onDemandCap > 0 {
		used := float64(0)
		if usedOK {
			used = math.Max(0, onDemandUsed)
		}
		quotas["On-demand"] = ufBGrokMakeQuota(used, onDemandCap, periodEnd, false)
	} else if !subscriptionAccess && capOK && onDemandCap == 0 && usedOK {
		quotas["On-demand"] = db.Record{
			"used": float64(1), "total": float64(1), "remainingPercentage": float64(0),
			"resetAt": periodEnd, "unlimited": false,
		}
	}

	prepaid, prepaidOK := ufBGrokFirstUnwrap(ufBFirstNonNil(config["prepaidBalance"], root["prepaidBalance"]))
	if prepaidOK && prepaid > 0 {
		quotas["Prepaid"] = db.Record{
			"used": float64(0), "total": prepaid, "remainingPercentage": float64(100),
			"resetAt": nil, "unlimited": false,
		}
	}

	usedPct, pctOK := ufBGrokFirstUnwrap(
		ufBFirstNonNil(config["creditUsagePercent"], config["credit_usage_percent"], root["creditUsagePercent"]))
	if pctOK && usedPct >= 0 {
		quotas["Weekly SuperGrok"] = ufBGrokMakeQuota(math.Max(0, math.Min(100, usedPct)), 100, periodEnd, false)
	}

	creditBags := []map[string]any{}
	for _, bag := range []any{root["credits"], root["creditBalance"], root["usage"],
		config["credits"], config["includedCredits"], config["subscriptionCredits"]} {
		if b, ok := bag.(map[string]any); ok {
			creditBags = append(creditBags, b)
		}
	}
	for _, bag := range creditBags {
		total, totalOK := ufBGrokFirstUnwrap(ufBFirstNonNil(bag["total"], bag["limit"], bag["cap"], bag["allocation"], bag["amount"]))
		used, usedOK2 := ufBGrokFirstUnwrap(ufBFirstNonNil(bag["used"], bag["spent"], bag["consumed"]))
		remaining, remOK := ufBGrokFirstUnwrap(ufBFirstNonNil(bag["remaining"], bag["balance"], bag["left"]))
		if totalOK && total > 0 {
			resolvedUsed := float64(0)
			if usedOK2 {
				resolvedUsed = used
			} else if remOK {
				resolvedUsed = math.Max(0, total-remaining)
			}
			if _, exists := quotas["Credits"]; !exists {
				reset := opParseResetTime(ufBFirstNonNil(truthyOrNil(bag["resetAt"]), truthyOrNil(bag["resetsAt"]), truthyOrNil(bag["end"])))
				if reset == nil {
					reset = periodEnd
				}
				quotas["Credits"] = ufBGrokMakeQuota(resolvedUsed, total, reset, false)
			}
		} else if remOK && remaining >= 0 {
			if _, exists := quotas["Credits"]; !exists {
				totalVal := remaining
				pct := float64(0)
				if remaining > 0 {
					totalVal = remaining
					pct = 100
				} else {
					totalVal = 1
				}
				quotas["Credits"] = db.Record{
					"used": float64(0), "total": totalVal, "remainingPercentage": pct,
					"resetAt": periodEnd, "unlimited": false,
				}
			}
		}
	}

	return ufBGrokParsed{
		plan:               ufBGrokResolvePlan(user, config),
		quotas:             quotas,
		subscriptionAccess: subscriptionAccess,
	}
}

// --- gRPC-web frame decoding (grokCliQuotaFrame.js) ---

type ufBGrokField struct {
	wireType int
	numVal   uint64
	bytes    []byte
}

func ufBGrokReadVarint(buf []byte, offset int) (uint64, int, bool) {
	var result uint64
	var shift uint
	pos := offset
	for {
		if pos >= len(buf) {
			return 0, 0, false
		}
		b := buf[pos]
		result |= uint64(b&0x7f) << shift
		pos++
		if b&0x80 == 0 {
			break
		}
		shift += 7
		if shift > 70 {
			return 0, 0, false
		}
	}
	return result, pos, true
}

func ufBGrokDecodeFields(buf []byte) (map[uint64]ufBGrokField, bool) {
	fields := map[uint64]ufBGrokField{}
	offset := 0
	for offset < len(buf) {
		tag, next, ok := ufBGrokReadVarint(buf, offset)
		if !ok {
			return nil, false
		}
		fieldNumber := tag >> 3
		wireType := int(tag & 0x7)
		if fieldNumber == 0 {
			return nil, false
		}
		offset = next
		switch wireType {
		case 0: // varint
			v, n, ok := ufBGrokReadVarint(buf, offset)
			if !ok {
				return nil, false
			}
			fields[fieldNumber] = ufBGrokField{wireType: 0, numVal: v}
			offset = n
		case 2: // length-delimited
			length, n, ok := ufBGrokReadVarint(buf, offset)
			if !ok || int(length) < 0 || n+int(length) > len(buf) {
				return nil, false
			}
			fields[fieldNumber] = ufBGrokField{wireType: 2, bytes: buf[n : n+int(length)]}
			offset = n + int(length)
		case 1: // fixed64
			if offset+8 > len(buf) {
				return nil, false
			}
			fields[fieldNumber] = ufBGrokField{wireType: 1, bytes: buf[offset : offset+8]}
			offset += 8
		case 5: // fixed32
			if offset+4 > len(buf) {
				return nil, false
			}
			fields[fieldNumber] = ufBGrokField{wireType: 5, bytes: buf[offset : offset+4]}
			offset += 4
		default:
			return nil, false
		}
	}
	return fields, true
}

func ufBGrokProbeFrame(buf []byte, offset int) (flag byte, payloadStart, payloadLength int, ok bool) {
	if offset < 0 || len(buf)-offset < 5 {
		return 0, 0, 0, false
	}
	flag = buf[offset]
	if flag != 0x00 && flag != 0x01 && flag != 0x80 && flag != 0x81 {
		return 0, 0, 0, false
	}
	payloadStart = offset + 5
	payloadLength = int(binary.BigEndian.Uint32(buf[offset+1 : offset+5]))
	if payloadLength > len(buf)-payloadStart {
		return 0, 0, 0, false
	}
	return flag, payloadStart, payloadLength, true
}

// ufBGrokDecodeCreditsFrame ports decodeGrokCreditsFrame (fail-open).
func ufBGrokDecodeCreditsFrame(buf []byte) (percentUsed float64, resetAt any, ok bool) {
	if len(buf) == 0 {
		return 0, nil, false
	}
	payload := buf
	if _, _, _, framed := ufBGrokProbeFrame(buf, 0); framed {
		found := false
		offset := 0
		for offset < len(buf) {
			flag, start, length, okF := ufBGrokProbeFrame(buf, offset)
			if !okF {
				return 0, nil, false
			}
			if flag&0x80 == 0 {
				payload = buf[start : start+length]
				found = true
				break
			}
			offset = start + length
		}
		if !found {
			return 0, nil, false
		}
	}
	top, okD := ufBGrokDecodeFields(payload)
	if !okD {
		return 0, nil, false
	}
	creditsField, has := top[1]
	if !has || creditsField.wireType != 2 {
		return 0, nil, false
	}
	credits, okD := ufBGrokDecodeFields(creditsField.bytes)
	if !okD {
		return 0, nil, false
	}
	ratio := float64(0)
	if f, has := credits[1]; has {
		switch f.wireType {
		case 5:
			ratio = float64(math.Float32frombits(binary.LittleEndian.Uint32(f.bytes)))
		case 1:
			ratio = math.Float64frombits(binary.LittleEndian.Uint64(f.bytes))
		default:
			return 0, nil, false
		}
	}
	if math.IsNaN(ratio) || math.IsInf(ratio, 0) || ratio < 0 {
		return 0, nil, false
	}
	percentUsed = math.Min(100, ratio*100)
	if f, has := credits[5]; has && f.wireType == 2 {
		if tsFields, okT := ufBGrokDecodeFields(f.bytes); okT {
			var seconds, nanos uint64
			if sf, has := tsFields[1]; has && sf.wireType == 0 {
				seconds = sf.numVal
			}
			if nf, has := tsFields[2]; has && nf.wireType == 0 {
				nanos = nf.numVal
			}
			millis := int64(seconds)*1000 + int64(math.Round(float64(nanos)/1e6))
			resetAt = time.UnixMilli(millis).UTC().Format("2006-01-02T15:04:05.000Z")
		}
	}
	return percentUsed, resetAt, true
}

// ufBGrokFetchCredits ports fetchGrokCliCreditsConfig (fail-open).
func ufBGrokFetchCredits(ctx context.Context, accessToken string) (float64, any, bool) {
	status, raw, _, err := ufBDo(ctx, "POST", ufBGrokGrpcCreditsURL, map[string]string{
		"Authorization": "Bearer " + accessToken,
		"Content-Type":  "application/grpc-web+proto",
		"X-Grpc-Web":    "1",
		"Accept":        "application/grpc-web+proto",
	}, []byte{0, 0, 0, 0, 0})
	if err != nil || status < 200 || status >= 300 {
		return 0, nil, false
	}
	return ufBGrokDecodeCreditsFrame(raw)
}

func ufBGrokUsage(ctx context.Context, conn db.Record, force bool) (db.Record, error) {
	accessToken := opStr(conn, "accessToken")
	if accessToken == "" {
		return db.Record{"message": "Grok CLI access token not available."}, nil
	}
	psd := opMap(conn, "providerSpecificData")
	headers := map[string]string{
		"Authorization":            "Bearer " + accessToken,
		"Accept":                   "application/json",
		"User-Agent":               ufBGrokCliUserAgent,
		"x-xai-token-auth":         "xai-grok-cli",
		"x-grok-client-identifier": ufBGrokCliClientID,
		"x-grok-client-version":    ufBGrokCliVersion,
		"x-grok-client-mode":       "headless",
	}
	if email := opStr(psd, "email"); email != "" {
		headers["x-email"] = email
	}
	userID := opStr(psd, "userId")
	if userID == "" {
		userID = opStr(psd, "principalId")
	}
	if userID != "" {
		headers["x-userid"] = userID
	}

	usage := opProviderUsage("grok-cli")
	billingURL := opStr(usage, "url")
	if billingURL == "" {
		billingURL = "https://cli-chat-proxy.grok.com/v1/billing?format=credits"
	}
	userURL := opStr(usage, "userUrl")
	if userURL == "" {
		userURL = "https://cli-chat-proxy.grok.com/v1/user?include=subscription"
	}

	type userResult struct{ user map[string]any }
	userCh := make(chan userResult, 1)
	go func() {
		st, raw, _, err := ufBDo(ctx, "GET", userURL, headers, nil)
		if err != nil || st < 200 || st >= 300 {
			userCh <- userResult{nil}
			return
		}
		userCh <- userResult{ufBJSONMap(raw)}
	}()

	status, raw, _, err := ufBDo(ctx, "GET", billingURL, headers, nil)
	if err != nil {
		return db.Record{"message": "Grok CLI usage error: " + err.Error()}, nil
	}
	if status == 401 || status == 403 {
		return db.Record{"message": "Grok CLI authentication expired. Please re-authorize."}, nil
	}
	if status < 200 || status >= 300 {
		trimmed := ""
		if len(raw) > 0 {
			text := string(raw)
			if len(text) > 200 {
				text = text[:200]
			}
			trimmed = ": " + text
		}
		return db.Record{"message": fmt.Sprintf("Grok CLI billing API error (%d)%s", status, trimmed)}, nil
	}
	billing := ufBJSONMap(raw)
	if billing == nil {
		return db.Record{"message": "Grok CLI billing response was not JSON."}, nil
	}
	user := (<-userCh).user

	parsed := ufBGrokParseBilling(billing, user)
	if plan := ufBGrokPlanFromToken(accessToken); plan != "" {
		parsed.plan = plan
	}

	if len(parsed.quotas) == 0 {
		if pct, resetAt, ok := ufBGrokFetchCredits(ctx, accessToken); ok {
			used := math.Round(math.Max(0, math.Min(100, pct)))
			return db.Record{
				"plan": parsed.plan,
				"quotas": map[string]db.Record{
					"Weekly SuperGrok": ufBGrokMakeQuota(used, 100, resetAt, false),
				},
			}, nil
		}
		msg := "Grok Build connected, but no credit allotment was returned. Free promo may be exhausted."
		if parsed.subscriptionAccess {
			msg = "Subscription access is active; Grok does not expose a numeric included quota."
		}
		return db.Record{"plan": parsed.plan, "message": msg, "quotas": map[string]db.Record{}}, nil
	}
	return db.Record{"plan": parsed.plan, "quotas": parsed.quotas}, nil
}

// ---------- zed (usage/zed.js + shared/zedAuth.js fetchZedAuthenticatedUser) ----------

func ufBZedPlanLabel(rawPlan string) string {
	raw := strings.TrimSpace(rawPlan)
	if raw == "" {
		return "Zed"
	}
	switch strings.ToLower(raw) {
	case "zed_free":
		return "Zed Free"
	case "zed_pro":
		return "Zed Pro"
	case "zed_pro_trial":
		return "Zed Pro Trial"
	case "zed_student":
		return "Zed Student"
	case "zed_business":
		return "Zed Business"
	}
	words := strings.Fields(strings.ReplaceAll(raw, "_", " "))
	for i, w := range words {
		words[i] = strings.ToUpper(w[:1]) + strings.ToLower(w[1:])
	}
	return strings.Join(words, " ")
}

// ufBZedParseLimit ports parseZedUsageLimit → (unlimited, total).
func ufBZedParseLimit(limit any) (bool, float64) {
	if limit == nil {
		return false, 0
	}
	if limit == "unlimited" {
		return true, 0
	}
	if m, ok := limit.(map[string]any); ok && m["unlimited"] == true {
		return true, 0
	}
	if n, ok := ufBNumRaw(limit); ok {
		if _, isStr := limit.(string); !isStr {
			return false, math.Max(0, n)
		}
	}
	if s, ok := limit.(string); ok {
		trimmed := strings.TrimSpace(s)
		if trimmed == "unlimited" {
			return true, 0
		}
		if n, err := strconv.ParseFloat(trimmed, 64); err == nil && !math.IsNaN(n) && !math.IsInf(n, 0) {
			return false, math.Max(0, n)
		}
		return false, 0
	}
	if m, ok := limit.(map[string]any); ok {
		limited := ufBFirstNonNil(m["limited"], m["Limited"])
		if n, isNum := ufBNumRaw(limited); isNum {
			if _, isStr := limited.(string); !isStr {
				return false, math.Max(0, n)
			}
		}
	}
	return false, 0
}

func ufBZedQuotaRow(usedRaw, limitRaw, resetAt any) db.Record {
	used := math.Max(0, opFinite(usedRaw, 0))
	unlimited, total := ufBZedParseLimit(limitRaw)
	if unlimited {
		return db.Record{
			"used": used, "total": float64(0), "remainingPercentage": float64(100),
			"resetAt": resetAt, "unlimited": true,
		}
	}
	if total <= 0 {
		return db.Record{
			"used": used, "total": float64(0), "remainingPercentage": float64(0),
			"resetAt": resetAt, "unlimited": false,
		}
	}
	clampedUsed := math.Min(used, total)
	remaining := math.Max(0, total-clampedUsed)
	return db.Record{
		"used": clampedUsed, "total": total,
		"remainingPercentage": (remaining / total) * 100,
		"resetAt":             resetAt, "unlimited": false,
	}
}

// ufBZedParseUser ports parseZedAuthenticatedUserUsage.
func ufBZedParseUser(userInfo map[string]any) db.Record {
	planMap, _ := userInfo["plan"].(map[string]any)
	planID := ufBFirstNonNil(
		truthyOrNil(planMap["plan_v3"]), truthyOrNil(planMap["plan_v2"]),
		truthyOrNil(planMap["plan"]), truthyOrNil(userInfo["plan_v3"]))
	subPeriod, _ := planMap["subscription_period"].(map[string]any)
	subPeriodCamel, _ := planMap["subscriptionPeriod"].(map[string]any)
	resetAt := opParseResetTime(subPeriod["ended_at"])
	if resetAt == nil {
		resetAt = opParseResetTime(subPeriodCamel["endedAt"])
	}

	quotas := map[string]db.Record{}
	usage, _ := planMap["usage"].(map[string]any)
	editPredictions := ufBFirstNonNil(usage["edit_predictions"], usage["editPredictions"])
	if editPredictions != nil {
		ep, _ := editPredictions.(map[string]any)
		quotas["Edit Predictions"] = ufBZedQuotaRow(ep["used"], ep["limit"], resetAt)
	}
	modelRequests := ufBFirstNonNil(usage["model_requests"], usage["modelRequests"])
	var tokenBillingNote any
	if modelRequests != nil {
		mr, _ := modelRequests.(map[string]any)
		limitRaw := mr["limit"]
		unlimited, total := ufBZedParseLimit(limitRaw)
		if unlimited || total > 0 {
			quotas["Hosted Model Requests"] = ufBZedQuotaRow(mr["used"], limitRaw, resetAt)
		}
		if !unlimited && total == 0 {
			tokenBillingNote = "Hosted AI models are billed per token (not request count). Edit Predictions are tracked below. Token spend is on dashboard.zed.dev."
		}
	}

	planLabel := "Zed"
	if s, ok := planID.(string); ok {
		planLabel = ufBZedPlanLabel(s)
	} else if planID != nil {
		planLabel = ufBZedPlanLabel(fmt.Sprintf("%v", planID))
	}
	trialStarted := ufBTruthy(planMap["trial_started_at"]) || ufBTruthy(planMap["trialStartedAt"])
	if trialStarted && !strings.Contains(strings.ToLower(planLabel), "trial") {
		planLabel += " (Trial active)"
	}
	var message any = tokenBillingNote
	hasOverdue := ufBTruthy(planMap["has_overdue_invoices"]) || ufBTruthy(planMap["hasOverdueInvoices"])
	if hasOverdue {
		message = "This Zed account has overdue invoices. Usage may be blocked until billing is resolved."
	}
	return db.Record{
		"plan":               planLabel,
		"quotas":             quotas,
		"message":            message,
		"hasOverdueInvoices": hasOverdue,
		"trialStarted":       trialStarted,
		"planId":             planID,
		"resetAt":            resetAt,
	}
}

func ufBZedUsage(ctx context.Context, conn db.Record, force bool) (db.Record, error) {
	accessToken := opStr(conn, "accessToken")
	psd := opMap(conn, "providerSpecificData")
	if strings.TrimSpace(accessToken) == "" {
		return db.Record{"message": "Zed access token not available. Re-connect Zed to view quota."}, nil
	}
	userID := opStr(psd, "userId")
	if userID == "" {
		return db.Record{"message": "Zed credential is missing user id. Re-connect Zed to view quota."}, nil
	}
	headers := map[string]string{
		"Accept":        "application/json",
		"Authorization": userID + " " + strings.TrimSpace(accessToken),
	}
	if systemID := opStr(psd, "systemId"); systemID != "" {
		headers["x-zed-system-id"] = systemID
	}
	status, raw, _, err := ufBDo(ctx, "GET", "https://cloud.zed.dev/client/users/me", headers, nil)
	if err != nil {
		return db.Record{"message": "Zed error: " + err.Error()}, nil
	}
	if status < 200 || status >= 300 {
		if status == 401 || status == 403 {
			return db.Record{"message": "Zed authentication failed. Sign in again from the dashboard or Zed editor."}, nil
		}
		// fetchJson error message: data.message || data.error.message ||
		// data.error || raw text || HTTP <status>.
		msg := ""
		if body := ufBJSONMap(raw); body != nil {
			msg, _ = body["message"].(string)
			if msg == "" {
				if em, ok := body["error"].(map[string]any); ok {
					msg, _ = em["message"].(string)
				}
			}
			if msg == "" {
				msg, _ = body["error"].(string)
			}
		}
		if msg == "" && len(raw) > 0 {
			msg = string(raw)
		}
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", status)
		}
		return db.Record{"message": "Zed error: " + msg}, nil
	}
	userInfo := ufBJSONMap(raw)
	if userInfo == nil {
		return db.Record{"message": "Zed error: Failed to fetch quota"}, nil
	}
	return ufBZedParseUser(userInfo), nil
}

// ---------- xiaomi-mimo (usage/xiaomi-mimo.js + shared/mimoAccount.js) ----------

const (
	ufBMimoAccountHost = "account.xiaomi.com"
	ufBMimoAPIUA       = "miNative PC/Normal Windows_NT/10.0.19045 SDKV/1.0.0 DEVT/PC DEVS/Windows APP/miaccount_desktop APPV/0.1.0"
	ufBMimoSSOUA       = "MiClaw/1.0"
	ufBMimoFallbackURL = "https://aistudio.xiaomimimo.com/open-apis/v1/user/usage"
)

var ufBMimoAPIBaseByRegion = map[string]string{
	"cn":  "https://mimo-server-cn.xiaomimimo.com",
	"sgp": "https://mimo-server-sgp.xiaomimimo.com",
	"ams": "https://mimo-server-ams.xiaomimimo.com",
	"ru":  "https://mimo-server-ru.xiaomimimo.com",
	"in":  "https://mimo-server-in.xiaomimimo.com",
}

var ufBMimoSIDByRegion = map[string]string{
	"cn": "mimopc", "sgp": "mimosgp", "ams": "mimoams", "ru": "mimoru", "in": "mimoin",
}

func ufBMimoServerBase(psd map[string]any) string {
	region := strings.ToLower(opStr(psd, "region"))
	if base, ok := ufBMimoAPIBaseByRegion[region]; ok {
		return base
	}
	return ufBMimoAPIBaseByRegion["sgp"]
}

func ufBMimoSID(psd map[string]any) string {
	region := strings.ToLower(opStr(psd, "region"))
	if sid, ok := ufBMimoSIDByRegion[region]; ok {
		return sid
	}
	return ufBMimoSIDByRegion["sgp"]
}

var (
	ufBMimoCookieMu    sync.Mutex
	ufBMimoCookieCache = map[string]struct {
		cookie string
		at     time.Time
	}{}
	ufBMimoNonceRe = regexp.MustCompile(`"nonce"\s*:\s*(\d+)`)
)

// ufBMimoAbsorbCookies ports absorbSetCookie + cookieHeader.
func ufBMimoAbsorbCookies(jar map[string]string, header http.Header) {
	for _, c := range header.Values("Set-Cookie") {
		part := strings.TrimSpace(strings.SplitN(c, ";", 2)[0])
		idx := strings.Index(part, "=")
		if idx <= 0 {
			continue
		}
		name, value := part[:idx], part[idx+1:]
		if value != "" {
			jar[name] = value
		}
	}
}

func ufBMimoCookieHeader(jar map[string]string) string {
	keys := make([]string, 0, len(jar))
	for k, v := range jar {
		if v != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+jar[k])
	}
	return strings.Join(parts, "; ")
}

// ufBMimoServiceCookie ports getServiceCookie/acquireServiceCookie for
// the psd-carried passToken path (mimoPassToken in providerSpecificData).
// The JS fallback source — MiMo Desktop's on-disk cookie DB — is not
// readable from the Go binary (same boundary Team G documented for the
// desktop passToken), so without a psd passToken there is no session.
func ufBMimoServiceCookie(ctx context.Context, psd map[string]any) (string, bool) {
	passToken := opStr(psd, "mimoPassToken")
	if passToken == "" {
		return "", false
	}
	apiBase := ufBMimoServerBase(psd)
	sid := ufBMimoSID(psd)
	keySum := sha256.Sum256([]byte(apiBase + "|" + passToken))
	cacheKey := hex.EncodeToString(keySum[:])

	ufBMimoCookieMu.Lock()
	if cached, ok := ufBMimoCookieCache[cacheKey]; ok && time.Since(cached.at) < 30*time.Minute {
		cookie := cached.cookie
		ufBMimoCookieMu.Unlock()
		return cookie, true
	}
	ufBMimoCookieMu.Unlock()

	jar := map[string]string{}
	if v := opStr(psd, "mimoUserId"); v != "" {
		jar["userId"] = v
	}
	jar["passToken"] = passToken
	if v := opStr(psd, "mimoCUserId"); v != "" {
		jar["cUserId"] = v
	}

	// PHASE 1 — serviceLogin with the target sid.
	p1Jar := map[string]string{}
	for _, k := range []string{"userId", "passToken", "cUserId"} {
		if jar[k] != "" {
			p1Jar[k] = jar[k]
		}
	}
	p1URL := fmt.Sprintf("https://%s/pass/serviceLogin?_locale=zh_CN&_snsNone=true&sid=%s&_json=true",
		ufBMimoAccountHost, url.QueryEscape(sid))
	_, raw, p1Header, err := ufBDo(ctx, "GET", p1URL, map[string]string{
		"Cookie":     ufBMimoCookieHeader(p1Jar),
		"User-Agent": ufBMimoSSOUA,
		"Accept":     "application/json",
	}, nil)
	if err != nil {
		return "", false
	}
	clean := strings.TrimPrefix(string(raw), "&&&START&&&")
	j := ufBJSONMap([]byte(clean))
	rawNonce := ""
	if m := ufBMimoNonceRe.FindStringSubmatch(clean); m != nil {
		rawNonce = m[1]
	}
	code, codeOK := ufBNumRaw(j["code"])
	location, _ := j["location"].(string)
	ssecurity, _ := j["ssecurity"].(string)
	if j == nil || !codeOK || code != 0 || location == "" || rawNonce == "" || ssecurity == "" {
		return "", false
	}
	ufBMimoAbsorbCookies(jar, p1Header)

	// PHASE 2 — clientSign redirect chain; NO Cookie header is sent.
	signInput := "nonce=" + rawNonce
	if strings.TrimSpace(ssecurity) != "" {
		signInput += "&" + ssecurity
	}
	signSum := sha1.Sum([]byte(signInput))
	clientSign := url.QueryEscape(base64.StdEncoding.EncodeToString(signSum[:]))
	sep := "&"
	if !strings.Contains(location, "?") {
		sep = "?"
	}
	current := location + sep + "clientSign=" + clientSign
	manualClient := &http.Client{
		Transport: opHTTPClient.Transport,
		Timeout:   opHTTPClient.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for hop := 0; hop < 8; hop++ {
		status, _, respHeader, herr := ufBDoClient(ctx, manualClient, "GET", current, map[string]string{
			"User-Agent": ufBMimoSSOUA,
		}, nil)
		if herr != nil {
			return "", false
		}
		ufBMimoAbsorbCookies(jar, respHeader)
		loc := respHeader.Get("Location")
		if status >= 300 && status < 400 && loc != "" {
			base, berr := url.Parse(current)
			if berr != nil {
				return "", false
			}
			ref, rerr := url.Parse(loc)
			if rerr != nil {
				return "", false
			}
			current = base.ResolveReference(ref).String()
			continue
		}
		break
	}
	if jar["serviceToken"] == "" && jar[sid+"_serviceToken"] != "" {
		jar["serviceToken"] = jar[sid+"_serviceToken"]
	}
	if jar["serviceToken"] == "" {
		return "", false
	}
	out := map[string]string{}
	for k, v := range jar {
		if v == "" {
			continue
		}
		if k == "serviceToken" || k == "userId" || strings.HasSuffix(k, "_ph") || strings.HasSuffix(k, "_slh") {
			out[k] = v
		}
	}
	cookie := ufBMimoCookieHeader(out)
	ufBMimoCookieMu.Lock()
	ufBMimoCookieCache[cacheKey] = struct {
		cookie string
		at     time.Time
	}{cookie, time.Now()}
	ufBMimoCookieMu.Unlock()
	return cookie, true
}

// ufBMimoAccountUsage ports getMimoAccountUsage.
func ufBMimoAccountUsage(ctx context.Context, psd map[string]any) (map[string]any, bool) {
	cookie, ok := ufBMimoServiceCookie(ctx, psd)
	if !ok {
		return nil, false
	}
	status, raw, _, err := ufBDo(ctx, "GET", ufBMimoServerBase(psd)+"/api/user/usage", map[string]string{
		"User-Agent": ufBMimoAPIUA,
		"Cookie":     cookie,
		"Accept":     "application/json",
	}, nil)
	if err != nil || status < 200 || status >= 300 {
		return nil, false
	}
	data := ufBJSONMap(raw)
	if data == nil || opFinite(data["code"], -1) != 0 {
		return nil, false
	}
	inner, _ := data["data"].(map[string]any)
	if inner == nil {
		return nil, false
	}
	return inner, true
}

func ufBMimoWeeklyQuota(percent float64, resetAt any) db.Record {
	remaining := math.Max(0, math.Min(100, math.Round(percent)))
	return db.Record{
		"plan": "Xiaomi MiMo Desktop",
		"quotas": map[string]db.Record{
			"Weekly": {
				"used": 100 - remaining, "total": float64(100),
				"remainingPercentage": remaining, "resetAt": resetAt, "unlimited": false,
			},
		},
	}
}

func ufBMimoResetDateISO(resetDate string) any {
	if resetDate == "" {
		return nil
	}
	t, err := time.Parse("2006-01-02", resetDate)
	if err != nil {
		return nil
	}
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

func ufBMimoUsage(ctx context.Context, conn db.Record, force bool) (db.Record, error) {
	accessToken := opStr(conn, "accessToken")
	psd := opMap(conn, "providerSpecificData")

	// Primary path: account-session weekly quota.
	if inner, ok := ufBMimoAccountUsage(ctx, psd); ok {
		if pct, isNum := ufBNumRaw(inner["percent"]); isNum {
			var resetAt any
			if ra, isNum := ufBNumRaw(inner["resetAt"]); isNum && ra > 0 {
				resetAt = time.UnixMilli(int64(ra * 1000)).UTC().Format("2006-01-02T15:04:05.000Z")
			} else if rd, isStr := inner["resetDate"].(string); isStr {
				resetAt = ufBMimoResetDateISO(rd)
			}
			return ufBMimoWeeklyQuota(pct, resetAt), nil
		}
	}

	// Fallback: sk- API key against the open-apis usage endpoint.
	key := accessToken
	if key == "" {
		key = opStr(psd, "apiKey")
	}
	if strings.TrimSpace(key) == "" {
		return db.Record{"message": "Xiaomi MiMo Desktop not connected. Add credentials to view usage."}, nil
	}
	tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	status, raw, _, err := ufBDo(tctx, "GET", ufBMimoFallbackURL, map[string]string{
		"Authorization": "Bearer " + strings.TrimSpace(key),
		"X-Mimo-Source": "mimocode-cli",
		"Accept":        "application/json",
	}, nil)
	if err != nil {
		return db.Record{"message": "Xiaomi MiMo Desktop usage error: " + err.Error()}, nil
	}
	if status == 401 {
		return db.Record{
			"plan":    "Xiaomi MiMo Desktop",
			"message": "Weekly quota requires Xiaomi account session. API key alone is insufficient.",
		}, nil
	}
	if status < 200 || status >= 300 {
		return db.Record{
			"plan":    "Xiaomi MiMo Desktop",
			"message": fmt.Sprintf("Usage API error (%d)", status),
		}, nil
	}
	data := ufBJSONMap(raw)
	inner, _ := data["data"].(map[string]any)
	if data == nil || opFinite(data["code"], -1) != 0 || inner == nil {
		return db.Record{
			"plan":    "Xiaomi MiMo Desktop",
			"message": "Usage endpoint returned unexpected response.",
		}, nil
	}
	pct, isNum := ufBNumRaw(inner["percent"])
	if !isNum {
		return db.Record{
			"plan":    "Xiaomi MiMo Desktop",
			"message": "Usage data missing percent field.",
		}, nil
	}
	resetDate, _ := inner["resetDate"].(string)
	return ufBMimoWeeklyQuota(pct, ufBMimoResetDateISO(resetDate)), nil
}

// ---------- commandcode (usage/commandcode.js) ----------

var ufBCommandCodePlanNames = map[string]string{
	"individual-go": "Go", "individual-goat": "GOAT", "individual-pro": "Pro",
	"individual-pro-v1": "Pro", "individual-provider": "Provider",
	"individual-max": "Max", "individual-ultra": "Ultra", "teams-pro": "Teams Pro",
}

var ufBCommandCodePlanCaps = map[string]float64{
	"individual-go": 10, "individual-goat": 70, "individual-pro": 30,
	"individual-pro-v1": 80, "individual-provider": 15, "individual-max": 150,
	"individual-ultra": 300, "teams-pro": 40,
}

func ufBCommandCodeBase() string {
	base := os.Getenv("COMMAND_CODE_API_BASE_URL")
	if base == "" {
		base = "https://api.commandcode.ai"
	}
	return strings.TrimSuffix(base, "/")
}

func ufBCommandCodeQS(route string, params map[string]any) string {
	keys := make([]string, 0, len(params))
	for k, v := range params {
		if v != nil {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return route
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		var sv string
		switch v := params[k].(type) {
		case string:
			sv = v
		case float64:
			sv = strconv.FormatFloat(v, 'f', -1, 64)
		default:
			sv = fmt.Sprintf("%v", v)
		}
		parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(sv))
	}
	return route + "?" + strings.Join(parts, "&")
}

func ufBCommandCodeWindowQuota(win any) db.Record {
	m, ok := win.(map[string]any)
	if !ok {
		return nil
	}
	used := opFinite(m["used"], 0)
	total := opFinite(m["cap"], 0)
	if total <= 0 && used <= 0 {
		return nil
	}
	return db.Record{
		"used":      used,
		"total":     total,
		"remaining": math.Max(0, total-used),
		"unlimited": false,
		"resetAt":   opParseResetTime(m["resetAt"]),
	}
}

func ufBCommandCodeUsage(ctx context.Context, conn db.Record, force bool) (db.Record, error) {
	apiKey := opStr(conn, "apiKey")
	if strings.TrimSpace(apiKey) == "" {
		return db.Record{"message": "Command Code API key not available. Add a key to view usage."}, nil
	}
	base := ufBCommandCodeBase()
	headers := map[string]string{
		"Authorization": "Bearer " + strings.TrimSpace(apiKey),
		"Accept":        "application/json",
	}
	authFail := db.Record{"plan": "Command Code", "message": "Command Code authentication failed. Check the API key."}

	status, raw, _, err := ufBDo(ctx, "GET", base+ufBCommandCodeQS("/alpha/whoami", map[string]any{"limits": "1"}), headers, nil)
	if err != nil {
		return db.Record{"message": "Command Code error: " + err.Error()}, nil
	}
	if status == 401 || status == 403 {
		return authFail, nil
	}
	if status < 200 || status >= 300 {
		return db.Record{"plan": "Command Code", "message": fmt.Sprintf("Command Code usage API error (%d)", status)}, nil
	}
	whoami := ufBJSONMap(raw)
	org := opMap(whoami, "org")
	var orgID any
	if org != nil {
		orgID = org["id"]
	}

	type ccResult struct {
		status int
		raw    []byte
		err    error
	}
	creditsCh := make(chan ccResult, 1)
	subsCh := make(chan ccResult, 1)
	go func() {
		st, rw, _, e := ufBDo(ctx, "GET", base+ufBCommandCodeQS("/alpha/billing/credits", map[string]any{"orgId": orgID}), headers, nil)
		creditsCh <- ccResult{st, rw, e}
	}()
	go func() {
		st, rw, _, e := ufBDo(ctx, "GET", base+ufBCommandCodeQS("/alpha/billing/subscriptions", map[string]any{"orgId": orgID}), headers, nil)
		subsCh <- ccResult{st, rw, e}
	}()
	creditsRes := <-creditsCh
	subsRes := <-subsCh
	if creditsRes.err != nil {
		return db.Record{"message": "Command Code error: " + creditsRes.err.Error()}, nil
	}
	if subsRes.err != nil {
		return db.Record{"message": "Command Code error: " + subsRes.err.Error()}, nil
	}
	if creditsRes.status == 401 || creditsRes.status == 403 || subsRes.status == 401 || subsRes.status == 403 {
		return authFail, nil
	}
	if creditsRes.status < 200 || creditsRes.status >= 300 {
		return db.Record{"plan": "Command Code", "message": fmt.Sprintf("Command Code credits API error (%d)", creditsRes.status)}, nil
	}
	if subsRes.status < 200 || subsRes.status >= 300 {
		return db.Record{"plan": "Command Code", "message": fmt.Sprintf("Command Code subscriptions API error (%d)", subsRes.status)}, nil
	}
	creditsBody := ufBJSONMap(creditsRes.raw)
	subsBody := ufBJSONMap(subsRes.raw)
	subsData := opMap(subsBody, "data")
	planID, _ := subsData["planId"].(string)
	plan := ufBCommandCodePlanNames[planID]
	if plan == "" {
		plan = planID
	}
	if plan == "" {
		plan = "Command Code"
	}
	cap := ufBCommandCodePlanCaps[planID]
	credits := opMap(creditsBody, "credits")
	remaining := opFinite(credits["monthlyCredits"], 0) +
		opFinite(credits["purchasedCredits"], 0) +
		opFinite(credits["freeCredits"], 0)
	used := float64(0)
	if cap > 0 {
		used = math.Max(0, cap-remaining)
	}
	total := remaining
	if cap > 0 {
		total = cap
	}
	quotas := map[string]db.Record{
		"Credits": {
			"used": used, "total": total, "remaining": remaining,
			"unlimited": cap <= 0,
			"resetAt":   opParseResetTime(subsData["currentPeriodEnd"]),
		},
	}
	windowLimits := opMap(creditsBody, "windowLimits")
	if q := ufBCommandCodeWindowQuota(windowLimits["fiveHour"]); q != nil {
		quotas["Session (5h)"] = q
	}
	if q := ufBCommandCodeWindowQuota(windowLimits["weekly"]); q != nil {
		quotas["Weekly"] = q
	}
	return db.Record{"plan": plan, "quotas": quotas}, nil
}

// ---------- cursor (usage/cursor.js) ----------

func ufBCursorCentsToUSD(cents float64) float64 {
	return math.Round(opFinite(cents, 0)) / 100
}

func ufBCursorRemainingFromPercentUsed(percentUsed any) float64 {
	used := math.Max(0, math.Min(100, opFinite(percentUsed, 0)))
	return math.Max(0, 100-used)
}

// ufBCursorAddPlanSpend ports addPlanSpendQuotas.
func ufBCursorAddPlanSpend(quotas map[string]db.Record, data map[string]any) {
	planUsage, ok := data["planUsage"].(map[string]any)
	if !ok {
		return
	}
	limitCents := opFinite(planUsage["limit"], 0)
	usedCents := opFinite(ufBFirstNonNil(planUsage["includedSpend"], planUsage["totalSpend"]), 0)
	remainingCents := opFinite(planUsage["remaining"], math.Max(0, limitCents-usedCents))
	resetAt := opParseResetTime(data["billingCycleEnd"])

	if limitCents > 0 {
		total := ufBCursorCentsToUSD(limitCents)
		used := ufBCursorCentsToUSD(usedCents)
		remainingUSD := ufBCursorCentsToUSD(remainingCents)
		var pct float64
		if planUsage["totalPercentUsed"] != nil {
			pct = ufBCursorRemainingFromPercentUsed(planUsage["totalPercentUsed"])
		} else if total > 0 {
			pct = (remainingUSD / total) * 100
		}
		quotas["Plan (USD)"] = db.Record{
			"used": used, "total": total, "remainingPercentage": pct, "resetAt": resetAt,
		}
	} else if planUsage["totalPercentUsed"] != nil {
		used := opFinite(planUsage["totalPercentUsed"], 0)
		quotas["Included usage"] = db.Record{
			"used": used, "total": float64(100),
			"remainingPercentage": ufBCursorRemainingFromPercentUsed(used), "resetAt": resetAt,
		}
	}
	if planUsage["autoPercentUsed"] != nil {
		used := opFinite(planUsage["autoPercentUsed"], 0)
		quotas["Auto models (%)"] = db.Record{
			"used": used, "total": float64(100),
			"remainingPercentage": ufBCursorRemainingFromPercentUsed(used), "resetAt": resetAt,
		}
	}
	if planUsage["apiPercentUsed"] != nil {
		used := opFinite(planUsage["apiPercentUsed"], 0)
		quotas["Named models (%)"] = db.Record{
			"used": used, "total": float64(100),
			"remainingPercentage": ufBCursorRemainingFromPercentUsed(used), "resetAt": resetAt,
		}
	}
}

// ufBCursorAddOnDemand ports addOnDemandQuota.
func ufBCursorAddOnDemand(quotas map[string]db.Record, data map[string]any) {
	spend, ok := data["spendLimitUsage"].(map[string]any)
	if !ok {
		return
	}
	resetAt := opParseResetTime(data["billingCycleEnd"])
	individualLimit := opFinite(spend["individualLimit"], 0)
	pooledLimit := opFinite(spend["pooledLimit"], 0)
	if individualLimit > 0 {
		used := ufBCursorCentsToUSD(opFinite(spend["individualUsed"], 0))
		total := ufBCursorCentsToUSD(individualLimit)
		remainingUSD := ufBCursorCentsToUSD(opFinite(spend["individualRemaining"],
			math.Max(0, individualLimit-opFinite(spend["individualUsed"], 0))))
		pct := float64(0)
		if total > 0 {
			pct = (remainingUSD / total) * 100
		}
		quotas["On-demand (USD)"] = db.Record{
			"used": used, "total": total, "remainingPercentage": pct, "resetAt": resetAt,
		}
		return
	}
	if pooledLimit > 0 {
		used := ufBCursorCentsToUSD(opFinite(spend["pooledUsed"], 0))
		total := ufBCursorCentsToUSD(pooledLimit)
		remainingUSD := ufBCursorCentsToUSD(opFinite(spend["pooledRemaining"],
			math.Max(0, pooledLimit-opFinite(spend["pooledUsed"], 0))))
		pct := float64(0)
		if total > 0 {
			pct = (remainingUSD / total) * 100
		}
		quotas["Team on-demand (USD)"] = db.Record{
			"used": used, "total": total, "remainingPercentage": pct, "resetAt": resetAt,
		}
	}
}

// ufBCursorAddAuthUsage ports addAuthUsageQuotas.
func ufBCursorAddAuthUsage(quotas map[string]db.Record, data map[string]any) bool {
	if data == nil {
		return false
	}
	resetAt := opParseResetTime(data["startOfMonth"])
	added := false
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		bucket, ok := data[key].(map[string]any)
		if !ok {
			continue
		}
		total := opFinite(bucket["maxRequestUsage"], 0)
		if total <= 0 {
			continue
		}
		used := opFinite(bucket["numRequests"], 0)
		quotas[key+" requests"] = db.Record{
			"used": used, "total": total,
			"remainingPercentage": math.Max(0, ((total-used)/total)*100),
			"resetAt":             resetAt,
		}
		added = true
	}
	return added
}

func ufBCursorUsage(ctx context.Context, conn db.Record, force bool) (db.Record, error) {
	accessToken := opStr(conn, "accessToken")
	if strings.TrimSpace(accessToken) == "" {
		return db.Record{"message": "Cursor access token not available. Reconnect Cursor to view quota."}, nil
	}
	token := strings.TrimSpace(accessToken)
	psd := opMap(conn, "providerSpecificData")
	machineID := opStr(psd, "machineId")
	usage := opProviderUsage("cursor")
	periodURL := opStr(usage, "url")
	planInfoURL := opStr(usage, "planInfoUrl")
	authUsageURL := opStr(usage, "authUsageUrl")
	if periodURL == "" {
		return db.Record{"message": "Cursor usage endpoint is not configured."}, nil
	}

	postConnect := func(rawURL string) (int, []byte, error) {
		headers := executors.BuildCursorHeaders(token, machineID, true)
		headers["content-type"] = "application/json"
		headers["accept"] = "application/json"
		status, raw, _, err := ufBDo(ctx, "POST", rawURL, headers, []byte("{}"))
		return status, raw, err
	}

	periodStatus, periodRaw, err := postConnect(periodURL)
	if err != nil {
		return db.Record{"message": "Cursor error: " + err.Error()}, nil
	}
	if periodStatus == 401 || periodStatus == 403 {
		return db.Record{"plan": "Cursor", "message": "Cursor authentication failed. Reconnect the Cursor provider."}, nil
	}
	periodOK := periodStatus >= 200 && periodStatus < 300
	quotas := map[string]db.Record{}
	var periodData map[string]any
	if periodOK {
		periodData = ufBJSONMap(periodRaw)
		ufBCursorAddPlanSpend(quotas, periodData)
		ufBCursorAddOnDemand(quotas, periodData)
	}

	if len(quotas) == 0 && authUsageURL != "" {
		bearer := token
		if strings.Contains(token, "::") {
			bearer = strings.Split(token, "::")[1]
		}
		authStatus, authRaw, _, aerr := ufBDo(ctx, "GET", authUsageURL, map[string]string{
			"Authorization": "Bearer " + bearer,
			"Accept":        "application/json",
		}, nil)
		if aerr != nil {
			return db.Record{"message": "Cursor error: " + aerr.Error()}, nil
		}
		if authStatus >= 200 && authStatus < 300 {
			ufBCursorAddAuthUsage(quotas, ufBJSONMap(authRaw))
		} else if !periodOK {
			msg := fmt.Sprintf("Cursor usage API error (%d)", periodStatus)
			if len(periodRaw) > 0 {
				text := string(periodRaw)
				if len(text) > 120 {
					text = text[:120]
				}
				msg += ": " + text
			}
			return db.Record{"plan": "Cursor", "message": msg}, nil
		}
	}

	if len(quotas) == 0 {
		msg := "Cursor connected. No quota data returned for this plan."
		if dm, ok := periodData["displayMessage"].(string); ok && dm != "" {
			msg = dm
		}
		return db.Record{"plan": "Cursor", "message": msg}, nil
	}

	plan := "Cursor"
	if planInfoURL != "" {
		if pStatus, pRaw, perr := postConnect(planInfoURL); perr == nil && pStatus >= 200 && pStatus < 300 {
			planData := ufBJSONMap(pRaw)
			planInfo := opMap(planData, "planInfo")
			if name, ok := planInfo["planName"].(string); ok && strings.TrimSpace(name) != "" {
				plan = "Cursor " + strings.TrimSpace(name)
			}
		}
	}
	return db.Record{"plan": plan, "quotas": quotas}, nil
}
