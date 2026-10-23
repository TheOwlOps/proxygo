package api

// usage_fetch_a.go — Phase-3 usage fetchers, lot A (Team U1).
//
// Faithful ports of the JS handlers in open-sse/services/usage/:
//   google.js  → gemini-cli (getGeminiUsage), antigravity (getAntigravityUsage
//                + antigravity-weekly.js overlay)
//   kiro.js    → kiro (getKiroUsage, 3-endpoint attempt chain)
//   glm.js     → glm / glm-cn (getGlmUsage + parseGlmQuotaResponse)
//   misc.js    → qoder / qoder-cn (getQoderUsage + the PAT→job-token
//                exchange wrapper from usage.js/qoderModels.js),
//                iflow (static message), ollama (getOllamaUsage)
//
// Fetchers register via init() into the plugin dispatch in ops.go
// (opRegisterUsageFetcher); ops.go is not modified. Like the four
// built-in fetchers (claude/codex/github/groq) they return JS-shaped
// {message} records instead of Go errors for upstream failures.
//
// Proxy semantics: the JS handlers receive per-connection proxyOptions
// (built by the usage route from resolveConnectionProxyConfig) and pass
// them to proxyAwareFetch. The Go plugin signature carries no
// proxyOptions and the Go usage route does not plumb them (the four
// built-in fetchers share this limitation), so these fetchers go
// through the shared opHTTPClient directly. Per-connection proxy
// support lands when the route grows proxy plumbing, not here.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"9router-go/internal/db"
)

func init() {
	opRegisterUsageFetcher("gemini-cli", ufAGeminiUsage)
	opRegisterUsageFetcher("antigravity", ufAAntigravityUsage)
	opRegisterUsageFetcher("kiro", ufAKiroUsage)
	opRegisterUsageFetcher("qoder", ufAQoderUsage)
	opRegisterUsageFetcher("qoder-cn", ufAQoderUsage)
	opRegisterUsageFetcher("iflow", ufAIflowUsage)
	opRegisterUsageFetcher("ollama", ufAOllamaUsage)
	opRegisterUsageFetcher("glm", ufAGLMUsage)
	opRegisterUsageFetcher("glm-cn", ufAGLMUsage)
}

// ---------- shared helpers ----------

// ufAEndpointOverrides lets tests point individual upstream endpoints
// at httptest servers. Keys are "<provider>.<registry-usage-key>" plus
// the synthetic "ollama.usageUrl" / "ollama.meUrl" / "<qoder>.exchangeUrl".
var ufAEndpointOverrides = map[string]string{}

func ufAEndpoint(provider, key string) string {
	if v, ok := ufAEndpointOverrides[provider+"."+key]; ok {
		return v
	}
	return opStr(opProviderUsage(provider), key)
}

func ufAEndpointDef(provider, key, def string) string {
	if v := ufAEndpoint(provider, key); v != "" {
		return v
	}
	return def
}

// ufAFetchRaw performs one HTTP call via the shared client and returns
// status + raw body. A non-nil error means a transport failure (the JS
// handlers' catch branches).
func ufAFetchRaw(ctx context.Context, method, rawURL string, headers map[string]string, body []byte) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rdr)
	if err != nil {
		return 0, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := opHTTPClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	return resp.StatusCode, raw, nil
}

func ufAParseJSON(raw []byte) (map[string]any, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, false
	}
	return m, true
}

// ufANum mirrors JS Number(value) || 0 for the shapes these APIs use.
func ufANum(v any) float64 { return opFinite(v, 0) }

// ufAJSNumString renders a JSON value the way a JS template literal
// would (5 → "5", "x" → "x").
func ufAJSNumString(v any) string {
	switch n := v.(type) {
	case float64:
		return strconv.FormatFloat(n, 'f', -1, 64)
	case string:
		return n
	case nil:
		return "undefined"
	default:
		return fmt.Sprintf("%v", n)
	}
}

// ufARound is JS Math.round for the non-negative values used here.
func ufARound(f float64) float64 { return math.Round(f) }

// ufACapitalize ports `s.charAt(0).toUpperCase() + s.slice(1).toLowerCase()`.
func ufACapitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}

// ufAClientMetadata ports CLIENT_METADATA (appConstants.js) as the
// oauthsvc loadCodeAssist call already resolved it on this platform.
func ufAClientMetadata() map[string]any {
	return map[string]any{
		"ideType":    "ANTIGRAVITY",
		"platform":   "PLATFORM_UNSPECIFIED",
		"pluginType": "GEMINI",
	}
}

// ufANormalizeProjectID ports normalizeCloudCodeProjectId.
func ufANormalizeProjectID(v any) string {
	switch p := v.(type) {
	case string:
		return strings.TrimSpace(p)
	case map[string]any:
		if s, ok := p["id"].(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func ufATimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 10*time.Second)
}

// ---------- GLM / GLM-CN (usage/glm.js) ----------

func ufAGLMUsage(ctx context.Context, conn db.Record, _ bool) (db.Record, error) {
	apiKey := opStr(conn, "apiKey")
	if apiKey == "" {
		apiKey = opStr(conn, "accessToken")
	}
	if apiKey == "" {
		return db.Record{"message": "GLM API key not available."}, nil
	}
	provider := opStr(conn, "provider")
	quotaURL := ufAEndpoint(provider, "url")

	status, raw, err := ufAFetchRaw(ctx, "GET", quotaURL, map[string]string{
		"Authorization": "Bearer " + apiKey,
		"Accept":        "application/json",
	}, nil)
	if err != nil {
		return db.Record{"message": "GLM error: " + err.Error()}, nil
	}
	if status < 200 || status >= 300 {
		if status == 401 {
			return db.Record{"message": "GLM API key invalid or expired."}, nil
		}
		return db.Record{"message": fmt.Sprintf("GLM quota API error (%d).", status)}, nil
	}
	jsonBody, ok := ufAParseJSON(raw)
	if !ok {
		// JS: response.json() throws → caught as a GLM error message.
		return db.Record{"message": "GLM error: invalid JSON response"}, nil
	}
	return ufAParseGLMQuota(jsonBody), nil
}

// ufAParseGLMQuota ports parseGlmQuotaResponse.
func ufAParseGLMQuota(jsonBody map[string]any) db.Record {
	data := opMap(jsonBody, "data")
	if data == nil {
		data = map[string]any{}
	}
	quotas := db.Record{}
	if limits, ok := data["limits"].([]any); ok {
		for _, lv := range limits {
			limit, _ := lv.(map[string]any)
			if limit == nil {
				continue
			}
			typ := opStr(limit, "type")
			if typ != "TOKENS_LIMIT" && typ != "CREDIT_LIMIT" {
				continue
			}
			usedPercent := ufANum(limit["percentage"])
			resetMs := ufANum(limit["nextResetTime"])
			remaining := math.Max(0, 100-usedPercent)
			unit, unitIsNum := limit["unit"].(float64)

			key := "session"
			switch {
			case unitIsNum && unit == 3:
				key = "Session (" + ufAJSNumString(limit["number"]) + "h)"
			case unitIsNum && unit == 6:
				key = "Weekly (7d)"
			case typ == "TOKENS_LIMIT":
				key = "Tokens"
			default:
				key = "Limit (" + ufAJSNumString(limit["number"]) + ")"
			}
			var resetAt any
			if resetMs > 0 {
				resetAt = time.UnixMilli(int64(resetMs)).UTC().Format("2006-01-02T15:04:05.000Z")
			}
			quotas[key] = db.Record{
				"used":                usedPercent,
				"total":               float64(100),
				"remaining":           remaining,
				"remainingPercentage": remaining,
				"resetAt":             resetAt,
				"unlimited":           false,
			}
		}
	}
	plan := "Unknown"
	if level := opStr(data, "level"); level != "" {
		plan = ufACapitalize(level)
	}
	return db.Record{"plan": plan, "quotas": quotas}
}

// ---------- Gemini CLI (usage/google.js getGeminiUsage) ----------

func ufAGeminiUsage(ctx context.Context, conn db.Record, _ bool) (db.Record, error) {
	accessToken := opStr(conn, "accessToken")
	if accessToken == "" {
		return db.Record{"plan": "Free", "message": "Gemini CLI access token not available."}, nil
	}
	psd := opMap(conn, "providerSpecificData")
	// usage.js providerDataWithProjectId: connection-level projectId
	// merges over providerSpecificData.
	projectID := ufANormalizeProjectID(psd["projectId"])
	if v := conn["projectId"]; v != nil {
		if p := ufANormalizeProjectID(v); p != "" {
			projectID = p
		}
	}
	plan := "Free"

	if projectID == "" {
		sub := ufAGeminiSubscriptionInfo(ctx, accessToken)
		if sub != nil {
			projectID = ufANormalizeProjectID(sub["cloudaicompanionProject"])
			if name := opStr(opMap(sub, "currentTier"), "name"); name != "" {
				plan = name
			}
		}
	}
	if projectID == "" {
		return db.Record{
			"plan":    plan,
			"message": "Gemini CLI project ID not available. Reconnect Gemini CLI, or configure a Google Cloud project with Gemini Code Assist access before checking quota.",
		}, nil
	}

	body, _ := json.Marshal(map[string]any{"project": projectID})
	cctx, cancel := ufATimeout(ctx)
	status, raw, err := ufAFetchRaw(cctx, "POST", ufAEndpoint("gemini-cli", "quotaUrl"), map[string]string{
		"Authorization": "Bearer " + accessToken,
		"Content-Type":  "application/json",
	}, body)
	cancel()
	if err != nil {
		return db.Record{"message": "Gemini CLI error: " + err.Error()}, nil
	}
	if status < 200 || status >= 300 {
		return db.Record{"plan": plan, "message": fmt.Sprintf("Gemini CLI quota error (%d).", status)}, nil
	}
	data, parseOK := ufAParseJSON(raw)
	if !parseOK {
		return db.Record{"message": "Gemini CLI error: invalid JSON response"}, nil
	}
	quotas := db.Record{}
	if buckets, ok := data["buckets"].([]any); ok {
		for _, bv := range buckets {
			bucket, _ := bv.(map[string]any)
			if bucket == nil {
				continue
			}
			modelID := opStr(bucket, "modelId")
			if modelID == "" || bucket["remainingFraction"] == nil {
				continue
			}
			frac := ufANum(bucket["remainingFraction"])
			total := float64(1000)
			remaining := ufARound(total * frac)
			quotas[modelID] = db.Record{
				"used":                math.Max(0, total-remaining),
				"total":               total,
				"resetAt":             opParseResetTime(bucket["resetTime"]),
				"remainingPercentage": frac * 100,
				"unlimited":           false,
			}
		}
	}
	return db.Record{"plan": plan, "quotas": quotas}, nil
}

func ufAGeminiSubscriptionInfo(ctx context.Context, accessToken string) map[string]any {
	body, _ := json.Marshal(map[string]any{"metadata": ufAClientMetadata()})
	cctx, cancel := ufATimeout(ctx)
	defer cancel()
	status, raw, err := ufAFetchRaw(cctx, "POST", ufAEndpoint("gemini-cli", "loadCodeAssistUrl"), map[string]string{
		"Authorization": "Bearer " + accessToken,
		"Content-Type":  "application/json",
	}, body)
	if err != nil || status < 200 || status >= 300 {
		return nil
	}
	data, _ := ufAParseJSON(raw)
	return data
}

// ---------- Antigravity (usage/google.js + antigravity-weekly.js) ----------

const (
	ufAAntigravityIDEVersion = "2.22.0" // ANTIGRAVITY_IDE_VERSION
	ufAAntigravityUA         = "antigravity/ide/" + ufAAntigravityIDEVersion + " darwin/arm64"
)

var ufAAntigravityImportantModels = map[string]bool{
	"gemini-3.8-flash-high": true, "gemini-3.8-flash-medium": true,
	"gemini-3.8-flash-low": true, "gemini-3.7-flash-high": true,
	"gemini-3.7-flash-medium": true, "gemini-3.7-flash-low": true,
	"gemini-3.6-flash-high": true, "gemini-3.6-flash-medium": true,
	"gemini-3.6-flash-low": true, "gemini-3.1-pro-high": true,
	"gemini-pro-agent": true, "gemini-3.1-pro-low": true,
	"claude-sonnet-5-5-high": true, "claude-sonnet-5-5-medium": true,
	"claude-sonnet-5-5-low": true, "claude-sonnet-5-5": true,
	"claude-opus-5-5-high": true, "claude-opus-5-5-medium": true,
	"claude-opus-5-5-low": true, "claude-opus-5-5": true,
	"claude-sonnet-4-6": true, "claude-opus-4-6-thinking": true,
	"gpt-oss-120b-medium": true, "gemini-3.1-flash-image": true,
}

func ufAAntigravityHeaders(accessToken string) map[string]string {
	return map[string]string{
		"Authorization":    "Bearer " + accessToken,
		"User-Agent":       ufAAntigravityUA,
		"Content-Type":     "application/json",
		"X-Client-Name":    "antigravity",
		"X-Client-Version": ufAAntigravityIDEVersion,
	}
}

func ufAAntigravityUsage(ctx context.Context, conn db.Record, _ bool) (db.Record, error) {
	accessToken := opStr(conn, "accessToken")
	subInfo := ufAAntigravitySubscriptionInfo(ctx, accessToken)
	var projectID any
	if subInfo != nil {
		projectID = subInfo["cloudaicompanionProject"]
	}

	body, _ := json.Marshal(ufAProjectBody(projectID))
	cctx, cancel := ufATimeout(ctx)
	status, raw, err := ufAFetchRaw(cctx, "POST", ufAEndpoint("antigravity", "quotaApiUrl"),
		ufAAntigravityHeaders(accessToken), body)
	cancel()
	if err != nil {
		return db.Record{"message": "Antigravity error: " + err.Error()}, nil
	}
	switch status {
	case 403:
		return db.Record{"message": "Antigravity quota API access forbidden. Chat may still work.", "quotas": db.Record{}}, nil
	case 401:
		return db.Record{"message": "Antigravity quota API authentication expired. Chat may still work.", "quotas": db.Record{}}, nil
	}
	if status < 200 || status >= 300 {
		return db.Record{"message": fmt.Sprintf("Antigravity error: Antigravity API error: %d", status)}, nil
	}
	data, parseOK := ufAParseJSON(raw)
	if !parseOK {
		return db.Record{"message": "Antigravity error: invalid JSON response"}, nil
	}
	quotas := db.Record{}

	paidTierID := opStr(opMap(subInfo, "paidTier"), "id")
	isFreeTier := paidTierID == "" || paidTierID == "free-tier"

	if !isFreeTier {
		if models, ok := data["models"].(map[string]any); ok {
			for modelKey, mv := range models {
				info, _ := mv.(map[string]any)
				if info == nil || info["quotaInfo"] == nil {
					continue
				}
				if opBool(info, "isInternal") || !ufAAntigravityImportantModels[modelKey] {
					continue
				}
				qi := opMap(info, "quotaInfo")
				frac := ufANum(qi["remainingFraction"])
				total := float64(1000)
				remaining := ufARound(total * frac)
				displayName := opStr(info, "displayName")
				if displayName == "" {
					displayName = modelKey
				}
				quotas[modelKey] = db.Record{
					"used":                total - remaining,
					"total":               total,
					"resetAt":             opParseResetTime(qi["resetTime"]),
					"remainingPercentage": frac * 100,
					"unlimited":           false,
					"displayName":         displayName,
				}
			}
		}
	}

	// Weekly overlay (best-effort; never breaks per-model results).
	weekly := ufAAntigravityWeeklyQuota(ctx, accessToken, projectID)
	ufAReconcileWeeklySession(weekly, quotas, "gemini_session", func(k string) bool {
		return strings.HasPrefix(k, "gemini-") && !strings.Contains(k, "image")
	})
	ufAReconcileWeeklySession(weekly, quotas, "claude_gpt_session", func(k string) bool {
		return strings.HasPrefix(k, "claude-")
	})
	for k, v := range weekly {
		quotas[k] = v
	}

	plan := "Unknown"
	if name := opStr(opMap(subInfo, "currentTier"), "name"); name != "" {
		plan = name
	}
	var subAny any
	if subInfo != nil {
		subAny = subInfo
	}
	return db.Record{"plan": plan, "quotas": quotas, "subscriptionInfo": subAny}, nil
}

func ufAAntigravitySubscriptionInfo(ctx context.Context, accessToken string) map[string]any {
	body, _ := json.Marshal(map[string]any{"metadata": ufAClientMetadata(), "mode": float64(1)})
	cctx, cancel := ufATimeout(ctx)
	defer cancel()
	status, raw, err := ufAFetchRaw(cctx, "POST", ufAEndpoint("antigravity", "loadProjectApiUrl"), map[string]string{
		"Authorization": "Bearer " + accessToken,
		"User-Agent":    ufAAntigravityUA,
		"Content-Type":  "application/json",
	}, body)
	if err != nil || status < 200 || status >= 300 {
		return nil
	}
	data, _ := ufAParseJSON(raw)
	return data
}

// ufAReconcileWeeklySession ports the exhausted-family reconciliation:
// when every model of a family sits at 0% remaining until a future
// reset, the family's 5h session row is marked exhausted too, with the
// latest model reset time.
func ufAReconcileWeeklySession(weekly, quotas db.Record, sessionKey string, family func(string) bool) {
	session, _ := weekly[sessionKey].(db.Record)
	if session == nil {
		return
	}
	var models []db.Record
	for k, v := range quotas {
		if family(k) {
			if q, _ := v.(db.Record); q != nil {
				models = append(models, q)
			}
		}
	}
	if len(models) == 0 {
		return
	}
	for _, q := range models {
		if ufANum(q["remainingPercentage"]) != 0 {
			return
		}
	}
	if ufANum(session["remainingPercentage"]) <= 0 {
		return
	}
	var maxReset any
	for _, q := range models {
		ra := q["resetAt"]
		if maxReset == nil {
			maxReset = ra
			continue
		}
		if s, ok := ra.(string); ok && s != "" {
			if cur, ok2 := maxReset.(string); ok2 && s > cur {
				maxReset = s
			}
		}
	}
	session["used"] = session["total"]
	session["remainingPercentage"] = float64(0)
	if maxReset != nil {
		session["resetAt"] = maxReset
	}
}

// ----- antigravity weekly summary (antigravity-weekly.js) -----

const ufAWeeklyCacheTTL = 180 * time.Second

var (
	ufAWeeklyMu    sync.Mutex
	ufAWeeklyCache = map[string]struct {
		result    db.Record
		expiresAt time.Time
	}{}
)

type ufAWeeklyGroup struct {
	pattern     *regexp.Regexp
	weeklyKey   string
	weeklyName  string
	sessionKey  string
	sessionName string
}

var ufAWeeklyGroups = []ufAWeeklyGroup{
	{regexp.MustCompile(`(?i)gemini`), "gemini_weekly", "Gemini (Weekly)", "gemini_session", "Gemini (5h)"},
	{regexp.MustCompile(`(?i)claude|gpt`), "claude_gpt_weekly", "Claude & GPT (Weekly)", "claude_gpt_session", "Claude & GPT (5h)"},
}

// ufAParseWeeklySummary ports parseWeeklyQuotaSummary.
func ufAParseWeeklySummary(data map[string]any) db.Record {
	result := db.Record{}
	if data == nil {
		return result
	}
	var groups []any
	if g, ok := data["groups"].([]any); ok {
		groups = g
	} else if g, ok := opMap(data, "quotaSummary")["groups"].([]any); ok {
		groups = g
	}
	if groups == nil {
		return result
	}
	for _, gv := range groups {
		group, _ := gv.(map[string]any)
		if group == nil {
			continue
		}
		displayName := opStr(group, "displayName")
		buckets, _ := group["buckets"].([]any)
		for _, bv := range buckets {
			bucket, _ := bv.(map[string]any)
			if bucket == nil {
				continue
			}
			windowType := strings.ToLower(opStr(bucket, "window"))
			bucketText := strings.ToLower(opStr(bucket, "bucketId") + " " + opStr(bucket, "displayName"))
			isWeekly := windowType == "weekly" || strings.Contains(bucketText, "weekly")
			isSession := windowType == "5h" || strings.Contains(bucketText, "five hour") ||
				strings.Contains(bucketText, "5h") || strings.Contains(bucketText, "daily") ||
				windowType == "daily"
			if !isWeekly && !isSession {
				continue
			}
			disabled := opBool(bucket, "disabled")
			if disabled && isWeekly {
				continue
			}
			var frac float64
			if disabled {
				frac = 0
			} else {
				f, ok := bucket["remainingFraction"].(float64)
				if !ok {
					if s, isStr := bucket["remainingFraction"].(string); isStr {
						parsed, perr := strconv.ParseFloat(s, 64)
						if perr != nil {
							continue
						}
						f = parsed
					} else {
						continue
					}
				}
				frac = f
			}
			for _, cfg := range ufAWeeklyGroups {
				if !cfg.pattern.MatchString(displayName) {
					continue
				}
				key, name := cfg.weeklyKey, cfg.weeklyName
				if isSession {
					key, name = cfg.sessionKey, cfg.sessionName
				}
				if _, exists := result[key]; exists {
					break
				}
				total := float64(1000)
				remaining := ufARound(total * frac)
				result[key] = db.Record{
					"used":                math.Max(0, total-remaining),
					"total":               total,
					"resetAt":             opParseResetTime(bucket["resetTime"]),
					"remainingPercentage": frac * 100,
					"unlimited":           false,
					"displayName":         name,
				}
				break
			}
		}
	}
	return result
}

func ufAAntigravityWeeklyQuota(ctx context.Context, accessToken string, projectID any) db.Record {
	key := accessToken + "::" + ufAWeeklyProjectKey(projectID)
	ufAWeeklyMu.Lock()
	if hit, ok := ufAWeeklyCache[key]; ok && time.Now().Before(hit.expiresAt) {
		ufAWeeklyMu.Unlock()
		return hit.result
	}
	ufAWeeklyMu.Unlock()

	result := db.Record{}
	summaryURL := ufAEndpoint("antigravity", "quotaSummaryApiUrl")
	if summaryURL != "" {
		body, _ := json.Marshal(ufAProjectBody(projectID))
		cctx, cancel := ufATimeout(ctx)
		status, raw, err := ufAFetchRaw(cctx, "POST", summaryURL, ufAAntigravityHeaders(accessToken), body)
		cancel()
		if err == nil && status >= 200 && status < 300 {
			data, _ := ufAParseJSON(raw)
			result = ufAParseWeeklySummary(data)
		}
	}
	if len(result) > 0 {
		ufAWeeklyMu.Lock()
		ufAWeeklyCache[key] = struct {
			result    db.Record
			expiresAt time.Time
		}{result, time.Now().Add(ufAWeeklyCacheTTL)}
		ufAWeeklyMu.Unlock()
	}
	return result
}

// ufAProjectBody ports the JS `{...(projectId ? {project} : {})}` spread.
func ufAProjectBody(projectID any) map[string]any {
	body := map[string]any{}
	if projectID != nil && projectID != "" {
		body["project"] = projectID
	}
	return body
}

func ufAWeeklyProjectKey(projectID any) string {
	switch p := projectID.(type) {
	case nil:
		return ""
	case string:
		return p
	default:
		return fmt.Sprintf("%v", p)
	}
}

// ---------- Kiro (usage/kiro.js) ----------

const (
	ufAKiroBuilderIDProfileARN = "arn:aws:codewhisperer:us-east-1:638616132270:profile/AAAACCCCXXXX"
	ufAKiroSocialProfileARN    = "arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK"
)

// ufAKiroDefaultProfileArn ports resolveDefaultProfileArn (social
// sign-ins → social profile, everything else → Builder ID profile).
func ufAKiroDefaultProfileArn(authMethod string) string {
	if authMethod == "google" || authMethod == "github" {
		return ufAKiroSocialProfileARN
	}
	return ufAKiroBuilderIDProfileARN
}

// ufAFalsy mirrors JS truthiness for the `a || b` chains in kiro.js.
func ufAFalsy(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case float64:
		return t == 0
	case bool:
		return !t
	}
	return false
}

func ufAParseKiroQuota(data map[string]any) db.Record {
	quotas := db.Record{}
	var resetAt any
	if data != nil {
		rawReset := data["nextDateReset"]
		if ufAFalsy(rawReset) {
			rawReset = data["resetDate"]
		}
		resetAt = opParseResetTime(rawReset)
	}
	if list, ok := data["usageBreakdownList"].([]any); ok {
		for _, bv := range list {
			breakdown, _ := bv.(map[string]any)
			if breakdown == nil {
				continue
			}
			resourceType := strings.ToLower(opStr(breakdown, "resourceType"))
			if resourceType == "" {
				resourceType = "unknown"
			}
			used := ufANum(breakdown["currentUsageWithPrecision"])
			total := ufANum(breakdown["usageLimitWithPrecision"])
			quotas[resourceType] = db.Record{
				"used":      used,
				"total":     total,
				"remaining": total - used,
				"resetAt":   resetAt,
				"unlimited": false,
			}
			if ft := opMap(breakdown, "freeTrialInfo"); ft != nil {
				freeUsed := ufANum(ft["currentUsageWithPrecision"])
				freeTotal := ufANum(ft["usageLimitWithPrecision"])
				freeExpiry := ft["freeTrialExpiry"]
				if ufAFalsy(freeExpiry) {
					freeExpiry = resetAt
				}
				freeReset := opParseResetTime(freeExpiry)
				quotas[resourceType+"_freetrial"] = db.Record{
					"used":      freeUsed,
					"total":     freeTotal,
					"remaining": freeTotal - freeUsed,
					"resetAt":   freeReset,
					"unlimited": false,
				}
			}
		}
	}
	plan := "Kiro"
	if title := opStr(opMap(data, "subscriptionInfo"), "subscriptionTitle"); title != "" {
		plan = title
	}
	return db.Record{"plan": plan, "quotas": quotas}
}

func ufAKiroUsage(ctx context.Context, conn db.Record, _ bool) (db.Record, error) {
	accessToken := opStr(conn, "accessToken")
	psd := opMap(conn, "providerSpecificData")
	authMethod := opStr(psd, "authMethod")
	if authMethod == "" {
		authMethod = "builder-id"
	}
	isApiKey := authMethod == "api_key"
	isExternalIdp := authMethod == "external_idp"

	profileArn := opStr(psd, "profileArn")
	if !isApiKey && profileArn == "" {
		profileArn = ufAKiroDefaultProfileArn(authMethod)
	}

	extra := map[string]string{}
	if isApiKey {
		extra["tokentype"] = "API_KEY"
	}
	if isExternalIdp {
		extra["TokenType"] = "EXTERNAL_IDP"
	}
	withExtra := func(h map[string]string) map[string]string {
		for k, v := range extra {
			h[k] = v
		}
		return h
	}

	cwHost := ufAEndpoint("kiro", "cwHost")
	qHost := ufAEndpoint("kiro", "qHost")
	limitsPath := ufAEndpoint("kiro", "limitsPath")

	type attempt struct {
		name string
		run  func() (int, []byte, error)
	}
	attempts := []attempt{
		{"codewhisperer-get", func() (int, []byte, error) {
			u := cwHost + limitsPath + "?isEmailRequired=true&origin=AI_EDITOR&resourceType=AGENTIC_REQUEST"
			return ufAFetchRaw(ctx, "GET", u, withExtra(map[string]string{
				"Authorization":    "Bearer " + accessToken,
				"Accept":           "application/json",
				"x-amz-user-agent": "aws-sdk-js/1.0.0 KiroIDE",
				"user-agent":       "aws-sdk-js/1.0.0 KiroIDE",
			}), nil)
		}},
		{"codewhisperer-post", func() (int, []byte, error) {
			bodyMap := map[string]any{"origin": "AI_EDITOR", "resourceType": "AGENTIC_REQUEST"}
			if profileArn != "" {
				bodyMap["profileArn"] = profileArn
			}
			body, _ := json.Marshal(bodyMap)
			return ufAFetchRaw(ctx, "POST", cwHost, withExtra(map[string]string{
				"Authorization": "Bearer " + accessToken,
				"Content-Type":  "application/x-amz-json-1.0",
				"x-amz-target":  "AmazonCodeWhispererService.GetUsageLimits",
				"Accept":        "application/json",
			}), body)
		}},
		{"q-get", func() (int, []byte, error) {
			q := "origin=AI_EDITOR"
			if profileArn != "" {
				q += "&profileArn=" + url.QueryEscape(profileArn)
			}
			q += "&resourceType=AGENTIC_REQUEST"
			return ufAFetchRaw(ctx, "GET", qHost+limitsPath+"?"+q, withExtra(map[string]string{
				"Authorization": "Bearer " + accessToken,
				"Accept":        "application/json",
			}), nil)
		}},
	}

	sawAuthError := false
	var errs []string
	for _, a := range attempts {
		status, raw, err := a.run()
		if err != nil {
			errs = append(errs, a.name+":"+err.Error())
			continue
		}
		if status < 200 || status >= 300 {
			if status == 401 || status == 403 {
				sawAuthError = true
			}
			entry := fmt.Sprintf("%s:%d", a.name, status)
			if len(raw) > 0 {
				entry += ":" + string(raw)
			}
			errs = append(errs, entry)
			continue
		}
		data, parseOK := ufAParseJSON(raw)
		if !parseOK {
			// JS: response.json() throws → the attempt is recorded as
			// failed and the chain moves on to the next endpoint.
			errs = append(errs, a.name+":invalid JSON response")
			continue
		}
		return ufAParseKiroQuota(data), nil
	}

	if sawAuthError && authMethod == "idc" {
		return db.Record{
			"message": "Kiro quota API is unavailable for the current AWS IAM Identity Center session. Chat may still work. If this persists after renewing your session, reconnect Kiro.",
			"quotas":  db.Record{},
		}, nil
	}
	if sawAuthError && (authMethod == "google" || authMethod == "github") {
		return db.Record{"message": "Kiro quota API authentication expired. Chat may still work.", "quotas": db.Record{}}, nil
	}
	if sawAuthError {
		return db.Record{"message": "Kiro quota API rejected the current token. Chat may still work.", "quotas": db.Record{}}, nil
	}
	msg := "Unable to fetch Kiro usage right now."
	if len(errs) > 0 {
		msg = fmt.Sprintf("Unable to fetch Kiro usage right now. (%s)", errs[len(errs)-1])
	}
	return db.Record{"message": msg, "quotas": db.Record{}}, nil
}

// ---------- Qoder / Qoder-CN (usage.js wrapper + misc.js getQoderUsage) ----------

const (
	ufAQoderPATPrefix          = "pt-"
	ufAQoderPATDefaultTTL      = 24 * time.Hour
	ufAQoderPATRefreshBuffer   = 5 * time.Minute
	ufAQoderNoResetSentinelMs  = float64(253402214400000)
	ufAQoderJobTokenPathSuffix = "/api/v1/jobToken/exchange"
	ufAQoderQuotaPathSuffix    = "/api/v2/quota/usage"
)

var (
	ufAQoderPatMu    sync.Mutex
	ufAQoderPatCache = map[string]struct {
		accessToken string
		expiresAt   time.Time
	}{}
)

func ufAQoderRegion(provider string) string {
	if provider == "qoder-cn" {
		return "cn"
	}
	return "intl"
}

// ufAQoderExchangeURL derives the PAT exchange endpoint from the
// region-correct quota URL in the registry (same openApi base).
func ufAQoderExchangeURL(provider string) string {
	if v, ok := ufAEndpointOverrides[provider+".exchangeUrl"]; ok {
		return v
	}
	quota := ufAEndpoint(provider, "url")
	if strings.HasSuffix(quota, ufAQoderQuotaPathSuffix) {
		return strings.TrimSuffix(quota, ufAQoderQuotaPathSuffix) + ufAQoderJobTokenPathSuffix
	}
	if parsed, err := url.Parse(quota); err == nil && parsed.Host != "" {
		return parsed.Scheme + "://" + parsed.Host + ufAQoderJobTokenPathSuffix
	}
	return ""
}

// ufAQoderExchangeJobToken ports exchangeJobToken + resolvePatCredential
// caching. (JS also resolves a userId for COSY signing; the usage
// handler consumes only the job token, so that lookup is skipped here.)
func ufAQoderExchangeJobToken(ctx context.Context, provider, pat string) (string, error) {
	region := ufAQoderRegion(provider)
	cacheKey := region + ":" + pat
	ufAQoderPatMu.Lock()
	if hit, ok := ufAQoderPatCache[cacheKey]; ok && time.Until(hit.expiresAt) > ufAQoderPATRefreshBuffer {
		ufAQoderPatMu.Unlock()
		return hit.accessToken, nil
	}
	ufAQoderPatMu.Unlock()

	body, _ := json.Marshal(map[string]any{"personal_token": pat})
	status, raw, err := ufAFetchRaw(ctx, "POST", ufAQoderExchangeURL(provider), map[string]string{
		"Content-Type":    "application/json",
		"Accept":          "application/json",
		"User-Agent":      "qodercli/1.0.0",
		"Cosy-Version":    "1.0.0",
		"Cosy-ClientType": "5",
	}, body)
	if err != nil {
		return "", err
	}
	if status < 200 || status >= 300 {
		text := string(raw)
		if len(text) > 200 {
			text = text[:200]
		}
		return "", fmt.Errorf("qoder PAT exchange failed: %d %s", status, text)
	}
	data, _ := ufAParseJSON(raw)
	token := opStr(data, "token")
	if token == "" {
		return "", fmt.Errorf("qoder PAT exchange returned no job token")
	}
	expiresAt := time.Now().Add(ufAQoderPATDefaultTTL)
	if s := opStr(data, "expires_at"); s != "" {
		if t, perr := time.Parse(time.RFC3339, s); perr == nil {
			expiresAt = t
		}
	} else if n, ok := data["expires_in"].(float64); ok && n > 0 {
		// JS quirk, mirrored: expires_in is added to Date.now() as-is
		// (milliseconds), not converted from seconds.
		expiresAt = time.Now().Add(time.Duration(n) * time.Millisecond)
	}
	ufAQoderPatMu.Lock()
	ufAQoderPatCache[cacheKey] = struct {
		accessToken string
		expiresAt   time.Time
	}{token, expiresAt}
	ufAQoderPatMu.Unlock()
	return token, nil
}

func ufAQoderUsage(ctx context.Context, conn db.Record, _ bool) (db.Record, error) {
	provider := opStr(conn, "provider")
	// usage.js getQoderUsageFor: PATs (from apiKey or accessToken) are
	// exchanged for a job token first; any failure falls back to the
	// connection's stored accessToken.
	raw := opStr(conn, "apiKey")
	if raw == "" {
		raw = opStr(conn, "accessToken")
	}
	token := opStr(conn, "accessToken")
	if strings.HasPrefix(raw, ufAQoderPATPrefix) {
		if jobToken, err := ufAQoderExchangeJobToken(ctx, provider, raw); err == nil {
			token = jobToken
		}
	}
	if token == "" {
		return db.Record{"message": "Qoder usage unavailable: no access token"}, nil
	}
	status, rawBody, err := ufAFetchRaw(ctx, "GET", ufAEndpoint(provider, "url"), map[string]string{
		"Authorization": "Bearer " + token,
		"Accept":        "application/json",
	}, nil)
	if err != nil {
		return db.Record{"message": "Qoder connected. Unable to fetch usage: " + err.Error()}, nil
	}
	if status < 200 || status >= 300 {
		return db.Record{"message": fmt.Sprintf("Qoder connected. Usage fetch returned %d.", status)}, nil
	}
	bodyMap, ok := ufAParseJSON(rawBody)
	if !ok {
		return db.Record{"message": "Qoder connected. Usage response was not JSON."}, nil
	}

	var expiresAtMs any
	neverExpires := false
	var resetAt any
	if bodyMap["expiresAt"] != nil {
		if n := ufANum(bodyMap["expiresAt"]); n > 0 {
			expiresAtMs = n
			neverExpires = n == ufAQoderNoResetSentinelMs
			if !neverExpires {
				resetAt = time.UnixMilli(int64(n)).UTC().Format("2006-01-02T15:04:05.000Z")
			}
		}
	}
	quotaRecord := func(block map[string]any) db.Record {
		unit := opStr(block, "unit")
		if unit == "" {
			unit = "credits"
		}
		return db.Record{
			"total":        ufANum(block["total"]),
			"used":         ufANum(block["used"]),
			"remaining":    ufANum(block["remaining"]),
			"unit":         unit,
			"resetAt":      resetAt,
			"neverExpires": neverExpires,
		}
	}
	quotas := db.Record{
		"user":         quotaRecord(opMap(bodyMap, "userQuota")),
		"organization": quotaRecord(opMap(bodyMap, "orgResourcePackage")),
	}
	if addOn := opMap(bodyMap, "addOnQuota"); addOn != nil {
		if addOnTotal := ufANum(addOn["total"]); addOnTotal > 0 {
			unit := opStr(addOn, "unit")
			if unit == "" {
				unit = "credits"
			}
			var detailURL any
			if s := opStr(addOn, "detailUrl"); s != "" {
				detailURL = s
			}
			quotas["addOn"] = db.Record{
				"total":        addOnTotal,
				"used":         ufANum(addOn["used"]),
				"remaining":    ufANum(addOn["remaining"]),
				"unit":         unit,
				"resetAt":      nil,
				"neverExpires": false,
				"detailUrl":    detailURL,
			}
		}
	}
	return db.Record{
		"quotas":               quotas,
		"totalUsagePercentage": ufANum(bodyMap["totalUsagePercentage"]),
		"isQuotaExceeded":      opBool(bodyMap, "isQuotaExceeded"),
		"expiresAt":            expiresAtMs,
	}, nil
}

// ---------- iFlow (misc.js getIflowUsage) ----------

func ufAIflowUsage(_ context.Context, _ db.Record, _ bool) (db.Record, error) {
	// The JS handler performs no fetch at all.
	return db.Record{"message": "iFlow connected. Usage tracked per request."}, nil
}

// ---------- Ollama (misc.js getOllamaUsage) ----------

var ufAOllamaWindows = []struct{ key, label string }{
	{"session", "Session (5h)"},
	{"weekly", "Weekly (7d)"},
	{"monthly", "Monthly"},
}

func ufAOllamaUsage(ctx context.Context, conn db.Record, _ bool) (db.Record, error) {
	apiKey := opStr(conn, "apiKey")
	if apiKey == "" {
		return db.Record{"message": "Ollama Cloud API key not available."}, nil
	}
	usageURL := ufAEndpointDef("ollama", "usageUrl", "https://ollama.com/api/usage")
	meURL := ufAEndpointDef("ollama", "meUrl", "https://ollama.com/api/me")
	headers := map[string]string{
		"Authorization": "Bearer " + apiKey,
		"Accept":        "application/json",
	}
	status, raw, err := ufAFetchRaw(ctx, "GET", usageURL, headers, nil)
	if err != nil {
		return db.Record{"message": "Ollama Cloud error: " + err.Error()}, nil
	}
	if status == 401 || status == 403 {
		return db.Record{"message": "Ollama Cloud API key invalid or expired."}, nil
	}
	if status < 200 || status >= 300 {
		return db.Record{"message": fmt.Sprintf("Ollama Cloud usage API error (%d).", status)}, nil
	}
	data, ok := ufAParseJSON(raw)
	if !ok {
		return db.Record{"message": "Ollama Cloud usage response was not JSON."}, nil
	}

	// Best-effort plan label from /api/me (fail-open).
	var me map[string]any
	if mStatus, mRaw, mErr := ufAFetchRaw(ctx, "POST", meURL, headers, []byte{}); mErr == nil && mStatus >= 200 && mStatus < 300 {
		me, _ = ufAParseJSON(mRaw)
	}
	planRaw := opStr(me, "Plan")
	plan := "Ollama Cloud"
	if planRaw != "" {
		plan = ufACapitalize(planRaw)
	}

	var monthlyResetAt any
	if strings.ToLower(planRaw) == "free" {
		if created := opStr(me, "CreatedAt"); created != "" {
			if t, perr := time.Parse(time.RFC3339, created); perr == nil {
				monthlyResetAt = ufANextMonthlyReset(t, time.Now())
			}
		}
	}

	limits := opMap(data, "limits")
	quotas := db.Record{}
	for _, w := range ufAOllamaWindows {
		lim := opMap(limits, w.key)
		if lim == nil || lim["usage"] == nil {
			continue
		}
		ratio, isNum := lim["usage"].(float64)
		if !isNum {
			if s, isStr := lim["usage"].(string); isStr {
				parsed, perr := strconv.ParseFloat(s, 64)
				if perr != nil {
					continue
				}
				ratio = parsed
			} else {
				continue
			}
		}
		ratio = math.Max(0, math.Min(1, ratio))
		usedPct := ufARound(ratio * 100)
		var resetAt any
		if w.key == "monthly" {
			resetAt = monthlyResetAt
		}
		quotas[w.label] = db.Record{
			"used":                usedPct,
			"total":               float64(100),
			"remainingPercentage": 100 - usedPct,
			"resetAt":             resetAt,
			"unlimited":           false,
		}
	}
	if len(quotas) == 0 {
		return db.Record{"plan": plan, "message": "Ollama Cloud connected. No usage limits reported.", "quotas": db.Record{}}, nil
	}
	return db.Record{"plan": plan, "quotas": quotas}, nil
}

// ufAAddUtcMonths ports addUtcMonths (day clamped to the target
// month's last day, UTC time-of-day preserved; JS also drops millis).
func ufAAddUtcMonths(d time.Time, months int) time.Time {
	total := int(d.Month()) - 1 + months
	year := d.Year() + total/12
	month := time.Month(((total%12)+12)%12 + 1)
	lastDay := time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
	day := d.Day()
	if day > lastDay {
		day = lastDay
	}
	return time.Date(year, month, day, d.Hour(), d.Minute(), d.Second(), 0, time.UTC)
}

// ufANextMonthlyReset ports nextMonthlyResetFromSignup.
func ufANextMonthlyReset(anchor, now time.Time) any {
	elapsedMonths := (now.Year()-anchor.Year())*12 + int(now.Month()) - int(anchor.Month())
	start := elapsedMonths
	if start < 0 {
		start = 0
	}
	for i := start; i <= elapsedMonths+1; i++ {
		candidate := ufAAddUtcMonths(anchor, i)
		if candidate.After(now) {
			return candidate.UTC().Format("2006-01-02T15:04:05.000Z")
		}
	}
	return nil
}
