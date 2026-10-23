package executors

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// XiaomiMimoExecutor ports open-sse/executors/xiaomi-mimo.js: a
// DefaultExecutor with a dual route for the v2.6 models
// (mimo-v2.6-pro / mimo-v2.6-flash / mimo-v2.6-pro-ultraspeed).
//
//   - Cloud route (default): the registry transports on
//     api.xiaomimimo.com (OpenAI format with Bearer key, Claude format with
//     x-api-key) — plain DefaultExecutor behaviour.
//   - Account route: when the connection carries desktop session
//     credentials (Specific["mimoPassToken"], or an already-resolved
//     account cookie), v2.6 models are served by the account service
//     (<mimo-server cluster>/api/route/chat/completions) authenticated with
//     a Xiaomi account-session COOKIE instead of the key, consuming the
//     weekly quota. The cookie is acquired by the two-phase serviceLogin
//     SSO handshake ported from open-sse/shared/mimoAccount.js (see
//     xmimoAcquireServiceCookie) and cached per passToken+cluster for
//     30 minutes; a 401 drops the cache and retries once with a fresh one.
//
// On the account route the body is also adjusted: reasoning_effort is
// bridged to output_config.effort (xhigh → high) and temperature/top_p
// default to 1.0 / 0.95 when absent.
//
// NOT ported: reading passToken from MiMo Desktop's Electron cookie DB
// (Chromium SQLite store, locked while Desktop runs) — connections without
// Specific["mimoPassToken"] simply stay on the cloud route, the same
// degrade the JS takes when the desktop jar is unavailable.
//
// Live-unverified: the real Xiaomi SSO endpoints and account service (no
// Xiaomi account here) — the handshake is exercised against httptest
// fixtures in xiaomi_mimo_test.go.
type XiaomiMimoExecutor struct{ *DefaultExecutor }

// NewXiaomiMimoExecutor builds the xiaomi-mimo executor.
func NewXiaomiMimoExecutor() *XiaomiMimoExecutor {
	x := &XiaomiMimoExecutor{DefaultExecutor: NewDefaultExecutor("xiaomi-mimo")}
	defaultBuildURL := x.Base.Hooks.BuildURL
	defaultBuildHeaders := x.Base.Hooks.BuildHeaders
	defaultTransform := x.Base.Hooks.TransformBody
	x.Base.Hooks.BuildURL = func(b *Base, req *Request, urlIndex int) (string, error) {
		if xmimoIsAccountRoute(req.Model, req.Cred) {
			return xmimoResolveMimoServerBase(req.Cred.Specific) + "/api/route/chat/completions", nil
		}
		return defaultBuildURL(b, req, urlIndex)
	}
	x.Base.Hooks.BuildHeaders = func(b *Base, req *Request, url string) (map[string]string, error) {
		if xmimoIsAccountRoute(req.Model, req.Cred) {
			if cookie := req.Cred.SpecificString(xmimoCookieKey); cookie != "" {
				accept := "application/json"
				if req.Stream {
					accept = "text/event-stream"
				}
				return map[string]string{
					"Content-Type": "application/json",
					"Accept":       accept,
					"User-Agent":   xmimoAPIUA,
					"Cookie":       cookie,
				}, nil
			}
		}
		return defaultBuildHeaders(b, req, url)
	}
	x.Base.Hooks.TransformBody = func(b *Base, req *Request) (map[string]any, error) {
		out, err := defaultTransform(b, req)
		if err != nil || out == nil {
			return out, err
		}
		if !xmimoIsAccountRoute(req.Model, req.Cred) {
			return out, nil
		}
		// Bridge reasoning_effort → output_config.effort (MiMo Desktop
		// behaviour): out.reasoning_effort || body.reasoning_effort ||
		// body.output_config.effort.
		var rawEffort any
		if v := out["reasoning_effort"]; xmimoTruthy(v) {
			rawEffort = v
		} else if req.Body != nil && xmimoTruthy(req.Body["reasoning_effort"]) {
			rawEffort = req.Body["reasoning_effort"]
		} else if req.Body != nil {
			if oc, _ := req.Body["output_config"].(map[string]any); oc != nil && xmimoTruthy(oc["effort"]) {
				rawEffort = oc["effort"]
			}
		}
		if xmimoTruthy(rawEffort) {
			delete(out, "reasoning_effort")
			norm := strings.ToLower(xmimoEffortString(rawEffort))
			if norm == "xhigh" {
				norm = "high"
			}
			oc := map[string]any{}
			if existing, _ := out["output_config"].(map[string]any); existing != nil {
				oc = cloneMap(existing)
			}
			oc["effort"] = norm
			out["output_config"] = oc
		}
		if out["temperature"] == nil {
			out["temperature"] = 1.0
		}
		if out["top_p"] == nil {
			out["top_p"] = 0.95
		}
		return out, nil
	}
	return x
}

// xmimoCookieKey is the JS COOKIE_KEY: where the resolved account cookie is
// carried on the per-request credentials (here: inside Specific, the Go
// credentials' providerSpecificData bag).
const xmimoCookieKey = "__mimoAccountCookie"

// xmimoAccountModels is the JS ACCOUNT_MODELS set (dual-route v2.6 models).
var xmimoAccountModels = map[string]bool{
	"mimo-v2.6-pro":            true,
	"mimo-v2.6-flash":          true,
	"mimo-v2.6-pro-ultraspeed": true,
}

// xmimoBareModel ports bareModel: strip a `provider/` prefix if present.
func xmimoBareModel(model string) string {
	if i := strings.Index(model, "/"); i >= 0 {
		return model[i+1:]
	}
	return model
}

// xmimoIsAccountRoute ports XiaomiMimoExecutor.isAccountRoute.
func xmimoIsAccountRoute(model string, cred Credential) bool {
	if !xmimoAccountModels[xmimoBareModel(model)] {
		return false
	}
	return cred.SpecificString(xmimoCookieKey) != "" || cred.SpecificString("mimoPassToken") != ""
}

func xmimoTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return t != ""
	case bool:
		return t
	case json.Number:
		f, _ := t.Float64()
		return f != 0
	case float64:
		return t != 0
	}
	return true
}

func xmimoEffortString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	raw, _ := json.Marshal(v)
	return string(raw)
}

func xmimoCredWithCookie(cred Credential, cookie string) Credential {
	out := cred
	specific := make(map[string]any, len(cred.Specific)+1)
	for k, v := range cred.Specific {
		specific[k] = v
	}
	specific[xmimoCookieKey] = cookie
	out.Specific = specific
	return out
}

// Execute ports XiaomiMimoExecutor.execute: non-account models go straight
// to DefaultExecutor; account models resolve the session cookie first (and
// retry once with a fresh cookie on a 401).
func (x *XiaomiMimoExecutor) Execute(ctx context.Context, p *ProviderInfo, cred Credential, body []byte) (*ExecResult, error) {
	model := ModelOf(BodyMap(body))
	if !xmimoIsAccountRoute(model, cred) {
		return x.Base.Execute(ctx, p, cred, body)
	}
	cookie := xmimoGetAccountCookie(ctx, cred.Specific)
	if cookie == "" {
		return x.Base.Execute(ctx, p, cred, body)
	}
	result, err := x.Base.Execute(ctx, p, xmimoCredWithCookie(cred, cookie), body)
	if err != nil || result == nil || result.Response == nil {
		return result, err
	}
	// A cached session can expire early — drop it and retry once fresh.
	if result.Response.StatusCode == 401 {
		xmimoInvalidateAccountCookieCache()
		fresh := xmimoGetAccountCookie(ctx, cred.Specific)
		if fresh != "" {
			drainClose(result.Response)
			return x.Base.Execute(ctx, p, xmimoCredWithCookie(cred, fresh), body)
		}
	}
	return result, nil
}

// --- mimoAccount.js port: account-service session cookie ---

// xmimoAPIBaseByRegion is API_BASE_BY_REGION (MiMo Desktop clusters).
var xmimoAPIBaseByRegion = map[string]string{
	"cn":  "https://mimo-server-cn.xiaomimimo.com",
	"sgp": "https://mimo-server-sgp.xiaomimimo.com",
	"ams": "https://mimo-server-ams.xiaomimimo.com",
	"ru":  "https://mimo-server-ru.xiaomimimo.com",
	"in":  "https://mimo-server-in.xiaomimimo.com",
}

const xmimoDefaultAPIBase = "https://mimo-server-sgp.xiaomimimo.com"

// xmimoSIDByRegion is SID_BY_REGION (cluster service sid: mimo<code>,
// except CN's legacy "mimopc").
var xmimoSIDByRegion = map[string]string{
	"cn": "mimopc", "sgp": "mimosgp", "ams": "mimoams", "ru": "mimoru", "in": "mimoin",
}

func xmimoSIDForRegion(region string) string {
	if sid, ok := xmimoSIDByRegion[strings.ToLower(region)]; ok {
		return sid
	}
	return xmimoSIDByRegion["sgp"]
}

// xmimoAPIUA is MIMO_API_UA (the User-Agent the account backend expects);
// xmimoSSOUA is the SSO handshake's User-Agent.
const xmimoAPIUA = "miNative PC/Normal Windows_NT/10.0.19045 SDKV/1.0.0 DEVT/PC DEVS/Windows APP/miaccount_desktop APPV/0.1.0"
const xmimoSSOUA = "MiClaw/1.0"

const xmimoCookieTTL = 30 * time.Minute

// xmimoAccountBase is the Xiaomi account host (ACCOUNT_HOST). A var purely
// as a test seam for the SSO handshake fixtures.
var xmimoAccountBase = "https://account.xiaomi.com"

// xmimoServerBaseOverride, when non-empty, replaces the resolved
// account-service base (test seam for httptest fixtures; production value
// is always "").
var xmimoServerBaseOverride = ""

// xmimoResolveMimoServerBase ports resolveMimoServerBase: cluster base from
// Specific["region"], SGP by default.
func xmimoResolveMimoServerBase(specific map[string]any) string {
	if xmimoServerBaseOverride != "" {
		return strings.TrimSuffix(xmimoServerBaseOverride, "/")
	}
	region := strings.ToLower(xmimoSpecificString(specific, "region"))
	if base, ok := xmimoAPIBaseByRegion[region]; ok {
		return base
	}
	return xmimoDefaultAPIBase
}

func xmimoSpecificString(specific map[string]any, key string) string {
	if specific == nil {
		return ""
	}
	s, _ := specific[key].(string)
	return s
}

// xmimoCookieJar is an insertion-ordered cookie jar (JS plain-object jar).
type xmimoCookieJar struct {
	order []string
	vals  map[string]string
}

func xmimoNewCookieJar() *xmimoCookieJar {
	return &xmimoCookieJar{vals: map[string]string{}}
}

func (j *xmimoCookieJar) set(name, value string) {
	if _, ok := j.vals[name]; !ok {
		j.order = append(j.order, name)
	}
	j.vals[name] = value
}

func (j *xmimoCookieJar) get(name string) string { return j.vals[name] }

// absorb ports absorbSetCookie (only name=value with a non-empty value).
func (j *xmimoCookieJar) absorb(resp *http.Response) {
	if resp == nil {
		return
	}
	for _, c := range resp.Cookies() {
		if c.Value != "" {
			j.set(c.Name, c.Value)
		}
	}
}

// header ports cookieHeader, optionally filtered by a name predicate.
func (j *xmimoCookieJar) header(keep func(string) bool) string {
	var parts []string
	for _, name := range j.order {
		v := j.vals[name]
		if v == "" {
			continue
		}
		if keep != nil && !keep(name) {
			continue
		}
		parts = append(parts, name+"="+v)
	}
	return strings.Join(parts, "; ")
}

var xmimoNonceRe = regexp.MustCompile(`"nonce"\s*:\s*(\d+)`)
var xmimoCookieKeepRe = regexp.MustCompile(`_(ph|slh)$`)

// xmimoSignatureClientSign ports signatureClientSign:
// sha1("nonce=<nonce>[&<ssecurity>]") → base64 → encodeURIComponent.
func xmimoSignatureClientSign(nonce, ssecurity string) string {
	input := "nonce=" + nonce
	if strings.TrimSpace(ssecurity) != "" {
		input += "&" + ssecurity
	}
	sum := sha1.Sum([]byte(input))
	encoded := base64.StdEncoding.EncodeToString(sum[:])
	// encodeURIComponent ≈ QueryEscape for the base64 alphabet, except
	// spaces (none here) and a few marks QueryEscape leaves alone anyway.
	return strings.ReplaceAll(url.QueryEscape(encoded), "+", "%20")
}

// --- Cookie cache (JS _cache, keyed per passToken+cluster) ---

type xmimoCachedCookie struct {
	cookie string
	at     time.Time
}

var (
	xmimoCookieCacheMu sync.Mutex
	xmimoCookieCache   = map[string]xmimoCachedCookie{}
)

func xmimoCookieCacheKey(apiBase, passToken string) string {
	sum := sha256.Sum256([]byte(apiBase + "|" + passToken))
	return hex.EncodeToString(sum[:])
}

// xmimoInvalidateAccountCookieCache ports invalidateMimoAccountCookieCache.
func xmimoInvalidateAccountCookieCache() {
	xmimoCookieCacheMu.Lock()
	defer xmimoCookieCacheMu.Unlock()
	xmimoCookieCache = map[string]xmimoCachedCookie{}
}

// xmimoGetAccountCookie ports getMimoAccountCookie (+ getServiceCookie's
// cache layer): the cached cookie when fresh, else a new SSO handshake.
// Returns "" on any failure — callers degrade to the cloud route, never
// throw (JS semantics).
func xmimoGetAccountCookie(ctx context.Context, specific map[string]any) string {
	passToken := xmimoSpecificString(specific, "mimoPassToken")
	if passToken == "" {
		// JS fallback: read MiMo Desktop's cookie DB — NOT ported (see the
		// type comment), so no passJar is available here.
		return ""
	}
	apiBase := xmimoResolveMimoServerBase(specific)
	key := xmimoCookieCacheKey(apiBase, passToken)
	xmimoCookieCacheMu.Lock()
	if cached, ok := xmimoCookieCache[key]; ok && time.Since(cached.at) < xmimoCookieTTL {
		cookie := cached.cookie
		xmimoCookieCacheMu.Unlock()
		return cookie
	}
	xmimoCookieCacheMu.Unlock()

	jar := xmimoNewCookieJar()
	jar.set("passToken", passToken)
	if v := xmimoSpecificString(specific, "mimoUserId"); v != "" {
		jar.set("userId", v)
	}
	if v := xmimoSpecificString(specific, "mimoCUserId"); v != "" {
		jar.set("cUserId", v)
	}
	region := strings.ToLower(xmimoSpecificString(specific, "region"))
	cookie := xmimoAcquireServiceCookie(ctx, jar, region)
	if cookie == "" {
		return ""
	}
	xmimoCookieCacheMu.Lock()
	xmimoCookieCache[key] = xmimoCachedCookie{cookie: cookie, at: time.Now()}
	xmimoCookieCacheMu.Unlock()
	return cookie
}

// xmimoAcquireServiceCookie ports acquireServiceCookie (desktop 2-phase
// path). NOTE: the JS forces a direct connection for the CN cluster
// (ignores proxyOptions); Go's HTTPClient proxy handling is the parent's
// transport concern and is used as-is here.
func xmimoAcquireServiceCookie(ctx context.Context, passJar *xmimoCookieJar, region string) string {
	sid := xmimoSIDForRegion(region)
	return xmimoAcquireViaDesktopPhases(ctx, passJar, sid)
}

// xmimoAcquireViaDesktopPhases ports acquireViaDesktopPhases:
// PHASE 1 serviceLogin (sid-scoped) → {code, location, ssecurity, nonce};
// PHASE 2 GET {location}&clientSign=sha1(...) with NO Cookie header,
// following the redirect chain manually and absorbing Set-Cookie until a
// serviceToken lands.
func xmimoAcquireViaDesktopPhases(ctx context.Context, passJar *xmimoCookieJar, sid string) string {
	jar := xmimoNewCookieJar()
	for _, name := range passJar.order {
		jar.set(name, passJar.vals[name])
	}

	// PHASE 1 — Desktop only sends userId, passToken, cUserId.
	p1Jar := xmimoNewCookieJar()
	if v := jar.get("userId"); v != "" {
		p1Jar.set("userId", v)
	}
	if v := jar.get("passToken"); v != "" {
		p1Jar.set("passToken", v)
	}
	if v := jar.get("cUserId"); v != "" {
		p1Jar.set("cUserId", v)
	}
	p1URL := xmimoAccountBase + "/pass/serviceLogin?_locale=zh_CN&_snsNone=true&sid=" + url.QueryEscape(sid) + "&_json=true"
	p1Req, err := http.NewRequestWithContext(ctx, http.MethodGet, p1URL, nil)
	if err != nil {
		return ""
	}
	p1Req.Header.Set("Cookie", p1Jar.header(nil))
	p1Req.Header.Set("User-Agent", xmimoSSOUA)
	p1Req.Header.Set("Accept", "application/json")
	p1, err := HTTPClient.Do(p1Req)
	if err != nil {
		return ""
	}
	rawBytes, err := io.ReadAll(p1.Body)
	jar.absorb(p1)
	p1.Body.Close()
	if err != nil {
		return ""
	}
	raw := strings.TrimPrefix(string(rawBytes), "&&&START&&&")
	// Nonce > 2^53 loses precision in JSON parsing — extract the raw
	// literal for signing (JS does the same).
	rawNonce := ""
	if m := xmimoNonceRe.FindStringSubmatch(raw); m != nil {
		rawNonce = m[1]
	}
	var j map[string]any
	if err := json.Unmarshal([]byte(raw), &j); err != nil || j == nil {
		return ""
	}
	nonce := rawNonce
	if nonce == "" {
		if n := getFloat(j, "nonce"); n != 0 {
			nonce = xmimoFormatNonce(n)
		}
	}
	if _, hasCode := j["code"]; !hasCode || getFloat(j, "code") != 0 || getStr(j, "location") == "" || nonce == "" || getStr(j, "ssecurity") == "" {
		return ""
	}

	// PHASE 2 — clientSign the redirect; MUST NOT send any Cookie header.
	sep := "?"
	if strings.Contains(getStr(j, "location"), "?") {
		sep = "&"
	}
	current := getStr(j, "location") + sep + "clientSign=" + xmimoSignatureClientSign(nonce, getStr(j, "ssecurity"))
	noRedirect := &http.Client{
		Transport: HTTPClient.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for hop := 0; hop < 8; hop++ {
		hopReq, err := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
		if err != nil {
			return ""
		}
		hopReq.Header.Set("User-Agent", xmimoSSOUA)
		res, err := noRedirect.Do(hopReq)
		if err != nil {
			return ""
		}
		jar.absorb(res)
		loc := res.Header.Get("Location")
		status := res.StatusCode
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<20))
		res.Body.Close()
		if status >= 300 && status < 400 && loc != "" {
			next, err := url.Parse(current)
			if err != nil {
				return ""
			}
			ref, err := url.Parse(loc)
			if err != nil {
				return ""
			}
			current = next.ResolveReference(ref).String()
			continue
		}
		break
	}

	sidKey := sid + "_serviceToken"
	if jar.get("serviceToken") == "" && jar.get(sidKey) != "" {
		jar.set("serviceToken", jar.get(sidKey))
	}
	if jar.get("serviceToken") == "" {
		return ""
	}
	// Only the service token, userId and *_ph/*_slh cookies are kept.
	return jar.header(func(name string) bool {
		return name == "serviceToken" || name == "userId" || xmimoCookieKeepRe.MatchString(name)
	})
}

// xmimoFormatNonce renders a JSON-parsed nonce without exponent notation.
func xmimoFormatNonce(f float64) string {
	raw, _ := json.Marshal(int64(f))
	return string(raw)
}
