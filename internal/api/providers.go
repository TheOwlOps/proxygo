// providers.go — Team F registrar: providers, provider-nodes, combos,
// models, tags and proxy-pools dashboard APIs.
//
// Faithful port of the Next.js routes under src/app/api/{providers,
// provider-nodes,combos,models,tags,proxy-pools}. All shared helpers are
// prefixed "pv" to avoid colliding with sibling registrars in this package.
//
// Team X follow-up (providers leftovers) — all former gaps below are now
// ported: OAuth refresh for codex/grok-cli/xai/nous delegates to
// internal/oauthsvc; live model resolvers for cursor (via internal/
// executors), kimchi, cline, clinepass, grok-cli, kiro, qoder/qoder-cn
// (incl. COSY signing) and zed; the Bedrock credential probe (SigV4) for
// test + validate (static credentials only — JS profile mode needs the
// AWS SDK, unavailable to this port, same as internal/executors); the
// Vercel-relay URL rewrite in pvFetchViaProxy; the model-catalog sync
// engine (sync.js) incl. the catalogOverride reader wired into
// pvRefineCaps and the background timer; combo rotation reset on
// update/delete via chatcore.ResetComboRotation.
package api

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"proxygo/internal/db"
	"proxygo/internal/executors"
	"proxygo/internal/modelcatalog"
	"proxygo/internal/oauthsvc"
	"proxygo/internal/providers"
)

// RegisterProviders mounts every Team F route.
func RegisterProviders(mux *http.ServeMux, deps Deps) {
	// JS starts the daily model-catalog syncer from the server
	// instrumentation hook; registration is the Go equivalent point.
	pvStartCatalogSync()
	w := func(h http.HandlerFunc) http.HandlerFunc { return Wrap(deps, h) }

	// providers
	mux.HandleFunc("GET /api/providers", w(pvProvidersList(deps)))
	mux.HandleFunc("POST /api/providers", w(pvProvidersCreate(deps)))
	mux.HandleFunc("GET /api/providers/client", w(pvProvidersClient(deps)))
	mux.HandleFunc("POST /api/providers/validate", w(pvProvidersValidate(deps)))
	mux.HandleFunc("POST /api/providers/test-batch", w(pvProvidersTestBatch(deps)))
	mux.HandleFunc("GET /api/providers/suggested-models", w(pvSuggestedModels(deps)))
	mux.HandleFunc("GET /api/providers/kilo/free-models", w(pvKiloFreeModels(deps)))
	mux.HandleFunc("GET /api/providers/{id}", w(pvProviderGet(deps)))
	mux.HandleFunc("PUT /api/providers/{id}", w(pvProviderUpdate(deps)))
	mux.HandleFunc("DELETE /api/providers/{id}", w(pvProviderDelete(deps)))
	mux.HandleFunc("GET /api/providers/{id}/models", w(pvProviderModels(deps)))
	mux.HandleFunc("GET /api/providers/{id}/overrides", w(pvProviderOverridesGet(deps)))
	mux.HandleFunc("PUT /api/providers/{id}/overrides", w(pvProviderOverridesPut(deps)))
	mux.HandleFunc("POST /api/providers/{id}/test", w(pvProviderTest(deps)))
	mux.HandleFunc("POST /api/providers/{id}/test-models", w(pvProviderTestModels(deps)))

	// provider-nodes
	mux.HandleFunc("GET /api/provider-nodes", w(pvNodesList(deps)))
	mux.HandleFunc("POST /api/provider-nodes", w(pvNodesCreate(deps)))
	mux.HandleFunc("POST /api/provider-nodes/validate", w(pvNodesValidate(deps)))
	mux.HandleFunc("PUT /api/provider-nodes/{id}", w(pvNodeUpdate(deps)))
	mux.HandleFunc("DELETE /api/provider-nodes/{id}", w(pvNodeDelete(deps)))

	// combos
	mux.HandleFunc("GET /api/combos", w(pvCombosList(deps)))
	mux.HandleFunc("POST /api/combos", w(pvCombosCreate(deps)))
	mux.HandleFunc("GET /api/combos/presets", w(pvComboPresetsGet(deps)))
	mux.HandleFunc("POST /api/combos/presets", w(pvComboPresetsPost(deps)))
	mux.HandleFunc("GET /api/combos/{id}", w(pvComboGet(deps)))
	mux.HandleFunc("PUT /api/combos/{id}", w(pvComboUpdate(deps)))
	mux.HandleFunc("DELETE /api/combos/{id}", w(pvComboDelete(deps)))

	// models
	mux.HandleFunc("GET /api/models", w(pvModelsList(deps)))
	mux.HandleFunc("PUT /api/models", w(pvModelsSetAlias(deps)))
	mux.HandleFunc("GET /api/models/alias", w(pvAliasList(deps)))
	mux.HandleFunc("PUT /api/models/alias", w(pvAliasPut(deps)))
	mux.HandleFunc("DELETE /api/models/alias", w(pvAliasDelete(deps)))
	mux.HandleFunc("GET /api/models/custom", w(pvCustomList(deps)))
	mux.HandleFunc("POST /api/models/custom", w(pvCustomCreate(deps)))
	mux.HandleFunc("DELETE /api/models/custom", w(pvCustomDelete(deps)))
	mux.HandleFunc("GET /api/models/disabled", w(pvDisabledList(deps)))
	mux.HandleFunc("POST /api/models/disabled", w(pvDisabledPost(deps)))
	mux.HandleFunc("DELETE /api/models/disabled", w(pvDisabledDelete(deps)))
	mux.HandleFunc("GET /api/models/availability", w(pvAvailabilityList(deps)))
	mux.HandleFunc("POST /api/models/availability", w(pvAvailabilityPost(deps)))
	mux.HandleFunc("GET /api/models/catalog-sync", w(pvCatalogSyncGet(deps)))
	mux.HandleFunc("POST /api/models/catalog-sync", w(pvCatalogSyncPost(deps)))
	mux.HandleFunc("POST /api/models/test", w(pvModelTest(deps)))

	// tags (Ollama-compatible static payload)
	mux.HandleFunc("GET /api/tags", w(pvTagsGet))
	mux.HandleFunc("OPTIONS /api/tags", w(pvTagsOptions))

	// proxy-pools
	mux.HandleFunc("GET /api/proxy-pools", w(pvPoolsList(deps)))
	mux.HandleFunc("POST /api/proxy-pools", w(pvPoolsCreate(deps)))
	mux.HandleFunc("POST /api/proxy-pools/cloudflare-deploy", w(pvPoolDeployCloudflare(deps)))
	mux.HandleFunc("POST /api/proxy-pools/deno-deploy", w(pvPoolDeployDeno(deps)))
	mux.HandleFunc("POST /api/proxy-pools/netlify-deploy", w(pvPoolDeployNetlify(deps)))
	mux.HandleFunc("POST /api/proxy-pools/vercel-deploy", w(pvPoolDeployVercel(deps)))
	mux.HandleFunc("GET /api/proxy-pools/{id}", w(pvPoolGet(deps)))
	mux.HandleFunc("PUT /api/proxy-pools/{id}", w(pvPoolUpdate(deps)))
	mux.HandleFunc("DELETE /api/proxy-pools/{id}", w(pvPoolDelete(deps)))
	mux.HandleFunc("POST /api/proxy-pools/{id}/test", w(pvPoolTest(deps)))
}

// ---------- small value helpers (db.Record / JSON body access) ----------

func pvStr(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	if s, ok := m[k].(string); ok {
		return s
	}
	return ""
}

func pvStrOr(m map[string]any, k string, def string) string {
	if s := pvStr(m, k); s != "" {
		return s
	}
	return def
}

// pvNum reads a JSON number (float64) from a record/body map.
func pvNum(m map[string]any, k string) (float64, bool) {
	if m == nil {
		return 0, false
	}
	switch v := m[k].(type) {
	case float64:
		return v, true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	}
	return 0, false
}

func pvBool(m map[string]any, k string) bool {
	if m == nil {
		return false
	}
	b, _ := m[k].(bool)
	return b
}

func pvHas(m map[string]any, k string) bool {
	if m == nil {
		return false
	}
	_, ok := m[k]
	return ok
}

func pvMap(m map[string]any, k string) map[string]any {
	if m == nil {
		return nil
	}
	if v, ok := m[k].(map[string]any); ok {
		return v
	}
	return nil
}

func pvSlice(m map[string]any, k string) []any {
	if m == nil {
		return nil
	}
	if v, ok := m[k].([]any); ok {
		return v
	}
	return nil
}

func pvCloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func pvStrSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func pvNowISO() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
}

func pvNowMs() int64 { return time.Now().UnixMilli() }

func pvUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// pvBase36Millis renders a unix-millis timestamp like JS Date.now().toString(36).
func pvBase36Millis() string {
	return strconv.FormatInt(time.Now().UnixMilli(), 36)
}

// pvParseTimeMs mirrors oauthCredentialManager.parseTimeMs: accepts ISO
// strings and epoch numbers (seconds or millis).
func pvParseTimeMs(v any) (int64, bool) {
	switch t := v.(type) {
	case string:
		if t == "" {
			return 0, false
		}
		if parsed, err := time.Parse(time.RFC3339Nano, t); err == nil {
			return parsed.UnixMilli(), true
		}
		if f, err := strconv.ParseFloat(t, 64); err == nil {
			return pvEpochToMs(f), true
		}
	case float64:
		return pvEpochToMs(t), true
	case int64:
		return pvEpochToMs(float64(t)), true
	}
	return 0, false
}

func pvEpochToMs(f float64) int64 {
	if f > 1e12 { // already millis
		return int64(f)
	}
	return int64(f * 1000)
}

// pvErrText extracts a JS-Error-like message from a Go error.
func pvErrText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// ---------- HTTP fetch machinery (mockable) ----------

// pvHTTPDo is the single funnel for outbound HTTP so tests can stub it.
var pvHTTPDo = func(req *http.Request) (*http.Response, error) {
	return http.DefaultClient.Do(req)
}

// pvFetchResult mirrors the bits of a fetch Response the JS routes use.
type pvFetchResult struct {
	Status     int
	StatusText string
	OK         bool
	Body       []byte
	Headers    http.Header
}

func (r *pvFetchResult) JSON() (any, error) {
	var v any
	err := json.Unmarshal(r.Body, &v)
	return v, err
}

func (r *pvFetchResult) JSONMap() map[string]any {
	v, err := r.JSON()
	if err != nil {
		return nil
	}
	m, _ := v.(map[string]any)
	return m
}

func (r *pvFetchResult) Text() string { return string(r.Body) }

// pvProxiedDo builds the Do function for a proxied request. It is a var so
// tests can substitute the transport without a live proxy.
var pvProxiedDo = func(proxyURL string) (func(*http.Request) (*http.Response, error), error) {
	pu, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	return client.Do, nil
}

// pvFetch performs one HTTP request. timeout<=0 means no client timeout
// (JS fetch default). proxyURL, when non-empty, routes through that proxy
// (Go's transport also honours socks5:// proxy URLs).
func pvFetch(ctx context.Context, method, rawURL string, headers map[string]string, body []byte, timeout time.Duration, proxyURL string) (*pvFetchResult, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rdr)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	do := pvHTTPDo
	if proxyURL != "" {
		if doFn, perr := pvProxiedDo(proxyURL); perr == nil && doFn != nil {
			do = doFn
		}
	}
	resp, err := do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	return &pvFetchResult{
		Status:     resp.StatusCode,
		StatusText: resp.Status,
		OK:         resp.StatusCode >= 200 && resp.StatusCode < 300,
		Body:       data,
		Headers:    resp.Header,
	}, nil
}

func pvFetchJSON(ctx context.Context, method, rawURL string, headers map[string]string, payload any, timeout time.Duration, proxyURL string) (*pvFetchResult, error) {
	var body []byte
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = b
		if headers == nil {
			headers = map[string]string{}
		}
		if _, ok := headers["Content-Type"]; !ok {
			headers["Content-Type"] = "application/json"
		}
	}
	return pvFetch(ctx, method, rawURL, headers, body, timeout, proxyURL)
}

// pvFetchErrMessage maps Go network errors to the JS getErrorMessage texts
// used by proxyTest / node validation. Go error strings differ from Node
// cause codes, so this matches on substrings.
func pvFetchErrMessage(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return "Request timeout - provider not responding"
	}
	switch {
	case strings.Contains(msg, "connection refused"):
		return "Connection refused - check if the URL is correct and the service is running"
	case strings.Contains(msg, "no such host"), strings.Contains(msg, "server misbehaving"):
		return "DNS lookup failed - check the URL hostname"
	case strings.Contains(msg, "certificate"), strings.Contains(msg, "x509"), strings.Contains(msg, "tls:"):
		return "SSL/TLS certificate error - the provider may have an invalid certificate"
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline exceeded"):
		return "Request timeout - provider not responding"
	}
	return "Network connection failed - check URL and network connectivity"
}

// ---------- registry helpers ----------

func pvReg(id string) (*providers.Provider, bool) {
	if id == "" {
		return nil, false
	}
	return providers.Get(id)
}

// pvNormalizeProviderId ports providerNormalization.normalizeProviderId.
func pvNormalizeProviderId(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return trimmed
	}
	if p, ok := providers.Get(trimmed); ok && p.ID == trimmed {
		return trimmed
	}
	slug := pvSlugify(trimmed)
	if slug != trimmed {
		if _, ok := providers.Get(slug); ok {
			return slug
		}
	}
	lower := strings.ToLower(trimmed)
	for _, p := range providers.All() {
		if strings.ToLower(p.Display.Name) == lower {
			return p.ID
		}
	}
	return trimmed
}

var pvSlugRe = regexp.MustCompile(`[^a-z0-9]+`)

func pvSlugify(s string) string {
	return pvSlugRe.ReplaceAllString(strings.ToLower(s), "-")
}

func pvRawStr(p *providers.Provider, k string) string {
	if p == nil {
		return ""
	}
	if s, ok := p.Raw[k].(string); ok {
		return s
	}
	return ""
}

func pvRawBool(p *providers.Provider, k string) bool {
	if p == nil {
		return false
	}
	b, _ := p.Raw[k].(bool)
	return b
}

func pvRawMap(p *providers.Provider, k string) map[string]any {
	if p == nil {
		return nil
	}
	if m, ok := p.Raw[k].(map[string]any); ok {
		return m
	}
	return nil
}

func pvAuthModes(p *providers.Provider) []string {
	if p == nil {
		return nil
	}
	return pvStrSlice(p.Raw["authModes"])
}

func pvHasAuthMode(p *providers.Provider, mode string) bool {
	for _, m := range pvAuthModes(p) {
		if m == mode {
			return true
		}
	}
	return false
}

func pvIsWebCookie(provider string) bool {
	p, ok := pvReg(provider)
	return ok && p.Category == "webCookie"
}

// pvUsesAwsForm ports usesAwsCredentialForm (registry credentialForm==="aws").
func pvUsesAwsForm(provider string) bool {
	p, ok := pvReg(provider)
	return ok && pvRawStr(p, "credentialForm") == "aws"
}

// pvApiKeySubstituteField ports the apiKeyOptionalWith logic: returns the
// providerSpecificData field that can substitute for an API key ("" = none).
func pvApiKeySubstituteField(provider string, psd map[string]any) string {
	p, ok := pvReg(provider)
	if !ok {
		return ""
	}
	field := pvRawStr(p, "apiKeyOptionalWith")
	if field == "" {
		return ""
	}
	if s := pvStr(psd, field); strings.TrimSpace(s) != "" {
		return field
	}
	return ""
}

// pvDefaultModel ports getDefaultModel(providerId): first catalog model id.
func pvDefaultModel(provider string) string {
	models := modelcatalog.Models(provider)
	for _, m := range models {
		if id := pvStr(m, "id"); id != "" {
			return id
		}
	}
	if p, ok := pvReg(provider); ok {
		for _, m := range p.Models {
			if m.ID != "" {
				return m.ID
			}
		}
	}
	return ""
}

// pvCatalogModels returns the static model entries for a provider
// (getProviderModels equivalent, Team K catalog).
func pvCatalogModels(provider string) []map[string]any {
	return modelcatalog.Models(provider)
}

// pvProviderAlias ports PROVIDER_ID_TO_ALIAS lookups.
func pvProviderAlias(provider string) string {
	if p, ok := pvReg(provider); ok && p.Alias != "" {
		return p.Alias
	}
	return provider
}

// pvAliasToID ports ALIAS_TO_ID.
func pvAliasToID(alias string) string {
	if p, ok := pvReg(alias); ok {
		return p.ID
	}
	return alias
}

// ---------- connection response shaping ----------

// pvSafeConnection ports toProviderConnectionResponse: strips secrets.
func pvSafeConnection(conn db.Record) map[string]any {
	if conn == nil {
		return nil
	}
	out := pvCloneMap(conn)
	for _, k := range []string{"apiKey", "accessToken", "refreshToken", "idToken"} {
		delete(out, k)
	}
	if pvUsesAwsForm(pvStr(conn, "provider")) {
		if psd := pvMap(out, "providerSpecificData"); psd != nil {
			cp := pvCloneMap(psd)
			delete(cp, "sessionToken")
			out["providerSpecificData"] = cp
		}
	}
	return out
}

func pvConnPSD(conn db.Record) map[string]any {
	return pvMap(conn, "providerSpecificData")
}

func pvIsCompatProvider(provider string) (openaiCompat, anthropicCompat, customEmbedding bool) {
	return strings.HasPrefix(provider, "openai-compatible-"),
		strings.HasPrefix(provider, "anthropic-compatible-"),
		strings.HasPrefix(provider, "custom-embedding-")
}

func pvAnyCompat(provider string) bool {
	a, b, c := pvIsCompatProvider(provider)
	return a || b || c
}

// ---------- connection proxy resolution (connectionProxy.js port) ----------

type pvProxyConfig struct {
	Source                 string
	ProxyPoolID            string
	ConnectionProxyEnabled bool
	ConnectionProxyURL     string
	ConnectionNoProxy      string
	StrictProxy            bool
	VercelRelayURL         string // relay-type pools (vercel/cloudflare/deno/netlify)
}

func pvTrimStr(v any) string {
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

// pvNormalizeProxyConfig ports normalizeProxyConfig from the providers
// route: validates the legacy per-connection proxy fields of a request body.
func pvNormalizeProxyConfig(body map[string]any) (enabled bool, proxyURL, noProxy string, errMsg string) {
	enabled = pvBool(body, "connectionProxyEnabled")
	proxyURL = pvTrimStr(body["connectionProxyUrl"])
	noProxy = pvTrimStr(body["connectionNoProxy"])
	if enabled && proxyURL == "" {
		return false, "", "", "Connection proxy URL is required when connection proxy is enabled"
	}
	return enabled, proxyURL, noProxy, ""
}

// pvResolveConnectionProxy ports resolveConnectionProxyConfig: pool first
// (psd.proxyPoolId), then legacy per-connection fields.
func pvResolveConnectionProxy(deps Deps, psd map[string]any) pvProxyConfig {
	legacyEnabled := pvBool(psd, "connectionProxyEnabled")
	legacyURL := pvTrimStr(psd["connectionProxyUrl"])
	legacyNoProxy := pvTrimStr(psd["connectionNoProxy"])
	out := pvProxyConfig{
		Source:                 "none",
		ConnectionProxyEnabled: legacyEnabled,
		ConnectionProxyURL:     legacyURL,
		ConnectionNoProxy:      legacyNoProxy,
	}
	poolID := pvTrimStr(psd["proxyPoolId"])
	if poolID == "" || poolID == "__none__" {
		if legacyEnabled && legacyURL != "" {
			out.Source = "legacy"
		}
		return out
	}
	out.ProxyPoolID = poolID
	pool, err := deps.Store.GetProxyPoolByID(poolID)
	if err != nil || pool == nil {
		// Unusable pool: keep any strict guarantee, fall back to legacy.
		if legacyEnabled && legacyURL != "" {
			out.Source = "legacy"
		}
		return out
	}
	poolStrict := pvBool(pool, "strictProxy")
	out.StrictProxy = poolStrict
	poolURL := pvTrimStr(pool["proxyUrl"])
	poolNoProxy := pvTrimStr(pool["noProxy"])
	isValidPool := pvBool(pool, "isActive") && poolURL != ""
	if !isValidPool {
		if legacyEnabled && legacyURL != "" {
			out.Source = "legacy"
		}
		return out
	}
	poolType := pvStrOr(pool, "type", "http")
	if poolType == "vercel" || poolType == "cloudflare" || poolType == "deno" || poolType == "netlify" {
		out.Source = poolType
		out.ConnectionProxyEnabled = false
		out.ConnectionProxyURL = ""
		out.ConnectionNoProxy = poolNoProxy
		out.VercelRelayURL = poolURL
		return out
	}
	out.Source = "pool"
	out.ConnectionProxyEnabled = true
	out.ConnectionProxyURL = poolURL
	out.ConnectionNoProxy = poolNoProxy
	return out
}

// pvProxyURLForFetch returns the proxy URL to hand to pvFetch for a resolved
// config, or "" for direct. Relay proxies rewrite URLs instead of acting as
// HTTP proxies; that mode is handled inside pvFetchViaProxy, so this helper
// only ever yields the plain HTTP-proxy URL.
func (c pvProxyConfig) pvProxyURLForFetch() string {
	if c.ConnectionProxyEnabled {
		return c.ConnectionProxyURL
	}
	return ""
}

// pvTestProxyURL ports testProxyUrl: HEAD https://google.com/ through the
// proxy (default timeout 8s).
func pvTestProxyURL(ctx context.Context, proxyURL string, timeout time.Duration) map[string]any {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	start := time.Now()
	res, err := pvFetch(ctx, http.MethodHead, "https://google.com/", map[string]string{"User-Agent": "ProxyGo"}, nil, timeout, proxyURL)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		msg := pvFetchErrMessage(err)
		var nerr net.Error
		if errors.As(err, &nerr) && nerr.Timeout() {
			msg = "Proxy test timed out"
		}
		return map[string]any{"ok": false, "status": 500, "error": msg}
	}
	return map[string]any{
		"ok":         res.OK,
		"status":     res.Status,
		"statusText": res.StatusText,
		"url":        "https://google.com/",
		"elapsedMs":  elapsed,
	}
}

// pvTestRelayURL ports testVercelRelay (used for relay-type pools).
func pvTestRelayURL(ctx context.Context, relayURL string) map[string]any {
	start := time.Now()
	res, err := pvFetch(ctx, http.MethodGet, relayURL, map[string]string{
		"x-relay-target": "https://httpbin.org",
		"x-relay-path":   "/get",
	}, nil, 10*time.Second, "")
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		return map[string]any{"ok": false, "status": 500, "error": pvFetchErrMessage(err), "elapsedMs": elapsed}
	}
	return map[string]any{"ok": res.OK, "status": res.Status, "statusText": res.StatusText, "elapsedMs": elapsed}
}

// ---------- providers CRUD ----------

// pvBuildNodeNameMap ports the GET-list nodeName enrichment.
func pvNodeNameMap(deps Deps) map[string]string {
	nodes, err := deps.Store.GetProviderNodes(db.NodeFilter{})
	if err != nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(nodes))
	for _, n := range nodes {
		out[pvStr(n, "id")] = pvStr(n, "name")
	}
	return out
}

func pvProvidersList(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conns, err := deps.Store.GetProviderConnections(db.ConnectionFilter{})
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to fetch providers")
			return
		}
		nodeNames := pvNodeNameMap(deps)
		out := make([]any, 0, len(conns))
		for _, c := range conns {
			safe := pvSafeConnection(c)
			oc, ac, _ := pvIsCompatProvider(pvStr(c, "provider"))
			if oc || ac {
				name := pvStr(c, "name")
				if name == "" {
					name = nodeNames[pvStr(c, "provider")]
				}
				if name == "" {
					name = pvStr(pvConnPSD(c), "nodeName")
				}
				if name == "" {
					name = pvStr(c, "provider")
				}
				safe["name"] = name
			}
			out = append(out, safe)
		}
		WriteJSON(w, http.StatusOK, map[string]any{"connections": out})
	}
}

// pvNormalizePSD ports normalizeProviderSpecificData (only ollama-local is
// special-cased upstream).
func pvNormalizePSD(provider string, body map[string]any, psd map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range psd {
		out[k] = v
	}
	if provider == "ollama-local" {
		base := pvStr(out, "baseUrl")
		if base == "" {
			base = pvStr(body, "baseUrl")
		}
		if base == "" {
			base = pvStr(body, "baseURL")
		}
		if base == "" {
			base = pvStr(body, "ollamaHostUrl")
		}
		if strings.TrimSpace(base) != "" {
			out["baseUrl"] = base
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func pvProvidersCreate(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
		provider := pvNormalizeProviderId(Str(body, "provider"))
		apiKey := Str(body, "apiKey")

		proxyEnabled, proxyURL, proxyNoProxy, perrMsg := pvNormalizeProxyConfig(body)
		if perrMsg != "" {
			Err(w, http.StatusBadRequest, perrMsg)
			return
		}

		// proxyPoolId: "__none__"/empty -> null; otherwise must exist.
		var proxyPoolID *string
		if pvHas(body, "proxyPoolId") {
			raw := pvTrimStr(body["proxyPoolId"])
			if raw != "" && raw != "__none__" {
				pool, perr := deps.Store.GetProxyPoolByID(raw)
				if perr != nil || pool == nil {
					Err(w, http.StatusBadRequest, "Proxy pool not found")
					return
				}
				proxyPoolID = &raw
			}
		}

		reg, regOK := pvReg(provider)
		isWebCookie := regOK && reg.Category == "webCookie"
		isValid := pvAnyCompat(provider)
		if regOK {
			if reg.Category == "apikey" || reg.Category == "freeTier" || isWebCookie || pvHasAuthMode(reg, "apikey") {
				isValid = true
			}
		}
		if !isValid {
			Err(w, http.StatusBadRequest, "Invalid provider")
			return
		}

		psdIn := pvMap(body, "providerSpecificData")
		if apiKey == "" && provider != "ollama-local" && pvApiKeySubstituteField(provider, psdIn) == "" {
			if isWebCookie {
				Err(w, http.StatusBadRequest, "Cookie value is required")
			} else {
				Err(w, http.StatusBadRequest, "API Key is required")
			}
			return
		}

		name := Str(body, "name")
		if name == "" {
			name = Str(body, "displayName")
		}
		if name == "" && regOK {
			name = reg.Display.Name
		}
		if name == "" {
			Err(w, http.StatusBadRequest, "Name is required")
			return
		}

		mergedPSD := pvNormalizePSD(provider, body, psdIn)

		openaiCompat, anthropicCompat, customEmbedding := pvIsCompatProvider(provider)
		if openaiCompat || anthropicCompat || customEmbedding {
			node, nerr := deps.Store.GetProviderNodeByID(provider)
			if nerr != nil || node == nil {
				switch {
				case openaiCompat:
					Err(w, http.StatusNotFound, "OpenAI Compatible node not found")
				case anthropicCompat:
					Err(w, http.StatusNotFound, "Anthropic Compatible node not found")
				default:
					Err(w, http.StatusNotFound, "Custom Embedding node not found")
				}
				return
			}
			repl := map[string]any{}
			if v := pvStr(node, "prefix"); v != "" {
				repl["prefix"] = v
			}
			if openaiCompat {
				if v := pvStr(node, "apiType"); v != "" {
					repl["apiType"] = v
				}
			}
			if v := pvStr(node, "baseUrl"); v != "" {
				repl["baseUrl"] = v
			}
			if v := pvStr(node, "name"); v != "" {
				repl["nodeName"] = v
			}
			mergedPSD = repl
		}
		if mergedPSD == nil {
			mergedPSD = map[string]any{}
		}
		mergedPSD["connectionProxyEnabled"] = proxyEnabled
		mergedPSD["connectionProxyUrl"] = proxyURL
		mergedPSD["connectionNoProxy"] = proxyNoProxy
		if proxyPoolID != nil {
			mergedPSD["proxyPoolId"] = *proxyPoolID
		}

		priority := float64(1)
		if v, ok := pvNum(body, "priority"); ok && v != 0 {
			priority = v
		}
		authType := "apikey"
		if isWebCookie {
			authType = "cookie"
		}
		allowOverwrite := pvHas(body, "id") || pvBool(body, "allowOverwrite") || pvBool(body, "overwrite")

		data := db.Record{
			"provider":             provider,
			"authType":             authType,
			"name":                 name,
			"apiKey":               apiKey,
			"priority":             priority,
			"providerSpecificData": mergedPSD,
			"isActive":             true,
			"testStatus":           pvStrOr(body, "testStatus", "unknown"),
			"allowOverwrite":       allowOverwrite,
		}
		if pvHas(body, "id") {
			data["id"] = body["id"]
		}
		// JS: globalPriority/defaultModel are `value || null` — always set.
		if v := body["globalPriority"]; v != nil {
			data["globalPriority"] = v
		} else {
			data["globalPriority"] = nil
		}
		if v := body["defaultModel"]; v != nil {
			data["defaultModel"] = v
		} else {
			data["defaultModel"] = nil
		}
		created, cerr := deps.Store.CreateProviderConnection(data)
		if cerr != nil {
			var conflict *db.NameConflictError
			if errors.As(cerr, &conflict) {
				WriteJSON(w, http.StatusConflict, map[string]any{
					"error":        conflict.Error(),
					"code":         "PROVIDER_NAME_CONFLICT",
					"existingId":   conflict.ExistingID,
					"existingName": conflict.ExistingName,
				})
				return
			}
			Err(w, http.StatusInternalServerError, "Failed to create provider")
			return
		}
		WriteJSON(w, http.StatusCreated, map[string]any{"connection": pvSafeConnection(created)})
	}
}

func pvProviderGet(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := deps.Store.GetProviderConnectionByID(r.PathValue("id"))
		if err != nil || conn == nil {
			Err(w, http.StatusNotFound, "Connection not found")
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"connection": pvSafeConnection(conn)})
	}
}

func pvProviderUpdate(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		existing, err := deps.Store.GetProviderConnectionByID(id)
		if err != nil || existing == nil {
			Err(w, http.StatusNotFound, "Connection not found")
			return
		}
		body, berr := ReadBodyJSON(r)
		if berr != nil {
			Err(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
		update := db.Record{}
		for _, k := range []string{"name", "priority", "globalPriority", "defaultModel", "isActive", "testStatus", "lastError", "lastErrorAt"} {
			if pvHas(body, k) {
				update[k] = body[k]
			}
		}
		if ak := Str(body, "apiKey"); ak != "" && pvStr(existing, "authType") == "apikey" {
			update["apiKey"] = ak
		}

		hasProxyField := pvHas(body, "connectionProxyEnabled") || pvHas(body, "connectionProxyUrl") || pvHas(body, "connectionNoProxy")
		var proxyEnabled bool
		var proxyURL, proxyNoProxy string
		if hasProxyField {
			var perrMsg string
			proxyEnabled, proxyURL, proxyNoProxy, perrMsg = pvNormalizeProxyConfig(body)
			if perrMsg != "" {
				Err(w, http.StatusBadRequest, perrMsg)
				return
			}
		}
		hasPoolField := pvHas(body, "proxyPoolId")
		var poolID *string
		if hasPoolField {
			raw := pvTrimStr(body["proxyPoolId"])
			if raw != "" && raw != "__none__" {
				pool, perr := deps.Store.GetProxyPoolByID(raw)
				if perr != nil || pool == nil {
					Err(w, http.StatusBadRequest, "Proxy pool not found")
					return
				}
				poolID = &raw
			}
		}

		existingPSD := pvConnPSD(existing)
		incomingPresent := pvHas(body, "providerSpecificData")
		if existingPSD != nil || incomingPresent || hasProxyField || hasPoolField {
			merged := map[string]any{}
			for k, v := range existingPSD {
				merged[k] = v
			}
			incoming := pvMap(body, "providerSpecificData")
			// AWS sessionToken semantics: "" keeps the stored token,
			// explicit null deletes it from the merged result.
			awsForm := pvUsesAwsForm(pvStr(existing, "provider"))
			sessionHandled := false
			for k, v := range incoming {
				if awsForm && k == "sessionToken" {
					sessionHandled = true
					if s, ok := v.(string); ok && s == "" {
						continue // keep existing
					}
					if v == nil {
						delete(merged, "sessionToken")
						continue
					}
				}
				merged[k] = v
			}
			_ = sessionHandled
			if hasProxyField {
				merged["connectionProxyEnabled"] = proxyEnabled
				merged["connectionProxyUrl"] = proxyURL
				merged["connectionNoProxy"] = proxyNoProxy
			}
			if hasPoolField {
				if poolID == nil {
					delete(merged, "proxyPoolId")
				} else {
					merged["proxyPoolId"] = *poolID
				}
			}
			update["providerSpecificData"] = merged
		}

		updated, uerr := deps.Store.UpdateProviderConnection(id, update)
		if uerr != nil || updated == nil {
			Err(w, http.StatusInternalServerError, "Failed to update connection")
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"connection": pvSafeConnection(updated)})
	}
}

func pvProviderDelete(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		deleted, err := deps.Store.DeleteProviderConnection(r.PathValue("id"))
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to delete connection")
			return
		}
		if !deleted {
			Err(w, http.StatusNotFound, "Connection not found")
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"message": "Connection deleted successfully"})
	}
}

// ---------- provider header overrides ----------

var (
	pvOverrideNameRe   = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
	pvOverrideBlocked  = map[string]bool{"host": true, "content-length": true, "content-type": true, "connection": true, "transfer-encoding": true, "authorization": true, "cookie": true}
	pvOverrideMaxCount = 20
	pvOverrideMaxValue = 8192
)

func pvCanonicalProviderID(id string) string {
	if p, ok := providers.Get(id); ok {
		return p.ID
	}
	return id
}

func pvGetOverridesMap(deps Deps) map[string]any {
	settings, err := deps.Store.GetSettings()
	if err != nil || settings == nil {
		return map[string]any{}
	}
	if m := pvMap(settings, "providerOverrides"); m != nil {
		return m
	}
	return map[string]any{}
}

func pvBuiltinHeaders(provider string) map[string]any {
	out := map[string]any{}
	if p, ok := pvReg(provider); ok {
		for k, v := range p.Transport.Headers {
			out[k] = v
		}
	}
	return out
}

func pvProviderOverridesGet(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		canonical := pvCanonicalProviderID(r.PathValue("id"))
		overrides := pvGetOverridesMap(deps)
		override := pvMap(overrides, canonical)
		headers := pvMap(override, "headers")
		if headers == nil {
			headers = map[string]any{}
		}
		WriteJSON(w, http.StatusOK, map[string]any{
			"headers":        headers,
			"builtinHeaders": pvBuiltinHeaders(canonical),
		})
	}
}

func pvProviderOverridesPut(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		canonical := pvCanonicalProviderID(r.PathValue("id"))
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
		raw := pvMap(body, "headers")
		if pvHas(body, "headers") && body["headers"] != nil && raw == nil {
			Err(w, http.StatusBadRequest, "headers must be an object")
			return
		}
		// Entries with empty values are dropped before counting/validating.
		entries := map[string]any{}
		for name, v := range raw {
			if v == nil {
				continue
			}
			if s, ok := v.(string); ok && s == "" {
				continue
			}
			entries[name] = v
		}
		if len(entries) > pvOverrideMaxCount {
			Err(w, http.StatusBadRequest, "Too many headers (max 20)")
			return
		}
		clean := map[string]any{}
		for name, v := range entries {
			if !pvOverrideNameRe.MatchString(name) {
				Err(w, http.StatusBadRequest, "Invalid header name: "+name)
				return
			}
			s, ok := v.(string)
			if !ok || strings.ContainsAny(s, "\r\n") {
				Err(w, http.StatusBadRequest, "Invalid value for header "+name)
				return
			}
			if len(s) > pvOverrideMaxValue {
				Err(w, http.StatusBadRequest, "Header "+name+" value too long (max 8192)")
				return
			}
			if pvOverrideBlocked[strings.ToLower(name)] {
				Err(w, http.StatusBadRequest, "Header "+name+" cannot be overridden")
				return
			}
			clean[name] = s
		}
		overrides := pvGetOverridesMap(deps)
		next := pvCloneMap(overrides)
		if len(clean) == 0 {
			delete(next, canonical)
		} else {
			next[canonical] = map[string]any{"headers": clean}
		}
		if _, uerr := deps.Store.UpdateSettings(db.Record{"providerOverrides": next}); uerr != nil {
			Err(w, http.StatusInternalServerError, "Failed to save overrides")
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"headers": clean})
	}
}

// ---------- provider-nodes ----------

func pvNodesList(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nodes, err := deps.Store.GetProviderNodes(db.NodeFilter{})
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to fetch provider nodes")
			return
		}
		out := make([]any, 0, len(nodes))
		for _, n := range nodes {
			out = append(out, n)
		}
		WriteJSON(w, http.StatusOK, map[string]any{"nodes": out})
	}
}

func pvSanitizeNodeBaseURL(nodeType, raw string) string {
	s := strings.TrimSuffix(raw, "/")
	if nodeType == "anthropic-compatible" && strings.HasSuffix(s, "/messages") {
		s = s[:len(s)-len("/messages")]
	}
	if nodeType == "custom-embedding" && strings.HasSuffix(s, "/embeddings") {
		s = s[:len(s)-len("/embeddings")]
	}
	return s
}

func pvNodesCreate(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
		name := Str(body, "name")
		prefix := Str(body, "prefix")
		apiType := Str(body, "apiType")
		baseURL := Str(body, "baseUrl")
		nodeType := pvStrOr(body, "type", "openai-compatible")
		if strings.TrimSpace(name) == "" {
			Err(w, http.StatusBadRequest, "Name is required")
			return
		}
		if strings.TrimSpace(prefix) == "" {
			Err(w, http.StatusBadRequest, "Prefix is required")
			return
		}
		var node db.Record
		var cerr error
		switch nodeType {
		case "openai-compatible":
			if apiType != "chat" && apiType != "responses" {
				Err(w, http.StatusBadRequest, "Invalid OpenAI compatible API type")
				return
			}
			if strings.TrimSpace(baseURL) == "" {
				baseURL = "https://api.openai.com/v1"
			}
			node, cerr = deps.Store.CreateProviderNode(db.Record{
				"id":      "openai-compatible-" + apiType + "-" + pvUUID(),
				"type":    "openai-compatible",
				"prefix":  strings.TrimSpace(prefix),
				"apiType": apiType,
				"baseUrl": strings.TrimSpace(baseURL),
				"name":    strings.TrimSpace(name),
			})
		case "custom-embedding":
			if strings.TrimSpace(baseURL) == "" {
				baseURL = "https://api.openai.com/v1"
			}
			node, cerr = deps.Store.CreateProviderNode(db.Record{
				"id":      "custom-embedding-" + pvUUID(),
				"type":    "custom-embedding",
				"prefix":  strings.TrimSpace(prefix),
				"baseUrl": pvSanitizeNodeBaseURL("custom-embedding", strings.TrimSpace(baseURL)),
				"name":    strings.TrimSpace(name),
			})
		case "anthropic-compatible":
			if strings.TrimSpace(baseURL) == "" {
				baseURL = "https://api.anthropic.com/v1"
			}
			node, cerr = deps.Store.CreateProviderNode(db.Record{
				"id":      "anthropic-compatible-" + pvUUID(),
				"type":    "anthropic-compatible",
				"prefix":  strings.TrimSpace(prefix),
				"baseUrl": pvSanitizeNodeBaseURL("anthropic-compatible", strings.TrimSpace(baseURL)),
				"name":    strings.TrimSpace(name),
			})
		default:
			Err(w, http.StatusBadRequest, "Invalid provider node type")
			return
		}
		if cerr != nil {
			Err(w, http.StatusInternalServerError, "Failed to create provider node")
			return
		}
		WriteJSON(w, http.StatusCreated, map[string]any{"node": node})
	}
}

func pvNodeUpdate(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		node, err := deps.Store.GetProviderNodeByID(id)
		if err != nil || node == nil {
			Err(w, http.StatusNotFound, "Provider node not found")
			return
		}
		body, berr := ReadBodyJSON(r)
		if berr != nil {
			Err(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
		name := Str(body, "name")
		prefix := Str(body, "prefix")
		apiType := Str(body, "apiType")
		baseURL := Str(body, "baseUrl")
		if strings.TrimSpace(name) == "" {
			Err(w, http.StatusBadRequest, "Name is required")
			return
		}
		if strings.TrimSpace(prefix) == "" {
			Err(w, http.StatusBadRequest, "Prefix is required")
			return
		}
		nodeType := pvStr(node, "type")
		if nodeType == "openai-compatible" && apiType != "chat" && apiType != "responses" {
			Err(w, http.StatusBadRequest, "Invalid OpenAI compatible API type")
			return
		}
		if strings.TrimSpace(baseURL) == "" {
			Err(w, http.StatusBadRequest, "Base URL is required")
			return
		}
		sanitized := pvSanitizeNodeBaseURL(nodeType, strings.TrimSpace(baseURL))
		updates := db.Record{
			"name":    strings.TrimSpace(name),
			"prefix":  strings.TrimSpace(prefix),
			"baseUrl": sanitized,
		}
		if nodeType == "openai-compatible" {
			updates["apiType"] = apiType
		}
		updated, uerr := deps.Store.UpdateProviderNode(id, updates)
		if uerr != nil || updated == nil {
			Err(w, http.StatusInternalServerError, "Failed to update provider node")
			return
		}
		// Sync the node's connections' providerSpecificData.
		conns, _ := deps.Store.GetProviderConnections(db.ConnectionFilter{Provider: id})
		for _, c := range conns {
			psd := map[string]any{}
			for k, v := range pvConnPSD(c) {
				psd[k] = v
			}
			psd["prefix"] = strings.TrimSpace(prefix)
			if nodeType == "openai-compatible" {
				psd["apiType"] = apiType
			} else {
				// JS spreads apiType: undefined -> key dropped in JSON.
				delete(psd, "apiType")
			}
			psd["baseUrl"] = sanitized
			psd["nodeName"] = pvStr(updated, "name")
			_, _ = deps.Store.UpdateProviderConnection(pvStr(c, "id"), db.Record{"providerSpecificData": psd})
		}
		WriteJSON(w, http.StatusOK, map[string]any{"node": updated})
	}
}

func pvNodeDelete(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		node, err := deps.Store.GetProviderNodeByID(id)
		if err != nil || node == nil {
			Err(w, http.StatusNotFound, "Provider node not found")
			return
		}
		_, _ = deps.Store.DeleteProviderConnectionsByProvider(id)
		if _, derr := deps.Store.DeleteProviderNode(id); derr != nil {
			Err(w, http.StatusInternalServerError, "Failed to delete provider node")
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"success": true})
	}
}

// ---------- combos ----------

var pvComboNameRe = regexp.MustCompile(`^[a-zA-Z0-9_.\-]+$`)

func pvCombosList(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		combos, err := deps.Store.GetCombos()
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to fetch combos")
			return
		}
		out := make([]any, 0, len(combos))
		for _, c := range combos {
			out = append(out, c)
		}
		WriteJSON(w, http.StatusOK, map[string]any{"combos": out})
	}
}

func pvCombosCreate(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
		name := Str(body, "name")
		if name == "" {
			Err(w, http.StatusBadRequest, "Name is required")
			return
		}
		if !pvComboNameRe.MatchString(name) {
			Err(w, http.StatusBadRequest, "Name can only contain letters, numbers, -, _ and .")
			return
		}
		if existing, gerr := deps.Store.GetComboByName(name); gerr == nil && existing != nil {
			Err(w, http.StatusBadRequest, "Combo name already exists")
			return
		}
		models := pvSlice(body, "models")
		if models == nil {
			models = []any{}
		}
		kind := body["kind"]
		if kind == nil {
			kind = nil
		}
		combo, cerr := deps.Store.CreateCombo(db.Record{"name": name, "models": models, "kind": kind})
		if cerr != nil {
			Err(w, http.StatusInternalServerError, "Failed to create combo")
			return
		}
		WriteJSON(w, http.StatusCreated, combo)
	}
}

func pvComboGet(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		combo, err := deps.Store.GetComboByID(r.PathValue("id"))
		if err != nil || combo == nil {
			Err(w, http.StatusNotFound, "Combo not found")
			return
		}
		WriteJSON(w, http.StatusOK, combo)
	}
}

func pvComboUpdate(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
		if name := Str(body, "name"); name != "" {
			if !pvComboNameRe.MatchString(name) {
				Err(w, http.StatusBadRequest, "Name can only contain letters, numbers, -, _ and .")
				return
			}
			if existing, gerr := deps.Store.GetComboByName(name); gerr == nil && existing != nil && pvStr(existing, "id") != id {
				Err(w, http.StatusBadRequest, "Combo name already exists")
				return
			}
		}
		// Capture the previous name to invalidate rotation state (JS PUT
		// handler: resetComboRotation(prev.name), plus the new name on
		// rename). deps.Chat may be nil in tests; ResetComboRotation is a
		// no-op on a nil *chatcore.Service.
		prev, _ := deps.Store.GetComboByID(id)
		updated, uerr := deps.Store.UpdateCombo(id, db.Record(body))
		if uerr != nil || updated == nil {
			Err(w, http.StatusNotFound, "Combo not found")
			return
		}
		if prev != nil {
			if prevName := pvStr(prev, "name"); prevName != "" {
				deps.Chat.ResetComboRotation(prevName)
				if newName := pvStr(updated, "name"); newName != "" && newName != prevName {
					deps.Chat.ResetComboRotation(newName)
				}
			}
		}
		WriteJSON(w, http.StatusOK, updated)
	}
}

func pvComboDelete(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		prev, _ := deps.Store.GetComboByID(r.PathValue("id"))
		deleted, err := deps.Store.DeleteCombo(r.PathValue("id"))
		if err != nil || !deleted {
			Err(w, http.StatusNotFound, "Combo not found")
			return
		}
		// JS DELETE handler: resetComboRotation(prev.name) after delete.
		if prev != nil {
			if prevName := pvStr(prev, "name"); prevName != "" {
				deps.Chat.ResetComboRotation(prevName)
			}
		}
		WriteJSON(w, http.StatusOK, map[string]any{"success": true})
	}
}

// comboPresets.js port: CLI_TOOLS.claude defaults (constants inlined from
// src/shared/constants/cliTools.js, the single source the JS reads).
var pvClaudeDefaultModels = []struct{ Alias, DefaultValue string }{
	{"fable", "cc/claude-fable-5"},
	{"opus", "cc/claude-opus-5"},
	{"sonnet", "cc/claude-sonnet-5"},
	{"haiku", "cc/claude-haiku-4-5-20251001"},
}

var pvClaudeModelAliases = []string{"default", "sonnet", "opus", "fable", "haiku", "opusplan"}

var pvClaudeExtraAliasTargets = map[string]string{
	"default":  "cc/claude-sonnet-5",
	"opusplan": "cc/claude-opus-5",
}

type pvPresetItem struct {
	Name   string   `json:"name"`
	Models []string `json:"models"`
	Exists bool     `json:"exists"`
}

func pvPushPresetItem(out *[]pvPresetItem, seen map[string]bool, name string, models []string) {
	if name == "" || !pvComboNameRe.MatchString(name) || seen[name] || len(models) == 0 {
		return
	}
	seen[name] = true
	*out = append(*out, pvPresetItem{Name: name, Models: models})
}

func pvItemsFromCatalog(providerAlias string, seen map[string]bool) []pvPresetItem {
	out := []pvPresetItem{}
	for _, m := range pvCatalogModels(providerAlias) {
		id := pvStr(m, "id")
		if id == "" {
			continue
		}
		pvPushPresetItem(&out, seen, id, []string{providerAlias + "/" + id})
	}
	return out
}

// pvBuildPresetItems ports buildPresetItems. Live Cursor models are a TODO:
// resolveCursorModels (open-sse/services/cursorModels.js) is Team L
// territory, so the static "cu" catalog fallback is used, exactly as JS
// does when the live lookup returns nothing.
func pvBuildPresetItems(source string, existingNames map[string]bool) []pvPresetItem {
	seen := map[string]bool{}
	var items []pvPresetItem
	if source == "cursor" {
		items = pvItemsFromCatalog("cu", seen)
	} else { // claude
		items = pvItemsFromCatalog("cc", seen)
		for _, dm := range pvClaudeDefaultModels {
			pvPushPresetItem(&items, seen, dm.Alias, []string{dm.DefaultValue})
		}
		for _, alias := range pvClaudeModelAliases {
			if seen[alias] {
				continue
			}
			target, ok := pvClaudeExtraAliasTargets[alias]
			if !ok {
				continue
			}
			pvPushPresetItem(&items, seen, alias, []string{target})
		}
	}
	for i := range items {
		items[i].Exists = existingNames[items[i].Name]
	}
	return items
}

func pvPresetItemsFor(deps Deps, source string) ([]pvPresetItem, error) {
	combos, err := deps.Store.GetCombos()
	if err != nil {
		return nil, err
	}
	existing := map[string]bool{}
	for _, c := range combos {
		existing[pvStr(c, "name")] = true
	}
	return pvBuildPresetItems(source, existing), nil
}

func pvComboPresetsGet(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		source := r.URL.Query().Get("source")
		if source != "cursor" && source != "claude" {
			Err(w, http.StatusBadRequest, "source must be 'cursor' or 'claude'")
			return
		}
		items, err := pvPresetItemsFor(deps, source)
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to preview combo presets")
			return
		}
		toCreate, toSkip := 0, 0
		arr := make([]any, 0, len(items))
		for _, it := range items {
			if it.Exists {
				toSkip++
			} else {
				toCreate++
			}
			arr = append(arr, it)
		}
		WriteJSON(w, http.StatusOK, map[string]any{
			"source": source, "items": arr, "toCreate": toCreate, "toSkip": toSkip,
		})
	}
}

func pvComboPresetsPost(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := ReadBodyJSON(r)
		source := Str(body, "source")
		if source != "cursor" && source != "claude" {
			Err(w, http.StatusBadRequest, "source must be 'cursor' or 'claude'")
			return
		}
		items, err := pvPresetItemsFor(deps, source)
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to create combo presets")
			return
		}
		created := []any{}
		skipped := []any{}
		for _, it := range items {
			if it.Exists {
				skipped = append(skipped, it.Name)
				continue
			}
			models := make([]any, len(it.Models))
			for i, m := range it.Models {
				models[i] = m
			}
			combo, cerr := deps.Store.CreateCombo(db.Record{"name": it.Name, "models": models})
			if cerr != nil {
				Err(w, http.StatusInternalServerError, "Failed to create combo presets")
				return
			}
			created = append(created, combo)
		}
		WriteJSON(w, http.StatusOK, map[string]any{
			"source": source, "created": created, "skipped": skipped,
			"createdCount": len(created), "skippedCount": len(skipped),
		})
	}
}

// ---------- tags ----------

const pvTagsPayload = `{"models":[{"name":"llama3.2","modified_at":"2025-12-26T00:00:00Z","size":2000000000,"digest":"abc123def456","details":{"format":"gguf","family":"llama","parameter_size":"3B","quantization_level":"Q4_K_M"}},{"name":"qwen2.5","modified_at":"2025-12-26T00:00:00Z","size":4000000000,"digest":"def456abc123","details":{"format":"gguf","family":"qwen","parameter_size":"7B","quantization_level":"Q4_K_M"}}]}`

func pvTagsHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "*")
}

func pvTagsGet(w http.ResponseWriter, r *http.Request) {
	pvTagsHeaders(w)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(pvTagsPayload))
}

func pvTagsOptions(w http.ResponseWriter, r *http.Request) {
	pvTagsHeaders(w)
	w.WriteHeader(http.StatusOK)
}

// pvCapsJSON embeds the capability tables extracted verbatim from
// open-sse/providers/capabilities.js (MODEL_CAPABILITIES,
// PROVIDER_CAPABILITIES, PATTERN_CAPABILITIES) at port time.
const pvCapsJSON = "{\"model\":{\"claude-fable-5-1\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"thinkingCanDisable\":false,\"contextWindow\":1000000,\"maxOutput\":128000},\"claude-opus-5.5\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000},\"claude-opus-5.5-thinking\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000},\"claude-opus-5.5-agentic\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000},\"claude-opus-5.5-thinking-agentic\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000},\"claude-opus-5-5\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000,\"thinkingCanDisable\":false,\"forcedToolChoice\":false},\"claude-opus-5-5-thinking\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000,\"thinkingCanDisable\":false,\"forcedToolChoice\":false},\"claude-opus-5-5-high\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000,\"thinkingCanDisable\":false,\"forcedToolChoice\":false},\"claude-opus-5-5-medium\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000,\"thinkingCanDisable\":false,\"forcedToolChoice\":false},\"claude-opus-5-5-low\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000,\"thinkingCanDisable\":false,\"forcedToolChoice\":false},\"claude-opus-5\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000},\"claude-opus-5-thinking\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000},\"claude-opus-5-agentic\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000},\"claude-opus-5-thinking-agentic\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000},\"claude-opus-4.6\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000},\"claude-opus-4.7\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000},\"claude-opus-4-7\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000},\"claude-opus-4.8\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000},\"claude-opus-4-6\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000},\"claude-opus-4-8\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000},\"claude-opus-4.8-thinking\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000},\"claude-opus-4-8-thinking\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000},\"claude-sonnet-4.6\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000},\"claude-sonnet-4-6\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000},\"claude-sonnet-5-5\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000,\"thinkingOffType\":\"between_tools\",\"forcedToolChoice\":false},\"claude-sonnet-5-5-thinking\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000,\"thinkingOffType\":\"between_tools\",\"forcedToolChoice\":false},\"claude-sonnet-5-5-high\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000,\"thinkingOffType\":\"between_tools\",\"forcedToolChoice\":false},\"claude-sonnet-5-5-medium\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000,\"thinkingOffType\":\"between_tools\",\"forcedToolChoice\":false},\"claude-sonnet-5-5-low\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000,\"thinkingOffType\":\"between_tools\",\"forcedToolChoice\":false},\"claude-sonnet-5\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000},\"claude-sonnet-5-thinking\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000},\"claude-sonnet-5-agentic\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000},\"claude-sonnet-5-thinking-agentic\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000},\"gpt-image-1\":{\"imageOutput\":true,\"tools\":false},\"glm-5.3-flash\":{\"vision\":true,\"videoInput\":true,\"pdf\":true,\"reasoning\":true,\"thinkingFormat\":\"zai\",\"thinkingCanDisable\":false,\"contextWindow\":1000000,\"maxOutput\":131072},\"glm-4.6v\":{\"vision\":true,\"videoInput\":true,\"reasoning\":true,\"thinkingFormat\":\"zai\",\"contextWindow\":128000,\"maxOutput\":32768},\"glm-4.5v\":{\"vision\":true,\"videoInput\":true,\"reasoning\":true,\"thinkingFormat\":\"zai\",\"contextWindow\":64000,\"maxOutput\":16384},\"glm-5.2\":{\"reasoning\":true,\"thinkingFormat\":\"zai\",\"thinkingCanDisable\":false,\"contextWindow\":1000000,\"maxOutput\":131072},\"deepseek-v4-flash-vision-exp\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"deepseek\",\"contextWindow\":1000000,\"maxOutput\":384000},\"deepseek-v4.1-flash\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"deepseek\",\"contextWindow\":1000000,\"maxOutput\":384000},\"deepseek-v4-1-flash\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"deepseek\",\"contextWindow\":1000000,\"maxOutput\":384000},\"deepseek-flash\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"deepseek\",\"contextWindow\":128000,\"maxOutput\":64000},\"vision-model\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"qwen\",\"contextWindow\":1000000},\"coder-model\":{\"reasoning\":true,\"thinkingFormat\":\"qwen\",\"contextWindow\":1000000},\"kimi-k3\":{\"vision\":true,\"videoInput\":true,\"reasoning\":true,\"thinkingFormat\":\"kimi\",\"thinkingCanDisable\":false,\"contextWindow\":1048576,\"maxOutput\":131072},\"k3\":{\"vision\":true,\"videoInput\":true,\"reasoning\":true,\"thinkingFormat\":\"kimi\",\"thinkingCanDisable\":false,\"contextWindow\":1048576,\"maxOutput\":131072},\"kimi-for-coding\":{\"vision\":true,\"videoInput\":true,\"reasoning\":true,\"thinkingFormat\":\"kimi\",\"thinkingCanDisable\":false,\"contextWindow\":262144,\"maxOutput\":65536},\"kimi-for-coding-highspeed\":{\"vision\":true,\"videoInput\":true,\"reasoning\":true,\"thinkingFormat\":\"kimi\",\"thinkingCanDisable\":false,\"contextWindow\":262144,\"maxOutput\":65536},\"kimi-k2.7-code\":{\"vision\":true,\"videoInput\":true,\"reasoning\":true,\"thinkingFormat\":\"kimi\",\"thinkingCanDisable\":false,\"contextWindow\":262144,\"maxOutput\":65536},\"kimi-k2.7-code-highspeed\":{\"vision\":true,\"videoInput\":true,\"reasoning\":true,\"thinkingFormat\":\"kimi\",\"thinkingCanDisable\":false,\"contextWindow\":262144,\"maxOutput\":65536},\"muse-spark-1.2-contributor-free\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":1048576,\"maxOutput\":131072},\"muse-spark-1.3-contributor-free\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":1048576,\"maxOutput\":131072},\"union-alpha\":{\"vision\":true,\"contextWindow\":262144,\"maxOutput\":131072},\"space-bunny-free\":{\"vision\":true,\"videoInput\":true,\"reasoning\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":1048576,\"maxOutput\":524288},\"space-bunny\":{\"vision\":true,\"videoInput\":true,\"reasoning\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":1048576,\"maxOutput\":524288},\"big-pickle\":{\"reasoning\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":32000},\"exo-free\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":1048576,\"maxOutput\":131072},\"fledge-alpha-free\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":1048576,\"maxOutput\":131072},\"longcat-2.0\":{\"reasoning\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":1000000,\"maxOutput\":131072},\"longcat-2.0-free\":{\"reasoning\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":1000000,\"maxOutput\":131072},\"longcat-2.5-preview-free\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":1000000,\"maxOutput\":131072},\"north-mini-code-free\":{\"reasoning\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":256000,\"maxOutput\":64000},\"ring-2.6-1t-free\":{\"reasoning\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":262000,\"maxOutput\":66000},\"x-preview-f-free\":{\"vision\":true,\"videoInput\":true,\"reasoning\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":1000000,\"maxOutput\":131072}},\"provider\":{\"nvidia\":{\"minimaxai/minimax-m2.7\":{\"reasoning\":true,\"thinkingFormat\":\"openai\",\"thinkingCanDisable\":false,\"contextWindow\":200000,\"maxOutput\":131072},\"minimaxai/minimax-m3\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"openai\",\"thinkingCanDisable\":false,\"contextWindow\":512000,\"maxOutput\":131072},\"z-ai/glm-5.2\":{\"reasoning\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":128000},\"deepseek-ai/deepseek-v4-pro\":{\"reasoning\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":1000000,\"maxOutput\":65536},\"deepseek-ai/deepseek-v4-flash\":{\"reasoning\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":1000000,\"maxOutput\":65536}},\"opencode-go\":{\"glm-5.3-flash\":{\"vision\":true,\"videoInput\":true,\"pdf\":true,\"reasoning\":true,\"thinkingFormat\":\"openai\",\"thinkingCanDisable\":false,\"contextWindow\":1000000,\"maxOutput\":131072},\"claude-haiku-5-5\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000}},\"commandcode\":{\"claude-haiku-5-5\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"commandcode\",\"thinkingEffortSupported\":true,\"contextWindow\":1000000,\"maxOutput\":128000}},\"codex\":{\"gpt-6-astra\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":272000,\"maxOutput\":128000},\"gpt-6-sol\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":272000,\"maxOutput\":128000},\"gpt-6-luna\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":272000,\"maxOutput\":128000},\"gpt-6-astra[1m]\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":872000,\"maxOutput\":128000},\"gpt-6-sol[1m]\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":872000,\"maxOutput\":128000},\"gpt-6-luna[1m]\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":872000,\"maxOutput\":128000},\"gpt-5.6-sol[1m]\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":872000,\"maxOutput\":128000},\"gpt-5.6-terra[1m]\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":872000,\"maxOutput\":128000},\"gpt-5.6-luna[1m]\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":872000,\"maxOutput\":128000},\"gpt-5.6-sol\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":372000,\"maxOutput\":128000},\"gpt-5.6-sol-review\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":372000,\"maxOutput\":128000},\"gpt-5.6-terra\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":272000,\"maxOutput\":128000},\"gpt-5.6-terra-review\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":272000,\"maxOutput\":128000},\"gpt-5.6-luna\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":272000,\"maxOutput\":128000},\"gpt-5.6-luna-review\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":272000,\"maxOutput\":128000}},\"kiro\":{\"gpt-5.6-sol\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":272000,\"maxOutput\":128000},\"gpt-5.6-terra\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":272000,\"maxOutput\":128000},\"gpt-5.6-luna\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":272000,\"maxOutput\":128000},\"gpt-5.6-sol-thinking\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":272000,\"maxOutput\":128000},\"gpt-5.6-terra-thinking\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":272000,\"maxOutput\":128000},\"gpt-5.6-luna-thinking\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":272000,\"maxOutput\":128000},\"gpt-5.6-sol-agentic\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":272000,\"maxOutput\":128000},\"gpt-5.6-terra-agentic\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":272000,\"maxOutput\":128000},\"gpt-5.6-luna-agentic\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":272000,\"maxOutput\":128000},\"gpt-5.6-sol-thinking-agentic\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":272000,\"maxOutput\":128000},\"gpt-5.6-terra-thinking-agentic\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":272000,\"maxOutput\":128000},\"gpt-5.6-luna-thinking-agentic\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":272000,\"maxOutput\":128000}},\"devin-cli\":{\"gpt-5.4-high\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":128000},\"gpt-5.4-medium\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":128000},\"gpt-5.4-low\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":128000},\"gpt-5.5-xhigh\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":128000},\"gpt-5.5-high\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":128000},\"gpt-5.5-medium\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":128000},\"gpt-5.5-low\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":128000}},\"codebuddy-cn\":{\"glm-5.2\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"openai\",\"thinkingCanDisable\":true,\"contextWindow\":1000000,\"maxOutput\":131072},\"glm-5.1\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"openai\",\"thinkingCanDisable\":false,\"contextWindow\":200000,\"maxOutput\":48000},\"glm-5.0\":{\"reasoning\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":48000},\"glm-4.7\":{\"reasoning\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":48000},\"minimax-m3\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"openai\",\"thinkingCanDisable\":false,\"contextWindow\":512000,\"maxOutput\":524288},\"kimi-k2.5\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"openai\",\"thinkingCanDisable\":false,\"contextWindow\":164000,\"maxOutput\":32000},\"hy3-preview\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"openai\",\"thinkingCanDisable\":false,\"contextWindow\":192000,\"maxOutput\":64000},\"deepseek-v4-flash\":{\"reasoning\":true,\"thinkingFormat\":\"openai\",\"thinkingCanDisable\":false,\"contextWindow\":1000000,\"maxOutput\":50000},\"deepseek-v3-2-volc\":{\"reasoning\":true,\"thinkingFormat\":\"openai\",\"thinkingCanDisable\":false,\"contextWindow\":96000,\"maxOutput\":32000},\"hy3\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"openai\",\"thinkingCanDisable\":false,\"contextWindow\":192000,\"maxOutput\":64000},\"hy4-preview\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"openai\",\"thinkingCanDisable\":false,\"contextWindow\":1000000,\"maxOutput\":64000},\"glm-5.3\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"openai\",\"thinkingCanDisable\":true,\"contextWindow\":1000000,\"maxOutput\":131072},\"glm-5.3-flash\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"openai\",\"thinkingCanDisable\":true,\"contextWindow\":1000000,\"maxOutput\":131072},\"kimi-k3-1\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"openai\",\"thinkingCanDisable\":false,\"contextWindow\":1000000,\"maxOutput\":1048576},\"kimi-k2.8-preview\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"openai\",\"thinkingCanDisable\":true,\"contextWindow\":300000,\"maxOutput\":131072},\"deepseek-v4-pro\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"openai\",\"thinkingCanDisable\":true,\"contextWindow\":1000000,\"maxOutput\":393216},\"deepseek-v4.1-flash\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"openai\",\"thinkingCanDisable\":true,\"contextWindow\":1000000,\"maxOutput\":393216}},\"poolside\":{\"laguna-s-2.1\":{\"reasoning\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":1000000,\"maxOutput\":32000},\"laguna-xs-2.1\":{\"reasoning\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":32000}},\"ollama\":{\"deepseek-v4.1-flash:cloud\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"deepseek\",\"contextWindow\":1000000,\"maxOutput\":384000}},\"minimax-code\":{\"MiniMax-M3.1-Flash-Preview\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"claude-adaptive\",\"thinkingCanDisable\":false,\"contextWindow\":512000,\"maxOutput\":128000},\"MiniMax-M3\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":512000,\"maxOutput\":128000},\"MiniMax-M2.7\":{\"reasoning\":true,\"thinkingFormat\":\"claude-adaptive\",\"thinkingCanDisable\":false,\"contextWindow\":200000,\"maxOutput\":128000},\"MiniMax-M2.7-highspeed\":{\"reasoning\":true,\"thinkingFormat\":\"claude-adaptive\",\"thinkingCanDisable\":false,\"contextWindow\":200000,\"maxOutput\":128000}},\"nous\":{\"meituan/longcat-2.0:free\":{\"tools\":true,\"reasoning\":true,\"thinkingFormat\":\"nous\",\"contextWindow\":1048756,\"maxOutput\":262144},\"meituan/longcat-2.5-preview:free\":{\"tools\":true,\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"nous\",\"contextWindow\":1048576,\"maxOutput\":131072},\"stepfun/step-5-preview:free\":{\"tools\":true,\"vision\":true,\"videoInput\":true,\"reasoning\":true,\"thinkingFormat\":\"nous\",\"contextWindow\":1000000,\"maxOutput\":64000},\"upstage/solar-mini4:free\":{\"tools\":true,\"reasoning\":true,\"thinkingFormat\":\"nous\",\"contextWindow\":524288,\"maxOutput\":131072},\"stepfun/step-3.7-flash:free\":{\"tools\":true,\"vision\":true,\"videoInput\":true,\"reasoning\":true,\"thinkingFormat\":\"nous\",\"contextWindow\":262144,\"maxOutput\":256000},\"poolside/laguna-s-2.1:free\":{\"tools\":true,\"reasoning\":true,\"thinkingFormat\":\"nous\",\"contextWindow\":262144,\"maxOutput\":131072},\"poolside/laguna-xs-2.1:free\":{\"tools\":true,\"reasoning\":true,\"thinkingFormat\":\"nous\",\"contextWindow\":262144,\"maxOutput\":32768},\"stealth/missingno\":{\"tools\":true,\"reasoning\":true,\"thinkingFormat\":\"nous\",\"contextWindow\":262144,\"maxOutput\":131072}},\"cx\":{\"gpt-6-astra\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":272000,\"maxOutput\":128000},\"gpt-6-sol\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":272000,\"maxOutput\":128000},\"gpt-6-luna\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":272000,\"maxOutput\":128000},\"gpt-6-astra[1m]\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":872000,\"maxOutput\":128000},\"gpt-6-sol[1m]\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":872000,\"maxOutput\":128000},\"gpt-6-luna[1m]\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":872000,\"maxOutput\":128000},\"gpt-5.6-sol[1m]\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":872000,\"maxOutput\":128000},\"gpt-5.6-terra[1m]\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":872000,\"maxOutput\":128000},\"gpt-5.6-luna[1m]\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":872000,\"maxOutput\":128000},\"gpt-5.6-sol\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":372000,\"maxOutput\":128000},\"gpt-5.6-sol-review\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":372000,\"maxOutput\":128000},\"gpt-5.6-terra\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":272000,\"maxOutput\":128000},\"gpt-5.6-terra-review\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":272000,\"maxOutput\":128000},\"gpt-5.6-luna\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":272000,\"maxOutput\":128000},\"gpt-5.6-luna-review\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":272000,\"maxOutput\":128000}},\"dv\":{\"gpt-5.4-high\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":128000},\"gpt-5.4-medium\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":128000},\"gpt-5.4-low\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":128000},\"gpt-5.5-xhigh\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":128000},\"gpt-5.5-high\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":128000},\"gpt-5.5-medium\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":128000},\"gpt-5.5-low\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":128000}},\"devin\":{\"gpt-5.4-high\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":128000},\"gpt-5.4-medium\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":128000},\"gpt-5.4-low\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":128000},\"gpt-5.5-xhigh\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":128000},\"gpt-5.5-high\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":128000},\"gpt-5.5-medium\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":128000},\"gpt-5.5-low\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":128000}},\"minimax-code-global\":{\"MiniMax-M3.1-Flash-Preview\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"claude-adaptive\",\"thinkingCanDisable\":false,\"contextWindow\":512000,\"maxOutput\":128000},\"MiniMax-M3\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":512000,\"maxOutput\":128000},\"MiniMax-M2.7\":{\"reasoning\":true,\"thinkingFormat\":\"claude-adaptive\",\"thinkingCanDisable\":false,\"contextWindow\":200000,\"maxOutput\":128000},\"MiniMax-M2.7-highspeed\":{\"reasoning\":true,\"thinkingFormat\":\"claude-adaptive\",\"thinkingCanDisable\":false,\"contextWindow\":200000,\"maxOutput\":128000}}},\"patterns\":[{\"pattern\":\"*claude*opus-5*\",\"caps\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000}},{\"pattern\":\"*claude*sonnet-5*\",\"caps\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\",\"contextWindow\":1000000,\"maxOutput\":128000}},{\"pattern\":\"*claude*opus-4.6*\",\"caps\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\"}},{\"pattern\":\"*claude*opus-4.7*\",\"caps\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\"}},{\"pattern\":\"*claude*opus-4.8*\",\"caps\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\"}},{\"pattern\":\"*claude*sonnet-4.6*\",\"caps\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\"}},{\"pattern\":\"*claude*sonnet-4.7*\",\"caps\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-adaptive\"}},{\"pattern\":\"*claude*haiku-5*\",\"caps\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-budget\"}},{\"pattern\":\"*claude*haiku-4*\",\"caps\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-budget\"}},{\"pattern\":\"*claude*opus-4*\",\"caps\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-budget\"}},{\"pattern\":\"*claude*sonnet-4*\",\"caps\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-budget\"}},{\"pattern\":\"*claude*haiku*\",\"caps\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-budget\"}},{\"pattern\":\"*claude*opus*\",\"caps\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-budget\"}},{\"pattern\":\"*claude*sonnet*\",\"caps\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-budget\"}},{\"pattern\":\"*claude*fable*\",\"caps\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-budget\",\"contextWindow\":1000000,\"maxOutput\":128000}},{\"pattern\":\"*claude*mythos*\",\"caps\":{\"vision\":true,\"pdf\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-budget\",\"contextWindow\":1000000,\"maxOutput\":128000}},{\"pattern\":\"*claude-3*\",\"caps\":{\"vision\":true}},{\"pattern\":\"*claude*\",\"caps\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"claude-budget\"}},{\"pattern\":\"*gemini*image*\",\"caps\":{\"vision\":true,\"imageOutput\":true,\"contextWindow\":1048576}},{\"pattern\":\"*gemini-4*\",\"caps\":{\"vision\":true,\"audioInput\":true,\"videoInput\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"gemini-level\",\"thinkingCanDisable\":false,\"contextWindow\":1048576,\"maxOutput\":65536}},{\"pattern\":\"*gemini-3.8*\",\"caps\":{\"vision\":true,\"audioInput\":true,\"videoInput\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"gemini-level\",\"thinkingCanDisable\":false,\"contextWindow\":1048576,\"maxOutput\":65536}},{\"pattern\":\"*gemini-3.7*\",\"caps\":{\"vision\":true,\"audioInput\":true,\"videoInput\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"gemini-level\",\"thinkingCanDisable\":false,\"contextWindow\":1048576,\"maxOutput\":65536}},{\"pattern\":\"*gemini-3*pro*\",\"caps\":{\"vision\":true,\"audioInput\":true,\"videoInput\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"gemini-level\",\"thinkingCanDisable\":false,\"contextWindow\":1048576,\"maxOutput\":65535}},{\"pattern\":\"*gemini-3*\",\"caps\":{\"vision\":true,\"audioInput\":true,\"videoInput\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"gemini-level\",\"thinkingCanDisable\":false,\"contextWindow\":1048576,\"maxOutput\":65536}},{\"pattern\":\"*gemini-2.5*\",\"caps\":{\"vision\":true,\"audioInput\":true,\"videoInput\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"gemini-budget\",\"thinkingRange\":{\"min\":0,\"max\":24576},\"contextWindow\":1048576,\"maxOutput\":65536}},{\"pattern\":\"*gemini-2*\",\"caps\":{\"vision\":true,\"audioInput\":true,\"videoInput\":true,\"search\":true,\"contextWindow\":1048576,\"maxOutput\":65536}},{\"pattern\":\"*gemini*\",\"caps\":{\"vision\":true,\"search\":true,\"contextWindow\":1048576}},{\"pattern\":\"*gemma*\",\"caps\":{\"vision\":true,\"contextWindow\":128000}},{\"pattern\":\"*nanobanana*\",\"caps\":{\"vision\":true,\"imageOutput\":true}},{\"pattern\":\"*gpt-6*\",\"caps\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":1050000,\"maxOutput\":128000}},{\"pattern\":\"*gpt-5*image*\",\"caps\":{\"imageOutput\":true}},{\"pattern\":\"*gpt-5*codex*\",\"caps\":{\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":400000,\"maxOutput\":128000}},{\"pattern\":\"*gpt-5.4-mini*\",\"caps\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":400000,\"maxOutput\":128000}},{\"pattern\":\"*gpt-5.4-nano*\",\"caps\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":400000,\"maxOutput\":128000}},{\"pattern\":\"*gpt-5.4*\",\"caps\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":1050000,\"maxOutput\":128000}},{\"pattern\":\"*gpt-5.5*\",\"caps\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":1050000,\"maxOutput\":128000}},{\"pattern\":\"*gpt-5.6*\",\"caps\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":1050000,\"maxOutput\":128000}},{\"pattern\":\"*gpt-5*\",\"caps\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":400000,\"maxOutput\":128000}},{\"pattern\":\"*gpt-4o*\",\"caps\":{\"vision\":true,\"search\":true,\"contextWindow\":128000,\"maxOutput\":16384}},{\"pattern\":\"*gpt-4.1*\",\"caps\":{\"vision\":true,\"contextWindow\":1000000,\"maxOutput\":32768}},{\"pattern\":\"*gpt-4-turbo*\",\"caps\":{\"vision\":true,\"contextWindow\":128000}},{\"pattern\":\"*gpt-4*\",\"caps\":{\"contextWindow\":128000}},{\"pattern\":\"*gpt-3.5*\",\"caps\":{\"contextWindow\":16385,\"maxOutput\":4096}},{\"pattern\":\"*gpt-oss*\",\"caps\":{\"reasoning\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":128000}},{\"pattern\":\"*o1-mini*\",\"caps\":{\"reasoning\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":128000}},{\"pattern\":\"*o1*\",\"caps\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":100000}},{\"pattern\":\"*o3*\",\"caps\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":100000}},{\"pattern\":\"*o4*\",\"caps\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":100000}},{\"pattern\":\"*grok*image*\",\"caps\":{\"imageOutput\":true}},{\"pattern\":\"*grok-code*\",\"caps\":{\"reasoning\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":256000}},{\"pattern\":\"*grok-4.6*\",\"caps\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":500000,\"maxOutput\":500000}},{\"pattern\":\"*grok-4.5*\",\"caps\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":500000,\"maxOutput\":64000}},{\"pattern\":\"*grok-4*\",\"caps\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":256000}},{\"pattern\":\"*grok-3*\",\"caps\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":131072}},{\"pattern\":\"*grok*\",\"caps\":{\"vision\":true,\"reasoning\":true,\"search\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":256000}},{\"pattern\":\"*qwen*vl*\",\"caps\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"qwen\",\"contextWindow\":262144}},{\"pattern\":\"*qwen*omni*\",\"caps\":{\"vision\":true,\"audioInput\":true,\"videoInput\":true,\"reasoning\":true,\"thinkingFormat\":\"qwen\",\"contextWindow\":262144,\"maxOutput\":65536}},{\"pattern\":\"*qwen*coder*\",\"caps\":{\"reasoning\":true,\"thinkingFormat\":\"qwen\",\"contextWindow\":1000000}},{\"pattern\":\"*qwen*max*\",\"caps\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"qwen\",\"contextWindow\":1000000,\"maxOutput\":65536}},{\"pattern\":\"*qwen3.5*\",\"caps\":{\"vision\":true,\"videoInput\":true,\"reasoning\":true,\"thinkingFormat\":\"qwen\",\"contextWindow\":1000000,\"maxOutput\":65536}},{\"pattern\":\"*qwen3.6*\",\"caps\":{\"vision\":true,\"videoInput\":true,\"reasoning\":true,\"thinkingFormat\":\"qwen\",\"contextWindow\":1000000,\"maxOutput\":65536}},{\"pattern\":\"*qwen3.7*\",\"caps\":{\"vision\":true,\"videoInput\":true,\"reasoning\":true,\"thinkingFormat\":\"qwen\",\"contextWindow\":1000000,\"maxOutput\":65536}},{\"pattern\":\"*qwen*plus*\",\"caps\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"qwen\",\"contextWindow\":1000000,\"maxOutput\":65536}},{\"pattern\":\"*qwen*235b*\",\"caps\":{\"reasoning\":true,\"thinkingFormat\":\"qwen\",\"contextWindow\":262144}},{\"pattern\":\"*qwq*\",\"caps\":{\"reasoning\":true,\"thinkingFormat\":\"qwen\",\"thinkingCanDisable\":false,\"contextWindow\":131072}},{\"pattern\":\"*qwen*\",\"caps\":{\"reasoning\":true,\"thinkingFormat\":\"qwen\",\"contextWindow\":262144}},{\"pattern\":\"*kimi*k3*\",\"caps\":{\"vision\":true,\"videoInput\":true,\"reasoning\":true,\"thinkingFormat\":\"kimi\",\"thinkingCanDisable\":false,\"contextWindow\":1048576,\"maxOutput\":131072}},{\"pattern\":\"*kimi*for-coding*\",\"caps\":{\"vision\":true,\"videoInput\":true,\"reasoning\":true,\"thinkingFormat\":\"kimi\",\"thinkingCanDisable\":false,\"contextWindow\":262144,\"maxOutput\":65536}},{\"pattern\":\"*kimi*k2.7*code*\",\"caps\":{\"vision\":true,\"videoInput\":true,\"reasoning\":true,\"thinkingFormat\":\"kimi\",\"thinkingCanDisable\":false,\"contextWindow\":262144,\"maxOutput\":65536}},{\"pattern\":\"*kimi*k2*\",\"caps\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"kimi\",\"contextWindow\":262144,\"maxOutput\":262144}},{\"pattern\":\"*kimi*\",\"caps\":{\"reasoning\":true,\"thinkingFormat\":\"kimi\",\"contextWindow\":262144}},{\"pattern\":\"*glm-5.3*\",\"caps\":{\"reasoning\":true,\"thinkingFormat\":\"zai\",\"thinkingEffortSupported\":true,\"thinkingCanDisable\":false,\"contextWindow\":1000000,\"maxOutput\":128000}},{\"pattern\":\"*glm-5.2*\",\"caps\":{\"reasoning\":true,\"thinkingFormat\":\"zai\",\"thinkingEffortSupported\":true,\"contextWindow\":1000000,\"maxOutput\":128000}},{\"pattern\":\"*glm-5*\",\"caps\":{\"reasoning\":true,\"thinkingFormat\":\"zai\",\"contextWindow\":200000,\"maxOutput\":128000}},{\"pattern\":\"*glm-4.7*\",\"caps\":{\"reasoning\":true,\"thinkingFormat\":\"zai\",\"contextWindow\":200000,\"maxOutput\":128000}},{\"pattern\":\"*glm-4*\",\"caps\":{\"reasoning\":true,\"thinkingFormat\":\"zai\",\"contextWindow\":200000}},{\"pattern\":\"*glm*\",\"caps\":{\"reasoning\":true,\"thinkingFormat\":\"zai\",\"contextWindow\":200000}},{\"pattern\":\"*deepseek-v4.*\",\"caps\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"deepseek\",\"thinkingEffortSupported\":true,\"contextWindow\":1000000,\"maxOutput\":128000}},{\"pattern\":\"*deepseek-v4*\",\"caps\":{\"reasoning\":true,\"thinkingFormat\":\"deepseek\",\"thinkingEffortSupported\":true,\"contextWindow\":1000000,\"maxOutput\":384000}},{\"pattern\":\"*reasoner*\",\"caps\":{\"reasoning\":true,\"thinkingFormat\":\"deepseek\",\"thinkingCanDisable\":false,\"contextWindow\":128000}},{\"pattern\":\"*deepseek-r*\",\"caps\":{\"reasoning\":true,\"thinkingFormat\":\"deepseek\",\"thinkingCanDisable\":false,\"contextWindow\":128000}},{\"pattern\":\"*deepseek-chat*\",\"caps\":{\"contextWindow\":128000}},{\"pattern\":\"*deepseek*\",\"caps\":{\"reasoning\":true,\"thinkingFormat\":\"deepseek\",\"contextWindow\":128000}},{\"pattern\":\"*minimax*image*\",\"caps\":{\"imageOutput\":true}},{\"pattern\":\"*minimax-m3*\",\"caps\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"minimax\",\"contextWindow\":1000000,\"maxOutput\":131072}},{\"pattern\":\"*minimax-m2.7*\",\"caps\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"minimax\",\"thinkingCanDisable\":false,\"contextWindow\":204800,\"maxOutput\":131072}},{\"pattern\":\"*minimax-m2.5*\",\"caps\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"minimax\",\"thinkingCanDisable\":false,\"contextWindow\":204800,\"maxOutput\":131072}},{\"pattern\":\"*minimax*\",\"caps\":{\"reasoning\":true,\"thinkingFormat\":\"minimax\",\"thinkingCanDisable\":false,\"contextWindow\":200000,\"maxOutput\":131072}},{\"pattern\":\"*mimo*v2.6*\",\"caps\":{\"vision\":true,\"audioInput\":true,\"videoInput\":true,\"reasoning\":true,\"thinkingFormat\":\"deepseek\",\"thinkingCanDisable\":false,\"contextWindow\":1048576,\"maxOutput\":131072}},{\"pattern\":\"*mimo*v2.5*\",\"caps\":{\"vision\":true,\"audioInput\":true,\"videoInput\":true,\"reasoning\":true,\"thinkingFormat\":\"deepseek\",\"thinkingCanDisable\":false,\"contextWindow\":1048576,\"maxOutput\":131072}},{\"pattern\":\"*mimo*omni*\",\"caps\":{\"vision\":true,\"audioInput\":true,\"reasoning\":true,\"thinkingFormat\":\"deepseek\",\"thinkingCanDisable\":false,\"contextWindow\":262144,\"maxOutput\":131072}},{\"pattern\":\"*mimo*\",\"caps\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"deepseek\",\"thinkingCanDisable\":false,\"contextWindow\":262144,\"maxOutput\":131072}},{\"pattern\":\"*llama-4*\",\"caps\":{\"vision\":true,\"contextWindow\":1000000}},{\"pattern\":\"*llama*\",\"caps\":{\"contextWindow\":128000}},{\"pattern\":\"*codestral*\",\"caps\":{\"contextWindow\":256000}},{\"pattern\":\"*mistral-large*\",\"caps\":{\"vision\":true,\"contextWindow\":256000}},{\"pattern\":\"*mistral*\",\"caps\":{\"contextWindow\":128000}},{\"pattern\":\"*command-a-vision*\",\"caps\":{\"vision\":true,\"contextWindow\":128000}},{\"pattern\":\"*command*\",\"caps\":{\"contextWindow\":128000}},{\"pattern\":\"*sonar*\",\"caps\":{\"search\":true,\"contextWindow\":128000}},{\"pattern\":\"*pplx*\",\"caps\":{\"search\":true,\"contextWindow\":128000}},{\"pattern\":\"*perplexity*\",\"caps\":{\"search\":true,\"contextWindow\":128000}},{\"pattern\":\"*laguna-s-2.1*free*\",\"caps\":{\"reasoning\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":32000}},{\"pattern\":\"*laguna-s-2.1*\",\"caps\":{\"reasoning\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":1000000,\"maxOutput\":32000}},{\"pattern\":\"*laguna*\",\"caps\":{\"reasoning\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":200000,\"maxOutput\":32000}},{\"pattern\":\"*muse*spark*\",\"caps\":{\"vision\":true,\"reasoning\":true,\"thinkingFormat\":\"openai\",\"contextWindow\":1048576,\"maxOutput\":131072}},{\"pattern\":\"*hunyuan*\",\"caps\":{\"reasoning\":true,\"thinkingFormat\":\"hunyuan\",\"contextWindow\":262144,\"maxOutput\":262144}},{\"pattern\":\"hy3*\",\"caps\":{\"reasoning\":true,\"thinkingFormat\":\"hunyuan\",\"contextWindow\":262144,\"maxOutput\":262144}},{\"pattern\":\"*step-*\",\"caps\":{\"reasoning\":true,\"thinkingFormat\":\"step\",\"contextWindow\":128000}},{\"pattern\":\"*nemotron*\",\"caps\":{\"reasoning\":true,\"contextWindow\":128000}},{\"pattern\":\"*ling-*\",\"caps\":{\"reasoning\":true,\"contextWindow\":128000}}]}"

// ---------- capabilities (open-sse/providers/capabilities.js port) ----------

type pvCapsTables struct {
	Model    map[string]map[string]any            `json:"model"`
	Provider map[string]map[string]map[string]any `json:"provider"`
	Patterns []struct {
		Pattern string         `json:"pattern"`
		Caps    map[string]any `json:"caps"`
	} `json:"patterns"`
}

var pvCapsOnce struct {
	once   sync.Once
	tables *pvCapsTables
}

func pvCapsData() *pvCapsTables {
	pvCapsOnce.once.Do(func() {
		t := &pvCapsTables{}
		_ = json.Unmarshal([]byte(pvCapsJSON), t)
		pvCapsOnce.tables = t
	})
	return pvCapsOnce.tables
}

var pvDefaultCaps = map[string]any{
	"vision": false, "pdf": false, "audioInput": false, "videoInput": false,
	"imageOutput": false, "audioOutput": false,
	"search": false, "tools": true, "reasoning": false,
	"thinkingFormat": nil, "thinkingCanDisable": true, "thinkingRange": nil,
	"thinkingEffortSupported": false,
	"contextWindow":           float64(200000), "maxOutput": float64(64000),
}

var pvNotVisionRe = regexp.MustCompile(`(?i)(^|[-_/:.])(image|img)([-_/:.]|$)|stable-image|gen[0-9]_image|nanobanana|imagine|t2v|i2v|flux|dall|sdxl|diffusion|embed|rerank|guard|moderation|tts|stt|whisper|voice|speech|audio`)
var pvVisionNameRe = regexp.MustCompile(`(?i)(^|[-_/:.])(vision|vl|vlm|multimodal|omni|visual)([-_/:.]|$)|[0-9]\.[0-9]+v([-_/:.]|$)|(^|[-_/:.])glm-[0-9]+v([-_/:.]|$)|(^|[-_/:.])(llava|pixtral|internvl|cogvlm|minicpm-v|moondream|idefics|fuyu)`)

func pvLooksLikeVision(model string) bool {
	if model == "" {
		return false
	}
	id := strings.ToLower(model)
	if pvNotVisionRe.MatchString(id) {
		return false
	}
	return pvVisionNameRe.MatchString(id)
}

// pvMatchPattern ports pricing.js matchPattern (glob, case-insensitive).
func pvMatchPattern(pattern, model string) bool {
	parts := strings.Split(pattern, "*")
	var sb strings.Builder
	sb.WriteString("^")
	for i, p := range parts {
		if i > 0 {
			sb.WriteString(".*")
		}
		sb.WriteString(regexp.QuoteMeta(p))
	}
	sb.WriteString("$")
	re, err := regexp.Compile("(?i)" + sb.String())
	if err != nil {
		return false
	}
	return re.MatchString(model)
}

var pvCommandCodeTextOnly = map[string]bool{
	"deepseek/deepseek-v4-pro": true, "deepseek/deepseek-v4-flash": true,
	"deepseek/deepseek-v4-flash-fast": true, "zai-org/glm-5.3": true,
	"zai-org/glm-5.2": true, "zai-org/glm-5.2-fast": true, "zai-org/glm-5.1": true,
	"zai-org/glm-5": true, "minimaxai/minimax-m2.7": true, "minimax/minimax-m2.7-free": true,
	"minimaxai/minimax-m2.5": true, "xiaomi/mimo-v2.5-pro": true,
	"qwen/qwen3.6-max-preview": true, "qwen/qwen3.7-max": true,
	"meituan/longcat-2.0:free": true, "stepfun/step-3.5-flash": true,
	"tencent/hy4-preview": true, "tencent/hy3": true, "tencent/hy3-paid": true,
	"nvidia/nemotron-3-ultra-550b-a55b": true, "poolside/laguna-s-2.1-free": true,
	"inclusionai/ling-3.0-flash-free": true, "inclusionai/ling-3.0-flash-sante:free": true,
}

func pvIsCommandCodeTextOnly(model string) bool {
	key := strings.ToLower(model)
	if pvCommandCodeTextOnly[key] {
		return true
	}
	for id := range pvCommandCodeTextOnly {
		base := id
		if i := strings.LastIndex(id, "/"); i >= 0 {
			base = id[i+1:]
		}
		if key == base || strings.HasSuffix(key, "/"+base) {
			return true
		}
	}
	return false
}

func pvMergeCaps(base, over map[string]any) map[string]any {
	out := pvCloneMap(base)
	for k, v := range over {
		out[k] = v
	}
	return out
}

// ---------- synced catalog reader (open-sse/providers/catalogOverride.js port) ----------

// pvCatalogDetached mirrors setCatalogSource(null) during collectEntries:
// while set, pvRefineCaps skips the synced-catalog overlay.
var pvCatalogDetached atomic.Bool

var pvSyncedCatalog = struct {
	sync.Mutex
	mtime     int64
	loaded    bool
	models    map[string]any
	providers map[string]any
}{mtime: -1}

// pvLoadSyncedCatalog ports catalogOverride load(): the parsed catalog
// file, cached until its mtime changes.
func pvLoadSyncedCatalog() (map[string]any, map[string]any) {
	pvSyncedCatalog.Lock()
	defer pvSyncedCatalog.Unlock()
	info, err := os.Stat(pvCatalogFile())
	if err != nil {
		pvSyncedCatalog.models, pvSyncedCatalog.providers = nil, nil
		pvSyncedCatalog.mtime = -1
		pvSyncedCatalog.loaded = true
		return nil, nil
	}
	mtime := info.ModTime().UnixMilli()
	if pvSyncedCatalog.loaded && mtime == pvSyncedCatalog.mtime {
		return pvSyncedCatalog.models, pvSyncedCatalog.providers
	}
	pvSyncedCatalog.mtime = mtime
	pvSyncedCatalog.loaded = true
	pvSyncedCatalog.models, pvSyncedCatalog.providers = nil, nil
	data, rerr := os.ReadFile(pvCatalogFile())
	if rerr != nil {
		return nil, nil
	}
	var parsed map[string]any
	if json.Unmarshal(data, &parsed) == nil {
		pvSyncedCatalog.models = pvMap(parsed, "models")
		pvSyncedCatalog.providers = pvMap(parsed, "providers")
	}
	return pvSyncedCatalog.models, pvSyncedCatalog.providers
}

// pvInvalidateSyncedCatalog ports invalidateCatalog().
func pvInvalidateSyncedCatalog() {
	pvSyncedCatalog.Lock()
	pvSyncedCatalog.mtime = -1
	pvSyncedCatalog.loaded = false
	pvSyncedCatalog.Unlock()
}

// pvCatalogModalities ports getCatalogModalities.
func pvCatalogModalities(provider, model string) map[string]any {
	if provider == "" {
		return nil
	}
	models, _ := pvLoadSyncedCatalog()
	if models == nil {
		return nil
	}
	m, _ := models[provider+":"+pvCatalogBaseID(model)].(map[string]any)
	return m
}

// pvCatalogLimits ports getCatalogLimits.
func pvCatalogLimits(provider, model string) map[string]any {
	if provider == "" {
		return nil
	}
	_, providersMap := pvLoadSyncedCatalog()
	byProvider, _ := providersMap[provider].(map[string]any)
	if byProvider == nil {
		return nil
	}
	if m, _ := byProvider[model].(map[string]any); m != nil {
		return m
	}
	m, _ := byProvider[pvCatalogBaseID(model)].(map[string]any)
	return m
}

// pvRefineCaps ports refine(): the synced-catalog overlay (strictly
// additive for modalities; limits override when positive) plus the vision
// name heuristic. The overlay is skipped while pvCatalogDetached is set
// (collectEntries semantics).
func pvRefineCaps(base map[string]any, provider, model string) map[string]any {
	result := pvMergeCaps(pvDefaultCaps, base)
	if !pvCatalogDetached.Load() {
		if modalities := pvCatalogModalities(provider, model); modalities != nil {
			for _, key := range []string{"vision", "pdf", "audioInput", "videoInput"} {
				if v, _ := modalities[key].(bool); v {
					result[key] = true
				}
			}
		}
		if limits := pvCatalogLimits(provider, model); limits != nil {
			if f, ok := pvNum(limits, "contextWindow"); ok && f > 0 {
				result["contextWindow"] = f
			}
			if f, ok := pvNum(limits, "maxOutput"); ok && f > 0 {
				result["maxOutput"] = f
			}
		}
	}
	if v, _ := result["vision"].(bool); !v && pvLooksLikeVision(model) {
		result["vision"] = true
	}
	return result
}

// pvCapabilities ports getCapabilitiesForModel(provider, model).
func pvCapabilities(provider, model string) map[string]any {
	if model == "" {
		return pvCloneMap(pvDefaultCaps)
	}
	tables := pvCapsData()
	baseModel := model
	if i := strings.LastIndex(model, "/"); i >= 0 {
		baseModel = model[i+1:]
	}
	if provider == "commandcode" || provider == "cmc" {
		pc := tables.Provider["commandcode"]
		if c := pc[model]; c != nil {
			return pvMergeCaps(pvDefaultCaps, c)
		}
		if c := pc[baseModel]; c != nil {
			return pvMergeCaps(pvDefaultCaps, c)
		}
		out := pvCloneMap(pvDefaultCaps)
		out["reasoning"] = true
		out["thinkingFormat"] = "commandcode"
		out["thinkingEffortSupported"] = true
		out["vision"] = !pvIsCommandCodeTextOnly(model)
		out["contextWindow"] = float64(1000000)
		out["maxOutput"] = float64(384000)
		return out
	}
	if provider != "" {
		if pc := tables.Provider[provider]; pc != nil {
			if c := pc[model]; c != nil {
				return pvMergeCaps(pvDefaultCaps, c)
			}
			if c := pc[baseModel]; c != nil {
				return pvMergeCaps(pvDefaultCaps, c)
			}
		}
	}
	if c := tables.Model[baseModel]; c != nil {
		return pvRefineCaps(c, provider, model)
	}
	if c := tables.Model[model]; c != nil {
		return pvRefineCaps(c, provider, model)
	}
	for _, p := range tables.Patterns {
		if pvMatchPattern(p.Pattern, baseModel) || pvMatchPattern(p.Pattern, model) {
			return pvRefineCaps(p.Caps, provider, model)
		}
	}
	return pvRefineCaps(nil, provider, model)
}

func pvCapsOut(c map[string]any) map[string]any {
	return map[string]any{
		"vision":        c["vision"],
		"search":        c["search"],
		"reasoning":     c["reasoning"],
		"contextWindow": c["contextWindow"],
		"maxOutput":     c["maxOutput"],
	}
}

// ---------- models ----------

// pvAIModels builds the AI_MODELS equivalent: one entry per catalog
// provider key (alias), in registry order, deduplicated by key.
func pvAIModels() []map[string]any {
	seen := map[string]bool{}
	out := []map[string]any{}
	for _, p := range providers.All() {
		key := p.Alias
		if key == "" {
			key = p.ID
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		for _, m := range modelcatalog.Models(p.ID) {
			id := pvStr(m, "id")
			if id == "" {
				continue
			}
			out = append(out, map[string]any{
				"provider": key,
				"model":    id,
				"name":     pvStrOr(m, "name", id),
			})
		}
	}
	return out
}

func pvModelsList(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		aliases, _ := deps.Store.GetModelAliases()
		disabled, _ := deps.Store.GetDisabledModels()
		models := []any{}
		seenFull := map[string]bool{}
		seenRouted := map[string]bool{}
		for _, m := range pvAIModels() {
			providerKey := pvStr(m, "provider")
			modelID := pvStr(m, "model")
			providerAlias := pvProviderAlias(pvAliasToID(providerKey))
			if providerAlias == "" {
				providerAlias = providerKey
			}
			list := pvStrSlice(disabled[providerAlias])
			if len(list) == 0 {
				list = pvStrSlice(disabled[providerKey])
			}
			skip := false
			for _, d := range list {
				if d == modelID {
					skip = true
					break
				}
			}
			if skip {
				continue
			}
			fullModel := providerKey + "/" + modelID
			routedModel := providerAlias + "/" + modelID
			alias := pvStr(aliases, fullModel)
			if alias == "" {
				alias = modelID
			}
			entry := map[string]any{
				"provider":    providerKey,
				"model":       modelID,
				"name":        m["name"],
				"fullModel":   fullModel,
				"routedModel": routedModel,
				"alias":       alias,
				"caps":        pvCapsOut(pvCapabilities(providerKey, modelID)),
			}
			seenFull[fullModel] = true
			seenRouted[routedModel] = true
			models = append(models, entry)
		}
		custom, _ := deps.Store.GetCustomModels()
		for _, cm := range custom {
			id := pvStr(cm, "id")
			if id == "" {
				continue
			}
			kind := pvStrOr(cm, "kind", "")
			if kind == "" {
				kind = pvStrOr(cm, "type", "llm")
			}
			if kind != "llm" {
				continue
			}
			providerAlias := pvStr(cm, "providerAlias")
			fullModel := providerAlias + "/" + id
			if seenRouted[fullModel] || seenFull[fullModel] {
				continue
			}
			providerID := pvAliasToID(providerAlias)
			caps := pvCapsOut(pvCapabilities(providerID, id))
			for k, v := range pvMap(cm, "caps") {
				caps[k] = v
			}
			alias := pvStr(aliases, fullModel)
			if alias == "" {
				alias = id
			}
			models = append(models, map[string]any{
				"provider":    providerAlias,
				"model":       id,
				"name":        pvStrOr(cm, "name", id),
				"fullModel":   fullModel,
				"routedModel": fullModel,
				"alias":       alias,
				"caps":        caps,
			})
		}
		WriteJSON(w, http.StatusOK, map[string]any{"models": models})
	}
}

func pvModelsSetAlias(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
		model := Str(body, "model")
		alias := Str(body, "alias")
		if model == "" || alias == "" {
			Err(w, http.StatusBadRequest, "Model and alias required")
			return
		}
		aliases, _ := deps.Store.GetModelAliases()
		for k, v := range aliases {
			if s, ok := v.(string); ok && s == alias && k != model {
				Err(w, http.StatusBadRequest, "Alias already in use")
				return
			}
		}
		// JS models route calls setModelAlias(model, alias) — the db
		// SetModelAlias(alias, model) signature means the stored key is the
		// model here (upstream quirk, mirrored literally).
		if serr := deps.Store.SetModelAlias(model, alias); serr != nil {
			Err(w, http.StatusInternalServerError, "Failed to update alias")
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"success": true, "model": model, "alias": alias})
	}
}

func pvAliasList(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		aliases, err := deps.Store.GetModelAliases()
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to fetch aliases")
			return
		}
		if aliases == nil {
			aliases = db.Record{}
		}
		WriteJSON(w, http.StatusOK, map[string]any{"aliases": aliases})
	}
}

func pvAliasPut(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
		model := Str(body, "model")
		alias := Str(body, "alias")
		if model == "" || alias == "" {
			Err(w, http.StatusBadRequest, "Model and alias required")
			return
		}
		if serr := deps.Store.SetModelAlias(alias, model); serr != nil {
			Err(w, http.StatusInternalServerError, "Failed to update alias")
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"success": true, "model": model, "alias": alias})
	}
}

func pvAliasDelete(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		alias := r.URL.Query().Get("alias")
		if alias == "" {
			Err(w, http.StatusBadRequest, "Alias required")
			return
		}
		if derr := deps.Store.DeleteModelAlias(alias); derr != nil {
			Err(w, http.StatusInternalServerError, "Failed to delete alias")
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"success": true})
	}
}

// sanitizeCaps: CAPACITY_META keys are vision + reasoning only.
func pvSanitizeCaps(caps map[string]any) map[string]any {
	if caps == nil {
		return nil
	}
	clean := map[string]any{}
	for _, k := range []string{"vision", "reasoning"} {
		if b, ok := caps[k].(bool); ok {
			clean[k] = b
		}
	}
	if len(clean) == 0 {
		return nil
	}
	return clean
}

func pvSanitizeTransport(transport, typ string) string {
	if typ != "stt" {
		return ""
	}
	t := strings.TrimSpace(transport)
	if t == "gemini-live" { // STT_TRANSPORTS whitelist
		return t
	}
	return ""
}

func pvCustomList(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		models, err := deps.Store.GetCustomModels()
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to fetch custom models")
			return
		}
		out := make([]any, 0, len(models))
		for _, m := range models {
			out = append(out, m)
		}
		WriteJSON(w, http.StatusOK, map[string]any{"models": out})
	}
}

func pvCustomCreate(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
		providerAlias := Str(body, "providerAlias")
		id := Str(body, "id")
		if providerAlias == "" || id == "" {
			Err(w, http.StatusBadRequest, "providerAlias and id required")
			return
		}
		typ := pvStrOr(body, "type", "llm")
		rec := db.Record{"providerAlias": providerAlias, "id": id, "type": typ}
		if pvHas(body, "name") {
			rec["name"] = body["name"]
		}
		if caps := pvSanitizeCaps(pvMap(body, "caps")); caps != nil {
			rec["caps"] = caps
		}
		if tr := pvSanitizeTransport(Str(body, "transport"), typ); tr != "" {
			rec["transport"] = tr
		}
		added, aerr := deps.Store.AddCustomModel(rec)
		if aerr != nil {
			Err(w, http.StatusInternalServerError, "Failed to add custom model")
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"success": true, "added": added})
	}
}

func pvCustomDelete(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		providerAlias := q.Get("providerAlias")
		id := q.Get("id")
		typ := q.Get("type")
		if typ == "" {
			typ = "llm"
		}
		if providerAlias == "" || id == "" {
			Err(w, http.StatusBadRequest, "providerAlias and id required")
			return
		}
		if derr := deps.Store.DeleteCustomModel(providerAlias, id, typ); derr != nil {
			Err(w, http.StatusInternalServerError, "Failed to delete custom model")
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"success": true})
	}
}

func pvDisabledList(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		all, err := deps.Store.GetDisabledModels()
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to fetch disabled models")
			return
		}
		if alias := r.URL.Query().Get("providerAlias"); alias != "" {
			ids := pvSlice(all, alias)
			if ids == nil {
				ids = []any{}
			}
			WriteJSON(w, http.StatusOK, map[string]any{"ids": ids})
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"disabled": all})
	}
}

func pvDisabledPost(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
		providerAlias := Str(body, "providerAlias")
		ids := pvSlice(body, "ids")
		if providerAlias == "" || ids == nil {
			Err(w, http.StatusBadRequest, "providerAlias and ids[] required")
			return
		}
		if derr := deps.Store.DisableModels(providerAlias, ids); derr != nil {
			Err(w, http.StatusInternalServerError, "Failed to disable models")
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"success": true})
	}
}

func pvDisabledDelete(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		providerAlias := q.Get("providerAlias")
		if providerAlias == "" {
			Err(w, http.StatusBadRequest, "providerAlias required")
			return
		}
		ids := []any{}
		if id := q.Get("id"); id != "" {
			ids = []any{id}
		}
		if derr := deps.Store.EnableModels(providerAlias, ids); derr != nil {
			Err(w, http.StatusInternalServerError, "Failed to enable models")
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"success": true})
	}
}

func pvAvailabilityList(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conns, err := deps.Store.GetProviderConnections(db.ConnectionFilter{})
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to fetch model availability")
			return
		}
		now := pvNowMs()
		models := []any{}
		for _, c := range conns {
			type lock struct {
				model string
				until any
			}
			locks := []lock{}
			keys := make([]string, 0, len(c))
			for k := range c {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if !strings.HasPrefix(k, "modelLock_") {
					continue
				}
				v := c[k]
				if v == nil || v == false || v == "" {
					continue
				}
				ms, ok := pvParseTimeMs(v)
				if !ok || ms <= now {
					continue
				}
				model := strings.TrimPrefix(k, "modelLock_")
				if model == "" {
					model = "__all"
				}
				locks = append(locks, lock{model: model, until: v})
			}
			name := pvStr(c, "name")
			if name == "" {
				name = pvStr(c, "email")
			}
			if name == "" {
				name = pvStr(c, "id")
			}
			var lastError any
			if le := c["lastError"]; le != nil {
				lastError = le
			}
			for _, l := range locks {
				models = append(models, map[string]any{
					"provider": pvStr(c, "provider"), "model": l.model, "status": "cooldown",
					"until": l.until, "connectionId": pvStr(c, "id"), "connectionName": name,
					"lastError": lastError,
				})
			}
			if len(locks) == 0 && pvStr(c, "testStatus") == "unavailable" {
				models = append(models, map[string]any{
					"provider": pvStr(c, "provider"), "model": "__all", "status": "unavailable",
					"connectionId": pvStr(c, "id"), "connectionName": name, "lastError": lastError,
				})
			}
		}
		WriteJSON(w, http.StatusOK, map[string]any{"models": models, "unavailableCount": len(models)})
	}
}

func pvAvailabilityPost(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, http.StatusBadRequest, "Invalid request")
			return
		}
		action := Str(body, "action")
		provider := Str(body, "provider")
		model := Str(body, "model")
		if action != "clearCooldown" || provider == "" || model == "" {
			Err(w, http.StatusBadRequest, "Invalid request")
			return
		}
		conns, _ := deps.Store.GetProviderConnections(db.ConnectionFilter{Provider: provider})
		lockKey := "modelLock_" + model
		for _, c := range conns {
			if c[lockKey] == nil {
				continue
			}
			update := db.Record{lockKey: nil}
			if pvStr(c, "testStatus") == "unavailable" {
				update["testStatus"] = "active"
				update["lastError"] = nil
				update["lastErrorAt"] = nil
				update["backoffLevel"] = 0
			}
			_, _ = deps.Store.UpdateProviderConnection(pvStr(c, "id"), update)
		}
		WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
	}
}

// pvCatalogFile ports CATALOG_FILE ($DATA_DIR/model-catalog.json).
func pvCatalogFile() string {
	return filepath.Join(db.DataDir(), "model-catalog.json")
}

func pvCatalogSyncGet(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state := pvGetSyncState()
		var catalog any
		if data, err := os.ReadFile(pvCatalogFile()); err == nil {
			var parsed map[string]any
			if json.Unmarshal(data, &parsed) == nil {
				models := pvMap(parsed, "models")
				providerMap := pvMap(parsed, "providers")
				catalog = map[string]any{
					"syncedAt":  parsed["syncedAt"],
					"models":    len(models),
					"providers": len(providerMap),
					"bytes":     len(data),
				}
			}
		}
		state["catalog"] = catalog
		WriteJSON(w, http.StatusOK, state)
	}
}

func pvCatalogSyncPost(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := pvSyncModelCatalog(r.Context())
		if result == nil {
			msg := "sync in progress"
			pvSyncMu.Lock()
			if s, _ := pvSyncState.LastError.(string); s != "" {
				msg = s
			}
			pvSyncMu.Unlock()
			Err(w, http.StatusServiceUnavailable, msg)
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"success": true, "result": result})
	}
}

// ---------- model catalog sync (src/lib/modelCatalog/sync.js port) ----------

const pvCatalogURL = "https://models.dev/api.json"
const pvCatalogVersion = 2

func pvCatalogRawFile() string {
	return filepath.Join(db.DataDir(), "model-catalog-raw.json")
}

var pvCatalogAliases = map[string]string{
	"github": "github-copilot", "glm": "zai", "glm-cn": "zhipuai",
	"claude": "anthropic", "gemini": "google", "kimi": "moonshotai",
	"kimi-cn": "moonshotai-cn", "qwen": "alibaba", "qwen-cn": "alibaba-cn",
	"zhipu": "zhipuai", "hunyuan": "tencent", "doubao": "volcengine",
	"cloudflare-ai": "cloudflare-workers-ai",
}

var pvModalityByInput = map[string]string{
	"image": "vision", "pdf": "pdf", "audio": "audioInput", "video": "videoInput",
}

// Process-global sync state (sync.js `state`).
var (
	pvSyncMu    sync.Mutex
	pvSyncState = struct {
		Running     bool
		LastSync    any
		LastError   any
		LastResult  any
		Etag        any
		FileVersion any
		restored    bool
	}{}
	pvSyncStartOnce sync.Once
)

// pvRestoreSyncStateLocked ports restoreEtag: resume etag/version/lastSync
// from the previously written catalog file. Caller holds pvSyncMu.
func pvRestoreSyncStateLocked() {
	if pvSyncState.restored {
		return
	}
	pvSyncState.restored = true
	data, err := os.ReadFile(pvCatalogFile())
	if err != nil {
		return
	}
	var parsed map[string]any
	if json.Unmarshal(data, &parsed) != nil {
		return
	}
	etag, _ := parsed["etag"].(string)
	if etag != "" {
		pvSyncState.Etag = etag
	} else {
		pvSyncState.Etag = nil
	}
	if v, ok := parsed["v"].(float64); ok && v != 0 {
		pvSyncState.FileVersion = v
	} else {
		pvSyncState.FileVersion = float64(1)
	}
	if info, serr := os.Stat(pvCatalogFile()); serr == nil {
		pvSyncState.LastSync = float64(info.ModTime().UnixMilli())
	}
}

// pvGetSyncState ports getSyncState().
func pvGetSyncState() map[string]any {
	pvSyncMu.Lock()
	defer pvSyncMu.Unlock()
	pvRestoreSyncStateLocked()
	return map[string]any{
		"running": pvSyncState.Running, "lastSync": pvSyncState.LastSync,
		"lastError": pvSyncState.LastError, "lastResult": pvSyncState.LastResult,
		"etag": pvSyncState.Etag, "fileVersion": pvSyncState.FileVersion,
		"file": pvCatalogFile(), "url": pvCatalogURL,
		"intervalMs": float64(24 * 60 * 60 * 1000),
	}
}

// pvCatalogBaseID ports baseId: "zai-org/GLM-4.6V:free" -> "glm-4.6v".
func pvCatalogBaseID(model string) string {
	if i := strings.LastIndex(model, "/"); i >= 0 {
		model = model[i+1:]
	}
	model = strings.ToLower(model)
	if i := strings.Index(model, ":"); i >= 0 {
		model = model[:i]
	}
	return model
}

type pvCatalogEntry struct {
	Provider         string
	Model            string
	ContextLength    float64
	HasContextLength bool
	Current          map[string]any
}

// pvCollectCatalogEntries ports collectEntries: every registry provider ×
// model with the hand-written tables' capabilities, the synced-catalog
// overlay detached (otherwise each delta is computed against the last one
// and the file erases itself over two runs).
func pvCollectCatalogEntries() []pvCatalogEntry {
	pvCatalogDetached.Store(true)
	defer pvCatalogDetached.Store(false)
	entries := []pvCatalogEntry{}
	for _, p := range providers.All() {
		rawModels, _ := p.Raw["models"].([]any)
		if rawModels != nil {
			for _, rm := range rawModels {
				mm, _ := rm.(map[string]any)
				if mm == nil {
					continue
				}
				id := pvStr(mm, "id")
				if id == "" {
					continue
				}
				e := pvCatalogEntry{Provider: p.ID, Model: id, Current: pvCapabilities(p.ID, id)}
				if f, ok := pvNum(mm, "contextLength"); ok {
					e.ContextLength, e.HasContextLength = f, true
				}
				entries = append(entries, e)
			}
			continue
		}
		for _, m := range p.Models {
			entries = append(entries, pvCatalogEntry{
				Provider: p.ID, Model: m.ID, Current: pvCapabilities(p.ID, m.ID),
			})
		}
	}
	return entries
}

// pvBuildCatalog ports build() from sync.js.
func pvBuildCatalog(catalog map[string]any, entries []pvCatalogEntry) (map[string]any, map[string]any) {
	localIds := map[string][]string{}
	for _, e := range entries {
		upstream := pvCatalogAliases[e.Provider]
		if upstream == "" {
			upstream = e.Provider
		}
		found := false
		for _, l := range localIds[upstream] {
			if l == e.Provider {
				found = true
			}
		}
		if !found {
			localIds[upstream] = append(localIds[upstream], e.Provider)
		}
	}
	byProvider := map[string]map[string]map[string]any{}
	models := map[string]any{}
	// Sorted provider iteration for deterministic output (JS uses object
	// insertion order; the maps are key-looked-up, never order-read).
	upstreamIDs := make([]string, 0, len(catalog))
	for id := range catalog {
		upstreamIDs = append(upstreamIDs, id)
	}
	sort.Strings(upstreamIDs)
	for _, providerID := range upstreamIDs {
		providerObj, _ := catalog[providerID].(map[string]any)
		locals := localIds[providerID]
		if locals == nil {
			locals = []string{providerID}
		}
		modelsById := map[string]map[string]any{}
		seen := map[string]bool{}
		rawModels := pvMap(providerObj, "models")
		modelIDs := make([]string, 0, len(rawModels))
		for id := range rawModels {
			modelIDs = append(modelIDs, id)
		}
		sort.Strings(modelIDs)
		for _, modelID := range modelIDs {
			model, _ := rawModels[modelID].(map[string]any)
			id := pvCatalogBaseID(modelID)
			modelsById[id] = model
			if seen[id] {
				continue
			}
			seen[id] = true
			declared := map[string]any{}
			if modalities := pvMap(model, "modalities"); modalities != nil {
				for _, input := range pvSlice(modalities, "input") {
					s, _ := input.(string)
					if key, ok := pvModalityByInput[s]; ok {
						declared[key] = true
					}
				}
			}
			if len(declared) > 0 {
				for _, local := range locals {
					models[local+":"+id] = declared
				}
				isLocal := false
				for _, l := range locals {
					if l == providerID {
						isLocal = true
					}
				}
				if !isLocal {
					models[providerID+":"+id] = declared
				}
			}
		}
		byProvider[providerID] = modelsById
	}
	providersOut := map[string]any{}
	for _, e := range entries {
		var upstream string
		if _, ok := catalog[e.Provider]; ok {
			upstream = e.Provider
		} else if alias := pvCatalogAliases[e.Provider]; alias != "" {
			if _, ok := catalog[alias]; ok {
				upstream = alias
			}
		}
		if upstream == "" {
			continue
		}
		rec := byProvider[upstream][pvCatalogBaseID(e.Model)]
		if rec == nil {
			continue
		}
		limits := pvMap(rec, "limit")
		delta := map[string]any{}
		curCtx, _ := pvNum(e.Current, "contextWindow")
		curOut, _ := pvNum(e.Current, "maxOutput")
		if c, ok := pvNum(limits, "context"); ok && c > 0 && !e.HasContextLength {
			ratio := 0.0
			if curCtx != 0 {
				ratio = absFloat(c-curCtx) / curCtx
			} else if c != curCtx {
				ratio = 1 // JS: x/0 -> Infinity > tolerance
			}
			if ratio > 0.1 {
				delta["contextWindow"] = c
			}
		}
		if o, ok := pvNum(limits, "output"); ok && o > 0 {
			ratio := 0.0
			if curOut != 0 {
				ratio = absFloat(o-curOut) / curOut
			} else if o != curOut {
				ratio = 1
			}
			if ratio > 0.1 {
				delta["maxOutput"] = o
			}
		}
		if len(delta) > 0 {
			pm, _ := providersOut[e.Provider].(map[string]any)
			if pm == nil {
				pm = map[string]any{}
				providersOut[e.Provider] = pm
			}
			pm[e.Model] = delta
		}
	}
	return models, providersOut
}

func absFloat(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}

// pvSlimCatalog ports slim(): the trimmed upstream catalog kept next to
// the merged file for the add-models skill.
func pvSlimCatalog(catalog map[string]any) map[string]any {
	out := map[string]any{}
	for providerID, rawProvider := range catalog {
		providerObj, _ := rawProvider.(map[string]any)
		models := map[string]any{}
		for modelID, rawModel := range pvMap(providerObj, "models") {
			model, _ := rawModel.(map[string]any)
			inputs := []any{}
			if modalities := pvMap(model, "modalities"); modalities != nil {
				for _, in := range pvSlice(modalities, "input") {
					if s, _ := in.(string); s != "text" {
						inputs = append(inputs, in)
					}
				}
			}
			entry := map[string]any{"i": inputs}
			if limits := pvMap(model, "limit"); limits != nil {
				if v, present := limits["context"]; present && v != nil {
					entry["c"] = v
				}
				if v, present := limits["output"]; present && v != nil {
					entry["o"] = v
				}
			}
			if r := model["reasoning"]; r != nil {
				if b, isBool := r.(bool); !isBool || b {
					entry["r"] = r
				}
			}
			models[modelID] = entry
		}
		out[providerID] = models
	}
	return out
}

func pvWriteFileAtomic(file string, contents []byte) error {
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return err
	}
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, contents, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, file)
}

// pvSyncModelCatalog ports syncModelCatalog: one sync run, returning the
// result summary or nil when it could not complete (already running or
// failed — pvSyncState.LastError carries the reason, like the JS state).
func pvSyncModelCatalog(ctx context.Context) map[string]any {
	pvSyncMu.Lock()
	if pvSyncState.Running {
		pvSyncMu.Unlock()
		return nil
	}
	pvRestoreSyncStateLocked()
	pvSyncState.Running = true
	etag, _ := pvSyncState.Etag.(string)
	fileVersion, _ := pvSyncState.FileVersion.(float64)
	pvSyncMu.Unlock()

	fail := func(err error) map[string]any {
		pvSyncMu.Lock()
		pvSyncState.LastError = pvErrText(err)
		pvSyncState.Running = false
		pvSyncMu.Unlock()
		return nil
	}

	headers := map[string]string{"Accept": "application/json"}
	if etag != "" && int(fileVersion) == pvCatalogVersion {
		headers["If-None-Match"] = etag
	}
	res, err := pvFetch(ctx, "GET", pvCatalogURL, headers, nil, 60*time.Second, "")
	if err != nil {
		return fail(err)
	}
	var result map[string]any
	if res.Status == 304 {
		result = map[string]any{"status": "unchanged"}
	} else if !res.OK {
		return fail(fmt.Errorf("HTTP %d", res.Status))
	} else {
		var catalog map[string]any
		if json.Unmarshal(res.Body, &catalog) != nil || catalog == nil {
			return fail(errors.New("models.dev catalog response was not valid JSON"))
		}
		newEtag := res.Headers.Get("ETag")
		entries := pvCollectCatalogEntries()
		models, providersMap := pvBuildCatalog(catalog, entries)
		serialized, merr := json.Marshal(map[string]any{
			"v": pvCatalogVersion, "etag": strOrNil(newEtag), "syncedAt": float64(pvNowMs()),
			"models": models, "providers": providersMap,
		})
		if merr != nil {
			return fail(merr)
		}
		if werr := pvWriteFileAtomic(pvCatalogFile(), serialized); werr != nil {
			return fail(werr)
		}
		rawSerialized, _ := json.Marshal(pvSlimCatalog(catalog))
		if werr := pvWriteFileAtomic(pvCatalogRawFile(), rawSerialized); werr != nil {
			return fail(werr)
		}
		pvSyncMu.Lock()
		if newEtag != "" {
			pvSyncState.Etag = newEtag
		} else {
			pvSyncState.Etag = nil
		}
		pvSyncState.FileVersion = float64(pvCatalogVersion)
		pvSyncMu.Unlock()
		pvInvalidateSyncedCatalog()
		result = map[string]any{
			"status": "updated", "etag": strOrNil(newEtag),
			"bytes": float64(len(serialized)), "models": float64(len(models)),
			"providers": float64(len(providersMap)),
		}
	}
	pvSyncMu.Lock()
	pvSyncState.LastSync = float64(pvNowMs())
	pvSyncState.LastError = nil
	pvSyncState.LastResult = result
	pvSyncState.Running = false
	pvSyncMu.Unlock()
	return result
}

func strOrNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// pvStartCatalogSync ports startModelCatalogSync: restore state and run
// the daily timer (60s startup delay, 30min retry on failure), disabled
// by MODEL_CATALOG_SYNC=off. Started once from RegisterProviders.
func pvStartCatalogSync() {
	if strings.EqualFold(os.Getenv("MODEL_CATALOG_SYNC"), "off") {
		return
	}
	pvSyncStartOnce.Do(func() {
		pvSyncMu.Lock()
		pvRestoreSyncStateLocked()
		pvSyncMu.Unlock()
		go func() {
			delay := 60 * time.Second
			for {
				time.Sleep(delay)
				result := pvSyncModelCatalog(context.Background())
				if result != nil {
					delay = 24 * time.Hour
				} else {
					delay = 30 * time.Minute
				}
			}
		}()
	})
}

// ---------- connection testing (test/testUtils.js port) ----------

const pvAppVersion = "0.5.104"

// Google OAuth client for gemini-cli/antigravity refresh — the upstream
// project's own published desktop OAuth client (open-sse/providers/shared.js
// GOOGLE_OAUTH_CLIENT), required for JS parity of the refresh flow.
const (
	pvGoogleClientID     = "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com"
	pvGoogleClientSecret = "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"
)

const pvNousValidationModel = "poolside/laguna-xs-2.1:free"
const pvNousChatURL = "https://inference-api.nousresearch.com/v1/chat/completions"

type pvOAuthTestCfg struct {
	URL            string
	BuildURL       func(token string) string
	Method         string
	AuthHeader     string
	AuthPrefix     string
	ExtraHeaders   map[string]string
	Body           string
	AcceptStatuses []int
	SoftFail       map[int]string
	CheckExpiry    bool
	TokenExists    bool
	NoAuth         bool
	Refreshable    bool
	UseAPIKey      bool
	HasConfig      bool
}

func pvOAuthCfg(provider string) *pvOAuthTestCfg {
	mk := func(c pvOAuthTestCfg) *pvOAuthTestCfg { c.HasConfig = true; return &c }
	switch provider {
	case "claude":
		return mk(pvOAuthTestCfg{CheckExpiry: true, Refreshable: true})
	case "codex":
		cliVersion := ""
		if p, ok := pvReg("codex"); ok {
			cliVersion = pvStr(pvRawMap(p, "transport"), "cliVersion")
		}
		return mk(pvOAuthTestCfg{
			URL: "https://chatgpt.com/backend-api/codex/responses", Method: "POST",
			AuthHeader: "Authorization", AuthPrefix: "Bearer ",
			ExtraHeaders:   map[string]string{"Content-Type": "application/json", "originator": "codex_cli_rs", "User-Agent": "codex_cli_rs/" + cliVersion},
			Body:           `{"model":"gpt-5.3-codex","input":[],"stream":false,"store":false}`,
			AcceptStatuses: []int{400}, Refreshable: true,
		})
	case "gemini-cli", "antigravity":
		return mk(pvOAuthTestCfg{
			URL: "https://www.googleapis.com/oauth2/v1/userinfo?alt=json", Method: "GET",
			AuthHeader: "Authorization", AuthPrefix: "Bearer ", Refreshable: true,
		})
	case "github":
		return mk(pvOAuthTestCfg{
			URL: "https://api.github.com/user", Method: "GET",
			AuthHeader: "Authorization", AuthPrefix: "Bearer ",
			ExtraHeaders: map[string]string{"User-Agent": "ProxyGo", "Accept": "application/vnd.github+json"},
		})
	case "iflow":
		return mk(pvOAuthTestCfg{
			Method: "GET", NoAuth: true,
			BuildURL: func(token string) string {
				return "https://iflow.cn/api/oauth/getUserInfo?accessToken=" + url.QueryEscape(token)
			},
		})
	case "kiro":
		return mk(pvOAuthTestCfg{CheckExpiry: true, Refreshable: true})
	case "qoder":
		return mk(pvOAuthTestCfg{URL: "https://openapi.qoder.sh/api/v1/userinfo", Method: "GET", AuthHeader: "Authorization", AuthPrefix: "Bearer "})
	case "qoder-cn":
		return mk(pvOAuthTestCfg{URL: "https://openapi.qoder.com.cn/api/v1/userinfo", Method: "GET", AuthHeader: "Authorization", AuthPrefix: "Bearer "})
	case "kimi", "kimi-coding":
		return mk(pvOAuthTestCfg{CheckExpiry: true, Refreshable: true})
	case "cursor", "codebuddy-cn", "codebuddy-intl":
		return mk(pvOAuthTestCfg{TokenExists: true})
	case "kilocode":
		return mk(pvOAuthTestCfg{URL: "https://api.kilo.ai/api/profile", Method: "GET", AuthHeader: "Authorization", AuthPrefix: "Bearer "})
	case "cline":
		return mk(pvOAuthTestCfg{Refreshable: true})
	case "gitlab":
		return mk(pvOAuthTestCfg{URL: "https://gitlab.com/api/v4/user", Method: "GET", AuthHeader: "Authorization", AuthPrefix: "Bearer "})
	case "kimchi":
		return mk(pvOAuthTestCfg{
			URL: "https://api.cast.ai/v1/llm/openai/supported-providers", Method: "GET",
			AuthHeader: "Authorization", AuthPrefix: "Bearer ",
			ExtraHeaders: map[string]string{"Accept": "application/json", "User-Agent": "kimchi/0.1.40"},
		})
	case "grok-cli":
		userURL := "https://cli-chat-proxy.grok.com/v1/user"
		headers := map[string]string{"Accept": "application/json"}
		if p, ok := pvReg("grok-cli"); ok {
			if t := pvRawMap(p, "transport"); t != nil {
				if u := pvStr(t, "userUrl"); u != "" {
					userURL = u
				}
			}
			for k, v := range p.Transport.Headers {
				headers[k] = v
			}
		}
		return mk(pvOAuthTestCfg{
			URL: userURL, Method: "GET", AuthHeader: "Authorization", AuthPrefix: "Bearer ",
			ExtraHeaders:   headers,
			Refreshable:    true,
			AcceptStatuses: []int{402},
			SoftFail:       map[int]string{402: "Connected, but Grok Build credits are exhausted (spending limit). Add credits or upgrade SuperGrok."},
		})
	case "muse":
		return mk(pvOAuthTestCfg{
			URL: "https://api.meta.ai/v1/models", Method: "GET",
			AuthHeader: "Authorization", AuthPrefix: "Bearer ",
			ExtraHeaders: map[string]string{"x-api-version": "1.0.0"},
		})
	case "nous":
		body, _ := json.Marshal(map[string]any{
			"model": pvNousValidationModel, "messages": []any{map[string]any{"role": "user", "content": "ping"}},
			"max_tokens": 1, "stream": false,
		})
		return mk(pvOAuthTestCfg{
			URL: pvNousChatURL, Method: "POST", AuthHeader: "Authorization", AuthPrefix: "Bearer ",
			ExtraHeaders: map[string]string{"Content-Type": "application/json"},
			Body:         string(body), Refreshable: true, UseAPIKey: true,
		})
	}
	return nil
}

type pvTestOutcome struct {
	Valid     bool
	Err       *string
	Warning   *string
	Refreshed bool
	NewTokens map[string]any
}

func pvStrPtr(s string) *string { return &s }

func pvOutcomeErr(msg string) pvTestOutcome {
	return pvTestOutcome{Valid: false, Err: pvStrPtr(msg)}
}

func pvOutcomeOK() pvTestOutcome { return pvTestOutcome{Valid: true} }

// pvFetchViaProxy ports fetchWithConnectionProxy / proxyAwareFetch (15s
// default timeout). Relay-type proxies (vercel/cloudflare/deno/netlify
// pools, all mapped onto VercelRelayURL — connectionProxy.js notes they use
// the exact same header spec) rewrite the request through the relay: the
// fetch goes to the relay URL itself with the original target carried in
// the x-relay-target (scheme://host) and x-relay-path (pathname+search)
// headers, method/body/headers otherwise unchanged.
func pvFetchViaProxy(ctx context.Context, rawURL, method string, headers map[string]string, body []byte, proxy pvProxyConfig) (*pvFetchResult, error) {
	if relay := strings.TrimSpace(proxy.VercelRelayURL); relay != "" {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			return nil, err
		}
		relayHeaders := make(map[string]string, len(headers)+2)
		for k, v := range headers {
			relayHeaders[k] = v
		}
		relayHeaders["x-relay-target"] = parsed.Scheme + "://" + parsed.Host
		path := parsed.EscapedPath()
		if path == "" {
			path = "/"
		}
		if parsed.RawQuery != "" {
			path += "?" + parsed.RawQuery
		}
		relayHeaders["x-relay-path"] = path
		return pvFetch(ctx, method, relay, relayHeaders, body, 15*time.Second, "")
	}
	return pvFetch(ctx, method, rawURL, headers, body, 15*time.Second, proxy.pvProxyURLForFetch())
}

// pvShouldRefresh ports shouldRefreshCredentials.
func pvShouldRefresh(provider string, conn db.Record) bool {
	lead := int64(5 * 60 * 1000) // TOKEN_EXPIRY_BUFFER_MS
	if p, ok := pvReg(provider); ok {
		if o := pvRawMap(p, "oauth"); o != nil {
			if v, ok2 := pvNum(o, "refreshLeadMs"); ok2 && v > 0 {
				lead = int64(v)
			}
			if provider == "kimi-coding" {
				if kp, kok := pvReg("kimi"); kok {
					if ko := pvRawMap(kp, "oauth"); ko != nil {
						if v, ok2 := pvNum(ko, "refreshLeadMs"); ok2 && v > 0 {
							lead = int64(v)
						}
					}
				}
			}
		}
	}
	now := pvNowMs()
	if exp, ok := pvParseTimeMs(firstNonNil(conn["expiresAt"], conn["tokenExpiresAt"])); ok {
		if exp-now < lead {
			return true
		}
	}
	// Proactive stale refresh (codex oauth.maxRefreshAgeMs).
	if p, ok := pvReg(provider); ok {
		if o := pvRawMap(p, "oauth"); o != nil {
			if maxAge, ok2 := pvNum(o, "maxRefreshAgeMs"); ok2 && maxAge > 0 && pvStr(conn, "refreshToken") != "" {
				last, lok := pvParseTimeMs(firstNonNil(conn["lastRefreshAt"], conn["lastRefresh"], pvMap(conn, "providerSpecificData")["lastRefreshAt"]))
				if !lok || now-last >= int64(maxAge) {
					return true
				}
			}
		}
	}
	return false
}

func firstNonNil(vals ...any) any {
	for _, v := range vals {
		if v != nil {
			return v
		}
	}
	return nil
}

// pvRefreshOAuthToken ports refreshOAuthToken. Providers the JS delegates
// to refreshProviderCredentials (codex, grok-cli, xai, nous) go through
// oauthsvc.RefreshAccessToken — Team G's port of the same oauth library the
// JS delegates to — and its token map is returned in the merged shape the
// callers persist (accessToken/refreshToken/apiKey/idToken/expiresIn/
// lastRefreshAt/providerSpecificData), exactly like the inline cases below.
func pvRefreshOAuthToken(ctx context.Context, conn db.Record) map[string]any {
	provider := pvStr(conn, "provider")
	refreshToken := pvStr(conn, "refreshToken")
	if refreshToken == "" {
		return nil
	}
	switch provider {
	case "gemini-cli", "antigravity":
		form := url.Values{
			"client_id":     {pvGoogleClientID},
			"client_secret": {pvGoogleClientSecret},
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
		}
		res, err := pvFetch(ctx, "POST", "https://oauth2.googleapis.com/token",
			map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			[]byte(form.Encode()), 0, "")
		if err != nil || !res.OK {
			return nil
		}
		data := res.JSONMap()
		if data == nil {
			return nil
		}
		out := map[string]any{"accessToken": pvStr(data, "access_token"), "expiresIn": data["expires_in"]}
		if rt := pvStr(data, "refresh_token"); rt != "" {
			out["refreshToken"] = rt
		} else {
			out["refreshToken"] = refreshToken
		}
		return out
	case "claude":
		tokenURL := "https://api.anthropic.com/v1/oauth/token"
		clientID := "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
		if p, ok := pvReg("claude"); ok {
			if o := pvRawMap(p, "oauth"); o != nil {
				tokenURL = pvStrOr(o, "tokenUrl", tokenURL)
				clientID = pvStrOr(o, "clientId", clientID)
			}
		}
		res, err := pvFetchJSON(ctx, "POST", tokenURL,
			map[string]string{"Accept": "application/json"},
			map[string]any{"grant_type": "refresh_token", "refresh_token": refreshToken, "client_id": clientID}, 0, "")
		if err != nil || !res.OK {
			return nil
		}
		data := res.JSONMap()
		if data == nil {
			return nil
		}
		out := map[string]any{"accessToken": pvStr(data, "access_token"), "expiresIn": data["expires_in"]}
		if rt := pvStr(data, "refresh_token"); rt != "" {
			out["refreshToken"] = rt
		} else {
			out["refreshToken"] = refreshToken
		}
		return out
	case "kiro":
		psd := pvConnPSD(conn)
		clientID := pvStr(psd, "clientId")
		if clientID == "" {
			clientID = pvStr(conn, "clientId")
		}
		clientSecret := pvStr(psd, "clientSecret")
		if clientSecret == "" {
			clientSecret = pvStr(conn, "clientSecret")
		}
		region := pvStr(psd, "region")
		if region == "" {
			region = pvStr(conn, "region")
		}
		if clientID != "" && clientSecret != "" {
			if region == "" {
				region = "us-east-1"
			}
			endpoint := "https://oidc." + region + ".amazonaws.com/token"
			res, err := pvFetchJSON(ctx, "POST", endpoint, nil, map[string]any{
				"clientId": clientID, "clientSecret": clientSecret,
				"refreshToken": refreshToken, "grantType": "refresh_token",
			}, 0, "")
			if err != nil || !res.OK {
				return nil
			}
			data := res.JSONMap()
			if data == nil {
				return nil
			}
			exp, _ := pvNum(data, "expiresIn")
			if exp == 0 {
				exp = 3600
			}
			out := map[string]any{"accessToken": pvStr(data, "accessToken"), "expiresIn": exp}
			if rt := pvStr(data, "refreshToken"); rt != "" {
				out["refreshToken"] = rt
			} else {
				out["refreshToken"] = refreshToken
			}
			return out
		}
		res, err := pvFetchJSON(ctx, "POST", "https://prod.us-east-1.auth.desktop.kiro.dev/refreshToken",
			map[string]string{"User-Agent": "kiro-cli/1.0.0"},
			map[string]any{"refreshToken": refreshToken}, 0, "")
		if err != nil || !res.OK {
			return nil
		}
		data := res.JSONMap()
		if data == nil {
			return nil
		}
		exp, _ := pvNum(data, "expiresIn")
		if exp == 0 {
			exp = 3600
		}
		out := map[string]any{"accessToken": pvStr(data, "accessToken"), "expiresIn": exp}
		if rt := pvStr(data, "refreshToken"); rt != "" {
			out["refreshToken"] = rt
		} else {
			out["refreshToken"] = refreshToken
		}
		return out
	case "cline":
		res, err := pvFetchJSON(ctx, "POST", "https://api.cline.bot/api/v1/auth/refresh",
			map[string]string{"Accept": "application/json"},
			map[string]any{"refreshToken": refreshToken, "grantType": "refresh_token", "clientType": "extension"}, 0, "")
		if err != nil || !res.OK {
			return nil
		}
		payload := res.JSONMap()
		data := pvMap(payload, "data")
		if data == nil {
			data = payload
		}
		if data == nil {
			return nil
		}
		expiresIn := float64(3600)
		if expAt, ok := pvParseTimeMs(data["expiresAt"]); ok {
			expiresIn = float64(max(int64(1), (expAt-pvNowMs())/1000))
		}
		out := map[string]any{"accessToken": pvStr(data, "accessToken"), "expiresIn": expiresIn}
		if rt := pvStr(data, "refreshToken"); rt != "" {
			out["refreshToken"] = rt
		} else {
			out["refreshToken"] = refreshToken
		}
		return out
	case "codex", "grok-cli", "xai", "nous":
		// JS: refreshOAuthToken delegates these to
		// refreshProviderCredentials -> refreshTokenByProvider
		// (open-sse/services/tokenRefresh.js). oauthsvc.RefreshAccessToken
		// is the Go port of that engine (per-provider token endpoints and
		// client ids from the registry oauth blocks).
		tokens, err := oauthsvc.RefreshAccessToken(ctx, provider, map[string]any(conn))
		if err != nil || tokens == nil {
			return nil
		}
		if pvStr(tokens, "accessToken") == "" && pvStr(tokens, "apiKey") == "" {
			return nil
		}
		return tokens
	}
	return nil
}

func pvClassifyOAuthProbe(res *pvFetchResult, cfg *pvOAuthTestCfg) (valid bool, errText *string, soft bool) {
	if res == nil {
		return false, pvStrPtr("No response"), false
	}
	accepted := res.OK
	for _, s := range cfg.AcceptStatuses {
		if res.Status == s {
			accepted = true
		}
	}
	if !accepted {
		switch res.Status {
		case 401:
			return false, pvStrPtr("Token invalid or revoked"), false
		case 403:
			return false, pvStrPtr("Access denied"), false
		}
		return false, pvStrPtr(fmt.Sprintf("API returned %d", res.Status)), false
	}
	if !res.OK {
		for _, s := range cfg.AcceptStatuses {
			if res.Status == s {
				if msg, ok := cfg.SoftFail[res.Status]; ok {
					return true, pvStrPtr(msg), true
				}
				return true, nil, false
			}
		}
	}
	return true, nil, false
}

func pvParseProviderError(body string, fallback string) string {
	if body == "" {
		return fallback
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(body), &parsed); err == nil {
		if e := pvMap(parsed, "error"); e != nil {
			if m := pvStr(e, "message"); strings.TrimSpace(m) != "" {
				return strings.TrimSpace(m)
			}
		}
		if m := pvStr(parsed, "message"); strings.TrimSpace(m) != "" {
			return strings.TrimSpace(m)
		}
		if es := pvStr(parsed, "error"); strings.TrimSpace(es) != "" {
			return strings.TrimSpace(es)
		}
	}
	if t := strings.TrimSpace(body); t != "" {
		return t
	}
	return fallback
}

func pvProbeCloudCodeAssist(ctx context.Context, conn db.Record, accessToken string, proxy pvProxyConfig) (bool, *string, int) {
	ua := "google-api-nodejs-client/9.15.1 gemini-cli/0.34.0"
	if pvStr(conn, "provider") == "antigravity" {
		ua = "google-api-nodejs-client/9.15.1 vscode-antigravity/1.107.0"
	}
	body := `{"metadata":{"ideType":"IDE_UNSPECIFIED","platform":"PLATFORM_UNSPECIFIED","pluginType":"GEMINI"}}`
	res, err := pvFetchViaProxy(ctx, "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist", "POST",
		map[string]string{"Authorization": "Bearer " + accessToken, "Content-Type": "application/json", "User-Agent": ua},
		[]byte(body), proxy)
	if err != nil {
		return false, pvStrPtr(pvErrText(err)), 0
	}
	if res.OK {
		return true, nil, res.Status
	}
	msg := pvParseProviderError(res.Text(), fmt.Sprintf("API returned %d", res.Status))
	return false, &msg, res.Status
}

func pvClineHeaders(token string) map[string]string {
	return map[string]string{
		"HTTP-Referer":       "https://cline.bot",
		"X-Title":            "Cline",
		"User-Agent":         "ProxyGo/" + pvAppVersion,
		"X-PLATFORM":         runtime.GOOS,
		"X-PLATFORM-VERSION": runtime.Version(),
		"X-CLIENT-TYPE":      "9router",
		"X-CLIENT-VERSION":   pvAppVersion,
		"X-CORE-VERSION":     pvAppVersion,
		"X-IS-MULTIROOT":     "false",
		"Authorization":      "Bearer " + token,
		"Accept":             "application/json",
	}
}

func pvTestOAuthConnection(ctx context.Context, conn db.Record, proxy pvProxyConfig) pvTestOutcome {
	provider := pvStr(conn, "provider")
	cfg := pvOAuthCfg(provider)
	if cfg == nil {
		return pvOutcomeErr("Provider test not supported")
	}
	if pvStr(conn, "accessToken") == "" {
		return pvOutcomeErr("No access token")
	}
	if cfg.TokenExists {
		return pvTestOutcome{Valid: true, NewTokens: nil}
	}
	accessToken := pvStr(conn, "accessToken")
	if cfg.UseAPIKey {
		if k := pvStr(conn, "apiKey"); k != "" {
			accessToken = k
		}
	}
	refreshed := false
	var newTokens map[string]any
	tokenExpired := pvShouldRefresh(provider, conn)
	if cfg.Refreshable && tokenExpired && pvStr(conn, "refreshToken") != "" {
		tokens := pvRefreshOAuthToken(ctx, conn)
		if tokens != nil {
			accessToken = pvStr(tokens, "accessToken")
			if cfg.UseAPIKey {
				if k := pvStr(tokens, "apiKey"); k != "" {
					accessToken = k
				}
			}
			refreshed = true
			newTokens = tokens
		} else {
			return pvOutcomeErr("Token expired and refresh failed")
		}
	}
	if cfg.CheckExpiry {
		if refreshed {
			return pvTestOutcome{Valid: true, Refreshed: true, NewTokens: newTokens}
		}
		if tokenExpired {
			return pvOutcomeErr("Token expired")
		}
		return pvTestOutcome{Valid: true}
	}
	if provider == "gemini-cli" || provider == "antigravity" {
		valid, errText, status := pvProbeCloudCodeAssist(ctx, conn, accessToken, proxy)
		if valid {
			return pvTestOutcome{Valid: true, Refreshed: refreshed, NewTokens: newTokens}
		}
		if status == 401 && cfg.Refreshable && !refreshed && pvStr(conn, "refreshToken") != "" {
			tokens := pvRefreshOAuthToken(ctx, conn)
			if tokens != nil && pvStr(tokens, "accessToken") != "" {
				v2, e2, _ := pvProbeCloudCodeAssist(ctx, conn, pvStr(tokens, "accessToken"), proxy)
				if v2 {
					return pvTestOutcome{Valid: true, Refreshed: true, NewTokens: tokens}
				}
				return pvTestOutcome{Valid: false, Err: e2, Refreshed: true, NewTokens: tokens}
			}
			return pvOutcomeErr("Token invalid or revoked")
		}
		return pvTestOutcome{Valid: false, Err: errText, Refreshed: refreshed}
	}
	if provider == "cline" {
		tryProbe := func(token string) pvTestOutcome {
			res, err := pvFetch(ctx, "GET", "https://api.cline.bot/api/v1/users/me", pvClineHeaders(token), nil, 15*time.Second, "")
			if err != nil {
				return pvOutcomeErr(pvErrText(err))
			}
			if res.OK {
				return pvTestOutcome{Valid: true, Refreshed: refreshed, NewTokens: newTokens}
			}
			switch res.Status {
			case 401:
				return pvTestOutcome{Valid: false, Err: pvStrPtr("Token invalid or revoked"), Refreshed: refreshed}
			case 403:
				return pvTestOutcome{Valid: false, Err: pvStrPtr("Access denied"), Refreshed: refreshed}
			}
			return pvTestOutcome{Valid: false, Err: pvStrPtr(fmt.Sprintf("API returned %d", res.Status)), Refreshed: refreshed}
		}
		initial := tryProbe(accessToken)
		if initial.Valid || initial.Err == nil || *initial.Err != "Token invalid or revoked" || pvStr(conn, "refreshToken") == "" {
			return initial
		}
		tokens := pvRefreshOAuthToken(ctx, conn)
		if tokens == nil || pvStr(tokens, "accessToken") == "" {
			return pvTestOutcome{Valid: false, Err: pvStrPtr("Token invalid or revoked")}
		}
		refreshed = true
		newTokens = tokens
		return tryProbe(pvStr(tokens, "accessToken"))
	}
	// Generic probe.
	doProbe := func(token string) (bool, *string, bool, *pvFetchResult) {
		u := cfg.URL
		if cfg.BuildURL != nil {
			u = cfg.BuildURL(token)
		}
		headers := map[string]string{}
		if !cfg.NoAuth {
			headers[cfg.AuthHeader] = cfg.AuthPrefix + token
		}
		for k, v := range cfg.ExtraHeaders {
			headers[k] = v
		}
		var body []byte
		if cfg.Body != "" {
			body = []byte(cfg.Body)
		}
		res, err := pvFetchViaProxy(ctx, u, cfg.Method, headers, body, proxy)
		if err != nil {
			return false, pvStrPtr(pvErrText(err)), false, nil
		}
		valid, errText, soft := pvClassifyOAuthProbe(res, cfg)
		return valid, errText, soft, res
	}
	valid, errText, soft, res := doProbe(accessToken)
	if valid {
		out := pvTestOutcome{Valid: true, Refreshed: refreshed, NewTokens: newTokens}
		if soft {
			out.Err = errText
			out.Warning = errText
		}
		return out
	}
	if res != nil && res.Status == 401 && cfg.Refreshable && !refreshed && pvStr(conn, "refreshToken") != "" {
		tokens := pvRefreshOAuthToken(ctx, conn)
		if tokens != nil {
			retryToken := pvStr(tokens, "accessToken")
			if cfg.UseAPIKey {
				if k := pvStr(tokens, "apiKey"); k != "" {
					retryToken = k
				}
			}
			v2, e2, soft2, _ := doProbe(retryToken)
			if v2 {
				out := pvTestOutcome{Valid: true, Refreshed: true, NewTokens: tokens}
				if soft2 {
					out.Err = e2
					out.Warning = e2
				}
				return out
			}
		}
		return pvOutcomeErr("Token invalid or revoked")
	}
	return pvTestOutcome{Valid: false, Err: errText, Refreshed: refreshed}
}

// ---------- Bedrock credential probe (probeBedrockCredentials port) ----------

type pvAwsCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Region          string
}

var pvAwsRegionRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)

// pvResolveAwsCredentials ports resolveAwsCredentials/resolveRegion for
// the static mode: apiKey is the secret access key, psd.accessKeyId the
// key id, psd.sessionToken the optional STS token. Profile mode
// (psd.profile) resolves through the AWS SDK in JS; the Go port has no SDK
// (same limitation as internal/executors' credential resolution), so it
// fails with an actionable error instead of pretending to probe.
func pvResolveAwsCredentials(conn db.Record) (pvAwsCredentials, error) {
	psd := pvConnPSD(conn)
	if pvStr(psd, "profile") != "" {
		return pvAwsCredentials{}, fmt.Errorf("Bedrock profile mode (providerSpecificData.profile %q) cannot be resolved by the Go port — the AWS SDK credential chain is not available; use static credentials (secret access key as the provider API key + providerSpecificData.accessKeyId) instead", pvStr(psd, "profile"))
	}
	region := ""
	source := ""
	for _, cand := range []struct{ value, source string }{
		{pvStr(psd, "region"), "providerSpecificData.region"},
		{os.Getenv("AWS_REGION"), "the AWS_REGION environment variable"},
		{os.Getenv("AWS_DEFAULT_REGION"), "the AWS_DEFAULT_REGION environment variable"},
		{"us-east-1", "the built-in default"},
	} {
		if cand.value != "" {
			region, source = cand.value, cand.source
			break
		}
	}
	rawRegion := region
	region = strings.TrimSpace(region)
	if !pvAwsRegionRe.MatchString(region) {
		quoted, _ := json.Marshal(rawRegion)
		return pvAwsCredentials{}, fmt.Errorf("Invalid AWS region %s from %s. A region looks like \"us-east-1\": lowercase letters, digits and hyphens only. It is used to build the Bedrock hostname, so anything else is rejected rather than sent to an unintended host.", quoted, source)
	}
	accessKeyID := pvStr(psd, "accessKeyId")
	secret := pvStr(conn, "apiKey")
	if accessKeyID == "" || secret == "" {
		return pvAwsCredentials{}, errors.New("Bedrock static credentials are incomplete. Set the AWS secret access key as the provider API key and providerSpecificData.accessKeyId to the AWS access key id, or set providerSpecificData.profile to use a local AWS profile instead.")
	}
	if strings.HasPrefix(accessKeyID, "ASIA") && pvStr(psd, "sessionToken") == "" {
		return pvAwsCredentials{}, errors.New("This looks like a temporary AWS access key (ASIA…) but no sessionToken was provided. Add providerSpecificData.sessionToken, or use providerSpecificData.profile so credentials are resolved and refreshed automatically.")
	}
	return pvAwsCredentials{
		AccessKeyID: accessKeyID, SecretAccessKey: secret,
		SessionToken: pvStr(psd, "sessionToken"), Region: region,
	}, nil
}

// pvEscapeURI ports awsSigv4 escapeUri (encodeURIComponent plus the extra
// AWS escapes for !'()*), leaving only the RFC 3986 unreserved set.
func pvEscapeURI(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			sb.WriteByte(c)
			continue
		}
		const hexd = "0123456789ABCDEF"
		sb.WriteByte('%')
		sb.WriteByte(hexd[c>>4])
		sb.WriteByte(hexd[c&0xf])
	}
	return sb.String()
}

func pvHMACSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// pvSignAwsRequest ports signAwsRequest (open-sse/utils/awsSigv4.js) for
// the query-less requests the probe signs: every path segment is escaped a
// second time in the canonical request, and the signed header set is the
// caller's headers + host + x-amz-date (+ x-amz-security-token). The
// returned map omits "host" (Go's transport derives it from the URL) but
// the signature covers it. internal/executors has an equivalent signer for
// the chat path; it is unexported, hence this local port.
func pvSignAwsRequest(method, rawURL string, headers map[string]string, body []byte, creds pvAwsCredentials, service string, now time.Time) (map[string]string, error) {
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return nil, errors.New("AWS SigV4 requires both accessKeyId and secretAccessKey")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if parsed.RawQuery != "" {
		return nil, fmt.Errorf("AWS SigV4 signing does not support query strings (got %q). Move the parameters into the request body, or add proper query canonicalisation first.", "?"+parsed.RawQuery)
	}
	amzDate := now.UTC().Format("20060102T150405Z")
	dateStamp := now.UTC().Format("20060102")

	toSign := map[string]string{}
	for k, v := range headers {
		toSign[k] = v
	}
	toSign["host"] = parsed.Host
	toSign["x-amz-date"] = amzDate
	if creds.SessionToken != "" {
		toSign["x-amz-security-token"] = creds.SessionToken
	}
	type hdr struct{ name, value string }
	entries := make([]hdr, 0, len(toSign))
	for k, v := range toSign {
		entries = append(entries, hdr{strings.ToLower(k), strings.Join(strings.Fields(v), " ")})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	var canonHeaders strings.Builder
	signedNames := make([]string, 0, len(entries))
	for _, e := range entries {
		canonHeaders.WriteString(e.name + ":" + e.value + "\n")
		signedNames = append(signedNames, e.name)
	}
	signedHeaders := strings.Join(signedNames, ";")

	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	segments := strings.Split(path, "/")
	for i, s := range segments {
		segments[i] = pvEscapeURI(s)
	}
	canonicalPath := strings.Join(segments, "/")
	if canonicalPath == "" {
		canonicalPath = "/"
	}

	payloadHash := sha256HexBytes(body)
	canonicalRequest := strings.Join([]string{
		strings.ToUpper(method), canonicalPath, "", canonHeaders.String(), signedHeaders, payloadHash,
	}, "\n")
	scope := dateStamp + "/" + creds.Region + "/" + service + "/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256HexBytes([]byte(canonicalRequest))
	kSigning := pvHMACSHA256(pvHMACSHA256(pvHMACSHA256(pvHMACSHA256(
		[]byte("AWS4"+creds.SecretAccessKey), []byte(dateStamp)), []byte(creds.Region)), []byte(service)), []byte("aws4_request"))
	signature := hex.EncodeToString(pvHMACSHA256(kSigning, []byte(stringToSign)))

	out := map[string]string{}
	for k, v := range toSign {
		if strings.EqualFold(k, "host") {
			continue
		}
		out[k] = v
	}
	out["Authorization"] = "AWS4-HMAC-SHA256 Credential=" + creds.AccessKeyID + "/" + scope +
		", SignedHeaders=" + signedHeaders + ", Signature=" + signature
	return out, nil
}

func sha256HexBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// pvProbeBedrockCredentials ports probeBedrockCredentials
// (open-sse/executors/bedrock.js): a SigV4-signed GET of the Bedrock
// control-plane /foundation-models. fetchFn performs the GET (the test
// path routes it through the connection proxy, validate uses plain fetch);
// the 8s probe timeout is applied by the caller-provided fetchFn context.
func pvProbeBedrockCredentials(ctx context.Context, conn db.Record, fetchFn func(rawURL string, headers map[string]string) (*pvFetchResult, error)) pvTestOutcome {
	resolved, err := pvResolveAwsCredentials(conn)
	if err != nil {
		return pvOutcomeErr(err.Error())
	}
	probeURL := "https://bedrock." + resolved.Region + ".amazonaws.com/foundation-models"
	signed, serr := pvSignAwsRequest("GET", probeURL, map[string]string{"Accept": "application/json"}, nil, resolved, "bedrock", time.Now())
	if serr != nil {
		return pvOutcomeErr(serr.Error())
	}
	res, ferr := fetchFn(probeURL, signed)
	if ferr != nil {
		if errors.Is(ferr, context.DeadlineExceeded) || ctx.Err() == context.DeadlineExceeded {
			return pvOutcomeErr("AWS credential probe timed out")
		}
		var nerr net.Error
		if errors.As(ferr, &nerr) && nerr.Timeout() {
			return pvOutcomeErr("AWS credential probe timed out")
		}
		// JS rethrows; the testUtils catch converts it to {valid:false}.
		return pvOutcomeErr(pvErrText(ferr))
	}
	if res.OK {
		return pvOutcomeOK()
	}
	errorType := strings.Split(res.Headers.Get("x-amzn-errortype"), ":")[0]
	if errorType == "AccessDeniedException" {
		// Signature accepted, action refused: credentials are genuine.
		return pvOutcomeOK()
	}
	label := errorType
	if label == "" {
		label = fmt.Sprintf("HTTP %d", res.Status)
	}
	msg := ""
	var parsed map[string]any
	if json.Unmarshal(res.Body, &parsed) == nil {
		msg = pvStr(parsed, "message")
	}
	out := "AWS rejected the credentials (" + label + ")"
	if msg != "" {
		out += ": " + msg
	}
	return pvOutcomeErr(out)
}

// pvOllamaLocalHost ports resolveOllamaLocalHost.
func pvOllamaLocalHost(conn db.Record) string {
	host := strings.TrimSpace(pvStr(pvConnPSD(conn), "baseUrl"))
	if host == "" {
		return "http://localhost:11434"
	}
	return strings.TrimSuffix(host, "/")
}

func pvTestAPIKeyConnection(ctx context.Context, conn db.Record, proxy pvProxyConfig) pvTestOutcome {
	provider := pvStr(conn, "provider")
	apiKey := pvStr(conn, "apiKey")
	psd := pvConnPSD(conn)
	fetchP := func(rawURL, method string, headers map[string]string, body []byte) (*pvFetchResult, error) {
		return pvFetchViaProxy(ctx, rawURL, method, headers, body, proxy)
	}
	bearer := map[string]string{"Authorization": "Bearer " + apiKey}
	not401 := func(res *pvFetchResult, err error) pvTestOutcome {
		if err != nil {
			return pvOutcomeErr(pvErrText(err))
		}
		valid := res.Status != 401
		if valid {
			return pvOutcomeOK()
		}
		return pvOutcomeErr("Invalid API key")
	}
	not401or403 := func(res *pvFetchResult, err error) pvTestOutcome {
		if err != nil {
			return pvOutcomeErr(pvErrText(err))
		}
		valid := res.Status != 401 && res.Status != 403
		if valid {
			return pvOutcomeOK()
		}
		return pvOutcomeErr("Invalid API key")
	}
	okOrInvalid := func(res *pvFetchResult, err error) pvTestOutcome {
		if err != nil {
			return pvOutcomeErr(pvErrText(err))
		}
		if res.OK {
			return pvOutcomeOK()
		}
		return pvOutcomeErr("Invalid API key")
	}
	anthropicProbe := func(u, model string) pvTestOutcome {
		body, _ := json.Marshal(map[string]any{
			"model": model, "max_tokens": 1,
			"messages": []any{map[string]any{"role": "user", "content": "test"}},
		})
		res, err := fetchP(u, "POST", map[string]string{
			"x-api-key": apiKey, "anthropic-version": "2023-06-01", "Content-Type": "application/json",
		}, body)
		return not401or403(res, err)
	}
	openaiProbe := func(u string) pvTestOutcome {
		body, _ := json.Marshal(map[string]any{
			"model": pvDefaultModel(provider), "max_tokens": 1,
			"messages": []any{map[string]any{"role": "user", "content": "test"}},
		})
		res, err := fetchP(u, "POST", map[string]string{
			"Authorization": "Bearer " + apiKey, "Content-Type": "application/json",
		}, body)
		return not401or403(res, err)
	}

	if oc, _, _ := pvIsCompatProvider(provider); oc {
		base := pvStr(psd, "baseUrl")
		if base == "" {
			return pvOutcomeErr("Missing base URL")
		}
		res, err := fetchP(strings.TrimSuffix(base, "/")+"/models", "GET", bearer, nil)
		if err != nil {
			return pvOutcomeErr(pvErrText(err))
		}
		if res.OK {
			return pvOutcomeOK()
		}
		return pvOutcomeErr("Invalid API key or base URL")
	}
	if _, ac, _ := pvIsCompatProvider(provider); ac {
		base := pvStr(psd, "baseUrl")
		if base == "" {
			return pvOutcomeErr("Missing base URL")
		}
		base = strings.TrimSuffix(base, "/")
		if strings.HasSuffix(base, "/messages") {
			base = base[:len(base)-len("/messages")]
		}
		model := pvStrOr(conn, "defaultModel", "claude-3-haiku-20240307")
		body, _ := json.Marshal(map[string]any{
			"model": model, "max_tokens": 1,
			"messages": []any{map[string]any{"role": "user", "content": "test"}},
		})
		res, err := fetchP(base+"/v1/messages", "POST", map[string]string{
			"x-api-key": apiKey, "anthropic-version": "2023-06-01",
			"Content-Type": "application/json", "Authorization": "Bearer " + apiKey,
		}, body)
		if err != nil {
			return pvOutcomeErr(pvErrText(err))
		}
		if res.Status != 401 && res.Status != 403 {
			return pvOutcomeOK()
		}
		return pvOutcomeErr("Invalid API key or base URL")
	}
	if pvUsesAwsForm(provider) {
		// JS: probeBedrockCredentials(connection, fetchWithConnectionProxy)
		// with the probe's own 8s abort bound.
		return pvProbeBedrockCredentials(ctx, conn, func(rawURL string, headers map[string]string) (*pvFetchResult, error) {
			pctx, cancel := context.WithTimeout(ctx, 8*time.Second)
			defer cancel()
			return pvFetchViaProxy(pctx, rawURL, "GET", headers, nil, proxy)
		})
	}

	switch provider {
	case "cloudflare-ai":
		accountID := pvStr(psd, "accountId")
		if accountID == "" {
			return pvOutcomeErr("Missing Account ID")
		}
		u := "https://api.cloudflare.com/client/v4/accounts/" + accountID + "/ai/v1/chat/completions"
		body, _ := json.Marshal(map[string]any{
			"model":    pvDefaultModel("cloudflare-ai"),
			"messages": []any{map[string]any{"role": "user", "content": "test"}}, "max_tokens": 1,
		})
		res, err := fetchP(u, "POST", map[string]string{"Authorization": "Bearer " + apiKey, "Content-Type": "application/json"}, body)
		if err != nil {
			return pvOutcomeErr(pvErrText(err))
		}
		if res.Status != 401 && res.Status != 403 && res.Status != 404 {
			return pvOutcomeOK()
		}
		return pvOutcomeErr("Invalid API token or Account ID")
	case "azure":
		endpoint := strings.TrimSuffix(pvStr(psd, "azureEndpoint"), "/")
		deployment := pvStrOr(psd, "deployment", "gpt-4")
		apiVersion := pvStrOr(psd, "apiVersion", "2024-10-01-preview")
		u := endpoint + "/openai/deployments/" + deployment + "/chat/completions?api-version=" + apiVersion
		headers := map[string]string{"api-key": apiKey, "Content-Type": "application/json"}
		if org := pvStr(psd, "organization"); org != "" {
			headers["OpenAI-Organization"] = org
		}
		body, _ := json.Marshal(map[string]any{
			"messages": []any{map[string]any{"role": "user", "content": "test"}}, "max_completion_tokens": 1,
		})
		res, err := fetchP(u, "POST", headers, body)
		if err != nil {
			return pvOutcomeErr(pvErrText(err))
		}
		if res.Status != 401 && res.Status != 403 {
			return pvOutcomeOK()
		}
		return pvOutcomeErr("Invalid API key or Azure configuration")
	case "openai":
		return okOrInvalid(fetchP("https://api.openai.com/v1/models", "GET", bearer, nil))
	case "vercel-ai-gateway":
		return okOrInvalid(fetchP("https://ai-gateway.vercel.sh/v1/models", "GET", bearer, nil))
	case "anthropic":
		body, _ := json.Marshal(map[string]any{
			"model": "claude-3-haiku-20240307", "max_tokens": 1,
			"messages": []any{map[string]any{"role": "user", "content": "test"}},
		})
		res, err := fetchP("https://api.anthropic.com/v1/messages", "POST", map[string]string{
			"x-api-key": apiKey, "anthropic-version": "2023-06-01", "Content-Type": "application/json",
		}, body)
		return not401(res, err)
	case "gemini":
		return okOrInvalid(fetchP("https://generativelanguage.googleapis.com/v1/models?key="+apiKey, "GET", nil, nil))
	case "openrouter":
		return okOrInvalid(fetchP("https://openrouter.ai/api/v1/auth/key", "GET", bearer, nil))
	case "nous":
		body, _ := json.Marshal(map[string]any{
			"model": pvNousValidationModel, "messages": []any{map[string]any{"role": "user", "content": "ping"}},
			"max_tokens": 1, "stream": false,
		})
		res, err := pvFetch(ctx, "POST", pvNousChatURL, map[string]string{
			"Authorization": "Bearer " + apiKey, "Content-Type": "application/json",
		}, body, 8*time.Second, proxy.pvProxyURLForFetch())
		if err != nil {
			return pvOutcomeErr(pvErrText(err))
		}
		if res.Status >= 200 && res.Status < 300 {
			return pvOutcomeOK()
		}
		if res.Status == 401 || res.Status == 403 {
			return pvOutcomeErr("Invalid or inactive API key")
		}
		return pvOutcomeErr(fmt.Sprintf("Unable to verify API key (Nous returned %d)", res.Status))
	case "glm":
		return anthropicProbe("https://api.z.ai/api/anthropic/v1/messages", "glm-4.7")
	case "glm-cn":
		return openaiProbe("https://open.bigmodel.cn/api/coding/paas/v4/chat/completions")
	case "minimax":
		return anthropicProbe("https://api.minimax.io/anthropic/v1/messages", "minimax-m2")
	case "minimax-cn":
		return anthropicProbe("https://api.minimaxi.com/anthropic/v1/messages", "minimax-m2")
	case "kimi":
		return anthropicProbe("https://api.kimi.com/coding/v1/messages", "kimi-latest")
	case "alicode":
		return openaiProbe("https://coding.dashscope.aliyuncs.com/v1/chat/completions")
	case "alicode-intl":
		return openaiProbe("https://coding-intl.dashscope.aliyuncs.com/v1/chat/completions")
	case "alims-intl":
		return openaiProbe("https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions")
	case "volcengine-ark", "byteplus":
		u := ""
		if p, ok := pvReg(provider); ok {
			u = p.Transport.BaseURL
		}
		return openaiProbe(u)
	case "tokenharbor", "dahl", "atria", "agnes", "bai", "muse":
		validateURL := ""
		if p, ok := pvReg(provider); ok {
			validateURL = pvStr(pvRawMap(p, "transport"), "validateUrl")
		}
		return okOrInvalid(fetchP(validateURL, "GET", bearer, nil))
	case "ollama":
		res, err := pvFetch(ctx, "GET", "https://ollama.com/api/tags", bearer, nil, 15*time.Second, "")
		return okOrInvalid(res, err)
	case "ollama-local":
		host := pvOllamaLocalHost(conn)
		res, err := pvFetch(ctx, "GET", host+"/api/tags", nil, nil, 15*time.Second, "")
		if err != nil {
			return pvOutcomeErr(pvErrText(err))
		}
		if res.OK {
			return pvOutcomeOK()
		}
		return pvOutcomeErr("Ollama not reachable at " + host)
	case "deepgram":
		return okOrInvalid(fetchP("https://api.deepgram.com/v1/projects", "GET", map[string]string{"Authorization": "Token " + apiKey}, nil))
	case "fal-ai":
		res, err := fetchP("https://api.fal.ai/v1/models?limit=1", "GET", map[string]string{"Authorization": "Key " + apiKey}, nil)
		return not401or403(res, err)
	case "grok-web":
		token := strings.TrimPrefix(apiKey, "sso=")
		statsig := "e:TypeError: Cannot read properties of null (reading 'children')"
		statsigB64 := base64Std(statsig)
		body, _ := json.Marshal(map[string]any{
			"temporary": true, "modelName": "grok-4", "message": "ping",
			"fileAttachments": []any{}, "imageAttachments": []any{},
			"disableSearch": false, "enableImageGeneration": false, "sendFinalMetadata": true,
		})
		res, err := fetchP("https://grok.com/rest/app-chat/conversations/new", "POST", map[string]string{
			"Accept": "*/*", "Content-Type": "application/json",
			"Cookie": "sso=" + token, "Origin": "https://grok.com", "Referer": "https://grok.com/",
			"User-Agent":       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
			"x-statsig-id":     statsigB64,
			"x-xai-request-id": pvUUID(),
			"traceparent":      "00-" + pvRandHex(16) + "-" + pvRandHex(8) + "-00",
		}, body)
		if err != nil {
			return pvOutcomeErr(pvErrText(err))
		}
		if res.Status != 401 && res.Status != 403 {
			return pvOutcomeOK()
		}
		return pvOutcomeErr("Invalid SSO cookie")
	case "perplexity-web":
		token := strings.TrimPrefix(apiKey, "__Secure-next-auth.session-token=")
		res, err := fetchP("https://www.perplexity.ai/api/auth/session", "GET", map[string]string{
			"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
			"Cookie":     "__Secure-next-auth.session-token=" + token,
		}, nil)
		if err != nil {
			return pvOutcomeErr(pvErrText(err))
		}
		if !res.OK {
			return pvOutcomeErr("Invalid session cookie")
		}
		data := res.JSONMap()
		if data != nil && data["user"] != nil {
			return pvOutcomeOK()
		}
		return pvOutcomeErr("Session expired — re-paste cookie")
	case "opencode":
		res, err := fetchP("https://opencode.ai/zen/v1/models", "GET", map[string]string{
			"Authorization": "Bearer public", "User-Agent": "opencode/1.18.31",
		}, nil)
		if err != nil {
			return pvOutcomeErr(pvErrText(err))
		}
		if res.OK {
			return pvOutcomeOK()
		}
		return pvOutcomeErr("OpenCode free tier unavailable")
	case "opencode-go":
		body, _ := json.Marshal(map[string]any{
			"model":      pvDefaultModel("opencode-go"),
			"messages":   []any{map[string]any{"role": "user", "content": "ping"}},
			"max_tokens": 1, "stream": false,
		})
		res, err := fetchP("https://opencode.ai/zen/go/v1/chat/completions", "POST", map[string]string{
			"Content-Type": "application/json", "Authorization": "Bearer " + apiKey,
		}, body)
		return not401or403(res, err)
	case "xiaomi-mimo":
		return okOrInvalid(fetchP("https://api.xiaomimimo.com/v1/models", "GET", bearer, nil))
	case "xiaomi-tokenplan":
		return okOrInvalid(fetchP("https://token-plan-sgp.xiaomimimo.com/v1/models", "GET", bearer, nil))
	case "blackbox":
		base := "https://api.blackbox.ai/v1"
		if p, ok := pvReg("blackbox"); ok && p.Transport.BaseURL != "" {
			base = strings.TrimSuffix(p.Transport.BaseURL, "/chat/completions")
		}
		return okOrInvalid(fetchP(base+"/models", "GET", bearer, nil))
	case "qoder", "qoder-cn":
		// JS references an undefined `provider` variable in this branch; the
		// ReferenceError is caught by the surrounding try and returned as the
		// error below. Mirrored faithfully (upstream bug).
		return pvOutcomeErr("provider is not defined")
	case "llm7":
		base := pvStrOr(psd, "baseUrl", "https://api.llm7.io/v1")
		res, err := fetchP(strings.TrimSuffix(base, "/")+"/models", "GET", bearer, nil)
		if err != nil {
			return pvOutcomeErr(pvErrText(err))
		}
		if res.OK {
			return pvOutcomeOK()
		}
		return pvOutcomeErr("Invalid API key or base URL")
	case "kimchi":
		res, err := fetchP("https://api.cast.ai/v1/llm/openai/supported-providers", "GET", map[string]string{
			"Accept": "application/json", "Authorization": "Bearer " + apiKey, "User-Agent": "kimchi/0.1.40",
		}, nil)
		return okOrInvalid(res, err)
	}
	// Models-GET Bearer group (res.ok semantics).
	if u, ok := pvModelsProbeURLs[provider]; ok {
		return okOrInvalid(fetchP(u, "GET", bearer, nil))
	}
	return pvOutcomeErr("Provider test not supported")
}

var pvModelsProbeURLs = map[string]string{
	"deepseek":    "https://api.deepseek.com/models",
	"groq":        "https://api.groq.com/openai/v1/models",
	"mistral":     "https://api.mistral.ai/v1/models",
	"xai":         "https://api.x.ai/v1/models",
	"nvidia":      "https://integrate.api.nvidia.com/v1/models",
	"perplexity":  "https://api.perplexity.ai/v1/models",
	"together":    "https://api.together.xyz/v1/models",
	"fireworks":   "https://api.fireworks.ai/inference/v1/models",
	"cerebras":    "https://api.cerebras.ai/v1/models",
	"cohere":      "https://api.cohere.ai/v1/models",
	"nebius":      "https://api.studio.nebius.ai/v1/models",
	"siliconflow": "https://api.siliconflow.com/v1/models",
	"hyperbolic":  "https://api.hyperbolic.xyz/v1/models",
	"chutes":      "https://llm.chutes.ai/v1/models",
	"assemblyai":  "https://api.assemblyai.com/v1/account",
	"nanobanana":  "https://api.nanobananaapi.ai/v1/models",
}

func base64Std(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func pvRandHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type pvSingleTestResult struct {
	Valid     bool
	Err       *string
	Refreshed bool
	LatencyMs int64
	TestedAt  string
}

// pvTestSingleConnection ports testSingleConnection (testUtils.js).
func pvTestSingleConnection(ctx context.Context, deps Deps, id string) pvSingleTestResult {
	conn, err := deps.Store.GetProviderConnectionByID(id)
	if err != nil || conn == nil {
		return pvSingleTestResult{Valid: false, Err: pvStrPtr("Connection not found"), LatencyMs: 0, TestedAt: pvNowISO()}
	}
	proxy := pvResolveConnectionProxy(deps, pvConnPSD(conn))
	if proxy.ConnectionProxyEnabled && proxy.ConnectionProxyURL != "" && proxy.VercelRelayURL == "" {
		proxyRes := pvTestProxyURL(ctx, proxy.ConnectionProxyURL, 8*time.Second)
		if ok, _ := proxyRes["ok"].(bool); !ok {
			proxyErr := pvStr(proxyRes, "error")
			if proxyErr == "" {
				proxyErr = fmt.Sprintf("Proxy test failed with status %v", proxyRes["status"])
			}
			_, _ = deps.Store.UpdateProviderConnection(id, db.Record{
				"testStatus": "error", "lastError": proxyErr, "lastErrorAt": pvNowISO(),
			})
			return pvSingleTestResult{Valid: false, Err: &proxyErr, LatencyMs: 0, TestedAt: pvNowISO()}
		}
	}
	start := time.Now()
	var result pvTestOutcome
	authType := pvStr(conn, "authType")
	if authType == "apikey" || authType == "cookie" {
		result = pvTestAPIKeyConnection(ctx, conn, proxy)
	} else {
		result = pvTestOAuthConnection(ctx, conn, proxy)
	}
	latency := time.Since(start).Milliseconds()

	softWarning := ""
	if result.Valid {
		if result.Warning != nil {
			softWarning = *result.Warning
		} else if result.Err != nil {
			softWarning = *result.Err
		}
	}
	update := db.Record{}
	if result.Valid {
		update["testStatus"] = "active"
	} else {
		update["testStatus"] = "error"
	}
	if result.Valid {
		if softWarning != "" {
			update["lastError"] = softWarning
			update["lastErrorAt"] = pvNowISO()
		} else {
			update["lastError"] = nil
			update["lastErrorAt"] = nil
		}
	} else {
		if result.Err != nil {
			update["lastError"] = *result.Err
		} else {
			update["lastError"] = nil
		}
		update["lastErrorAt"] = pvNowISO()
	}
	if result.Refreshed && result.NewTokens != nil {
		nt := result.NewTokens
		for _, k := range []string{"accessToken", "refreshToken", "apiKey", "idToken", "lastRefreshAt"} {
			if v, ok := nt[k]; ok && v != nil {
				update[k] = v
			}
		}
		if v, ok := nt["expiresIn"]; ok && v != nil {
			update["expiresIn"] = v
			if f, ok2 := pvNum(nt, "expiresIn"); ok2 && f != 0 {
				update["expiresAt"] = time.Now().Add(time.Duration(f) * time.Second).UTC().Format("2006-01-02T15:04:05.000Z")
			}
		} else if v, ok := nt["expiresAt"]; ok && v != nil {
			update["expiresAt"] = v
		}
		if psd := pvMap(nt, "providerSpecificData"); psd != nil {
			merged := map[string]any{}
			for k, v := range pvConnPSD(conn) {
				merged[k] = v
			}
			for k, v := range psd {
				merged[k] = v
			}
			update["providerSpecificData"] = merged
		}
	}
	_, _ = deps.Store.UpdateProviderConnection(id, update)
	return pvSingleTestResult{
		Valid: result.Valid, Err: result.Err, Refreshed: result.Refreshed,
		LatencyMs: latency, TestedAt: pvNowISO(),
	}
}

func pvProviderTest(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := pvTestSingleConnection(r.Context(), deps, r.PathValue("id"))
		if result.Err != nil && *result.Err == "Connection not found" {
			Err(w, http.StatusNotFound, "Connection not found")
			return
		}
		var errVal any
		if result.Err != nil {
			errVal = *result.Err
		}
		WriteJSON(w, http.StatusOK, map[string]any{
			"valid": result.Valid, "error": errVal, "refreshed": result.Refreshed,
		})
	}
}

// pvAuthGroup ports test-batch getAuthGroup.
func pvAuthGroup(provider string, conn db.Record) string {
	if conn != nil {
		if at := pvStr(conn, "authType"); at != "" {
			if at == "oauth" {
				if p, ok := pvReg(provider); ok && p.Category == "free" {
					return "free"
				}
				return "oauth"
			}
			return at
		}
	}
	if p, ok := pvReg(provider); ok {
		switch p.Category {
		case "free":
			return "free"
		case "oauth":
			return "oauth"
		case "apikey":
			return "apikey"
		}
	}
	if oc, ac, _ := pvIsCompatProvider(provider); oc || ac {
		return "compatible"
	}
	return "apikey"
}

func pvProvidersTestBatch(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
		mode := Str(body, "mode")
		providerID := Str(body, "providerId")
		if mode == "" {
			Err(w, http.StatusBadRequest, "mode is required")
			return
		}
		tr := true
		all, aerr := deps.Store.GetProviderConnections(db.ConnectionFilter{IsActive: &tr})
		if aerr != nil {
			Err(w, http.StatusInternalServerError, "Batch test failed")
			return
		}
		var toTest []db.Record
		switch {
		case mode == "provider" && providerID != "":
			for _, c := range all {
				if pvStr(c, "provider") == providerID {
					toTest = append(toTest, c)
				}
			}
		case mode == "oauth" || mode == "free" || mode == "apikey":
			for _, c := range all {
				if pvAuthGroup(pvStr(c, "provider"), c) == mode {
					toTest = append(toTest, c)
				}
			}
		case mode == "compatible":
			for _, c := range all {
				if oc, ac, _ := pvIsCompatProvider(pvStr(c, "provider")); oc || ac {
					toTest = append(toTest, c)
				}
			}
		case mode == "all":
			toTest = all
		default:
			Err(w, http.StatusBadRequest, "Invalid mode. Use: provider, oauth, free, apikey, compatible, all")
			return
		}
		var providerIDVal any
		if providerID != "" {
			providerIDVal = providerID
		}
		if len(toTest) == 0 {
			WriteJSON(w, http.StatusOK, map[string]any{
				"mode": mode, "providerId": providerIDVal, "results": []any{},
				"summary":  map[string]any{"total": 0, "passed": 0, "failed": 0},
				"testedAt": pvNowISO(),
			})
			return
		}
		results := []any{}
		passed := 0
		for _, c := range toTest {
			data := pvTestSingleConnection(r.Context(), deps, pvStr(c, "id"))
			name := pvStr(c, "name")
			if name == "" {
				name = pvStr(c, "email")
			}
			if name == "" {
				name = pvStr(c, "provider")
			}
			authType := pvStr(c, "authType")
			if authType == "" {
				authType = pvAuthGroup(pvStr(c, "provider"), c)
			}
			var errVal any
			if data.Err != nil {
				errVal = *data.Err
			}
			if data.Valid {
				passed++
			}
			results = append(results, map[string]any{
				"provider": pvStr(c, "provider"), "connectionId": pvStr(c, "id"),
				"connectionName": name, "authType": authType,
				"valid": data.Valid, "latencyMs": data.LatencyMs, "error": errVal,
				"diagnosis": nil, "statusCode": nil, "testedAt": data.TestedAt,
			})
		}
		WriteJSON(w, http.StatusOK, map[string]any{
			"mode": mode, "providerId": providerIDVal, "results": results,
			"testedAt": pvNowISO(),
			"summary":  map[string]any{"total": len(results), "passed": passed, "failed": len(results) - passed},
		})
	}
}

// ---------- providers/validate ----------

func pvXiaomiTokenplanBase(psd map[string]any) string {
	region := pvStr(psd, "region")
	if region == "" {
		if p, ok := pvReg("xiaomi-tokenplan"); ok {
			region = pvRawStr(p, "defaultRegion")
		}
	}
	if region == "" {
		region = "sgp"
	}
	return "https://token-plan-" + region + ".xiaomimimo.com/v1"
}

// pvProbeWebProvider ports probeWebProvider; returns (handled, valid).
func pvProbeWebProvider(ctx context.Context, provider, apiKey string) (bool, bool) {
	p, ok := pvReg(provider)
	if !ok {
		return false, false
	}
	kinds := pvStrSlice(p.Raw["serviceKinds"])
	if len(kinds) == 0 {
		kinds = []string{"llm"}
	}
	webOnly := true
	for _, k := range kinds {
		if k != "webSearch" && k != "webFetch" {
			webOnly = false
		}
	}
	if !webOnly {
		return false, false
	}
	cfg := pvRawMap(p, "searchConfig")
	if cfg == nil {
		cfg = pvRawMap(p, "fetchConfig")
	}
	if cfg == nil {
		return false, false
	}
	if pvStr(cfg, "authType") == "none" {
		return true, true
	}
	u := pvStr(cfg, "validateUrl")
	if u == "" {
		u = pvStr(cfg, "baseUrl")
	}
	headers := map[string]string{"Content-Type": "application/json"}
	switch pvStr(cfg, "authHeader") {
	case "bearer":
		headers["Authorization"] = "Bearer " + apiKey
	case "x-api-key":
		headers["x-api-key"] = apiKey
	case "x-subscription-token":
		headers["x-subscription-token"] = apiKey
	case "key":
		u += "?key=" + url.QueryEscape(apiKey) + "&q=ping&cx=test"
	case "api_key":
		u += "?api_key=" + url.QueryEscape(apiKey) + "&q=ping&engine=google"
	}
	var body []byte
	method := pvStrOr(cfg, "method", "GET")
	if method == "POST" {
		body = []byte(`{"query":"ping","q":"ping","url":"https://example.com"}`)
	}
	res, err := pvFetch(ctx, method, u, headers, body, 8*time.Second, "")
	if err != nil {
		// JS fetch throw propagates to the route catch -> {valid:false}.
		return true, false
	}
	return true, res.Status != 401 && res.Status != 403
}

var pvMediaKinds = map[string]bool{"tts": true, "embedding": true, "stt": true, "image": true, "video": true, "music": true, "imageToText": true}

// pvProbeMediaProvider ports probeMediaProvider; returns (handled, valid).
func pvProbeMediaProvider(ctx context.Context, provider, apiKey string) (bool, bool) {
	p, ok := pvReg(provider)
	if !ok {
		return false, false
	}
	kinds := pvStrSlice(p.Raw["serviceKinds"])
	if len(kinds) == 0 {
		kinds = []string{"llm"}
	}
	mediaOnly := true
	for _, k := range kinds {
		if !pvMediaKinds[k] {
			mediaOnly = false
		}
	}
	if !mediaOnly {
		return false, false
	}
	var cfg map[string]any
	for _, key := range []string{"ttsConfig", "sttConfig", "embeddingConfig", "imageConfig", "videoConfig", "musicConfig"} {
		if m := pvRawMap(p, key); m != nil {
			cfg = m
			break
		}
	}
	if cfg == nil {
		return true, true
	}
	if pvRawBool(p, "noAuth") || pvStr(cfg, "authType") == "none" {
		return true, true
	}
	authHeader := pvStr(cfg, "authHeader")
	if authHeader == "playht" || authHeader == "aws-sigv4" {
		return true, true
	}
	headers := map[string]string{"Content-Type": "application/json"}
	for k, v := range pvMap(cfg, "extraHeaders") {
		if s, ok := v.(string); ok {
			headers[k] = s
		}
	}
	switch authHeader {
	case "bearer":
		headers["Authorization"] = "Bearer " + apiKey
	case "key":
		headers["Authorization"] = "Key " + apiKey
	case "x-api-key":
		headers["x-api-key"] = apiKey
	case "x-key":
		headers["x-key"] = apiKey
	case "xi-api-key":
		headers["xi-api-key"] = apiKey
	case "token":
		headers["Authorization"] = "Token " + apiKey
	case "basic":
		headers["Authorization"] = "Basic " + apiKey
	default:
		return false, false
	}
	method := pvStrOr(cfg, "method", "POST")
	var body []byte
	if method != "GET" {
		model := pvDefaultModel(provider)
		if model == "" {
			model = "test"
		}
		body, _ = json.Marshal(map[string]any{"input": "ping", "text": "ping", "prompt": "ping", "model": model})
	}
	res, err := pvFetch(ctx, method, pvStr(cfg, "baseUrl"), headers, body, 8*time.Second, "")
	if err != nil {
		return true, false
	}
	return true, res.Status != 401 && res.Status != 403
}

func pvProvidersValidate(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
		provider := pvNormalizeProviderId(Str(body, "provider"))
		apiKey := Str(body, "apiKey")
		psd := pvMap(body, "providerSpecificData")
		reg, _ := pvReg(provider)
		isNoAuth := reg != nil && pvRawBool(reg, "noAuth")
		if provider == "" || (apiKey == "" && provider != "ollama-local" && !isNoAuth && pvApiKeySubstituteField(provider, psd) == "") {
			Err(w, http.StatusBadRequest, "Provider and API key required")
			return
		}
		bearer := map[string]string{"Authorization": "Bearer " + apiKey}
		respond := func(valid bool, errText *string) {
			var e any
			if errText != nil {
				e = *errText
			}
			WriteJSON(w, http.StatusOK, map[string]any{"valid": valid, "error": e})
		}
		invalidKey := pvStrPtr("Invalid API key")

		if oc, _, _ := pvIsCompatProvider(provider); oc {
			node, nerr := deps.Store.GetProviderNodeByID(provider)
			if nerr != nil || node == nil {
				Err(w, http.StatusNotFound, "OpenAI Compatible node not found")
				return
			}
			res, ferr := pvFetch(ctx, "GET", strings.TrimSuffix(pvStr(node, "baseUrl"), "/")+"/models", bearer, nil, 0, "")
			valid := ferr == nil && res.OK
			if valid {
				respond(true, nil)
			} else {
				respond(false, invalidKey)
			}
			return
		}
		if _, _, ce := pvIsCompatProvider(provider); ce {
			node, nerr := deps.Store.GetProviderNodeByID(provider)
			if nerr != nil || node == nil {
				Err(w, http.StatusNotFound, "Custom Embedding node not found")
				return
			}
			base := strings.TrimSuffix(pvStr(node, "baseUrl"), "/")
			res, ferr := pvFetch(ctx, "GET", base+"/models", bearer, nil, 0, "")
			if ferr == nil && res.OK {
				WriteJSON(w, http.StatusOK, map[string]any{"valid": true})
				return
			}
			if ferr == nil && (res.Status == 401 || res.Status == 403) {
				respond(false, invalidKey)
				return
			}
			embBody, _ := json.Marshal(map[string]any{"model": "test", "input": "ping"})
			emb, ferr2 := pvFetch(ctx, "POST", base+"/embeddings", map[string]string{"Authorization": "Bearer " + apiKey, "Content-Type": "application/json"}, embBody, 0, "")
			valid := ferr2 == nil && emb.Status != 401 && emb.Status != 403
			if valid {
				respond(true, nil)
			} else {
				respond(false, invalidKey)
			}
			return
		}
		if _, ac, _ := pvIsCompatProvider(provider); ac {
			node, nerr := deps.Store.GetProviderNodeByID(provider)
			if nerr != nil || node == nil {
				Err(w, http.StatusNotFound, "Anthropic Compatible node not found")
				return
			}
			base := strings.TrimSpace(strings.TrimSuffix(pvStr(node, "baseUrl"), "/"))
			if strings.HasSuffix(base, "/messages") {
				base = base[:len(base)-len("/messages")]
			}
			model := pvStrOr(node, "defaultModel", "claude-3-haiku-20240307")
			msgBody, _ := json.Marshal(map[string]any{
				"model": model, "max_tokens": 1,
				"messages": []any{map[string]any{"role": "user", "content": "test"}},
			})
			res, ferr := pvFetch(ctx, "POST", base+"/v1/messages", map[string]string{
				"x-api-key": apiKey, "anthropic-version": "2023-06-01",
				"Content-Type": "application/json", "Authorization": "Bearer " + apiKey,
			}, msgBody, 0, "")
			valid := ferr == nil && res.Status != 401 && res.Status != 403
			if valid {
				respond(true, nil)
			} else {
				respond(false, invalidKey)
			}
			return
		}
		if provider == "cloudflare-ai" {
			accountID := pvStr(psd, "accountId")
			if accountID == "" {
				WriteJSON(w, http.StatusOK, map[string]any{"valid": false, "error": "Missing Account ID"})
				return
			}
			u := "https://api.cloudflare.com/client/v4/accounts/" + accountID + "/ai/v1/chat/completions"
			cfBody, _ := json.Marshal(map[string]any{
				"model":    pvDefaultModel("cloudflare-ai"),
				"messages": []any{map[string]any{"role": "user", "content": "test"}}, "max_tokens": 1,
			})
			res, ferr := pvFetch(ctx, "POST", u, map[string]string{"Authorization": "Bearer " + apiKey, "Content-Type": "application/json"}, cfBody, 0, "")
			valid := ferr == nil && res.Status != 401 && res.Status != 403 && res.Status != 404
			if valid {
				respond(true, nil)
			} else {
				respond(false, pvStrPtr("Invalid API token or Account ID"))
			}
			return
		}
		if provider == "azure" {
			endpoint := strings.TrimSuffix(pvStr(psd, "azureEndpoint"), "/")
			deployment := pvStrOr(psd, "deployment", "gpt-4")
			apiVersion := pvStrOr(psd, "apiVersion", "2024-10-01-preview")
			u := endpoint + "/openai/deployments/" + deployment + "/chat/completions?api-version=" + apiVersion
			headers := map[string]string{"api-key": apiKey, "Content-Type": "application/json"}
			if org := pvStr(psd, "organization"); org != "" {
				headers["OpenAI-Organization"] = org
			}
			azBody, _ := json.Marshal(map[string]any{
				"messages": []any{map[string]any{"role": "user", "content": "test"}}, "max_tokens": 1,
			})
			res, ferr := pvFetch(ctx, "POST", u, headers, azBody, 0, "")
			valid := ferr == nil && res.Status != 401 && res.Status != 403
			if valid {
				respond(true, nil)
			} else {
				respond(false, pvStrPtr("Invalid API key or Azure configuration"))
			}
			return
		}
		if pvUsesAwsForm(provider) {
			// JS: probeBedrockCredentials({apiKey, providerSpecificData},
			// fetch) and its {valid, error} JSON is returned verbatim.
			probeConn := db.Record{"apiKey": apiKey, "providerSpecificData": psd}
			outcome := pvProbeBedrockCredentials(ctx, probeConn, func(rawURL string, headers map[string]string) (*pvFetchResult, error) {
				return pvFetch(ctx, "GET", rawURL, headers, nil, 8*time.Second, "")
			})
			respond(outcome.Valid, outcome.Err)
			return
		}
		if handled, valid := pvProbeWebProvider(ctx, provider, apiKey); handled {
			if valid {
				respond(true, nil)
			} else {
				respond(false, invalidKey)
			}
			return
		}
		if handled, valid := pvProbeMediaProvider(ctx, provider, apiKey); handled {
			if valid {
				respond(true, nil)
			} else {
				respond(false, invalidKey)
			}
			return
		}

		isValid := false
		var errText *string
		transportBase := ""
		var transportHeaders map[string]string
		if reg != nil {
			transportBase = reg.Transport.BaseURL
			transportHeaders = reg.Transport.Headers
		}
		switch provider {
		case "openai":
			res, ferr := pvFetch(ctx, "GET", "https://api.openai.com/v1/models", bearer, nil, 0, "")
			isValid = ferr == nil && res.OK
		case "vercel-ai-gateway":
			res, ferr := pvFetch(ctx, "GET", "https://ai-gateway.vercel.sh/v1/models", bearer, nil, 0, "")
			isValid = ferr == nil && res.OK
		case "anthropic":
			aBody, _ := json.Marshal(map[string]any{
				"model": "claude-3-haiku-20240307", "max_tokens": 1,
				"messages": []any{map[string]any{"role": "user", "content": "test"}},
			})
			res, ferr := pvFetch(ctx, "POST", "https://api.anthropic.com/v1/messages", map[string]string{
				"x-api-key": apiKey, "anthropic-version": "2023-06-01", "Content-Type": "application/json",
			}, aBody, 0, "")
			isValid = ferr == nil && res.Status != 401
		case "gemini":
			res, ferr := pvFetch(ctx, "GET", "https://generativelanguage.googleapis.com/v1/models?key="+apiKey, nil, nil, 0, "")
			isValid = ferr == nil && res.OK
		case "openrouter":
			res, ferr := pvFetch(ctx, "GET", "https://openrouter.ai/api/v1/models", bearer, nil, 0, "")
			isValid = ferr == nil && res.OK
		case "nous":
			nBody, _ := json.Marshal(map[string]any{
				"model": pvNousValidationModel, "messages": []any{map[string]any{"role": "user", "content": "ping"}},
				"max_tokens": 1, "stream": false,
			})
			res, ferr := pvFetch(ctx, "POST", pvNousChatURL, map[string]string{
				"Authorization": "Bearer " + apiKey, "Content-Type": "application/json",
			}, nBody, 8*time.Second, "")
			if ferr == nil {
				isValid = res.Status >= 200 && res.Status < 300
				if !isValid {
					if res.Status == 401 || res.Status == 403 {
						errText = pvStrPtr("Invalid or inactive API key")
					} else {
						errText = pvStrPtr(fmt.Sprintf("Unable to verify API key (Nous returned %d)", res.Status))
					}
				}
			}
		case "glm", "glm-cn", "kimi", "minimax", "minimax-cn", "alicode-intl", "alims-intl", "alicode", "agentrouter":
			isOpenAIFormat := provider == "glm-cn" || provider == "alicode" || provider == "alicode-intl" || provider == "alims-intl"
			testModel := pvDefaultModel(provider)
			if isOpenAIFormat {
				gBody, _ := json.Marshal(map[string]any{
					"model": testModel, "max_tokens": 1,
					"messages": []any{map[string]any{"role": "user", "content": "test"}},
				})
				res, ferr := pvFetch(ctx, "POST", transportBase, map[string]string{
					"Authorization": "Bearer " + apiKey, "Content-Type": "application/json",
				}, gBody, 0, "")
				isValid = ferr == nil && res.Status != 401 && res.Status != 403
			} else {
				if testModel == "" {
					testModel = "claude-sonnet-4-20250514"
				}
				headers := map[string]string{
					"x-api-key": apiKey, "anthropic-version": "2023-06-01", "Content-Type": "application/json",
				}
				for k, v := range transportHeaders {
					headers[k] = v
				}
				gBody, _ := json.Marshal(map[string]any{
					"model": testModel, "max_tokens": 1,
					"messages": []any{map[string]any{"role": "user", "content": "test"}},
				})
				res, ferr := pvFetch(ctx, "POST", transportBase, headers, gBody, 0, "")
				isValid = ferr == nil && res.Status != 401 && res.Status != 403
			}
		case "volcengine-ark", "byteplus":
			vBody, _ := json.Marshal(map[string]any{
				"model": pvDefaultModel(provider), "max_tokens": 1,
				"messages": []any{map[string]any{"role": "user", "content": "test"}},
			})
			res, ferr := pvFetch(ctx, "POST", transportBase, map[string]string{
				"Authorization": "Bearer " + apiKey, "Content-Type": "application/json",
			}, vBody, 0, "")
			isValid = ferr == nil && res.Status != 401 && res.Status != 403
		case "deepseek", "groq", "xai", "mistral", "perplexity", "together", "fireworks",
			"cerebras", "cohere", "nebius", "siliconflow", "hyperbolic", "ollama",
			"ollama-local", "assemblyai", "nanobanana", "chutes", "xiaomi-mimo",
			"xiaomi-tokenplan", "nvidia":
			endpoint := ""
			if reg != nil {
				endpoint = pvStr(pvRawMap(reg, "transport"), "validateUrl")
			}
			if provider == "ollama-local" {
				endpoint = pvOllamaLocalHost(db.Record{"providerSpecificData": psd}) + "/api/tags"
			}
			if provider == "xiaomi-tokenplan" {
				endpoint = pvXiaomiTokenplanBase(psd) + "/models"
			}
			headers := map[string]string{}
			if apiKey != "" {
				headers["Authorization"] = "Bearer " + apiKey
			}
			res, ferr := pvFetch(ctx, "GET", endpoint, headers, nil, 8*time.Second, "")
			if ferr == nil {
				switch provider {
				case "xai":
					isValid = res.Status == 200 || res.Status == 403
				case "xiaomi-tokenplan":
					isValid = res.Status != 401
				default:
					isValid = res.OK
				}
			}
		case "opencode-go":
			oBody, _ := json.Marshal(map[string]any{
				"model":      pvDefaultModel("opencode-go"),
				"messages":   []any{map[string]any{"role": "user", "content": "ping"}},
				"max_tokens": 1, "stream": false,
			})
			res, ferr := pvFetch(ctx, "POST", "https://opencode.ai/zen/go/v1/chat/completions", map[string]string{
				"Content-Type": "application/json", "Authorization": "Bearer " + apiKey,
			}, oBody, 0, "")
			isValid = ferr == nil && res.Status != 401 && res.Status != 403
		case "commandcode":
			// TODO: openaiToCommandCodeRequest lives in the translator
			// package as the "commandcode" target format; the validate route
			// needs the raw payload builder — approximate with the same wire
			// body shape (model/messages/max_tokens/stream) the translator
			// emits for a minimal request.
			model := pvDefaultModel("commandcode")
			cBody, _ := json.Marshal(map[string]any{
				"model": model, "messages": []any{map[string]any{"role": "user", "content": "ping"}},
				"max_tokens": 1, "stream": false,
			})
			headers := map[string]string{"Content-Type": "application/json", "x-session-id": pvUUID(), "Authorization": "Bearer " + apiKey}
			for k, v := range transportHeaders {
				headers[k] = v
			}
			res, ferr := pvFetch(ctx, "POST", transportBase, headers, cBody, 0, "")
			isValid = ferr == nil && res.Status != 401 && res.Status != 403
		case "deepgram":
			res, ferr := pvFetch(ctx, "GET", "https://api.deepgram.com/v1/projects", map[string]string{"Authorization": "Token " + apiKey}, nil, 0, "")
			isValid = ferr == nil && res.OK
		case "blackbox":
			bBody, _ := json.Marshal(map[string]any{
				"model": "gpt-4o", "messages": []any{map[string]any{"role": "user", "content": "test"}}, "max_tokens": 10,
			})
			res, ferr := pvFetch(ctx, "POST", "https://api.blackbox.ai/chat/completions", map[string]string{
				"Authorization": "Bearer " + apiKey, "Content-Type": "application/json",
			}, bBody, 0, "")
			isValid = ferr == nil && (res.Status == 200 || res.Status == 400)
		case "vertex", "vertex-partner":
			var sa map[string]any
			if json.Unmarshal([]byte(apiKey), &sa) == nil && pvStr(sa, "type") == "service_account" {
				isValid = pvStr(sa, "client_email") != "" && pvStr(sa, "private_key") != "" && pvStr(sa, "project_id") != ""
			} else {
				res, ferr := pvFetch(ctx, "POST", "https://aiplatform.googleapis.com/v1/publishers/google/models/__probe__:generateContent?key="+apiKey,
					map[string]string{"Content-Type": "application/json"}, []byte("{}"), 0, "")
				isValid = ferr == nil && res.Status != 401 && res.Status != 403
			}
		case "grok-web":
			token := strings.TrimPrefix(apiKey, "sso=")
			gBody, _ := json.Marshal(map[string]any{
				"temporary": true, "modelName": "grok-4", "modelMode": "MODEL_MODE_GROK_4", "message": "ping",
				"fileAttachments": []any{}, "imageAttachments": []any{},
				"disableSearch": false, "enableImageGeneration": false, "returnImageBytes": false,
				"returnRawGrokInXaiRequest": false, "enableImageStreaming": false, "imageGenerationCount": 0,
				"forceConcise": false, "toolOverrides": map[string]any{}, "enableSideBySide": true,
				"sendFinalMetadata": true, "isReasoning": false, "disableTextFollowUps": true,
				"disableMemory": true, "forceSideBySide": false, "isAsyncChat": false,
				"disableSelfHarmShortCircuit": false,
			})
			res, ferr := pvFetch(ctx, "POST", "https://grok.com/rest/app-chat/conversations/new", map[string]string{
				"Accept": "*/*", "Content-Type": "application/json",
				"Cookie": "sso=" + token, "Origin": "https://grok.com", "Referer": "https://grok.com/",
				"User-Agent":       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
				"x-statsig-id":     base64Std("e:TypeError: Cannot read properties of null (reading 'children')"),
				"x-xai-request-id": pvUUID(),
				"traceparent":      "00-" + pvRandHex(16) + "-" + pvRandHex(8) + "-00",
			}, gBody, 0, "")
			if ferr == nil {
				if res.Status == 401 || res.Status == 403 {
					isValid = false
					errText = pvStrPtr("Invalid SSO cookie — re-paste from grok.com DevTools → Cookies → sso")
				} else {
					isValid = true
				}
			}
		case "perplexity-web":
			token := strings.TrimPrefix(apiKey, "__Secure-next-auth.session-token=")
			tz := time.Local.String()
			if z := os.Getenv("TZ"); z != "" {
				tz = z
			}
			pBody, _ := json.Marshal(map[string]any{
				"query_str": "ping",
				"params": map[string]any{
					"query_str": "ping", "search_focus": "internet", "mode": "concise", "model_preference": "pplx_pro",
					"sources": []any{"web"}, "attachments": []any{},
					"frontend_uuid": pvUUID(), "frontend_context_uuid": pvUUID(),
					"version": "2.18", "language": "en-US", "timezone": tz,
					"search_recency_filter": nil, "is_incognito": true, "use_schematized_api": true, "last_backend_uuid": nil,
				},
			})
			res, ferr := pvFetch(ctx, "POST", "https://www.perplexity.ai/rest/sse/perplexity_ask", map[string]string{
				"Content-Type": "application/json", "Accept": "text/event-stream",
				"Origin": "https://www.perplexity.ai", "Referer": "https://www.perplexity.ai/",
				"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
				"X-App-ApiClient": "default", "X-App-ApiVersion": "2.18",
				"Cookie": "__Secure-next-auth.session-token=" + token,
			}, pBody, 0, "")
			if ferr == nil {
				if res.Status == 401 || res.Status == 403 {
					isValid = false
					errText = pvStrPtr("Invalid session cookie — re-paste __Secure-next-auth.session-token from perplexity.ai")
				} else {
					isValid = true
				}
			}
		case "qoder", "qoder-cn":
			// JS: resolveQoderCredentials({provider, apiKey,
			// providerSpecificData}) then resolveQoderModels — valid iff
			// the live catalog yields models. A PAT exchange failure is
			// the one error that surfaces verbatim.
			probeConn := db.Record{"provider": provider, "apiKey": apiKey, "providerSpecificData": psd}
			if strings.HasPrefix(apiKey, "pt-") {
				jobToken, jobUserID, _, jerr := pvQoderExchangeJobToken(ctx, apiKey, pvQoderRegion(provider))
				if jerr != nil {
					isValid = false
					errText = pvStrPtr(jerr.Error())
					break
				}
				probeConn["accessToken"] = jobToken
				probeConn["apiKey"] = "" // resolved creds carry no apiKey (JS)
				if jobUserID != "" {
					mergedPSD := pvCloneMap(psd)
					mergedPSD["userId"] = jobUserID
					probeConn["providerSpecificData"] = mergedPSD
				}
			}
			qmodels, _ := pvResolveQoderModels(ctx, probeConn)
			isValid = len(qmodels) > 0
		default:
			if reg == nil || reg.Transport.Format != "openai" || transportBase == "" {
				Err(w, http.StatusBadRequest, "Provider validation not supported")
				return
			}
			if pvRawBool(reg, "noAuth") {
				isValid = true
				break
			}
			headers := map[string]string{"Content-Type": "application/json"}
			for k, v := range transportHeaders {
				headers[k] = v
			}
			if pvStr(pvRawMap(reg, "transport"), "authHeader") == "x-api-key" {
				headers["X-API-Key"] = apiKey
			} else {
				headers["Authorization"] = "Bearer " + apiKey
			}
			modelsURL := strings.TrimSuffix(transportBase, "/chat/completions") + "/models"
			modelsURL = strings.Replace(modelsURL, "/chatbot", "/models", 1)
			if strings.HasSuffix(transportBase, "/chat/completions") {
				modelsURL = strings.TrimSuffix(transportBase, "/chat/completions") + "/models"
			} else if strings.HasSuffix(transportBase, "/chatbot") {
				modelsURL = strings.TrimSuffix(transportBase, "/chatbot") + "/models"
			}
			probeDone := false
			if res, ferr := pvFetch(ctx, "GET", modelsURL, headers, nil, 8*time.Second, ""); ferr == nil {
				if res.Status == 401 || res.Status == 403 {
					isValid = false
					probeDone = true
				} else if res.OK {
					isValid = true
					probeDone = true
				}
			}
			if !probeDone {
				dm := pvDefaultModel(provider)
				if dm == "" {
					dm = "test"
				}
				cBody, _ := json.Marshal(map[string]any{
					"model": dm, "messages": []any{map[string]any{"role": "user", "content": "ping"}}, "max_tokens": 1,
				})
				res, ferr := pvFetch(ctx, "POST", transportBase, headers, cBody, 10*time.Second, "")
				isValid = ferr == nil && res.Status != 401 && res.Status != 403
			}
		}
		if isValid {
			respond(true, nil)
		} else if errText != nil {
			respond(false, errText)
		} else {
			respond(false, invalidKey)
		}
	}
}

// ---------- providers/client ----------

var pvClientSafeFields = []string{
	"id", "provider", "authType", "name", "email", "displayName",
	"priority", "globalPriority", "isActive", "defaultModel",
	"testStatus", "lastError", "lastErrorAt", "errorCode",
	"expiresAt", "lastUsedAt", "consecutiveUseCount",
	"createdAt", "updatedAt",
}

var pvClientSafePSDFields = []string{
	"baseUrl", "azureEndpoint", "deployment", "apiVersion", "accountId",
	"region", "projectId", "resourceUrl", "proxyPoolId",
	"connectionProxyEnabled", "connectionProxyUrl", "connectionNoProxy",
	"githubLogin", "githubName", "githubEmail", "githubUserId",
	"username", "firstName", "lastName", "authMethod", "authKind",
	"profileArn",
}

var pvMaskTokenRe = regexp.MustCompile(`[a-zA-Z0-9_-]{32,}`)

func pvMaskName(name string) string {
	if len(name) <= 16 {
		return name
	}
	if pvMaskTokenRe.MatchString(name) {
		return name[:8] + "***"
	}
	return name
}

func pvUsageProviders() (supported []string, apikey map[string]bool) {
	apikey = map[string]bool{}
	for _, p := range providers.All() {
		features := pvRawMap(p, "features")
		if pvBool(features, "usage") {
			supported = append(supported, p.ID)
		}
		if pvBool(features, "usageApikey") {
			apikey[p.ID] = true
		}
	}
	return supported, apikey
}

func pvParsePositiveInt(s string, fallback int) int {
	if s == "" {
		return fallback
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func pvProvidersClient(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// TODO(Team G): backfillCodexEmails() (lib/oauth/providers) not ported.
		q := r.URL.Query()
		providerFilter := q.Get("provider")
		if providerFilter == "" {
			providerFilter = "all"
		}
		accountStatus := q.Get("accountStatus")
		if accountStatus == "" {
			accountStatus = "all"
		}
		sortMode := q.Get("sort")
		if sortMode == "" {
			sortMode = "priority"
		}
		page := pvParsePositiveInt(q.Get("page"), 1)
		pageSize := pvParsePositiveInt(q.Get("pageSize"), 20)
		if pageSize > 500 {
			pageSize = 500
		}
		supported, apikeyUsage := pvUsageProviders()
		supportedSet := map[string]bool{}
		orderIdx := map[string]int{}
		for i, id := range supported {
			supportedSet[id] = true
			orderIdx[id] = i
		}
		all, err := deps.Store.GetProviderConnections(db.ConnectionFilter{})
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to fetch providers")
			return
		}
		eligible := []db.Record{}
		for _, c := range all {
			prov := pvStr(c, "provider")
			if !supportedSet[prov] {
				continue
			}
			if pvStr(c, "authType") == "oauth" || apikeyUsage[prov] {
				eligible = append(eligible, c)
			}
		}
		optSet := map[string]bool{}
		for _, c := range eligible {
			optSet[pvStr(c, "provider")] = true
		}
		providerOptions := make([]string, 0, len(optSet))
		for k := range optSet {
			providerOptions = append(providerOptions, k)
		}
		sort.Strings(providerOptions)
		providerFiltered := []db.Record{}
		for _, c := range eligible {
			if providerFilter == "all" || pvStr(c, "provider") == providerFilter {
				providerFiltered = append(providerFiltered, c)
			}
		}
		accountFiltered := []db.Record{}
		for _, c := range providerFiltered {
			active := true
			if v, ok := c["isActive"].(bool); ok {
				active = v
			}
			switch accountStatus {
			case "active":
				if !active {
					continue
				}
			case "inactive":
				if active {
					continue
				}
			}
			accountFiltered = append(accountFiltered, c)
		}
		if sortMode == "provider" {
			sort.SliceStable(accountFiltered, func(i, j int) bool {
				oa, ob := orderIdx[pvStr(accountFiltered[i], "provider")], orderIdx[pvStr(accountFiltered[j], "provider")]
				if oa != ob {
					return oa < ob
				}
				return pvStr(accountFiltered[i], "provider") < pvStr(accountFiltered[j], "provider")
			})
		} else {
			sort.SliceStable(accountFiltered, func(i, j int) bool {
				pa, okA := pvNum(accountFiltered[i], "priority")
				pb, okB := pvNum(accountFiltered[j], "priority")
				if !okA {
					pa = 9007199254740991
				}
				if !okB {
					pb = 9007199254740991
				}
				if pa != pb {
					return pa < pb
				}
				return pvStr(accountFiltered[i], "provider") < pvStr(accountFiltered[j], "provider")
			})
		}
		total := len(accountFiltered)
		totalPages := (total + pageSize - 1) / pageSize
		if totalPages < 1 {
			totalPages = 1
		}
		currentPage := page
		if currentPage > totalPages {
			currentPage = totalPages
		}
		offset := (currentPage - 1) * pageSize
		end := offset + pageSize
		if end > total {
			end = total
		}
		pageConns := []any{}
		if offset < total {
			for _, c := range accountFiltered[offset:end] {
				safe := map[string]any{}
				for _, f := range pvClientSafeFields {
					if v, ok := c[f]; ok && v != nil {
						safe[f] = v
					}
				}
				if n := pvStr(safe, "name"); n != "" {
					safe["name"] = pvMaskName(n)
				}
				if psd := pvConnPSD(c); psd != nil {
					sp := map[string]any{}
					for _, f := range pvClientSafePSDFields {
						if v, ok := psd[f]; ok && v != nil {
							sp[f] = v
						}
					}
					safe["providerSpecificData"] = sp
				}
				pageConns = append(pageConns, safe)
			}
		}
		opts := make([]any, len(providerOptions))
		for i, o := range providerOptions {
			opts[i] = o
		}
		WriteJSON(w, http.StatusOK, map[string]any{
			"connections":     pageConns,
			"providerOptions": opts,
			"pagination": map[string]any{
				"page": currentPage, "pageSize": pageSize, "total": total, "totalPages": totalPages,
			},
			"totals": map[string]any{
				"eligibleConnections":         len(eligible),
				"providerFilteredConnections": len(providerFiltered),
			},
		})
	}
}

// ---------- suggested-models ----------

func pvIsZeroPrice(v any) bool {
	switch t := v.(type) {
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return err == nil && f == 0
	case float64:
		return t == 0
	}
	return false
}

func pvAsPositiveInt(v any) (int64, bool) {
	f, ok := v.(float64)
	if !ok {
		return 0, false
	}
	if f == float64(int64(f)) && f > 0 {
		return int64(f), true
	}
	return 0, false
}

func pvRawModelList(payload any) []map[string]any {
	var arr []any
	switch t := payload.(type) {
	case []any:
		arr = t
	case map[string]any:
		if d, ok := t["data"].([]any); ok {
			arr = d
		} else if m, ok := t["models"].([]any); ok {
			arr = m
		}
	}
	out := []map[string]any{}
	for _, e := range arr {
		if m, ok := e.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func pvIsTextCapable(m map[string]any) bool {
	arch := pvMap(m, "architecture")
	if arch == nil {
		return true
	}
	mods := pvSlice(arch, "output_modalities")
	if len(mods) == 0 {
		return true
	}
	for _, v := range mods {
		if v == "text" {
			return true
		}
	}
	return false
}

// pvNormalizeNousModels ports nous.js normalizeNousModels.
func pvNormalizeNousModels(payload any) []map[string]any {
	out := []map[string]any{}
	for _, m := range pvRawModelList(payload) {
		if !pvIsTextCapable(m) {
			continue
		}
		id := strings.TrimSpace(pvStr(m, "id"))
		if id == "" {
			continue
		}
		entry := map[string]any{"id": id, "name": pvStrOr(m, "name", id)}
		ctxVal := m["context_length"]
		if ctxVal == nil {
			ctxVal = pvMap(m, "top_provider")["context_length"]
		}
		if c, ok := pvAsPositiveInt(ctxVal); ok {
			entry["contextLength"] = c
		}
		if mo, ok := pvAsPositiveInt(pvMap(m, "top_provider")["max_completion_tokens"]); ok {
			entry["maxOutputTokens"] = mo
		}
		if d := pvStr(m, "description"); d != "" {
			entry["description"] = d
		}
		out = append(out, entry)
	}
	return out
}

// pvNormalizeNousFreeModels ports nous.js normalizeNousFreeModels.
func pvNormalizeNousFreeModels(payload any) []map[string]any {
	free := []any{}
	for _, m := range pvRawModelList(payload) {
		ctxVal := m["context_length"]
		if ctxVal == nil {
			ctxVal = pvMap(m, "top_provider")["context_length"]
		}
		ctx, _ := pvAsPositiveInt(ctxVal)
		pricing := pvMap(m, "pricing")
		if pvIsTextCapable(m) && pvIsZeroPrice(pricing["prompt"]) && pvIsZeroPrice(pricing["completion"]) && ctx >= 200000 {
			free = append(free, m)
		}
	}
	out := pvNormalizeNousModels(free)
	sort.SliceStable(out, func(i, j int) bool {
		ci, _ := out[i]["contextLength"].(int64)
		cj, _ := out[j]["contextLength"].(int64)
		return ci > cj
	})
	return out
}

func pvSuggestedFilter(typ string, raw []any) ([]any, bool) {
	asMaps := func() []map[string]any {
		out := []map[string]any{}
		for _, e := range raw {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	out := []any{}
	switch typ {
	case "openrouter-free":
		items := []map[string]any{}
		for _, m := range asMaps() {
			pricing := pvMap(m, "pricing")
			ctxF, _ := pvNum(m, "context_length")
			if pvStr(pricing, "prompt") == "0" && pvStr(pricing, "completion") == "0" && ctxF >= 200000 {
				items = append(items, map[string]any{"id": m["id"], "name": m["name"], "contextLength": m["context_length"]})
			}
		}
		sort.SliceStable(items, func(i, j int) bool {
			ci, _ := pvNum(items[i], "contextLength")
			cj, _ := pvNum(items[j], "contextLength")
			return ci > cj
		})
		for _, it := range items {
			out = append(out, it)
		}
		return out, true
	case "opencode-free":
		for _, m := range asMaps() {
			id := pvStr(m, "id")
			if (strings.HasSuffix(id, "-free") || id == "big-pickle") && id != "deepseek-v4-flash-free" {
				out = append(out, map[string]any{"id": id, "name": id})
			}
		}
		return out, true
	case "opencode-go":
		for _, m := range asMaps() {
			if id, ok := m["id"].(string); ok {
				out = append(out, map[string]any{"id": id, "name": id})
			}
		}
		return out, true
	case "mimo-free":
		for _, m := range asMaps() {
			id := pvStr(m, "id")
			name := pvStr(m, "name")
			if strings.HasPrefix(id, "mimo") || strings.Contains(strings.ToLower(name), "mimo") {
				out = append(out, map[string]any{"id": id, "name": pvStrOr(m, "name", id)})
			}
		}
		return out, true
	case "minimax-code":
		if len(raw) == 0 {
			return out, true
		}
		env, _ := raw[0].(map[string]any)
		var provCfg map[string]any
		for _, p := range pvSlice(env, "providers") {
			if pm, ok := p.(map[string]any); ok && pvStr(pm, "providerId") == "minimax" {
				provCfg = pvMap(pm, "config")
			}
		}
		models := pvMap(provCfg, "models")
		type entry struct {
			id, name string
			ctx      float64
			hasCtx   bool
		}
		entries := []entry{}
		for id, mv := range models {
			mm, ok := mv.(map[string]any)
			if !ok || strings.TrimSpace(id) == "" {
				continue
			}
			e := entry{id: id, name: pvStrOr(mm, "name", id)}
			if c, ok2 := pvNum(pvMap(mm, "limit"), "context"); ok2 {
				e.ctx = c
				e.hasCtx = true
			}
			entries = append(entries, e)
		}
		sort.SliceStable(entries, func(i, j int) bool { return entries[i].ctx > entries[j].ctx })
		for _, e := range entries {
			item := map[string]any{"id": e.id, "name": e.name}
			if e.hasCtx {
				item["contextLength"] = e.ctx
			}
			out = append(out, item)
		}
		return out, true
	case "airforce-free":
		items := []map[string]any{}
		for _, m := range asMaps() {
			id := pvStr(m, "id")
			media := pvStr(m, "media_type")
			if (pvStr(m, "tier") == "free" || strings.HasSuffix(id, ":free")) && pvBool(m, "supports_chat") &&
				(media == "" || media == "chat" || media == "text") {
				items = append(items, map[string]any{"id": id, "name": pvStrOr(m, "name", id), "contextLength": m["context_length"]})
			}
		}
		sort.SliceStable(items, func(i, j int) bool { return pvStr(items[i], "id") < pvStr(items[j], "id") })
		for _, it := range items {
			out = append(out, it)
		}
		return out, true
	case "nous-free":
		for _, m := range pvNormalizeNousFreeModels(raw) {
			out = append(out, m)
		}
		return out, true
	}
	return nil, false
}

func pvSuggestedModels(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		rawURL := q.Get("url")
		typ := q.Get("type")
		if rawURL == "" || typ == "" {
			Err(w, http.StatusBadRequest, "Missing url or type")
			return
		}
		// Validate the filter type before fetching (unknown -> 400).
		if _, ok := pvSuggestedFilter(typ, []any{}); !ok {
			Err(w, http.StatusBadRequest, "Unknown filter type")
			return
		}
		res, err := pvFetch(r.Context(), "GET", rawURL, nil, nil, 0, "")
		if err != nil || !res.OK {
			WriteJSON(w, http.StatusOK, map[string]any{"data": []any{}})
			return
		}
		var parsed any
		if jerr := json.Unmarshal(res.Body, &parsed); jerr != nil {
			WriteJSON(w, http.StatusOK, map[string]any{"data": []any{}})
			return
		}
		var raw any = parsed
		if pm, ok := parsed.(map[string]any); ok {
			if d, ok2 := pm["data"]; ok2 && d != nil {
				raw = d
			} else if mv, ok3 := pm["models"]; ok3 && mv != nil {
				raw = mv
			}
		}
		var arr []any
		switch t := raw.(type) {
		case []any:
			arr = t
		case map[string]any:
			arr = []any{t}
		default:
			arr = []any{}
		}
		data, _ := pvSuggestedFilter(typ, arr)
		if data == nil {
			data = []any{}
		}
		WriteJSON(w, http.StatusOK, map[string]any{"data": data})
	}
}

// ---------- kilo/free-models ----------

var pvKiloCache struct {
	mu     sync.Mutex
	models []any
	ts     int64
}

var pvKiloModelsURL = "https://api.kilo.ai/api/gateway/models"

func pvKiloFreeModels(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		now := pvNowMs()
		pvKiloCache.mu.Lock()
		cached := pvKiloCache.models
		cachedTs := pvKiloCache.ts
		pvKiloCache.mu.Unlock()
		if cached != nil && now-cachedTs < 60*60*1000 {
			WriteJSON(w, http.StatusOK, map[string]any{"models": cached, "cached": true})
			return
		}
		fail := func(errMsg string) {
			if cached != nil {
				WriteJSON(w, http.StatusOK, map[string]any{"models": cached, "cached": true, "warning": errMsg})
				return
			}
			WriteJSON(w, http.StatusBadGateway, map[string]any{"models": []any{}, "error": "Failed to fetch Kilo models: " + errMsg})
		}
		res, err := pvFetch(r.Context(), "GET", pvKiloModelsURL, map[string]string{"Accept": "application/json"}, nil, 10*time.Second, "")
		if err != nil {
			fail(pvErrText(err))
			return
		}
		if !res.OK {
			fail(fmt.Sprintf("Kilo API returned %d", res.Status))
			return
		}
		parsed := res.JSONMap()
		freeModels := []any{}
		for _, m := range pvSlice(parsed, "data") {
			mm, ok := m.(map[string]any)
			if !ok || !pvBool(mm, "isFree") {
				continue
			}
			ctxLen, _ := pvNum(mm, "context_length")
			freeModels = append(freeModels, map[string]any{
				"id": mm["id"], "name": mm["name"], "isFree": true, "context_length": ctxLen,
			})
		}
		pvKiloCache.mu.Lock()
		pvKiloCache.models = freeModels
		pvKiloCache.ts = pvNowMs()
		pvKiloCache.mu.Unlock()
		WriteJSON(w, http.StatusOK, map[string]any{"models": freeModels, "cached": false})
	}
}

// ---------- providers/[id]/models ----------

func pvParseOpenAIStyle(data any) []any {
	switch t := data.(type) {
	case []any:
		return t
	case map[string]any:
		for _, k := range []string{"data", "models", "results"} {
			if arr, ok := t[k].([]any); ok {
				return arr
			}
		}
	}
	return []any{}
}

func pvParseDataOnly(data any) []any {
	if m, ok := data.(map[string]any); ok {
		if arr, ok := m["data"].([]any); ok {
			return arr
		}
	}
	return []any{}
}

func pvParseGeminiModels(data any) []any {
	if m, ok := data.(map[string]any); ok {
		if arr, ok := m["models"].([]any); ok {
			return arr
		}
	}
	return []any{}
}

func pvParseGeminiCliModels(data any) []any {
	m, _ := data.(map[string]any)
	if m == nil {
		return []any{}
	}
	if arr, ok := m["models"].([]any); ok {
		out := []any{}
		for _, item := range arr {
			im, _ := item.(map[string]any)
			id := pvStr(im, "id")
			if id == "" {
				id = pvStr(im, "model")
			}
			if id == "" {
				id = pvStr(im, "name")
			}
			if id == "" {
				continue
			}
			name := pvStr(im, "displayName")
			if name == "" {
				name = pvStrOr(im, "name", id)
			}
			out = append(out, map[string]any{"id": id, "name": name})
		}
		return out
	}
	if obj, ok := m["models"].(map[string]any); ok {
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := []any{}
		for _, id := range keys {
			info, _ := obj[id].(map[string]any)
			if pvBool(info, "isInternal") {
				continue
			}
			name := pvStr(info, "displayName")
			if name == "" {
				name = pvStrOr(info, "name", id)
			}
			out = append(out, map[string]any{"id": id, "name": name})
		}
		return out
	}
	return []any{}
}

func pvParseCodexModels(data any) []any {
	out := []any{}
	for _, item := range pvParseOpenAIStyle(data) {
		im, _ := item.(map[string]any)
		id := pvStr(im, "id")
		if id == "" {
			id = pvStr(im, "slug")
		}
		if id == "" {
			id = pvStr(im, "model")
		}
		if id == "" {
			id = pvStr(im, "name")
		}
		if id == "" {
			continue
		}
		name := pvStr(im, "display_name")
		if name == "" {
			name = pvStr(im, "displayName")
		}
		if name == "" {
			name = pvStrOr(im, "name", id)
		}
		normalized := pvCloneMap(im)
		normalized["id"] = id
		normalized["name"] = name
		typ := pvStrOr(im, "type", "llm")
		isChat := typ != "image" && !strings.Contains(strings.ToLower(id), "embed")
		if !isChat || strings.HasSuffix(id, "-review") {
			out = append(out, normalized)
			continue
		}
		review := pvCloneMap(normalized)
		review["id"] = id + "-review"
		review["name"] = name + " Review"
		review["upstreamModelId"] = id
		review["quotaFamily"] = "review"
		out = append(out, normalized, review)
	}
	return out
}

func pvParseGithubModels(data any) []any {
	m, _ := data.(map[string]any)
	arr, _ := m["data"].([]any)
	out := []any{}
	for _, item := range arr {
		im, _ := item.(map[string]any)
		caps := pvMap(im, "capabilities")
		if pvStr(caps, "type") != "chat" {
			continue
		}
		if pvStr(pvMap(im, "policy"), "state") == "disabled" {
			continue
		}
		out = append(out, map[string]any{
			"id": im["id"], "name": pvStrOr(im, "name", pvStr(im, "id")),
			"version": im["version"], "capabilities": caps,
			"isDefault": pvBool(im, "model_picker_enabled"),
		})
	}
	return out
}

func pvParseNousRouted(data any) []any {
	out := []any{}
	for _, m := range pvNormalizeNousModels(data) {
		routed := pvCloneMap(m)
		routed["upstreamModelId"] = m["id"]
		routed["id"] = "nous/" + pvStr(m, "id")
		out = append(out, routed)
	}
	return out
}

func pvStaticModels(providerID string) []any {
	out := []any{}
	for _, m := range pvCatalogModels(providerID) {
		cp := pvCloneMap(m)
		cp["name"] = pvStrOr(m, "name", pvStr(m, "id"))
		out = append(out, cp)
	}
	return out
}

// pvPersistTokens ports updateProviderCredentials for refreshed OAuth tokens.
func pvPersistTokens(deps Deps, conn db.Record, tokens map[string]any) {
	update := db.Record{}
	if v := pvStr(tokens, "accessToken"); v != "" {
		update["accessToken"] = v
	}
	if v := pvStr(tokens, "refreshToken"); v != "" {
		update["refreshToken"] = v
	}
	if v, ok := tokens["expiresIn"]; ok && v != nil {
		update["expiresIn"] = v
		if f, ok2 := pvNum(tokens, "expiresIn"); ok2 && f != 0 {
			update["expiresAt"] = time.Now().Add(time.Duration(f) * time.Second).UTC().Format("2006-01-02T15:04:05.000Z")
		}
	}
	if len(update) > 0 {
		_, _ = deps.Store.UpdateProviderConnection(pvStr(conn, "id"), update)
	}
}

type pvModelsOutcome struct {
	Models    []any
	Warning   string
	ErrStatus int
	ErrMsg    string
}

// pvOAuthModelsResolver ports buildOAuthResolver. refreshFn may be nil
// (Team G token-refresh services not ported for that provider).
func pvOAuthModelsResolver(ctx context.Context, deps Deps, conn db.Record, label string,
	refreshFn func(db.Record) map[string]any,
	fetchFn func(token string) (*pvFetchResult, error),
	parseFn func(data any) []any) pvModelsOutcome {
	accessToken := pvStr(conn, "accessToken")
	if accessToken == "" {
		return pvModelsOutcome{ErrStatus: 401, ErrMsg: "No valid token found"}
	}
	warning := ""
	res, err := fetchFn(accessToken)
	if err == nil && res != nil && !res.OK && (res.Status == 401 || res.Status == 403) && pvStr(conn, "refreshToken") != "" && refreshFn != nil {
		if refreshed := refreshFn(conn); refreshed != nil && pvStr(refreshed, "accessToken") != "" {
			pvPersistTokens(deps, conn, refreshed)
			res, err = fetchFn(pvStr(refreshed, "accessToken"))
		}
	}
	if err != nil {
		warning = label + ": " + pvErrText(err)
	} else if res != nil && res.OK {
		var data any
		_ = json.Unmarshal(res.Body, &data)
		if models := parseFn(data); len(models) > 0 {
			return pvModelsOutcome{Models: models}
		}
	} else if res != nil {
		warning = fmt.Sprintf("%s: %d %s", label, res.Status, res.Text())
	}
	return pvModelsOutcome{Models: []any{}, Warning: warning}
}

type pvModelsCfg struct {
	URL        string
	Method     string
	Headers    map[string]string
	AuthHeader string
	AuthPrefix string
	AuthQuery  string
	Body       map[string]any
	Parse      func(data any) []any
}

func pvOpenAICfg(u string) pvModelsCfg {
	return pvModelsCfg{
		URL: u, Method: "GET", Headers: map[string]string{"Content-Type": "application/json"},
		AuthHeader: "Authorization", AuthPrefix: "Bearer ", Parse: pvParseOpenAIStyle,
	}
}

func pvAnthropicCfg() pvModelsCfg {
	return pvModelsCfg{
		URL: "https://api.anthropic.com/v1/models", Method: "GET",
		Headers:    map[string]string{"Anthropic-Version": "2023-06-01", "Content-Type": "application/json"},
		AuthHeader: "x-api-key", Parse: pvParseDataOnly,
	}
}

func pvModelsConfig(provider string) (pvModelsCfg, bool) {
	switch provider {
	case "muse":
		return pvModelsCfg{
			URL: "https://api.meta.ai/v1/models", Method: "GET",
			Headers:    map[string]string{"Content-Type": "application/json", "x-api-version": "1.0.0"},
			AuthHeader: "Authorization", AuthPrefix: "Bearer ", Parse: pvParseDataOnly,
		}, true
	case "claude", "anthropic":
		return pvAnthropicCfg(), true
	case "gemini":
		return pvModelsCfg{
			URL: "https://generativelanguage.googleapis.com/v1beta/models", Method: "GET",
			Headers:   map[string]string{"Content-Type": "application/json"},
			AuthQuery: "key", Parse: pvParseGeminiModels,
		}, true
	case "antigravity":
		return pvModelsCfg{
			URL: "https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal:models", Method: "POST",
			Headers:    map[string]string{"Content-Type": "application/json"},
			AuthHeader: "Authorization", AuthPrefix: "Bearer ", Body: map[string]any{}, Parse: pvParseGeminiModels,
		}, true
	case "github":
		return pvModelsCfg{
			URL: "https://api.githubcopilot.com/models", Method: "GET",
			Headers: map[string]string{
				"Content-Type": "application/json", "Copilot-Integration-Id": "vscode-chat",
				"editor-version": "vscode/1.107.1", "editor-plugin-version": "copilot-chat/0.26.7",
				"user-agent": "GitHubCopilotChat/0.26.7",
			},
			AuthHeader: "Authorization", AuthPrefix: "Bearer ", Parse: pvParseGithubModels,
		}, true
	case "nous":
		c := pvOpenAICfg("https://inference-api.nousresearch.com/v1/models")
		c.Parse = pvParseNousRouted
		return c, true
	case "alicode":
		c := pvOpenAICfg("https://coding.dashscope.aliyuncs.com/v1/models")
		c.Parse = pvParseDataOnly
		return c, true
	case "alicode-intl":
		c := pvOpenAICfg("https://coding-intl.dashscope.aliyuncs.com/v1/models")
		c.Parse = pvParseDataOnly
		return c, true
	case "alims-intl":
		c := pvOpenAICfg("https://dashscope-intl.aliyuncs.com/compatible-mode/v1/models")
		c.Parse = pvParseDataOnly
		return c, true
	}
	openAIStyle := map[string]string{
		"openai": "https://api.openai.com/v1/models", "openrouter": "https://openrouter.ai/api/v1/models",
		"volcengine-ark": "https://ark.cn-beijing.volces.com/api/coding/v3/models",
		"byteplus":       "https://ark.ap-southeast.bytepluses.com/api/coding/v3/models",
		"deepseek":       "https://api.deepseek.com/models", "groq": "https://api.groq.com/openai/v1/models",
		"xai": "https://api.x.ai/v1/models", "mistral": "https://api.mistral.ai/v1/models",
		"perplexity": "https://api.perplexity.ai/v1/models", "perplexity-agent": "https://api.perplexity.ai/v1/models",
		"together": "https://api.together.xyz/v1/models", "fireworks": "https://api.fireworks.ai/inference/v1/models",
		"cerebras": "https://api.cerebras.ai/v1/models", "cohere": "https://api.cohere.ai/v1/models",
		"nebius": "https://api.studio.nebius.ai/v1/models", "siliconflow": "https://api.siliconflow.com/v1/models",
		"hyperbolic": "https://api.hyperbolic.xyz/v1/models", "ollama": "https://ollama.com/api/tags",
		"nanobanana": "https://api.nanobananaapi.ai/v1/models", "chutes": "https://llm.chutes.ai/v1/models",
		"nvidia": "https://integrate.api.nvidia.com/v1/models", "assemblyai": "https://api.assemblyai.com/v1/models",
		"vercel-ai-gateway": "https://ai-gateway.vercel.sh/v1/models",
		"tokenharbor":       "https://tokenharbor.ai/v1/models", "dahl": "https://inference.dahl.global/v1/models",
		"atria": "https://api.atria-asi.ai/v1/models", "agnes": "https://apihub.agnes-ai.com/v1/models",
		"bai": "https://api.b.ai/v1/models",
	}
	if u, ok := openAIStyle[provider]; ok {
		return pvOpenAICfg(u), true
	}
	return pvModelsCfg{}, false
}

// ---------- live model resolvers (open-sse/services ports) ----------

// pvJSNumStr formats a JSON number the way JS String(number) does for the
// magnitudes model catalogs carry.
func pvJSNumStr(f float64) string {
	if f == float64(int64(f)) && f < 1e15 && f > -1e15 {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// pvResolveKimchiModels ports resolveKimchiModels + normalizeKimchiModel
// (open-sse/services/kimchiModels.js). Returns nil on any failure so the
// caller falls back to the static catalog, exactly like the JS service.
// (The JS 5-minute catalog cache is bypassed by the route's forceRefresh,
// so it is not reproduced here.)
func pvResolveKimchiModels(ctx context.Context, conn db.Record) []any {
	psd := pvConnPSD(conn)
	token := pvStr(conn, "accessToken")
	if token == "" {
		token = pvStr(conn, "apiKey")
	}
	if token == "" {
		token = pvStr(psd, "apiKey")
	}
	if token == "" {
		return nil
	}
	endpoint := strings.TrimRight(pvStrOr(psd, "kimchiEndpoint", "https://llm.kimchi.dev"), "/")
	res, err := pvFetch(ctx, "GET", endpoint+"/v1/models/metadata?include_in_cli=true",
		map[string]string{"Accept": "application/json", "Authorization": "Bearer " + token, "User-Agent": "kimchi/0.1.40"},
		nil, 20*time.Second, "")
	if err != nil || !res.OK {
		return nil
	}
	data := res.JSONMap()
	rawList := pvSlice(data, "models")
	models := []any{}
	for _, raw := range rawList {
		item, _ := raw.(map[string]any)
		if item == nil {
			continue
		}
		id := ""
		for _, k := range []string{"slug", "id", "model", "name"} {
			if s := pvStr(item, k); s != "" {
				id = s
				break
			}
		}
		if strings.TrimSpace(id) == "" {
			continue
		}
		id = strings.TrimSpace(id)
		modalities := []any{}
		for _, m := range pvSlice(item, "input_modalities") {
			if s, _ := m.(string); s == "text" || s == "image" {
				modalities = append(modalities, s)
			}
		}
		hasImage := false
		for _, m := range modalities {
			if m == "image" {
				hasImage = true
			}
		}
		limits := pvMap(item, "limits")
		contextLength, hasCtx := pvNum(limits, "context_window")
		if !hasCtx {
			contextLength, hasCtx = pvNum(item, "contextLength")
		}
		if !hasCtx {
			contextLength, hasCtx = pvNum(item, "context_length")
		}
		maxOut, hasMaxOut := pvNum(limits, "max_output_tokens")
		if !hasMaxOut {
			maxOut, hasMaxOut = pvNum(item, "maxOutputTokens")
		}
		if !hasMaxOut {
			maxOut, hasMaxOut = pvNum(item, "max_output_tokens")
		}
		upstreamProvider := pvStr(item, "provider")
		reasoning := pvBool(item, "reasoning")
		kind := "llm"
		if hasImage {
			kind = "imageToText"
		}
		name := pvStr(item, "display_name")
		if name == "" {
			name = pvStr(item, "displayName")
		}
		if name == "" {
			name = pvStr(item, "name")
		}
		if name == "" {
			name = id
		}
		caps := map[string]any{"vision": hasImage, "reasoning": reasoning}
		if hasCtx && contextLength != 0 {
			caps["contextWindow"] = contextLength
		}
		if hasMaxOut && maxOut != 0 {
			caps["maxOutput"] = maxOut
		}
		if upstreamProvider != "" {
			caps["upstreamProvider"] = upstreamProvider
		}
		model := pvCloneMap(item)
		model["id"] = id
		model["name"] = strings.TrimSpace(name)
		model["provider"] = upstreamProvider
		model["upstreamProvider"] = upstreamProvider
		model["reasoning"] = reasoning
		model["inputModalities"] = modalities
		model["kind"] = kind
		model["type"] = kind
		model["capabilities"] = caps
		if hasCtx && contextLength != 0 {
			model["contextLength"] = contextLength
		}
		if hasMaxOut && maxOut != 0 {
			model["maxOutputTokens"] = maxOut
		}
		if upstreamProvider == "anthropic" {
			model["compat"] = map[string]any{"supportsReasoningEffort": false, "cacheControlFormat": "anthropic"}
		}
		models = append(models, model)
	}
	if len(models) == 0 {
		return nil
	}
	return models
}

// pvResolveCursorModelsLive ports the models route's cursor customResolver
// via internal/executors' ResolveCursorModels (Team L's port of
// open-sse/services/cursorModels.js — HTTP/2 GetUsableModels protobuf).
// Returns nil on any failure (no token/machineId, upstream error) so the
// caller falls back to the static catalog.
func pvResolveCursorModelsLive(ctx context.Context, conn db.Record) []any {
	p, ok := pvReg("cursor")
	if !ok {
		return nil
	}
	info := &executors.ProviderInfo{ID: "cursor", Raw: p.Raw}
	cred := executors.Credential{
		AccessToken: pvStr(conn, "accessToken"),
		Specific:    pvConnPSD(conn),
	}
	catalog := executors.ResolveCursorModels(ctx, info, cred)
	if len(catalog) == 0 {
		return nil
	}
	models := []any{}
	for _, m := range catalog {
		entry := map[string]any{"id": m.ID, "name": m.Name}
		if m.HasFlags {
			entry["defaultOn"] = m.DefaultOn
			entry["isChatOnly"] = m.IsChatOnly
			entry["supportsAgent"] = m.SupportsAgent
			entry["isHidden"] = m.IsHidden
		}
		models = append(models, entry)
	}
	return models
}

// pvClineAccessToken ports getClineAccessToken (open-sse/shared/clineAuth.js):
// WorkOS JWTs (eyJ…) get the `workos:` prefix; anything else passes verbatim.
var pvClineJWTRe = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)

func pvClineAccessToken(token string) string {
	trimmed := strings.TrimSpace(token)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(trimmed), "workos:") {
		return trimmed
	}
	if pvClineJWTRe.MatchString(trimmed) {
		return "workos:" + trimmed
	}
	return trimmed
}

// pvFetchClineRawModels ports fetchClineRawModels (clinepassModels.js):
// the raw /api/v1/models list, or nil on any failure.
func pvFetchClineRawModels(ctx context.Context, conn db.Record) []any {
	isAPIKey := pvStr(conn, "apiKey") != ""
	token := pvStr(conn, "apiKey")
	if !isAPIKey {
		token = pvStr(conn, "accessToken")
	}
	if token == "" {
		return nil
	}
	var headers map[string]string
	if isAPIKey {
		headers = map[string]string{"Accept": "application/json", "Authorization": "Bearer " + token}
	} else {
		headers = pvClineHeaders(token)
		headers["Authorization"] = "Bearer " + pvClineAccessToken(token)
		headers["Accept"] = "application/json"
	}
	res, err := pvFetch(ctx, "GET", "https://api.cline.bot/api/v1/models", headers, nil, 5*time.Second, "")
	if err != nil || !res.OK {
		return nil
	}
	var data any
	if json.Unmarshal(res.Body, &data) != nil {
		return nil
	}
	if arr, ok := data.([]any); ok {
		return arr
	}
	if m, ok := data.(map[string]any); ok {
		if arr, ok := m["data"].([]any); ok {
			return arr
		}
	}
	return nil
}

// pvResolveClineModels ports resolveClineModels / resolveClinepassModels.
// clinepass keeps only cline-pass/* ids; cline returns the whole catalog
// plus the unauthenticated recommended-models free tier merged in
// (first writer wins). Nil on any failure → static fallback.
func pvResolveClineModels(ctx context.Context, conn db.Record, passOnly bool) []any {
	rawList := pvFetchClineRawModels(ctx, conn)
	if rawList == nil {
		return nil
	}
	models := []any{}
	seen := map[string]bool{}
	for _, raw := range rawList {
		item, _ := raw.(map[string]any)
		if item == nil {
			continue
		}
		id := pvStr(item, "id")
		if passOnly {
			if !strings.HasPrefix(id, "cline-pass/") {
				continue
			}
		} else if strings.TrimSpace(id) == "" {
			continue
		}
		name := pvStr(item, "name")
		if name == "" {
			name = id
		}
		models = append(models, map[string]any{"id": id, "name": name})
		seen[id] = true
	}
	if !passOnly {
		// Free tier feed: additive only — a dead feed never fails the list.
		res, err := pvFetch(ctx, "GET", "https://api.cline.bot/api/v1/ai/cline/recommended-models",
			map[string]string{"Accept": "application/json"}, nil, 5*time.Second, "")
		if err == nil && res.OK {
			var data any
			if json.Unmarshal(res.Body, &data) == nil {
				if m, ok := data.(map[string]any); ok {
					for _, raw := range pvSlice(m, "free") {
						item, _ := raw.(map[string]any)
						if item == nil {
							continue
						}
						id := pvStr(item, "id")
						if strings.TrimSpace(id) == "" || seen[id] {
							continue
						}
						name := pvStr(item, "name")
						if name == "" {
							name = id
						}
						models = append(models, map[string]any{"id": id, "name": name})
						seen[id] = true
					}
				}
			}
		}
	}
	if len(models) == 0 {
		return nil
	}
	return models
}

// pvParseGrokCliModels ports parseGrokCliModels (grokCliModels.js).
func pvParseGrokCliModels(data any) []any {
	type entry struct {
		key string
		raw any
	}
	entries := []entry{}
	var listVal any
	if arr, ok := data.([]any); ok {
		listVal = arr
	} else if m, ok := data.(map[string]any); ok {
		for _, k := range []string{"data", "models", "results"} {
			if v, present := m[k]; present && v != nil {
				listVal = v
				break
			}
		}
	}
	switch v := listVal.(type) {
	case []any:
		for _, item := range v {
			entries = append(entries, entry{"", item})
		}
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			entries = append(entries, entry{k, v[k]})
		}
	}
	models := []any{}
	seen := map[string]bool{}
	for _, e := range entries {
		var item map[string]any
		if s, ok := e.raw.(string); ok {
			item = map[string]any{"id": s}
		} else if m, ok := e.raw.(map[string]any); ok {
			item = m
		} else {
			continue
		}
		id := ""
		for _, cand := range []any{item["id"], item["model_id"], item["modelId"], item["model"], item["slug"], e.key, item["name"]} {
			if cand == nil {
				continue
			}
			switch c := cand.(type) {
			case string:
				id = c
			case float64:
				id = pvJSNumStr(c)
			case bool:
				id = strconv.FormatBool(c)
			}
			break
		}
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		name := id
		for _, k := range []string{"display_name", "displayName", "name"} {
			if s := pvStr(item, k); s != "" {
				name = s
				break
			}
		}
		model := pvCloneMap(item)
		model["id"] = id
		model["name"] = name
		ctxLen, hasCtx := float64(0), false
		for _, k := range []string{"context_length", "contextLength", "context_window", "contextWindow"} {
			if f, ok := pvNum(item, k); ok {
				ctxLen, hasCtx = f, true
				break
			}
		}
		maxOut, hasMax := float64(0), false
		for _, k := range []string{"max_output_tokens", "maxOutputTokens"} {
			if f, ok := pvNum(item, k); ok {
				maxOut, hasMax = f, true
				break
			}
		}
		if hasCtx && ctxLen > 0 {
			model["contextLength"] = ctxLen
		}
		if hasMax && maxOut > 0 {
			model["maxOutputTokens"] = maxOut
		}
		if id == "grok-build" {
			if f, _ := pvNum(model, "contextLength"); f == 0 {
				model["contextLength"] = float64(500000)
			}
			if f, _ := pvNum(model, "maxOutputTokens"); f == 0 {
				model["maxOutputTokens"] = float64(64000)
			}
		}
		models = append(models, model)
	}
	return models
}

// pvResolveGrokCliModels ports resolveGrokCliModels (grokCliModels.js) as
// wired by the models route: fetch through the connection's resolved
// proxy config, refresh once on 401/403 via pvRefreshOAuthToken (the
// oauthCredentialManager equivalent) and persist through pvPersistTokens.
func pvResolveGrokCliModels(ctx context.Context, deps Deps, conn db.Record) ([]any, string) {
	accessToken := pvStr(conn, "accessToken")
	if accessToken == "" {
		return []any{}, "Grok CLI access token is missing."
	}
	psd := pvConnPSD(conn)
	proxy := pvResolveConnectionProxy(deps, psd)
	headers := func(token string) map[string]string {
		h := map[string]string{
			"Authorization":            "Bearer " + token,
			"Accept":                   "application/json",
			"User-Agent":               "grok-shell/1.0.44 (linux; x86_64)",
			"x-xai-token-auth":         "xai-grok-cli",
			"x-grok-client-version":    "1.0.44",
			"x-grok-client-identifier": "grok-shell",
			"x-grok-client-mode":       "headless",
		}
		if email := pvStr(psd, "email"); email != "" {
			h["x-email"] = email
		}
		if uid := pvStr(psd, "userId"); uid != "" {
			h["x-userid"] = uid
		} else if uid := pvStr(psd, "principalId"); uid != "" {
			h["x-userid"] = uid
		}
		return h
	}
	res, err := pvFetchViaProxy(ctx, "https://cli-chat-proxy.grok.com/v1/models", "GET", headers(accessToken), nil, proxy)
	if err == nil && res != nil && (res.Status == 401 || res.Status == 403) && pvStr(conn, "refreshToken") != "" {
		if refreshed := pvRefreshOAuthToken(ctx, conn); refreshed != nil && pvStr(refreshed, "accessToken") != "" {
			pvPersistTokens(deps, conn, refreshed)
			res, err = pvFetchViaProxy(ctx, "https://cli-chat-proxy.grok.com/v1/models", "GET", headers(pvStr(refreshed, "accessToken")), nil, proxy)
		}
	}
	if err != nil {
		return []any{}, "Grok CLI model discovery failed: " + pvErrText(err)
	}
	if res == nil || !res.OK {
		status := 0
		detail := ""
		if res != nil {
			status = res.Status
			detail = res.Text()
		}
		if len(detail) > 160 {
			detail = detail[:160]
		}
		warning := fmt.Sprintf("Grok CLI model discovery failed (%d)", status)
		if detail != "" {
			warning += ": " + detail
		}
		return []any{}, warning
	}
	var data any
	_ = json.Unmarshal(res.Body, &data)
	models := pvParseGrokCliModels(data)
	if len(models) == 0 {
		return []any{}, "Grok CLI returned no selectable models."
	}
	return models, ""
}

// pvKiroFingerprintHeaders ports buildKiroFingerprintHeaders (kiroModels.js).
func pvKiroFingerprintHeaders(conn db.Record) map[string]string {
	psd := pvConnPSD(conn)
	seed := pvStr(psd, "clientId")
	if seed == "" {
		seed = pvStr(conn, "refreshToken")
	}
	if seed == "" {
		seed = pvStr(psd, "profileArn")
	}
	if seed == "" {
		seed = pvStr(conn, "accessToken")
	}
	if seed == "" {
		seed = "kiro-anonymous"
	}
	sum := sha256HexBytes([]byte(seed))
	userAgent := "aws-sdk-js/1.0.0 ua/2.1 os/windows#10.0.26200 lang/js md/nodejs#22.21.1 " +
		"api/codewhispererruntime#1.0.0 m/N,E KiroIDE-0.10.32-" + sum
	return map[string]string{
		"User-Agent":                  userAgent,
		"x-amz-user-agent":            "aws-sdk-js/1.0.0 KiroIDE-0.10.32-" + sum,
		"x-amzn-kiro-agent-mode":      "vibe",
		"x-amzn-codewhisperer-optout": "true",
		"amz-sdk-request":             "attempt=1; max=1",
		"amz-sdk-invocation-id":       pvUUID(),
		"Accept":                      "application/json",
	}
}

func pvKiroRegionFromProfileArn(profileArn string) string {
	parts := strings.Split(profileArn, ":")
	if len(parts) >= 4 && parts[3] != "" {
		return parts[3]
	}
	return "us-east-1"
}

// pvFetchKiroCatalogRaw ports fetchKiroCatalogRaw: the raw models array,
// or an error carrying the upstream status (0 when not HTTP).
func pvFetchKiroCatalogRaw(ctx context.Context, conn db.Record) ([]any, int, error) {
	psd := pvConnPSD(conn)
	profileArn := pvStr(psd, "profileArn")
	region := pvKiroRegionFromProfileArn(profileArn)
	params := url.Values{"origin": {"AI_EDITOR"}}
	if profileArn != "" {
		params.Set("profileArn", profileArn)
	}
	u := "https://q." + region + ".amazonaws.com/ListAvailableModels?" + params.Encode()
	headers := pvKiroFingerprintHeaders(conn)
	headers["Authorization"] = "Bearer " + pvStr(conn, "accessToken")
	res, err := pvFetch(ctx, "GET", u, headers, nil, 30*time.Second, "")
	if err != nil {
		return nil, 0, err
	}
	if !res.OK {
		return nil, res.Status, fmt.Errorf("Kiro ListAvailableModels %d: %s", res.Status, res.Text())
	}
	data := res.JSONMap()
	return pvSlice(data, "models"), 0, nil
}

func pvKiroStripSyntheticSuffixes(id string) string {
	out := strings.TrimSuffix(id, "-agentic")
	out = strings.TrimSuffix(out, "-thinking")
	return out
}

func pvKiroDisplayName(modelName, modelID string, rate any) string {
	base := strings.TrimSpace(modelName)
	if base == "" {
		base = strings.TrimSpace(modelID)
	}
	if base == "" {
		base = "Kiro"
	}
	rateF, ok := rate.(float64)
	if !ok || rateF == 1.0 || rateF <= 0 {
		return "Kiro " + base
	}
	return fmt.Sprintf("Kiro %s (%sx credit)", base, strconv.FormatFloat(rateF, 'f', 1, 64))
}

// pvResolveKiroModels ports resolveKiroModels (kiroModels.js) plus the
// route's field mapping. Any failure yields an empty list and the JS
// fallback warning (the route returns models: [] for Kiro, not the static
// catalog). A 401 triggers one refresh + retry, persisted via
// pvPersistTokens (the route's onCredentialsRefreshed equivalent).
func pvResolveKiroModels(ctx context.Context, deps Deps, conn db.Record) ([]any, string) {
	fail := func() ([]any, string) {
		return []any{}, "Kiro returned no models; falling back to static catalog."
	}
	if pvStr(conn, "accessToken") == "" {
		return fail()
	}
	raw, status, err := pvFetchKiroCatalogRaw(ctx, conn)
	if err != nil {
		if status == 401 && pvStr(conn, "refreshToken") != "" {
			refreshed := pvRefreshOAuthToken(ctx, conn)
			if refreshed == nil || pvStr(refreshed, "accessToken") == "" {
				return fail()
			}
			pvPersistTokens(deps, conn, refreshed)
			retry := pvCloneMap(conn)
			retry["accessToken"] = pvStr(refreshed, "accessToken")
			if rt := pvStr(refreshed, "refreshToken"); rt != "" {
				retry["refreshToken"] = rt
			}
			raw, _, err = pvFetchKiroCatalogRaw(ctx, retry)
			if err != nil {
				return fail()
			}
		} else {
			return fail()
		}
	}
	expanded := []any{}
	for _, rawModel := range raw {
		m, _ := rawModel.(map[string]any)
		if m == nil {
			continue
		}
		upstreamID := pvStr(m, "modelId")
		if upstreamID == "" {
			upstreamID = pvStr(m, "id")
		}
		if upstreamID == "" {
			continue
		}
		display := pvKiroDisplayName(pvStr(m, "modelName"), upstreamID, m["rateMultiplier"])
		ctxLen := float64(200000)
		if tl := pvMap(m, "tokenLimits"); tl != nil {
			if f, ok := pvNum(tl, "maxInputTokens"); ok && f != 0 {
				ctxLen = f
			}
		}
		rateMult := 1.0
		if f, ok := m["rateMultiplier"].(float64); ok {
			rateMult = f
		}
		safe := pvKiroStripSyntheticSuffixes(upstreamID)
		isAuto := safe == "auto"
		type variant struct {
			suffix     string
			label      string
			thinking   bool
			agentic    bool
			includeNow bool
		}
		variants := []variant{
			{"", "", false, false, true},
			{"-thinking", " (Thinking)", true, false, true},
			{"-agentic", " (Agentic)", false, true, !isAuto},
			{"-thinking-agentic", " (Thinking + Agentic)", true, true, !isAuto},
		}
		for _, v := range variants {
			if !v.includeNow {
				continue
			}
			expanded = append(expanded, map[string]any{
				"id":              safe + v.suffix,
				"name":            display + v.label,
				"upstreamModelId": upstreamID,
				"contextLength":   ctxLen,
				"rateMultiplier":  rateMult,
				"capabilities":    map[string]any{"thinking": v.thinking, "agentic": v.agentic},
				"description":     pvStr(m, "description"),
			})
		}
	}
	if len(expanded) == 0 {
		return fail()
	}
	return expanded, ""
}

// ---------- Qoder COSY signing (open-sse/shared/qoder ports) ----------

const pvQoderRSAPublicKey = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDA8iMH5c02LilrsERw9t6Pv5Nc
4k6Pz1EaDicBMpdpxKduSZu5OANqUq8er4GM95omAGIOPOh+Nx0spthYA2BqGz+l
6HRkPJ7S236FZz73In/KVuLnwI8JJ2CbuJap8kvheCCZpmAWpb/cPx/3Vr/J6I17
XcW+ML9FoCI6AOvOzwIDAQAB
-----END PUBLIC KEY-----`

func pvQoderRegion(provider string) string {
	if provider == "qoder-cn" {
		return "cn"
	}
	return "intl"
}

func pvQoderOpenAPIBase(region string) string {
	if region == "cn" {
		return "https://openapi.qoder.com.cn"
	}
	return "https://openapi.qoder.sh"
}

// pvQoderInferenceBase ports qoderInferenceBase: CN serves every token
// kind from the gateway; intl job tokens (jt-…) go to api2, the rest api3.
func pvQoderInferenceBase(accessToken, apiKey string, region string) string {
	if region == "cn" {
		return "https://gateway.qoder.com.cn"
	}
	raw := apiKey
	if raw == "" {
		raw = accessToken
	}
	if raw != "" && !strings.HasPrefix(raw, "pt-") &&
		(strings.HasPrefix(raw, "jt-") || strings.HasPrefix(accessToken, "jt-")) {
		return "https://api2.qoder.sh"
	}
	return "https://api3.qoder.sh"
}

func pvMD5Hex(b []byte) string {
	sum := md5.Sum(b)
	return hex.EncodeToString(sum[:])
}

// pvBuildCosyHeaders ports buildCosyHeaders (open-sse/shared/qoder/cosy.js):
// AES-128-CBC user-info payload with the key RSA-PKCS1-wrapped, MD5
// signature over payload/key/timestamp/body/sigPath.
func pvBuildCosyHeaders(body []byte, requestURL string, userID, authToken, name, email, machineID string) (map[string]string, error) {
	if userID == "" {
		return nil, errors.New("cosy: user id is empty")
	}
	if authToken == "" {
		return nil, errors.New("cosy: auth token is empty")
	}
	aesKey := pvUUID()
	if len(aesKey) > 16 {
		aesKey = aesKey[:16]
	}
	userInfo := `{"uid":` + pvJSONString(userID) + `,"security_oauth_token":` + pvJSONString(authToken) +
		`,"name":` + pvJSONString(name) + `,"aid":"","email":` + pvJSONString(email) + `}`
	keyBytes := []byte(aesKey)
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}
	plain := []byte(userInfo)
	pad := 16 - (len(plain) % 16)
	padded := make([]byte, len(plain)+pad)
	copy(padded, plain)
	for i := len(plain); i < len(padded); i++ {
		padded[i] = byte(pad)
	}
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, keyBytes).CryptBlocks(ciphertext, padded)
	infoB64 := base64.StdEncoding.EncodeToString(ciphertext)

	pemBlock, _ := pem.Decode([]byte(pvQoderRSAPublicKey))
	if pemBlock == nil {
		return nil, errors.New("cosy: bad RSA public key")
	}
	pubAny, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("cosy: RSA public key is not RSA")
	}
	wrapped, err := rsa.EncryptPKCS1v15(rand.Reader, pub, keyBytes)
	if err != nil {
		return nil, err
	}
	cosyKey := base64.StdEncoding.EncodeToString(wrapped)

	requestID := pvUUID()
	payloadJSON := `{"version":"v1","requestId":` + pvJSONString(requestID) + `,"info":` + pvJSONString(infoB64) +
		`,"cosyVersion":"1.0.0","ideVersion":""}`
	payloadB64 := base64.StdEncoding.EncodeToString([]byte(payloadJSON))
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	sigPath := ""
	if parsed, perr := url.Parse(requestURL); perr == nil {
		sigPath = parsed.Path
		if strings.HasPrefix(sigPath, "/algo") {
			sigPath = sigPath[len("/algo"):]
		}
	}
	sigInput := payloadB64 + "\n" + cosyKey + "\n" + timestamp + "\n" + string(body) + "\n" + sigPath
	sig := pvMD5Hex([]byte(sigInput))
	if machineID == "" {
		machineID = pvUUID()
	}
	return map[string]string{
		"Authorization":          "Bearer COSY." + payloadB64 + "." + sig,
		"Cosy-Key":               cosyKey,
		"Cosy-User":              userID,
		"Cosy-Date":              timestamp,
		"Cosy-Version":           "1.0.0",
		"Cosy-Machineid":         machineID,
		"Cosy-Machinetoken":      machineID,
		"Cosy-Machinetype":       "5",
		"Cosy-Machineos":         "x86_64_windows",
		"Cosy-Clienttype":        "5",
		"Cosy-Clientip":          "127.0.0.1",
		"Cosy-Bodyhash":          pvMD5Hex(body),
		"Cosy-Bodylength":        strconv.Itoa(len(body)),
		"Cosy-Sigpath":           sigPath,
		"Cosy-Data-Policy":       "disagree",
		"Cosy-Organization-Id":   "",
		"Cosy-Organization-Tags": "",
		"Login-Version":          "v2",
		"X-Request-Id":           pvUUID(),
	}, nil
}

func pvJSONString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// PAT → job-token cache (resolvePatCredential port).
var (
	pvQoderPATMu    sync.Mutex
	pvQoderPATCache = map[string]struct {
		AccessToken string
		UserID      string
		ExpiresAt   int64
	}{}
)

// pvQoderExchangeJobToken ports exchangeJobToken + fetchUserIdForJobToken.
func pvQoderExchangeJobToken(ctx context.Context, pat, region string) (string, string, int64, error) {
	exchangeURL := pvQoderOpenAPIBase(region) + "/api/v1/jobToken/exchange"
	body, _ := json.Marshal(map[string]any{"personal_token": pat})
	res, err := pvFetch(ctx, "POST", exchangeURL, map[string]string{
		"Content-Type": "application/json", "Accept": "application/json",
		"User-Agent": "qodercli/1.0.0", "Cosy-Version": "1.0.0", "Cosy-ClientType": "5",
	}, body, 15*time.Second, "")
	if err != nil {
		return "", "", 0, err
	}
	if !res.OK {
		text := res.Text()
		if len(text) > 200 {
			text = text[:200]
		}
		return "", "", 0, fmt.Errorf("qoder PAT exchange failed: %d %s", res.Status, text)
	}
	data := res.JSONMap()
	jobToken := pvStr(data, "token")
	if jobToken == "" {
		return "", "", 0, errors.New("qoder PAT exchange returned no job token")
	}
	expiresAt := pvNowMs() + 24*60*60*1000
	if s := pvStr(data, "expires_at"); s != "" {
		if t, perr := time.Parse(time.RFC3339, s); perr == nil {
			expiresAt = t.UnixMilli()
		}
	} else if f, ok := pvNum(data, "expires_in"); ok && f > 0 {
		// JS adds the raw expires_in to Date.now() (its own quirk, kept).
		expiresAt = pvNowMs() + int64(f)
	}
	userID := ""
	ures, uerr := pvFetch(ctx, "GET", pvQoderOpenAPIBase(region)+"/api/v1/userinfo", map[string]string{
		"Authorization": "Bearer " + jobToken, "Accept": "application/json", "User-Agent": "qodercli/1.0.0",
	}, nil, 15*time.Second, "")
	if uerr == nil && ures.OK {
		udata := ures.JSONMap()
		userID = pvStr(udata, "id")
		if userID == "" {
			userID = pvStr(udata, "userId")
		}
		if userID == "" {
			userID = pvStr(udata, "user_id")
		}
	}
	return jobToken, userID, expiresAt, nil
}

// pvResolveQoderModels ports resolveQoderModels + fetchQoderCatalogRaw
// (open-sse/services/qoderModels.js) and the route's id-prefix mapping.
// Failures yield an empty list + the JS warning; the route returns
// models: [] for Qoder (no static fallback in the response).
func pvResolveQoderModels(ctx context.Context, conn db.Record) ([]any, string) {
	provider := pvStr(conn, "provider")
	region := pvQoderRegion(provider)
	psd := pvConnPSD(conn)
	accessToken := pvStr(conn, "accessToken")
	apiKey := pvStr(conn, "apiKey")

	// resolveQoderCredentials: PAT (pt-…) exchanges for a job token.
	raw := apiKey
	if raw == "" {
		raw = accessToken
	}
	userID := pvStr(psd, "userId")
	if strings.HasPrefix(raw, "pt-") {
		cacheKey := region + ":" + raw
		pvQoderPATMu.Lock()
		cached, hasCached := pvQoderPATCache[cacheKey]
		pvQoderPATMu.Unlock()
		if hasCached && cached.ExpiresAt-pvNowMs() > 5*60*1000 {
			accessToken = cached.AccessToken
			if cached.UserID != "" {
				userID = cached.UserID
			}
		} else {
			jobToken, jobUserID, expiresAt, err := pvQoderExchangeJobToken(ctx, raw, region)
			if err != nil {
				// resolveQoderModels swallows this into null.
				return []any{}, "Qoder returned no models; falling back to static catalog."
			}
			pvQoderPATMu.Lock()
			pvQoderPATCache[cacheKey] = struct {
				AccessToken string
				UserID      string
				ExpiresAt   int64
			}{jobToken, jobUserID, expiresAt}
			pvQoderPATMu.Unlock()
			accessToken = jobToken
			if jobUserID != "" {
				userID = jobUserID
			}
		}
		apiKey = ""
	}
	if accessToken == "" || userID == "" {
		return []any{}, "Qoder returned no models; falling back to static catalog."
	}
	modelListURL := pvQoderInferenceBase(accessToken, apiKey, region) + "/algo/api/v2/model/list"
	cosy, err := pvBuildCosyHeaders(nil, modelListURL, userID, accessToken,
		pvStr(conn, "displayName"), pvStr(conn, "email"), pvStr(psd, "machineId"))
	if err != nil {
		return []any{}, "Failed to fetch Qoder models: " + err.Error()
	}
	headers := map[string]string{"Accept": "application/json", "Accept-Encoding": "identity"}
	for k, v := range cosy {
		headers[k] = v
	}
	res, ferr := pvFetch(ctx, "GET", modelListURL, headers, nil, 15*time.Second, "")
	if ferr != nil || !res.OK {
		return []any{}, "Qoder returned no models; falling back to static catalog."
	}
	data := res.JSONMap()
	chat := pvSlice(data, "chat")
	if chat == nil {
		return []any{}, "Qoder returned no models; falling back to static catalog."
	}
	models := []any{}
	for _, rawEntry := range chat {
		entry, _ := rawEntry.(map[string]any)
		if entry == nil {
			continue
		}
		key := pvStr(entry, "key")
		if key == "" {
			continue
		}
		if v, present := entry["enable"]; present {
			if b, isBool := v.(bool); isBool && !b {
				continue
			}
		}
		name := pvStr(entry, "display_name")
		if name == "" {
			name = key
		}
		ctxLen := float64(131072)
		if f, ok := pvNum(entry, "max_input_tokens"); ok && f != 0 {
			ctxLen = f
		}
		maxOut, _ := pvNum(entry, "max_output_tokens")
		models = append(models, map[string]any{
			"id":              provider + "/" + key,
			"name":            name,
			"contextLength":   ctxLen,
			"isVL":            pvBool(entry, "is_vl"),
			"isReasoning":     pvBool(entry, "is_reasoning"),
			"maxOutputTokens": maxOut,
			"description":     pvStr(entry, "description"),
		})
	}
	if len(models) == 0 {
		return []any{}, "Qoder returned no models; falling back to static catalog."
	}
	return models, ""
}

// ---------- Zed live models (open-sse/shared/zedAuth.js port) ----------

var (
	pvZedTokenMu    sync.Mutex
	pvZedTokenCache = map[string]struct {
		Token     string
		ExpiresAt int64
	}{}
)

func pvZedNormalizeOrgID(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		if len(t) > 0 {
			if s, ok := t[0].(string); ok {
				return s
			}
		}
	case map[string]any:
		if s, ok := t["id"].(string); ok {
			return s
		}
	case float64:
		return pvJSNumStr(t)
	case bool:
		return strconv.FormatBool(t)
	}
	return ""
}

// pvZedFetchJSON ports zedAuth fetchJson: parse text as JSON, throw the
// JS-shaped error (message || error.message || error || text || HTTP n).
func pvZedFetchJSON(ctx context.Context, method, rawURL string, headers map[string]string, body []byte) (map[string]any, *pvFetchResult, error) {
	res, err := pvFetch(ctx, method, rawURL, headers, body, 0, "")
	if err != nil {
		return nil, nil, err
	}
	var data map[string]any
	if len(res.Body) > 0 {
		var parsed any
		if json.Unmarshal(res.Body, &parsed) == nil {
			if m, ok := parsed.(map[string]any); ok {
				data = m
			}
		}
		if data == nil {
			data = map[string]any{"raw": res.Text()}
		}
	}
	if !res.OK {
		msg := ""
		if data != nil {
			msg = pvStr(data, "message")
			if msg == "" {
				if e := pvMap(data, "error"); e != nil {
					msg = pvStr(e, "message")
				}
			}
			if msg == "" {
				msg = pvStr(data, "error")
			}
		}
		if msg == "" {
			msg = res.Text()
		}
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", res.Status)
		}
		return data, res, errors.New(msg)
	}
	if data == nil {
		data = map[string]any{}
	}
	return data, res, nil
}

func pvZedUserAuthHeader(conn db.Record) (string, error) {
	psd := pvConnPSD(conn)
	userID := pvStr(psd, "userId")
	if userID == "" {
		userID = pvStr(conn, "userId")
	}
	token := pvStr(conn, "accessToken")
	if token == "" {
		token = pvStr(conn, "apiKey")
	}
	if userID == "" || token == "" {
		return "", errors.New("Zed credential is missing userId or accessToken")
	}
	return userID + " " + token, nil
}

// pvZedLlmToken ports fetchZedLlmToken (50-minute cache, forceRefresh
// bypasses it), resolving the organization on the way when needed.
func pvZedLlmToken(ctx context.Context, conn db.Record, forceRefresh bool) (string, error) {
	const cloudBase = "https://cloud.zed.dev"
	psd := pvConnPSD(conn)
	orgID := pvZedNormalizeOrgID(psd["organizationId"])
	if orgID == "" {
		orgID = pvZedNormalizeOrgID(psd["defaultOrganizationId"])
	}
	auth, err := pvZedUserAuthHeader(conn)
	if err != nil {
		return "", err
	}
	systemID := pvStr(psd, "systemId")
	if systemID == "" {
		systemID = pvStr(conn, "systemId")
	}
	if orgID == "" {
		headers := map[string]string{"Accept": "application/json", "Authorization": auth}
		if systemID != "" {
			headers["x-zed-system-id"] = systemID
		}
		userInfo, _, ferr := pvZedFetchJSON(ctx, "GET", cloudBase+"/client/users/me", headers, nil)
		if ferr != nil {
			return "", ferr
		}
		orgID = pvZedNormalizeOrgID(userInfo["default_organization_id"])
		if orgID == "" {
			orgID = pvZedNormalizeOrgID(userInfo["defaultOrganizationId"])
		}
		if orgID == "" {
			orgs := pvSlice(userInfo, "organizations")
			var first, personal map[string]any
			for _, o := range orgs {
				om, _ := o.(map[string]any)
				if om == nil {
					continue
				}
				if first == nil {
					first = om
				}
				if pvBool(om, "is_personal") {
					personal = om
					break
				}
			}
			chosen := personal
			if chosen == nil {
				chosen = first
			}
			if chosen != nil {
				orgID = pvZedNormalizeOrgID(chosen["id"])
			}
		}
	}
	if orgID == "" {
		return "", errors.New("No Zed organization selected")
	}
	userID := pvStr(psd, "userId")
	if userID == "" {
		userID = pvStr(conn, "userId")
	}
	if userID == "" {
		userID = "unknown"
	}
	token := pvStr(conn, "accessToken")
	if token == "" {
		token = pvStr(conn, "apiKey")
	}
	tail := token
	if len(tail) > 16 {
		tail = tail[len(tail)-16:]
	}
	cacheKey := userID + ":" + orgID + ":" + tail
	pvZedTokenMu.Lock()
	cached, hasCached := pvZedTokenCache[cacheKey]
	pvZedTokenMu.Unlock()
	if !forceRefresh && hasCached && cached.ExpiresAt > pvNowMs() {
		return cached.Token, nil
	}
	headers := map[string]string{
		"Content-Type": "application/json", "Accept": "application/json", "Authorization": auth,
	}
	if systemID != "" {
		headers["x-zed-system-id"] = systemID
	}
	body, _ := json.Marshal(map[string]any{"organization_id": orgID})
	data, _, ferr := pvZedFetchJSON(ctx, "POST", cloudBase+"/client/llm_tokens", headers, body)
	if ferr != nil {
		return "", ferr
	}
	llmToken := ""
	switch t := data["token"].(type) {
	case string:
		llmToken = t
	case []any:
		if len(t) > 0 {
			llmToken, _ = t[0].(string)
		}
	case map[string]any:
		llmToken, _ = t["value"].(string)
	}
	if llmToken == "" {
		return "", errors.New("Zed did not return an LLM token")
	}
	pvZedTokenMu.Lock()
	pvZedTokenCache[cacheKey] = struct {
		Token     string
		ExpiresAt int64
	}{llmToken, pvNowMs() + 50*60*1000}
	pvZedTokenMu.Unlock()
	return llmToken, nil
}

func pvZedNormalizeID(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		if len(t) > 0 {
			if s, ok := t[0].(string); ok {
				return s
			}
		}
	case map[string]any:
		if s, ok := t["id"].(string); ok {
			return s
		}
	case float64:
		return pvJSNumStr(t)
	case bool:
		return strconv.FormatBool(t)
	}
	return ""
}

// pvResolveZedModels ports resolveZedModels + zedLlmFetch and the route's
// field mapping (ZED_HOSTED_CONFIG: cloud + llm bases are both
// https://cloud.zed.dev). No access token → the service returns null →
// the route's "returned no live models" warning; upstream errors →
// "Failed to fetch Zed models: <msg>".
func pvResolveZedModels(ctx context.Context, conn db.Record) ([]any, string) {
	if pvStr(conn, "accessToken") == "" {
		return []any{}, "Zed returned no live models."
	}
	fetchModels := func(forceRefresh bool) (map[string]any, *pvFetchResult, error) {
		llmToken, err := pvZedLlmToken(ctx, conn, forceRefresh)
		if err != nil {
			return nil, nil, err
		}
		headers := map[string]string{
			"Accept": "application/json", "x-zed-client-supports-x-ai": "true",
			"Authorization": "Bearer " + llmToken,
		}
		res, ferr := pvFetch(ctx, "GET", "https://cloud.zed.dev/models", headers, nil, 0, "")
		if ferr != nil {
			return nil, nil, ferr
		}
		if !res.OK {
			return nil, res, fmt.Errorf("Zed models failed: %d %s", res.Status, res.Text())
		}
		var data map[string]any
		if json.Unmarshal(res.Body, &data) != nil || data == nil {
			data = map[string]any{}
		}
		return data, res, nil
	}
	data, res, err := fetchModels(false)
	// zedLlmFetch: shouldRefreshZedLlmToken(first response) — status 401 or
	// an expired/outdated token header — forces one re-mint + retry.
	if res != nil && (res.Status == 401 ||
		res.Headers.Get("x-zed-expired-token") != "" ||
		res.Headers.Get("x-zed-outdated-token") != "") {
		data, res, err = fetchModels(true)
	}
	if err != nil {
		return []any{}, "Failed to fetch Zed models: " + err.Error()
	}
	_ = res
	models := []any{}
	for _, raw := range pvSlice(data, "models") {
		m, _ := raw.(map[string]any)
		if m == nil {
			continue
		}
		id := pvZedNormalizeID(m["id"])
		if id == "" {
			continue
		}
		if pvBool(m, "is_disabled") {
			continue
		}
		name := pvStr(m, "display_name")
		if name == "" {
			name = pvStr(m, "displayName")
		}
		if name == "" {
			name = id
		}
		effort := m["supported_effort_levels"]
		if effort == nil {
			effort = m["supportedEffortLevels"]
		}
		if effort == nil {
			effort = []any{}
		}
		numOrNil := func(keys ...string) any {
			for _, k := range keys {
				if v, present := m[k]; present && v != nil {
					return v
				}
			}
			return nil
		}
		models = append(models, map[string]any{
			"id":                           id,
			"name":                         name,
			"provider":                     m["provider"],
			"contextLength":                numOrNil("max_token_count", "maxTokenCount"),
			"contextLengthInMaxMode":       numOrNil("max_token_count_in_max_mode", "maxTokenCountInMaxMode"),
			"maxOutputTokens":              numOrNil("max_output_tokens", "maxOutputTokens"),
			"supportsTools":                pvBool(m, "supports_tools"),
			"supportsImages":               pvBool(m, "supports_images"),
			"supportsThinking":             pvBool(m, "supports_thinking"),
			"supportsDisablingThinking":    pvBool(m, "supports_disabling_thinking"),
			"supportsFastMode":             pvBool(m, "supports_fast_mode"),
			"supportsServerSideCompaction": pvBool(m, "supports_server_side_compaction"),
			"supportedEffortLevels":        effort,
			"supportsStreamingTools":       pvBool(m, "supports_streaming_tools"),
			"supportsParallelToolCalls":    pvBool(m, "supports_parallel_tool_calls"),
		})
	}
	if len(models) == 0 {
		return []any{}, "Zed returned no live models."
	}
	return models, ""
}

// pvCustomResolverProviders are providers whose models come from a
// customResolver in JS; the live resolvers above back them, falling back
// exactly like JS does when the live lookup yields nothing.
func pvResolveCustomModels(ctx context.Context, deps Deps, conn db.Record) (pvModelsOutcome, bool) {
	provider := pvStr(conn, "provider")
	switch provider {
	case "ollama-local":
		host := pvOllamaLocalHost(conn)
		res, err := pvFetch(ctx, "GET", host+"/api/tags", map[string]string{"Content-Type": "application/json"}, nil, 0, "")
		if err != nil {
			return pvModelsOutcome{ErrStatus: 500, ErrMsg: "Failed to fetch models: 0"}, true
		}
		if !res.OK {
			return pvModelsOutcome{ErrStatus: res.Status, ErrMsg: fmt.Sprintf("Failed to fetch models: %d", res.Status)}, true
		}
		var data any
		_ = json.Unmarshal(res.Body, &data)
		return pvModelsOutcome{Models: pvParseOpenAIStyle(data)}, true
	case "codex":
		cliVersion := ""
		if p, ok := pvReg("codex"); ok {
			cliVersion = pvStr(pvRawMap(p, "transport"), "cliVersion")
		}
		modelsURL := "https://chatgpt.com/backend-api/codex/models?client_version=" + cliVersion
		// JS buildOAuthResolver refreshFn = refreshCodexToken — the same
		// oauthsvc-backed refresh pvRefreshOAuthToken now delegates to.
		refreshFn := func(c db.Record) map[string]any {
			return pvRefreshOAuthToken(ctx, c)
		}
		out := pvOAuthModelsResolver(ctx, deps, conn, "Failed to fetch Codex models", refreshFn,
			func(token string) (*pvFetchResult, error) {
				return pvFetch(ctx, "GET", modelsURL, map[string]string{
					"Content-Type": "application/json", "Accept": "application/json",
					"Authorization": "Bearer " + token, "originator": "codex_cli_rs",
				}, nil, 0, "")
			}, pvParseCodexModels)
		return out, true
	case "gemini-cli":
		refreshFn := func(c db.Record) map[string]any {
			return pvRefreshOAuthToken(ctx, c)
		}
		out := pvOAuthModelsResolver(ctx, deps, conn, "Failed to fetch Gemini CLI models", refreshFn,
			func(token string) (*pvFetchResult, error) {
				payload := map[string]any{}
				if pid := pvStr(conn, "projectId"); pid != "" {
					payload["project"] = pid
				} else if pid := pvStr(pvConnPSD(conn), "projectId"); pid != "" {
					payload["project"] = pid
				}
				return pvFetchJSON(ctx, "POST", "https://cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels",
					map[string]string{
						"Authorization": "Bearer " + token, "User-Agent": "google-api-nodejs-client/9.15.1",
						"X-Goog-Api-Client": "google-cloud-sdk vscode_cloudshelleditor/0.1",
					}, payload, 0, "")
			}, pvParseGeminiCliModels)
		return out, true
	case "kimchi":
		if models := pvResolveKimchiModels(ctx, conn); len(models) > 0 {
			return pvModelsOutcome{Models: models}, true
		}
		return pvModelsOutcome{Models: pvStaticModels("kimchi"), Warning: "Kimchi returned no live models; falling back to static catalog."}, true
	case "cursor":
		if models := pvResolveCursorModelsLive(ctx, conn); len(models) > 0 {
			return pvModelsOutcome{Models: models}, true
		}
		return pvModelsOutcome{Models: pvStaticModels("cursor"), Warning: "Cursor returned no live models; falling back to static catalog."}, true
	case "cline":
		if models := pvResolveClineModels(ctx, conn, false); len(models) > 0 {
			return pvModelsOutcome{Models: models}, true
		}
		return pvModelsOutcome{Models: pvStaticModels("cline"), Warning: "Cline returned no live models; falling back to static catalog."}, true
	case "clinepass":
		if models := pvResolveClineModels(ctx, conn, true); len(models) > 0 {
			return pvModelsOutcome{Models: models}, true
		}
		return pvModelsOutcome{Models: pvStaticModels("clinepass"), Warning: "ClinePass returned no live models; falling back to static catalog."}, true
	case "grok-cli":
		models, warning := pvResolveGrokCliModels(ctx, deps, conn)
		if len(models) > 0 {
			return pvModelsOutcome{Models: models}, true
		}
		if warning == "" {
			warning = "Grok CLI returned no live models; using static catalog."
		}
		return pvModelsOutcome{Models: pvStaticModels("grok-cli"), Warning: warning}, true
	case "kiro":
		models, warning := pvResolveKiroModels(ctx, deps, conn)
		return pvModelsOutcome{Models: models, Warning: warning}, true
	case "qoder", "qoder-cn":
		models, warning := pvResolveQoderModels(ctx, conn)
		return pvModelsOutcome{Models: models, Warning: warning}, true
	case "zed":
		models, warning := pvResolveZedModels(ctx, conn)
		return pvModelsOutcome{Models: models, Warning: warning}, true
	}
	return pvModelsOutcome{}, false
}

// pvResolveProviderModels is the shared core of GET /providers/[id]/models.
func pvResolveProviderModels(ctx context.Context, deps Deps, conn db.Record) pvModelsOutcome {
	provider := pvStr(conn, "provider")
	psd := pvConnPSD(conn)
	if oc, _, _ := pvIsCompatProvider(provider); oc {
		base := pvStr(psd, "baseUrl")
		if base == "" {
			return pvModelsOutcome{ErrStatus: 400, ErrMsg: "No base URL configured for OpenAI compatible provider"}
		}
		res, err := pvFetch(ctx, "GET", strings.TrimSuffix(base, "/")+"/models", map[string]string{
			"Content-Type": "application/json", "Authorization": "Bearer " + pvStr(conn, "apiKey"),
		}, nil, 0, "")
		if err != nil {
			return pvModelsOutcome{ErrStatus: 500, ErrMsg: "Failed to fetch models"}
		}
		if !res.OK {
			return pvModelsOutcome{ErrStatus: res.Status, ErrMsg: fmt.Sprintf("Failed to fetch models: %d", res.Status)}
		}
		data := res.JSONMap()
		models := pvSlice(data, "data")
		if models == nil {
			models = pvSlice(data, "models")
		}
		if models == nil {
			models = []any{}
		}
		return pvModelsOutcome{Models: models}
	}
	if _, ac, _ := pvIsCompatProvider(provider); ac {
		base := pvStr(psd, "baseUrl")
		if base == "" {
			return pvModelsOutcome{ErrStatus: 400, ErrMsg: "No base URL configured for Anthropic compatible provider"}
		}
		base = strings.TrimSuffix(base, "/")
		if strings.HasSuffix(base, "/messages") {
			base = base[:len(base)-len("/messages")]
		}
		res, err := pvFetch(ctx, "GET", base+"/models", map[string]string{
			"Content-Type": "application/json", "x-api-key": pvStr(conn, "apiKey"),
			"anthropic-version": "2023-06-01", "Authorization": "Bearer " + pvStr(conn, "apiKey"),
		}, nil, 0, "")
		if err != nil {
			return pvModelsOutcome{ErrStatus: 500, ErrMsg: "Failed to fetch models"}
		}
		if !res.OK {
			return pvModelsOutcome{ErrStatus: res.Status, ErrMsg: fmt.Sprintf("Failed to fetch models: %d", res.Status)}
		}
		data := res.JSONMap()
		models := pvSlice(data, "data")
		if models == nil {
			models = pvSlice(data, "models")
		}
		if models == nil {
			models = []any{}
		}
		return pvModelsOutcome{Models: models}
	}
	if out, handled := pvResolveCustomModels(ctx, deps, conn); handled {
		return out
	}
	cfg, ok := pvModelsConfig(provider)
	if !ok {
		return pvModelsOutcome{ErrStatus: 400, ErrMsg: "Provider " + provider + " does not support models listing"}
	}
	token := pvStr(psd, "copilotToken")
	if token == "" {
		token = pvStr(conn, "accessToken")
	}
	if token == "" {
		token = pvStr(conn, "apiKey")
	}
	if token == "" {
		return pvModelsOutcome{ErrStatus: 401, ErrMsg: "No valid token found"}
	}
	u := cfg.URL
	if cfg.AuthQuery != "" {
		u += "?" + cfg.AuthQuery + "=" + token
	}
	headers := map[string]string{}
	for k, v := range cfg.Headers {
		headers[k] = v
	}
	if cfg.AuthHeader != "" && cfg.AuthQuery == "" {
		headers[cfg.AuthHeader] = cfg.AuthPrefix + token
	}
	var body []byte
	if cfg.Body != nil && cfg.Method == "POST" {
		body, _ = json.Marshal(cfg.Body)
	}
	res, err := pvFetch(ctx, cfg.Method, u, headers, body, 0, "")
	if err != nil {
		return pvModelsOutcome{ErrStatus: 500, ErrMsg: "Failed to fetch models"}
	}
	if !res.OK {
		return pvModelsOutcome{ErrStatus: res.Status, ErrMsg: fmt.Sprintf("Failed to fetch models: %d", res.Status)}
	}
	var data any
	_ = json.Unmarshal(res.Body, &data)
	return pvModelsOutcome{Models: cfg.Parse(data)}
}

func pvProviderModels(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := deps.Store.GetProviderConnectionByID(r.PathValue("id"))
		if err != nil || conn == nil {
			Err(w, http.StatusNotFound, "Connection not found")
			return
		}
		out := pvResolveProviderModels(r.Context(), deps, conn)
		if out.ErrMsg != "" {
			status := out.ErrStatus
			if status == 0 {
				status = 500
			}
			Err(w, status, out.ErrMsg)
			return
		}
		resp := map[string]any{
			"provider": pvStr(conn, "provider"), "connectionId": pvStr(conn, "id"), "models": out.Models,
		}
		if out.Warning != "" {
			resp["warning"] = out.Warning
		}
		WriteJSON(w, http.StatusOK, resp)
	}
}

// ---------- model ping (models/test/ping.js port) ----------

// pvPingBaseOverride lets tests point pings at a mock internal server.
var pvPingBaseOverride = ""

func pvPingBaseURL() string {
	if pvPingBaseOverride != "" {
		return pvPingBaseOverride
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "20128"
	}
	return "http://127.0.0.1:" + port
}

func pvInternalHeaders(deps Deps) map[string]string {
	headers := map[string]string{"Content-Type": "application/json"}
	keys, err := deps.Store.GetAPIKeys()
	if err == nil {
		var firstActive map[string]any
		var firstUnrestricted map[string]any
		for _, k := range keys {
			if v, ok := k["isActive"].(bool); ok && !v {
				continue
			}
			if firstActive == nil {
				firstActive = k
			}
			restricted := false
			if acc := pvMap(k, "access"); acc != nil {
				restricted = pvBool(acc, "restricted")
			}
			if !restricted && firstUnrestricted == nil {
				firstUnrestricted = k
			}
		}
		chosen := firstUnrestricted
		if chosen == nil {
			chosen = firstActive
		}
		if chosen != nil {
			if key := pvStr(chosen, "key"); key != "" {
				headers["Authorization"] = "Bearer " + key
			}
		}
	}
	// TODO: x-9r-cli-token (getConsistentMachineId) is not ported; the Go
	// chat server does not require it.
	return headers
}

func pvSilentWAV() []byte {
	const sampleRate = 16000
	const channels = 1
	const bitsPerSample = 16
	sampleCount := sampleRate * 250 / 1000
	dataSize := sampleCount * channels * (bitsPerSample / 8)
	buf := new(bytes.Buffer)
	writeStr := func(s string) { buf.WriteString(s) }
	u32 := func(v uint32) {
		_ = buf.WriteByte(byte(v))
		_ = buf.WriteByte(byte(v >> 8))
		_ = buf.WriteByte(byte(v >> 16))
		_ = buf.WriteByte(byte(v >> 24))
	}
	u16 := func(v uint16) {
		_ = buf.WriteByte(byte(v))
		_ = buf.WriteByte(byte(v >> 8))
	}
	writeStr("RIFF")
	u32(uint32(36 + dataSize))
	writeStr("WAVE")
	writeStr("fmt ")
	u32(16)
	u16(1)
	u16(channels)
	u32(sampleRate)
	u32(sampleRate * channels * (bitsPerSample / 8))
	u16(channels * (bitsPerSample / 8))
	u16(bitsPerSample)
	writeStr("data")
	u32(uint32(dataSize))
	buf.Write(make([]byte, dataSize))
	return buf.Bytes()
}

func pvPingDetail(parsed map[string]any, raw string, maxLen int) string {
	detail := ""
	if parsed != nil {
		if e := pvMap(parsed, "error"); e != nil {
			detail = pvStr(e, "message")
		}
		if detail == "" {
			detail = pvStr(parsed, "msg")
		}
		if detail == "" {
			detail = pvStr(parsed, "message")
		}
		if detail == "" {
			detail = pvStr(parsed, "error")
		}
	}
	if detail == "" {
		detail = raw
	}
	if len(detail) > maxLen {
		detail = detail[:maxLen]
	}
	return detail
}

func pvPingHTTPError(status int, parsed map[string]any, raw string, maxLen int) string {
	detail := pvPingDetail(parsed, raw, maxLen)
	if detail != "" {
		return fmt.Sprintf("HTTP %d: %s", status, detail)
	}
	return fmt.Sprintf("HTTP %d", status)
}

// pvPingModel ports pingModelByKind. Paths use the Go server's canonical
// /v1 mount (JS used /api/v1 via the Next rewrite to the same handlers).
func pvPingModel(ctx context.Context, deps Deps, model, kind string) map[string]any {
	headers := pvInternalHeaders(deps)
	base := pvPingBaseURL()
	start := time.Now()
	doPost := func(path string, payload any) (*pvFetchResult, int64) {
		body, _ := json.Marshal(payload)
		res, err := pvFetch(ctx, "POST", base+path, headers, body, 15*time.Second, "")
		latency := time.Since(start).Milliseconds()
		if err != nil {
			return &pvFetchResult{Status: 0, Body: []byte(pvErrText(err))}, latency
		}
		return res, latency
	}
	parse := func(res *pvFetchResult) map[string]any {
		var m map[string]any
		_ = json.Unmarshal(res.Body, &m)
		return m
	}
	switch kind {
	case "embedding":
		res, latency := doPost("/v1/embeddings", map[string]any{"model": model, "input": "test"})
		parsed := parse(res)
		if !res.OK {
			return map[string]any{"ok": false, "latencyMs": latency, "error": pvPingHTTPError(res.Status, parsed, res.Text(), 240), "status": res.Status}
		}
		data := pvSlice(parsed, "data")
		has := len(data) > 0
		if has {
			first, _ := data[0].(map[string]any)
			_, has = first["embedding"].([]any)
		}
		if !has {
			return map[string]any{"ok": false, "latencyMs": latency, "status": res.Status, "error": "Provider returned no embedding data"}
		}
		return map[string]any{"ok": true, "latencyMs": latency, "error": nil, "status": res.Status}
	case "image":
		res, latency := doPost("/v1/images/generations", map[string]any{"model": model, "prompt": "test"})
		parsed := parse(res)
		if !res.OK {
			return map[string]any{"ok": false, "latencyMs": latency, "error": pvPingHTTPError(res.Status, parsed, res.Text(), 240), "status": res.Status}
		}
		if len(pvSlice(parsed, "data")) == 0 {
			return map[string]any{"ok": false, "latencyMs": latency, "status": res.Status, "error": "Provider returned no image data for this model"}
		}
		return map[string]any{"ok": true, "latencyMs": latency, "error": nil, "status": res.Status}
	case "stt":
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fw, _ := mw.CreateFormFile("file", "test.wav")
		_, _ = fw.Write(pvSilentWAV())
		_ = mw.WriteField("model", model)
		_ = mw.Close()
		sttHeaders := map[string]string{}
		for k, v := range headers {
			if !strings.EqualFold(k, "Content-Type") {
				sttHeaders[k] = v
			}
		}
		sttHeaders["Content-Type"] = mw.FormDataContentType()
		res, err := pvFetch(ctx, "POST", base+"/v1/audio/transcriptions", sttHeaders, buf.Bytes(), 15*time.Second, "")
		latency := time.Since(start).Milliseconds()
		if err != nil {
			return map[string]any{"ok": false, "latencyMs": latency, "error": pvErrText(err), "status": 0}
		}
		parsed := parse(res)
		if !res.OK {
			return map[string]any{"ok": false, "latencyMs": latency, "error": pvPingHTTPError(res.Status, parsed, res.Text(), 240), "status": res.Status}
		}
		if strings.TrimSpace(pvStr(parsed, "text")) == "" {
			return map[string]any{"ok": false, "latencyMs": latency, "status": res.Status, "error": "Provider returned no transcription text for this model"}
		}
		return map[string]any{"ok": true, "latencyMs": latency, "error": nil, "status": res.Status}
	case "systemone":
		res, latency := doPost("/v1/systemone", map[string]any{
			"model": model,
			"state": "Customer: I was charged twice for my order this morning.",
			"questions": map[string]any{
				"probe": map[string]any{"type": "noul", "instructions": "Is the customer reporting a billing problem?"},
			},
		})
		parsed := parse(res)
		if !res.OK {
			return map[string]any{"ok": false, "latencyMs": latency, "error": pvPingHTTPError(res.Status, parsed, res.Text(), 240), "status": res.Status}
		}
		answers := pvMap(parsed, "answers")
		if len(answers) == 0 {
			return map[string]any{"ok": false, "latencyMs": latency, "status": res.Status, "error": "Provider returned no answers for this model"}
		}
		return map[string]any{"ok": true, "latencyMs": latency, "error": nil, "status": res.Status}
	}
	// llm (default)
	res, latency := doPost("/v1/chat/completions", map[string]any{
		"model": model, "max_tokens": 1024, "stream": false,
		"messages": []any{map[string]any{"role": "user", "content": "hi"}},
	})
	parsed := parse(res)
	// TODO: unwrapClineEnvelope (transport.quirks.clineEnvelope) not applied.
	if !res.OK {
		return map[string]any{"ok": false, "latencyMs": latency, "error": pvPingHTTPError(res.Status, parsed, res.Text(), 500), "status": res.Status}
	}
	if parsed != nil {
		if st, ok := parsed["status"]; ok && st != nil {
			stStr := fmt.Sprintf("%v", st)
			msg := pvStr(parsed, "msg")
			if msg == "" {
				msg = pvStr(parsed, "message")
			}
			if stStr != "200" && stStr != "0" && msg != "" {
				if len(msg) > 240 {
					msg = msg[:240]
				}
				return map[string]any{"ok": false, "latencyMs": latency, "status": res.Status, "error": fmt.Sprintf("Provider status %s: %s", stStr, msg)}
			}
		}
		if parsed["error"] != nil {
			msg := pvStr(pvMap(parsed, "error"), "message")
			if msg == "" {
				msg = pvStr(parsed, "error")
			}
			if msg == "" {
				msg = "Provider returned an error"
			}
			if len(msg) > 240 {
				msg = msg[:240]
			}
			return map[string]any{"ok": false, "latencyMs": latency, "status": res.Status, "error": msg}
		}
	}
	choices := pvSlice(parsed, "choices")
	hasChoices := len(choices) > 0
	if hasChoices {
		first, _ := choices[0].(map[string]any)
		msgMap := pvMap(first, "message")
		hasReasoning := pvStr(msgMap, "reasoning") != "" || pvStr(msgMap, "reasoning_content") != "" ||
			pvStr(msgMap, "thinking") != "" || pvStr(msgMap, "thinking_content") != ""
		contentEmpty := strings.TrimSpace(pvStr(msgMap, "content")) == ""
		if pvStr(first, "finish_reason") == "length" && contentEmpty && hasReasoning {
			return map[string]any{"ok": true, "latencyMs": latency, "error": nil, "status": res.Status, "note": "reasoning-only response (length-limited)"}
		}
	}
	if !hasChoices {
		return map[string]any{"ok": false, "latencyMs": latency, "status": res.Status, "error": "Provider returned no completion choices for this model"}
	}
	return map[string]any{"ok": true, "latencyMs": latency, "error": nil, "status": res.Status}
}

func pvModelTest(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
		model := Str(body, "model")
		if model == "" {
			Err(w, http.StatusBadRequest, "Model required")
			return
		}
		kind := pvStrOr(body, "kind", "llm")
		result := pvPingModel(r.Context(), deps, model, kind)
		WriteJSON(w, http.StatusOK, result)
	}
}

func pvProviderTestModels(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		conn, err := deps.Store.GetProviderConnectionByID(id)
		if err != nil || conn == nil {
			Err(w, http.StatusNotFound, "Connection not found")
			return
		}
		providerID := pvStr(conn, "provider")
		oc, ac, _ := pvIsCompatProvider(providerID)
		isCompatible := oc || ac
		alias := pvProviderAlias(providerID)
		models := pvCatalogModels(alias)
		if isCompatible && len(models) == 0 {
			out := pvResolveProviderModels(r.Context(), deps, conn)
			if out.ErrMsg == "" {
				models = nil
				for _, m := range out.Models {
					mm, _ := m.(map[string]any)
					mid := pvStr(mm, "id")
					if mid == "" {
						mid = pvStr(mm, "name")
					}
					models = append(models, map[string]any{"id": mid, "name": pvStrOr(mm, "name", mid)})
				}
			}
		}
		if len(models) == 0 {
			Err(w, http.StatusBadRequest, "No models configured for this provider")
			return
		}
		kindOf := func(m map[string]any) string {
			if k := pvStr(m, "kind"); k != "" {
				return k
			}
			return pvStrOr(m, "type", "llm")
		}
		results := make([]any, len(models))
		first := models[0]
		firstRes := pvPingModel(r.Context(), deps, alias+"/"+pvStr(first, "id"), kindOf(first))
		entry := map[string]any{"modelId": pvStr(first, "id"), "name": pvStrOr(first, "name", pvStr(first, "id"))}
		for k, v := range firstRes {
			entry[k] = v
		}
		results[0] = entry
		if len(models) > 1 {
			var wg sync.WaitGroup
			for i := 1; i < len(models); i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					m := models[i]
					res := pvPingModel(r.Context(), deps, alias+"/"+pvStr(m, "id"), kindOf(m))
					e := map[string]any{"modelId": pvStr(m, "id"), "name": pvStrOr(m, "name", pvStr(m, "id"))}
					for k, v := range res {
						e[k] = v
					}
					results[i] = e
				}(i)
			}
			wg.Wait()
		}
		WriteJSON(w, http.StatusOK, map[string]any{
			"provider": providerID, "connectionId": id, "results": results,
		})
	}
}

// ---------- SSRF guard (ssrfGuard.js layer-1 port: assertPublicUrl) ----------

func pvBlockedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 0: // 0.0.0.0/8
			return true
		case v4[0] == 10:
			return true
		case v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127: // CGNAT 100.64/10
			return true
		case v4[0] == 127:
			return true
		case v4[0] == 169 && v4[1] == 254:
			return true
		case v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31:
			return true
		case v4[0] == 192 && v4[1] == 168:
			return true
		}
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsPrivate() {
		return true
	}
	// NAT64 well-known prefix 64:ff9b::/96 embeds an IPv4 tail.
	if len(ip) == net.IPv6len && ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b {
		return pvBlockedIP(ip[12:])
	}
	return false
}

// pvAssertPublicURL ports assertPublicUrl (literal host checks only).
func pvAssertPublicURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "localhost" || host == "ip6-localhost" || host == "ip6-loopback" {
		return errors.New("Blocked URL: internal host")
	}
	for _, suffix := range []string{".internal", ".local", ".localhost"} {
		if strings.HasSuffix(host, suffix) {
			return errors.New("Blocked URL: internal host")
		}
	}
	if ip := net.ParseIP(host); ip != nil && pvBlockedIP(ip) {
		return errors.New("Blocked URL: internal host")
	}
	return nil
}

// ---------- provider-nodes/validate ----------

func pvNodeValidateErrMessage(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "connection refused"):
		return "Connection refused - provider node offline or unreachable"
	case strings.Contains(msg, "no such host"), strings.Contains(msg, "server misbehaving"):
		return "DNS lookup failed - invalid domain or network issue"
	case strings.Contains(msg, "certificate has expired"), strings.Contains(msg, "x509: certificate has expired"):
		return "SSL certificate expired"
	case strings.Contains(msg, "certificate"), strings.Contains(msg, "x509"):
		return "SSL certificate verification failed"
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline exceeded"):
		return "Request timeout (>10s) - provider node not responding"
	}
	return "Network connection failed - check URL and network connectivity"
}

func pvModelsErrMessage(status int) string {
	switch {
	case status == 401 || status == 403:
		return "API key unauthorized"
	case status == 404:
		return "/models endpoint not found - try chat validation with model ID"
	case status >= 500:
		return "Server error - try again later"
	}
	return fmt.Sprintf("Unexpected response (%d)", status)
}

func pvChatErrMessage(status int) string {
	switch {
	case status == 401 || status == 403:
		return "API key unauthorized"
	case status == 400:
		return "Invalid model or bad request"
	case status == 404:
		return "Chat endpoint not found"
	case status >= 500:
		return "Server error - try again later"
	}
	return fmt.Sprintf("Chat request failed (%d)", status)
}

func pvNodesValidate(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
		baseURL := Str(body, "baseUrl")
		apiKey := Str(body, "apiKey")
		typ := Str(body, "type")
		modelID := Str(body, "modelId")
		if baseURL == "" || apiKey == "" {
			Err(w, http.StatusBadRequest, "Base URL and API key required")
			return
		}
		if _, uerr := url.ParseRequestURI(baseURL); uerr != nil {
			if _, uerr2 := url.Parse(baseURL); uerr2 != nil || !strings.Contains(baseURL, "://") {
				Err(w, http.StatusBadRequest, "Invalid URL format")
				return
			}
		}
		if !IsLocalRequest(r) {
			if serr := pvAssertPublicURL(baseURL); serr != nil {
				Err(w, http.StatusBadRequest, "URL not allowed")
				return
			}
		}
		fail500 := func(err error) {
			WriteJSON(w, http.StatusInternalServerError, map[string]any{"valid": false, "error": pvNodeValidateErrMessage(err)})
		}
		if typ == "custom-embedding" {
			normalized := strings.TrimSuffix(strings.TrimSpace(baseURL), "/")
			if strings.TrimSpace(modelID) == "" {
				WriteJSON(w, http.StatusOK, map[string]any{"valid": false, "error": "Model ID required for embedding validation"})
				return
			}
			embBody, _ := json.Marshal(map[string]any{"model": strings.TrimSpace(modelID), "input": "ping"})
			res, ferr := pvFetch(ctx, "POST", normalized+"/embeddings", map[string]string{
				"Authorization": "Bearer " + apiKey, "Content-Type": "application/json",
			}, embBody, 10*time.Second, "")
			if ferr != nil {
				fail500(ferr)
				return
			}
			if res.OK {
				parsed := res.JSONMap()
				var dims any
				data := pvSlice(parsed, "data")
				if len(data) > 0 {
					if first, ok := data[0].(map[string]any); ok {
						if emb, ok := first["embedding"].([]any); ok {
							dims = len(emb)
						}
					}
				}
				WriteJSON(w, http.StatusOK, map[string]any{"valid": true, "method": "embeddings", "dimensions": dims})
				return
			}
			if res.Status == 401 || res.Status == 403 {
				WriteJSON(w, http.StatusOK, map[string]any{"valid": false, "error": "API key unauthorized"})
				return
			}
			errText := fmt.Sprintf("Embeddings request failed (%d)", res.Status)
			if t := res.Text(); t != "" {
				if len(t) > 200 {
					t = t[:200]
				}
				errText += ": " + t
			}
			WriteJSON(w, http.StatusOK, map[string]any{"valid": false, "error": errText, "method": "embeddings"})
			return
		}
		// Shared models-then-chat flow for anthropic-compatible + default.
		normalized := strings.TrimSuffix(strings.TrimSpace(baseURL), "/")
		if typ == "anthropic-compatible" && strings.HasSuffix(normalized, "/messages") {
			normalized = normalized[:len(normalized)-len("/messages")]
		}
		modelsHeaders := map[string]string{"Authorization": "Bearer " + apiKey}
		chatHeaders := map[string]string{"Authorization": "Bearer " + apiKey, "Content-Type": "application/json"}
		if typ == "anthropic-compatible" {
			modelsHeaders["x-api-key"] = apiKey
			modelsHeaders["anthropic-version"] = "2023-06-01"
			chatHeaders["x-api-key"] = apiKey
			chatHeaders["anthropic-version"] = "2023-06-01"
		}
		res, ferr := pvFetch(ctx, "GET", normalized+"/models", modelsHeaders, nil, 10*time.Second, "")
		if ferr != nil {
			fail500(ferr)
			return
		}
		if res.OK {
			WriteJSON(w, http.StatusOK, map[string]any{"valid": true})
			return
		}
		if res.Status == 401 || res.Status == 403 {
			WriteJSON(w, http.StatusOK, map[string]any{"valid": false, "error": "API key unauthorized"})
			return
		}
		if modelID != "" {
			chatBody, _ := json.Marshal(map[string]any{
				"model": modelID, "messages": []any{map[string]any{"role": "user", "content": "ping"}}, "max_tokens": 1,
			})
			chatRes, cerr := pvFetch(ctx, "POST", normalized+"/chat/completions", chatHeaders, chatBody, 10*time.Second, "")
			if cerr != nil {
				fail500(cerr)
				return
			}
			if chatRes.OK {
				WriteJSON(w, http.StatusOK, map[string]any{"valid": true, "method": "chat"})
				return
			}
			WriteJSON(w, http.StatusOK, map[string]any{"valid": false, "error": pvChatErrMessage(chatRes.Status), "method": "chat"})
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"valid": false, "error": pvModelsErrMessage(res.Status)})
	}
}

// ---------- proxy-pools ----------

var pvValidProxyTypes = map[string]bool{"http": true, "vercel": true, "cloudflare": true, "deno": true, "netlify": true}

func pvNormalizePoolType(t string) string {
	if pvValidProxyTypes[t] {
		return t
	}
	return "http"
}

func pvPoolUsageMap(deps Deps) map[string]int {
	usage := map[string]int{}
	conns, err := deps.Store.GetProviderConnections(db.ConnectionFilter{})
	if err != nil {
		return usage
	}
	for _, c := range conns {
		if pid := pvStr(pvConnPSD(c), "proxyPoolId"); pid != "" {
			usage[pid]++
		}
	}
	return usage
}

func pvPoolsList(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		filter := db.ProxyPoolFilter{}
		switch q.Get("isActive") {
		case "true":
			t := true
			filter.IsActive = &t
		case "false":
			f := false
			filter.IsActive = &f
		}
		pools, err := deps.Store.GetProxyPools(filter)
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to fetch proxy pools")
			return
		}
		includeUsage := q.Get("includeUsage") == "true"
		usage := pvPoolUsageMap(deps)
		out := make([]any, 0, len(pools))
		for _, p := range pools {
			if includeUsage {
				cp := pvCloneMap(p)
				cp["boundConnectionCount"] = usage[pvStr(p, "id")]
				out = append(out, cp)
			} else {
				out = append(out, p)
			}
		}
		WriteJSON(w, http.StatusOK, map[string]any{"proxyPools": out})
	}
}

func pvPoolsCreate(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
		name := strings.TrimSpace(Str(body, "name"))
		proxyURL := strings.TrimSpace(Str(body, "proxyUrl"))
		if name == "" {
			Err(w, http.StatusBadRequest, "Name is required")
			return
		}
		if proxyURL == "" {
			Err(w, http.StatusBadRequest, "Proxy URL is required")
			return
		}
		isActive := true
		if pvHas(body, "isActive") {
			isActive = pvBool(body, "isActive")
		}
		pool, cerr := deps.Store.CreateProxyPool(db.Record{
			"name": name, "proxyUrl": proxyURL,
			"noProxy":     strings.TrimSpace(Str(body, "noProxy")),
			"isActive":    isActive,
			"strictProxy": pvBool(body, "strictProxy"),
			"type":        pvNormalizePoolType(Str(body, "type")),
		})
		if cerr != nil {
			Err(w, http.StatusInternalServerError, "Failed to create proxy pool")
			return
		}
		WriteJSON(w, http.StatusCreated, map[string]any{"proxyPool": pool})
	}
}

func pvPoolGet(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pool, err := deps.Store.GetProxyPoolByID(r.PathValue("id"))
		if err != nil || pool == nil {
			Err(w, http.StatusNotFound, "Proxy pool not found")
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"proxyPool": pool})
	}
}

func pvPoolUpdate(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		existing, err := deps.Store.GetProxyPoolByID(id)
		if err != nil || existing == nil {
			Err(w, http.StatusNotFound, "Proxy pool not found")
			return
		}
		body, berr := ReadBodyJSON(r)
		if berr != nil {
			Err(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
		updates := db.Record{}
		if pvHas(body, "name") {
			name := strings.TrimSpace(Str(body, "name"))
			if name == "" {
				Err(w, http.StatusBadRequest, "Name is required")
				return
			}
			updates["name"] = name
		}
		if pvHas(body, "proxyUrl") {
			proxyURL := strings.TrimSpace(Str(body, "proxyUrl"))
			if proxyURL == "" {
				Err(w, http.StatusBadRequest, "Proxy URL is required")
				return
			}
			updates["proxyUrl"] = proxyURL
		}
		if pvHas(body, "noProxy") {
			updates["noProxy"] = strings.TrimSpace(Str(body, "noProxy"))
		}
		if pvHas(body, "isActive") {
			updates["isActive"] = pvBool(body, "isActive")
		}
		if pvHas(body, "strictProxy") {
			updates["strictProxy"] = pvBool(body, "strictProxy")
		}
		if pvHas(body, "type") {
			updates["type"] = pvNormalizePoolType(Str(body, "type"))
		}
		updated, uerr := deps.Store.UpdateProxyPool(id, updates)
		if uerr != nil || updated == nil {
			Err(w, http.StatusInternalServerError, "Failed to update proxy pool")
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"proxyPool": updated})
	}
}

func pvPoolDelete(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		existing, err := deps.Store.GetProxyPoolByID(id)
		if err != nil || existing == nil {
			Err(w, http.StatusNotFound, "Proxy pool not found")
			return
		}
		bound := pvPoolUsageMap(deps)[id]
		if bound > 0 {
			WriteJSON(w, http.StatusConflict, map[string]any{
				"error": "Proxy pool is currently in use", "boundConnectionCount": bound,
			})
			return
		}
		if _, derr := deps.Store.DeleteProxyPool(id); derr != nil {
			Err(w, http.StatusInternalServerError, "Failed to delete proxy pool")
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"success": true})
	}
}

func pvPoolTest(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		pool, err := deps.Store.GetProxyPoolByID(id)
		if err != nil || pool == nil {
			Err(w, http.StatusNotFound, "Proxy pool not found")
			return
		}
		var result map[string]any
		poolType := pvStrOr(pool, "type", "http")
		if poolType == "vercel" || poolType == "cloudflare" || poolType == "deno" || poolType == "netlify" {
			result = pvTestRelayURL(r.Context(), pvStr(pool, "proxyUrl"))
			if _, hasErr := result["error"]; hasErr {
				// testVercelRelay reports raw error text on transport failure.
				if msg := pvStr(result, "error"); strings.Contains(msg, "timed out") || strings.Contains(msg, "timeout") {
					result["error"] = "Relay test timed out"
				}
			}
		} else {
			result = pvTestProxyURL(r.Context(), pvStr(pool, "proxyUrl"), 8*time.Second)
		}
		ok, _ := result["ok"].(bool)
		now := pvNowISO()
		lastErr := pvStr(result, "error")
		if !ok && lastErr == "" {
			statusF, _ := pvNum(result, "status")
			lastErr = fmt.Sprintf("Proxy test failed with status %d", int(statusF))
		}
		update := db.Record{
			"testStatus":   map[bool]string{true: "active", false: "error"}[ok],
			"lastTestedAt": now,
			"isActive":     ok,
		}
		if ok {
			update["lastError"] = nil
		} else {
			update["lastError"] = lastErr
		}
		_, _ = deps.Store.UpdateProxyPool(id, update)
		var statusText any
		if st := pvStr(result, "statusText"); st != "" {
			statusText = st
		}
		var errVal any
		if e := pvStr(result, "error"); e != "" {
			errVal = e
		}
		elapsed, _ := pvNum(result, "elapsedMs")
		status, _ := pvNum(result, "status")
		WriteJSON(w, http.StatusOK, map[string]any{
			"ok": ok, "status": int(status), "statusText": statusText,
			"error": errVal, "elapsedMs": int64(elapsed), "testedAt": now,
		})
	}
}

// ---------- proxy-pool relay deploys ----------

// Relay source payloads are copied verbatim from the JS deploy routes.
const pvCloudflareRelayCode = `
export default {
  async fetch(request, env, ctx) {
    const target = request.headers.get("x-relay-target");
    const relayPath = request.headers.get("x-relay-path") || "/";
    
    if (!target) {
      return new Response(JSON.stringify({ error: "Missing x-relay-target header" }), {
        status: 400,
        headers: { "content-type": "application/json" },
      });
    }

    const targetUrl = target.replace(/\/$/, "") + relayPath;
    const newRequestInit = {
      method: request.method,
      headers: new Headers(request.headers),
    };

    if (request.method !== "GET" && request.method !== "HEAD") {
      newRequestInit.body = request.body;
      newRequestInit.duplex = "half";
    }

    newRequestInit.headers.delete("x-relay-target");
    newRequestInit.headers.delete("x-relay-path");
    newRequestInit.headers.delete("host");

    try {
      const response = await fetch(targetUrl, newRequestInit);
      return new Response(response.body, {
        status: response.status,
        headers: response.headers,
      });
    } catch (error) {
      return new Response(JSON.stringify({ error: error.message }), {
        status: 502,
        headers: { "content-type": "application/json" },
      });
    }
  },
};
`

const pvVercelRelayCode = `
export const config = { runtime: "edge" };

export default async function handler(req) {
  const target = req.headers.get("x-relay-target");
  const relayPath = req.headers.get("x-relay-path") || "/";
  if (!target) {
    return new Response(JSON.stringify({ error: "Missing x-relay-target header" }), {
      status: 400,
      headers: { "content-type": "application/json" },
    });
  }

  const targetUrl = target.replace(/\/$/, "") + relayPath;

  const rawHeaders = {};
  for (const [k, v] of req.headers.entries()) rawHeaders[k] = v;
  delete rawHeaders["x-relay-target"];
  delete rawHeaders["x-relay-path"];
  delete rawHeaders["host"];

  const response = await fetch(targetUrl, {
    method: req.method,
    headers: rawHeaders,
    body: req.method !== "GET" && req.method !== "HEAD" ? req.body : undefined,
    duplex: "half",
  });

  return new Response(response.body, {
    status: response.status,
    headers: response.headers,
  });
}
`

const pvDenoRelayCode = `Deno.serve(async (request) => {
  const target = request.headers.get("x-relay-target");
  const relayPath = request.headers.get("x-relay-path") || "/";

  if (!target) {
    return new Response(JSON.stringify({ error: "Missing x-relay-target header" }), {
      status: 400,
      headers: { "content-type": "application/json" },
    });
  }

  const targetUrl = target.replace(/\/$/, "") + relayPath;
  const newHeaders = new Headers(request.headers);
  newHeaders.delete("x-relay-target");
  newHeaders.delete("x-relay-path");
  newHeaders.delete("host");

  const init = {
    method: request.method,
    headers: newHeaders,
  };

  if (request.method !== "GET" && request.method !== "HEAD") {
    init.body = request.body;
    init.duplex = "half";
  }

  try {
    const response = await fetch(targetUrl, init);
    return new Response(response.body, {
      status: response.status,
      headers: response.headers,
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 502,
      headers: { "content-type": "application/json" },
    });
  }
});`

func pvCreateRelayPool(deps Deps, name, deployURL, typ string) (db.Record, error) {
	return deps.Store.CreateProxyPool(db.Record{
		"name": name, "proxyUrl": deployURL, "type": typ,
		"noProxy": "", "isActive": true, "strictProxy": false,
	})
}

func pvDeployFail(w http.ResponseWriter, err error) {
	msg := pvErrText(err)
	if msg == "" {
		msg = "Deploy failed"
	}
	Err(w, http.StatusInternalServerError, msg)
}

func pvPoolDeployCloudflare(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
		accountID := strings.TrimSpace(Str(body, "accountId"))
		apiToken := strings.TrimSpace(Str(body, "apiToken"))
		projectName := strings.TrimSpace(Str(body, "projectName"))
		if projectName == "" {
			projectName = "relay-" + pvBase36Millis()
		}
		if accountID == "" || apiToken == "" {
			Err(w, http.StatusBadRequest, "Cloudflare Account ID and API Token are required")
			return
		}
		scriptURL := "https://api.cloudflare.com/client/v4/accounts/" + accountID + "/workers/scripts/" + projectName
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fw, _ := mw.CreatePart(map[string][]string{
			"Content-Disposition": {`form-data; name="index.js"; filename="index.js"`},
			"Content-Type":        {"application/javascript+module"},
		})
		_, _ = fw.Write([]byte(pvCloudflareRelayCode))
		mw2, _ := mw.CreatePart(map[string][]string{
			"Content-Disposition": {`form-data; name="metadata"; filename="metadata.json"`},
			"Content-Type":        {"application/json"},
		})
		meta, _ := json.Marshal(map[string]any{
			"main_module": "index.js", "compatibility_date": "2024-03-20",
			"observability": map[string]any{"enabled": true},
		})
		_, _ = mw2.Write(meta)
		_ = mw.Close()
		uploadRes, ferr := pvFetch(ctx, "PUT", scriptURL, map[string]string{
			"Authorization": "Bearer " + apiToken, "Content-Type": mw.FormDataContentType(),
		}, buf.Bytes(), 0, "")
		if ferr != nil {
			pvDeployFail(w, ferr)
			return
		}
		if !uploadRes.OK {
			errData := uploadRes.JSONMap()
			msg := "Failed to upload Worker to Cloudflare"
			if errs, ok := errData["errors"].([]any); ok && len(errs) > 0 {
				if e0, ok := errs[0].(map[string]any); ok {
					msg = pvStrOr(e0, "message", msg)
				}
			}
			Err(w, uploadRes.Status, msg)
			return
		}
		// Enable workers.dev subdomain (non-fatal).
		_, _ = pvFetchJSON(ctx, "POST", scriptURL+"/subdomain", map[string]string{"Authorization": "Bearer " + apiToken}, map[string]any{"enabled": true}, 0, "")
		subRes, serr := pvFetch(ctx, "GET", "https://api.cloudflare.com/client/v4/accounts/"+accountID+"/workers/subdomain", map[string]string{
			"Authorization": "Bearer " + apiToken, "Content-Type": "application/json",
		}, nil, 0, "")
		deployURL := ""
		if serr == nil && subRes.OK {
			data := subRes.JSONMap()
			if result := pvMap(data, "result"); result != nil {
				if sub := pvStr(result, "subdomain"); sub != "" {
					deployURL = "https://" + projectName + "." + sub + ".workers.dev"
				}
			}
		}
		if deployURL == "" {
			Err(w, http.StatusBadRequest, "Worker deployed but failed to retrieve workers.dev subdomain. Make sure you have setup a workers.dev subdomain in Cloudflare Dashboard.")
			return
		}
		pool, cerr := pvCreateRelayPool(deps, projectName, deployURL, "cloudflare")
		if cerr != nil {
			pvDeployFail(w, cerr)
			return
		}
		WriteJSON(w, http.StatusCreated, map[string]any{"proxyPool": pool, "deployUrl": deployURL})
	}
}

func pvPoolDeployVercel(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
		vercelToken := Str(body, "vercelToken")
		projectName := strings.TrimSpace(Str(body, "projectName"))
		if projectName == "" {
			projectName = "relay-" + pvBase36Millis()
		}
		if vercelToken == "" {
			Err(w, http.StatusBadRequest, "Vercel API token is required")
			return
		}
		pkgJSON, _ := json.Marshal(map[string]any{"name": projectName, "version": "1.0.0"})
		vercelJSON, _ := json.Marshal(map[string]any{
			"rewrites": []any{map[string]any{"source": "/(.*)", "destination": "/api/relay"}},
		})
		deployRes, ferr := pvFetchJSON(ctx, "POST", "https://api.vercel.com/v13/deployments", map[string]string{
			"Authorization": "Bearer " + vercelToken,
		}, map[string]any{
			"name": projectName,
			"files": []any{
				map[string]any{"file": "api/relay.js", "data": pvVercelRelayCode},
				map[string]any{"file": "package.json", "data": string(pkgJSON)},
				map[string]any{"file": "vercel.json", "data": string(vercelJSON)},
			},
			"projectSettings": map[string]any{"framework": nil},
			"target":          "production",
		}, 0, "")
		if ferr != nil {
			pvDeployFail(w, ferr)
			return
		}
		if !deployRes.OK {
			errData := deployRes.JSONMap()
			msg := pvStr(pvMap(errData, "error"), "message")
			if msg == "" {
				msg = "Failed to create Vercel deployment"
			}
			Err(w, deployRes.Status, msg)
			return
		}
		deployment := deployRes.JSONMap()
		deploymentID := pvStr(deployment, "id")
		if deploymentID == "" {
			deploymentID = pvStr(deployment, "uid")
		}
		projectID := pvStr(deployment, "projectId")
		if projectID == "" {
			projectID = projectName
		}
		// Disable deployment protection (result ignored, like JS).
		_, _ = pvFetchJSON(ctx, "PATCH", "https://api.vercel.com/v9/projects/"+projectID, map[string]string{
			"Authorization": "Bearer " + vercelToken,
		}, map[string]any{"ssoProtection": nil}, 0, "")
		// Poll until ready (3s interval, 120s budget).
		var ready map[string]any
		deadline := time.Now().Add(120 * time.Second)
		for {
			res, perr := pvFetch(ctx, "GET", "https://api.vercel.com/v13/deployments/"+deploymentID, map[string]string{
				"Authorization": "Bearer " + vercelToken,
			}, nil, 0, "")
			if perr != nil {
				pvDeployFail(w, perr)
				return
			}
			ready = res.JSONMap()
			state := pvStr(ready, "readyState")
			if state == "READY" {
				break
			}
			if state == "ERROR" || state == "CANCELED" {
				Err(w, http.StatusInternalServerError, "Deployment failed: "+state)
				return
			}
			if time.Now().After(deadline) {
				Err(w, http.StatusInternalServerError, "Deployment timed out")
				return
			}
			time.Sleep(3 * time.Second)
		}
		deployURL := "https://" + pvStr(ready, "url")
		pool, cerr := pvCreateRelayPool(deps, projectName, deployURL, "vercel")
		if cerr != nil {
			pvDeployFail(w, cerr)
			return
		}
		WriteJSON(w, http.StatusCreated, map[string]any{"proxyPool": pool, "deployUrl": deployURL})
	}
}

func pvPoolDeployDeno(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
		denoToken := strings.TrimSpace(Str(body, "denoToken"))
		orgDomain := strings.TrimSpace(Str(body, "orgDomain"))
		projectName := strings.TrimSpace(Str(body, "projectName"))
		if projectName == "" {
			projectName = "relay-" + pvBase36Millis()
		}
		if orgDomain == "" {
			Err(w, http.StatusBadRequest, "Organization domain is required")
			return
		}
		if denoToken == "" {
			Err(w, http.StatusBadRequest, "Deno Deploy API token is required")
			return
		}
		const denoAPI = "https://api.deno.com/v2"
		headers := map[string]string{"Authorization": "Bearer " + denoToken}
		deleteApp := func(appID string) {
			_, _ = pvFetch(ctx, "DELETE", denoAPI+"/apps/"+appID, map[string]string{"Authorization": "Bearer " + denoToken}, nil, 0, "")
		}
		createRes, ferr := pvFetchJSON(ctx, "POST", denoAPI+"/apps", headers, map[string]any{
			"slug":   projectName,
			"labels": map[string]any{"custom.kind": "proxygo-relay"},
			"config": map[string]any{
				"install": "deno install",
				"runtime": map[string]any{"type": "dynamic", "entrypoint": "main.ts"},
			},
		}, 0, "")
		if ferr != nil {
			pvDeployFail(w, ferr)
			return
		}
		if !createRes.OK {
			if createRes.Status == 409 {
				Err(w, http.StatusConflict, fmt.Sprintf("App %q already exists. Choose a different name.", projectName))
				return
			}
			Err(w, createRes.Status, fmt.Sprintf("Failed to create app (%d): %s", createRes.Status, createRes.Text()))
			return
		}
		app := createRes.JSONMap()
		appID := pvStr(app, "id")
		deployRes, derr := pvFetchJSON(ctx, "POST", denoAPI+"/apps/"+appID+"/deploy", headers, map[string]any{
			"assets": map[string]any{
				"main.ts": map[string]any{"kind": "file", "content": pvDenoRelayCode, "encoding": "utf-8"},
			},
		}, 0, "")
		if derr != nil {
			pvDeployFail(w, derr)
			return
		}
		if !deployRes.OK {
			deleteApp(appID)
			Err(w, deployRes.Status, fmt.Sprintf("Deploy failed (%d): %s", deployRes.Status, deployRes.Text()))
			return
		}
		revision := deployRes.JSONMap()
		revisionID := pvStr(revision, "id")
		status := pvStr(revision, "status")
		attempts := 0
		for status == "queued" || status == "building" {
			if attempts >= 30 {
				Err(w, http.StatusInternalServerError, "Deploy timed out after 60 seconds")
				return
			}
			time.Sleep(2 * time.Second)
			statusRes, serr := pvFetch(ctx, "GET", denoAPI+"/revisions/"+revisionID, map[string]string{"Authorization": "Bearer " + denoToken}, nil, 0, "")
			if serr != nil || !statusRes.OK {
				break
			}
			status = pvStr(statusRes.JSONMap(), "status")
			attempts++
		}
		if status != "succeeded" {
			deleteApp(appID)
			Err(w, http.StatusInternalServerError, "Deploy failed with status: "+status)
			return
		}
		orgSlug := strings.Split(orgDomain, ".")[0]
		deployURL := "https://" + projectName + "." + orgSlug + ".deno.net"
		pool, cerr := pvCreateRelayPool(deps, projectName, deployURL, "deno")
		if cerr != nil {
			pvDeployFail(w, cerr)
			return
		}
		WriteJSON(w, http.StatusCreated, map[string]any{"proxyPool": pool, "deployUrl": deployURL})
	}
}

const pvNetlifyRelayCode = `exports.handler = async (event) => {
  const headers = {};
  for (const [k, v] of Object.entries(event.headers || {})) {
    headers[k.toLowerCase()] = v;
  }

  const target = headers["x-relay-target"];
  const relayPath = headers["x-relay-path"] || "/";

  if (!target) {
    return {
      statusCode: 400,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ error: "Missing x-relay-target header" }),
    };
  }

  const targetUrl = target.replace(/\/$/, "") + relayPath;
  const forwardHeaders = { ...event.headers };
  for (const k of Object.keys(forwardHeaders)) {
    const lower = k.toLowerCase();
    if (lower === "x-relay-target" || lower === "x-relay-path" || lower === "host") {
      delete forwardHeaders[k];
    }
  }

  try {
    const upstream = await fetch(targetUrl, {
      method: event.httpMethod,
      headers: forwardHeaders,
      body: event.httpMethod !== "GET" && event.httpMethod !== "HEAD" && event.body
        ? event.isBase64Encoded
          ? Buffer.from(event.body, "base64")
          : event.body
        : undefined,
    });
    // Lambda response body must be a string: returning the stream object
    // fails with cannot-unmarshal-object-into-Go-struct-field (live 502).
    // So buffer here: text for API payloads (JSON/SSE), base64 for binary.
    // Tradeoff vs the other relays: SSE arrives buffered, stays valid SSE.
    const responseHeaders = {};
    upstream.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });
    const contentType = upstream.headers.get("content-type") || "";
    const isText = new RegExp("^(text/|[^;]*json|[^;]*event-stream|[^;]*javascript|[^;]*xml|[^;]*urlencoded)", "i").test(contentType);
    const rawBody = await upstream.arrayBuffer();
    const responseBody = isText
      ? Buffer.from(rawBody).toString("utf8")
      : Buffer.from(rawBody).toString("base64");
    return {
      statusCode: upstream.status,
      headers: responseHeaders,
      body: responseBody,
      isBase64Encoded: !isText,
    };
  } catch (error) {
    return {
      statusCode: 502,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ error: error.message || "Relay fetch failed" }),
    };
  }
};
`

const pvNetlifyIndexHTML = "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>ProxyGo Relay</title></head>\n<body><p>ProxyGo relay function lives at <code>/.netlify/functions/relay</code>.</p></body></html>\n"

var pvNetlifyNameRe = regexp.MustCompile(`[^a-z0-9-]`)
var pvNetlifyDashRe = regexp.MustCompile(`-+`)

func pvSanitizeNetlifyName(raw string) string {
	name := strings.TrimSpace(strings.ToLower(raw))
	if name == "" {
		return "relay-" + pvBase36Millis()
	}
	cleaned := pvNetlifyDashRe.ReplaceAllString(pvNetlifyNameRe.ReplaceAllString(name, "-"), "-")
	cleaned = strings.Trim(cleaned, "-")
	if cleaned == "" {
		return "relay-" + pvBase36Millis()
	}
	return cleaned
}

// pvBuildStoredZip builds a stored (uncompressed) single-entry zip, the
// bundle shape Netlify digest deploys expect for runtime=js functions.
func pvBuildStoredZip(name string, content []byte) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	hdr := &zip.FileHeader{Name: name, Method: zip.Store}
	fw, err := zw.CreateHeader(hdr)
	if err == nil {
		_, _ = fw.Write(content)
	}
	_ = zw.Close()
	return buf.Bytes()
}

func pvNetlifyReadError(res *pvFetchResult, fallback string) string {
	data := res.JSONMap()
	if msg := pvStr(data, "message"); msg != "" {
		return msg
	}
	if msg := pvStr(data, "error"); msg != "" {
		return msg
	}
	return fallback
}

func pvPoolDeployNetlify(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
		token := pvStr(body, "netlifyToken")
		if s, ok := body["netlifyToken"].(string); ok {
			token = strings.TrimSpace(s)
		}
		rawName := pvStr(body, "projectName")
		if !pvHas(body, "projectName") {
			rawName = pvStr(body, "siteName")
		}
		siteName := pvSanitizeNetlifyName(rawName)
		if token == "" {
			Err(w, http.StatusBadRequest, "Netlify API token is required")
			return
		}
		const netlifyAPI = "https://api.netlify.com/api/v1"
		authHeaders := map[string]string{"Authorization": "Bearer " + token, "User-Agent": "ProxyGo"}
		jsonHeaders := map[string]string{"Authorization": "Bearer " + token, "User-Agent": "ProxyGo", "Content-Type": "application/json"}

		siteRes, ferr := pvFetchJSON(ctx, "POST", netlifyAPI+"/sites", jsonHeaders, map[string]any{"name": siteName}, 0, "")
		if ferr != nil {
			pvDeployFail(w, ferr)
			return
		}
		if !siteRes.OK {
			message := pvNetlifyReadError(siteRes, "Failed to create Netlify site")
			status := siteRes.Status
			hint := ""
			if status == 422 {
				status = 409
				hint = fmt.Sprintf(" Site name %q is taken — choose a different name.", siteName)
			}
			Err(w, status, message+"."+hint)
			return
		}
		site := siteRes.JSONMap()
		siteID := pvStr(site, "id")
		if siteID == "" {
			siteID = pvStr(site, "site_id")
		}
		siteURL := pvStr(site, "ssl_url")
		if siteURL == "" {
			siteURL = pvStr(site, "url")
		}
		if siteID == "" || siteURL == "" {
			Err(w, http.StatusBadGateway, "Netlify site created but no site URL returned")
			return
		}
		zipBytes := pvBuildStoredZip("relay.js", []byte(pvNetlifyRelayCode))
		zipSum := sha256.Sum256(zipBytes)
		zipSHA := hex.EncodeToString(zipSum[:])
		indexSum := sha1.Sum([]byte(pvNetlifyIndexHTML))
		indexSHA := hex.EncodeToString(indexSum[:])

		deployRes, derr := pvFetchJSON(ctx, "POST", netlifyAPI+"/sites/"+siteID+"/deploys", jsonHeaders, map[string]any{
			"files":     map[string]any{"/index.html": indexSHA},
			"functions": map[string]any{"relay": zipSHA},
		}, 0, "")
		if derr != nil {
			pvDeployFail(w, derr)
			return
		}
		if !deployRes.OK {
			Err(w, deployRes.Status, pvNetlifyReadError(deployRes, "Failed to create Netlify deploy"))
			return
		}
		deploy := deployRes.JSONMap()
		deployID := pvStr(deploy, "id")
		if deployID == "" {
			Err(w, http.StatusBadGateway, "Netlify deploy created but no deploy ID returned")
			return
		}
		requiredFiles := map[string]bool{}
		for _, v := range pvSlice(deploy, "required") {
			if s, ok := v.(string); ok {
				requiredFiles[s] = true
			}
		}
		requiredFns := map[string]bool{}
		for _, v := range pvSlice(deploy, "required_functions") {
			if s, ok := v.(string); ok {
				requiredFns[s] = true
			}
		}
		octetHeaders := map[string]string{"Authorization": "Bearer " + token, "User-Agent": "ProxyGo", "Content-Type": "application/octet-stream"}
		if requiredFiles[indexSHA] {
			fileRes, uerr := pvFetch(ctx, "PUT", netlifyAPI+"/deploys/"+deployID+"/files/index.html", octetHeaders, []byte(pvNetlifyIndexHTML), 0, "")
			if uerr != nil {
				pvDeployFail(w, uerr)
				return
			}
			if !fileRes.OK {
				Err(w, fileRes.Status, pvNetlifyReadError(fileRes, "Failed to upload site file to Netlify"))
				return
			}
		}
		if requiredFns[zipSHA] {
			fnRes, uerr := pvFetch(ctx, "PUT", netlifyAPI+"/deploys/"+deployID+"/functions/relay?runtime=js", octetHeaders, zipBytes, 0, "")
			if uerr != nil {
				pvDeployFail(w, uerr)
				return
			}
			if !fnRes.OK {
				Err(w, fnRes.Status, pvNetlifyReadError(fnRes, "Failed to upload relay function to Netlify"))
				return
			}
		}
		// Poll until ready (3s interval, 120s budget).
		deadline := time.Now().Add(120 * time.Second)
		for {
			pollRes, perr := pvFetch(ctx, "GET", netlifyAPI+"/deploys/"+deployID, authHeaders, nil, 0, "")
			if perr != nil {
				pvDeployFail(w, perr)
				return
			}
			data := pollRes.JSONMap()
			state := pvStr(data, "state")
			if state == "ready" {
				break
			}
			if state == "error" {
				msg := pvStr(data, "error_message")
				if msg == "" {
					msg = "Netlify deploy failed"
				}
				Err(w, http.StatusInternalServerError, msg)
				return
			}
			if time.Now().After(deadline) {
				Err(w, http.StatusInternalServerError, "Netlify deploy timed out")
				return
			}
			time.Sleep(3 * time.Second)
		}
		relayURL := strings.TrimSuffix(siteURL, "/") + "/.netlify/functions/relay"
		pool, cerr := pvCreateRelayPool(deps, siteName, relayURL, "netlify")
		if cerr != nil {
			pvDeployFail(w, cerr)
			return
		}
		WriteJSON(w, http.StatusCreated, map[string]any{"proxyPool": pool, "deployUrl": relayURL})
	}
}
