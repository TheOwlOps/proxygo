// ops.go — Team H registrar: usage, translator, media-providers (TTS
// voices), MCP-over-SSE bridge, headroom, pxpipe and tunnel APIs.
//
// Faithful port of the Next.js routes under src/app/api/{usage,
// translator,media-providers,mcp,headroom,pxpipe,tunnel}, backed by
// internal/tunnel (src/lib/tunnel) and internal/mitm (password cache for
// the tailscale routes).
//
// Documented port gaps (details at each site):
//   - Usage fetchers: claude, codex, github, groq are fully ported
//     (incl. Claude reset grants + Codex reset credits). The remaining
//     JS handlers (gemini-cli, antigravity, kiro, qoder, iflow, ollama,
//     glm(-cn), minimax(-cn), minimax-code(-global), vercel-ai-gateway,
//     codebuddy-cn/intl, grok-cli, kimi, opencode-go/zen, deepseek, zed,
//     xiaomi-mimo, commandcode, cursor) return 501 with a clear error —
//     they are each bespoke signed/scraped protocols (open-sse/services/
//     usage/*.js, ~3.3k LOC) and were not ported in this phase; unknown
//     providers keep the JS shape {message:"Usage API not implemented…"}.
//   - Connection proxy options (connectionProxy/vercel relay) from the
//     JS routes are not applied to usage/refresh calls (direct fetch).
//   - pxpipe: the JS loads pxpipe-proxy as an in-process library,
//     which a Go binary cannot do. The package also ships a standalone
//     server entry (bin/cli.js → dist/node.js), so the Go port
//     supervises that as a child process via internal/pxpipe
//     (pid/state file, PXPIPE_LOG pointed at the same events.jsonl
//     stats/logs read). install/events/stats/logs are filesystem-real;
//     health runs the JS self-test in a one-shot node process. The Go
//     chat pipeline does not route through the child proxy (that is
//     the token-saver wiring, not this package).
//   - Translator console-logs: the JS patches console.* process-wide;
//     the Go port keeps its own ring buffer fed via AddConsoleLog()
//     (exported for other packages) — it does not capture Go's log pkg.
//   - Translator logs dir: JS uses <cwd>/logs/translator; the Go port
//     deliberately uses DATA_DIR/logs/translator so the packaged
//     binary doesn't write into the install directory.
package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"9router-go/internal/chatcore"
	"9router-go/internal/db"
	"9router-go/internal/executors"
	"9router-go/internal/mitm"
	"9router-go/internal/providers"
	"9router-go/internal/pxpipe"
	"9router-go/internal/translator"
	"9router-go/internal/tunnel"
)

// RegisterOps mounts every Team H route.
func RegisterOps(mux *http.ServeMux, deps Deps) {
	w := func(h http.HandlerFunc) http.HandlerFunc { return Wrap(deps, h) }

	// MITM hooks: settings-backed alias map + sudo password cache are
	// shared by the tunnel routes (tailscale-check/install read the
	// cached password exactly like the JS routes do).
	mitm.InitDBHooks(
		func() (map[string]any, error) {
			s, err := deps.Store.GetSettings()
			return map[string]any(s), err
		},
		func(updates map[string]any) error {
			_, err := deps.Store.UpdateSettings(db.Record(updates))
			return err
		},
		func(tool string) (map[string]string, bool) {
			rec, err := deps.Store.GetMitmAlias(tool)
			if err != nil || rec == nil {
				return nil, false
			}
			out := map[string]string{}
			for k, v := range rec {
				if s, ok := v.(string); ok {
					out[k] = s
				}
			}
			return out, true
		},
	)
	// CLI-tools MITM hooks (Team I's clitools.go vars) → internal/mitm
	// (parent wiring). MitmWriteAliasForTool stays nil: the route then
	// performs the same aliases.json merge-write locally, as in JS.
	MitmGetStatus = func() MitmStatus {
		m := mitm.GetMitmStatus()
		st := MitmStatus{DNSStatus: map[string]bool{}}
		st.Running, _ = m["running"].(bool)
		if p, ok := m["pid"].(int); ok {
			st.PID = p
		}
		st.CertExists, _ = m["certExists"].(bool)
		st.CertTrusted, _ = m["certTrusted"].(bool)
		if dns, ok := m["dnsStatus"].(map[string]bool); ok {
			st.DNSStatus = dns
		}
		st.HasCachedPassword = mitm.GetCachedPassword() != ""
		return st
	}
	MitmStartServer = func(apiKey, sudoPassword string, forceKillPort443 bool) error {
		_, err := mitm.StartServer(apiKey, sudoPassword, forceKillPort443)
		var pbe *mitm.PortBusyError
		if errors.As(err, &pbe) {
			return fmt.Errorf("PORT_443_BUSY: %s (PID %d)", pbe.Name, pbe.PID)
		}
		return err
	}
	MitmStopServer = mitm.StopServer
	MitmEnableToolDNS = func(tool, sudoPassword string) error {
		_, err := mitm.EnableToolDNS(tool, sudoPassword)
		return err
	}
	MitmDisableToolDNS = func(tool, sudoPassword string) error {
		_, err := mitm.DisableToolDNS(tool, sudoPassword)
		return err
	}
	MitmTrustCert = func(sudoPassword string) error {
		_, err := mitm.TrustCert(sudoPassword)
		return err
	}
	MitmGetCachedPassword = func() (string, bool) {
		p := mitm.GetCachedPassword()
		return p, p != ""
	}
	MitmSetCachedPassword = mitm.SetCachedPassword
	MitmLoadEncryptedPassword = func() string {
		p, err := mitm.LoadEncryptedPassword()
		if err != nil {
			return ""
		}
		return p
	}
	MitmIsSudoPasswordRequired = mitm.IsSudoPasswordRequired

	tunnel.PasswordProvider = func() string {
		if p := mitm.GetCachedPassword(); p != "" {
			return p
		}
		p, _ := mitm.LoadEncryptedPassword()
		return p
	}

	// usage/*
	mux.HandleFunc("GET /api/usage/stats", w(opUsageStats(deps)))
	mux.HandleFunc("GET /api/usage/chart", w(opUsageChart(deps)))
	mux.HandleFunc("GET /api/usage/history", w(opUsageHistory(deps)))
	mux.HandleFunc("GET /api/usage/providers", w(opUsageProviders(deps)))
	mux.HandleFunc("GET /api/usage/logs", w(opUsageLogs(deps)))
	mux.HandleFunc("GET /api/usage/request-logs", w(opUsageLogs(deps)))
	mux.HandleFunc("GET /api/usage/request-details", w(opUsageRequestDetails(deps)))
	mux.HandleFunc("GET /api/usage/stream", w(opUsageStream(deps)))
	mux.HandleFunc("GET /api/usage/{connectionId}", w(opUsageConnection(deps)))
	mux.HandleFunc("POST /api/usage/{connectionId}/claude-reset", w(opUsageClaudeReset(deps)))
	mux.HandleFunc("GET /api/usage/{connectionId}/codex-reset-credits", w(opUsageCodexResetCreditsGet(deps)))
	mux.HandleFunc("POST /api/usage/{connectionId}/codex-reset-credits", w(opUsageCodexResetCreditsPost(deps)))

	// translator/*
	mux.HandleFunc("GET /api/translator/load", w(opTranslatorLoad(deps)))
	mux.HandleFunc("POST /api/translator/save", w(opTranslatorSave(deps)))
	mux.HandleFunc("POST /api/translator/translate", w(opTranslatorTranslate(deps)))
	mux.HandleFunc("POST /api/translator/send", w(opTranslatorSend(deps)))
	mux.HandleFunc("GET /api/translator/console-logs", w(opTranslatorConsoleLogsGet(deps)))
	mux.HandleFunc("DELETE /api/translator/console-logs", w(opTranslatorConsoleLogsDelete(deps)))
	mux.HandleFunc("GET /api/translator/console-logs/stream", w(opTranslatorConsoleLogsStream(deps)))

	// media-providers/*
	mux.HandleFunc("GET /api/media-providers/tts/voices", w(opVoicesGeneric(deps)))
	mux.HandleFunc("GET /api/media-providers/tts/deepgram/voices", w(opVoicesDeepgram(deps)))
	mux.HandleFunc("GET /api/media-providers/tts/elevenlabs/voices", w(opVoicesElevenlabs(deps)))
	mux.HandleFunc("GET /api/media-providers/tts/inworld/voices", w(opVoicesInworld(deps)))
	mux.HandleFunc("GET /api/media-providers/tts/minimax/voices", w(opVoicesMinimax(deps)))

	// mcp/*
	mux.HandleFunc("GET /api/mcp/{plugin}/sse", w(opMcpSSE(deps)))
	mux.HandleFunc("POST /api/mcp/{plugin}/message", w(opMcpMessage(deps)))

	// tunnel/*
	mux.HandleFunc("GET /api/tunnel/status", w(opTunnelStatus(deps)))
	mux.HandleFunc("POST /api/tunnel/enable", w(opTunnelEnable(deps)))
	mux.HandleFunc("POST /api/tunnel/disable", w(opTunnelDisable(deps)))
	mux.HandleFunc("GET /api/tunnel/tailscale-check", w(opTailscaleCheck(deps)))
	mux.HandleFunc("POST /api/tunnel/tailscale-enable", w(opTailscaleEnable(deps)))
	mux.HandleFunc("POST /api/tunnel/tailscale-disable", w(opTailscaleDisable(deps)))
	mux.HandleFunc("POST /api/tunnel/tailscale-install", w(opTailscaleInstall(deps)))

	// headroom/*
	mux.HandleFunc("GET /api/headroom/status", w(opHeadroomStatus(deps)))
	mux.HandleFunc("POST /api/headroom/start", w(opHeadroomStart(deps)))
	mux.HandleFunc("POST /api/headroom/stop", w(opHeadroomStop(deps)))
	mux.HandleFunc("POST /api/headroom/restart", w(opHeadroomRestart(deps)))
	mux.HandleFunc("GET /api/headroom/extras", w(opHeadroomExtrasGet(deps)))
	mux.HandleFunc("POST /api/headroom/extras", w(opHeadroomExtrasPost(deps)))
	mux.HandleFunc("DELETE /api/headroom/extras", w(opHeadroomExtrasDelete(deps)))
	mux.HandleFunc("/api/headroom/proxy/{path...}", w(opHeadroomProxy(deps)))

	// pxpipe/*
	mux.HandleFunc("GET /api/pxpipe/status", w(opPxpipeStatus(deps)))
	mux.HandleFunc("GET /api/pxpipe/health", w(opPxpipeHealth(deps)))
	mux.HandleFunc("POST /api/pxpipe/health", w(opPxpipeHealth(deps)))
	mux.HandleFunc("POST /api/pxpipe/start", w(opPxpipeStart(deps)))
	mux.HandleFunc("POST /api/pxpipe/stop", w(opPxpipeStop(deps)))
	mux.HandleFunc("POST /api/pxpipe/restart", w(opPxpipeRestart(deps)))
	mux.HandleFunc("POST /api/pxpipe/install", w(opPxpipeInstall(deps)))
	mux.HandleFunc("GET /api/pxpipe/stats", w(opPxpipeStats(deps)))
	mux.HandleFunc("GET /api/pxpipe/logs", w(opPxpipeLogs(deps)))
}

// ---------- shared helpers ("op" prefix; package api is shared) ----------

func opStr(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	if s, ok := m[k].(string); ok {
		return s
	}
	return ""
}

func opNum(m map[string]any, k string) float64 {
	if m == nil {
		return 0
	}
	switch v := m[k].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case json.Number:
		f, _ := v.Float64()
		return f
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(v), 64)
		return f
	}
	return 0
}

func opBool(m map[string]any, k string) bool {
	if m == nil {
		return false
	}
	b, _ := m[k].(bool)
	return b
}

func opMap(m map[string]any, k string) map[string]any {
	if m == nil {
		return nil
	}
	if v, ok := m[k].(map[string]any); ok {
		return v
	}
	return nil
}

func opStrSlice(m map[string]any, k string) []string {
	var out []string
	if arr, ok := m[k].([]any); ok {
		for _, v := range arr {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// opFinite ports shared.js toFiniteNumber.
func opFinite(v any, fallback float64) float64 {
	switch n := v.(type) {
	case float64:
		if !math.IsNaN(n) && !math.IsInf(n, 0) {
			return n
		}
	case string:
		if strings.TrimSpace(n) != "" {
			if f, err := strconv.ParseFloat(strings.TrimSpace(n), 64); err == nil {
				return f
			}
		}
	}
	return fallback
}

// opParseResetTime ports shared.js parseResetTime → ISO string or nil.
func opParseResetTime(v any) any {
	if v == nil {
		return nil
	}
	iso := func(t time.Time) any { return t.UTC().Format("2006-01-02T15:04:05.000Z") }
	switch n := v.(type) {
	case float64:
		if n < 1e12 {
			return iso(time.UnixMilli(int64(n * 1000)))
		}
		return iso(time.UnixMilli(int64(n)))
	case string:
		if regexp.MustCompile(`^\d+$`).MatchString(n) {
			f, _ := strconv.ParseFloat(n, 64)
			if f < 1e12 {
				return iso(time.UnixMilli(int64(f * 1000)))
			}
			return iso(time.UnixMilli(int64(f)))
		}
		if t, err := time.Parse(time.RFC3339, n); err == nil {
			return iso(t)
		}
		if t, err := time.Parse("2006-01-02T15:04:05", n); err == nil {
			return iso(t)
		}
		return nil
	}
	return nil
}

// opToISO ports codex.js toIsoDate (accepts epoch s/ms or date string).
func opToISO(v any) any {
	if v == nil {
		return nil
	}
	switch n := v.(type) {
	case float64:
		if n < 1e12 {
			return time.UnixMilli(int64(n * 1000)).UTC().Format("2006-01-02T15:04:05.000Z")
		}
		return time.UnixMilli(int64(n)).UTC().Format("2006-01-02T15:04:05.000Z")
	case string:
		if t, err := time.Parse(time.RFC3339, n); err == nil {
			return t.UTC().Format("2006-01-02T15:04:05.000Z")
		}
		return nil
	}
	return nil
}

func opUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// opHTTPClient is the shared outbound client for provider APIs.
var opHTTPClient = &http.Client{Timeout: 30 * time.Second}

// opFetchJSON performs a request and decodes a JSON body (any shape).
func opFetchJSON(ctx context.Context, method, rawURL string, headers map[string]string, body []byte) (int, map[string]any, http.Header, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rdr)
	if err != nil {
		return 0, nil, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := opHTTPClient.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	var parsed map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &parsed)
	}
	return resp.StatusCode, parsed, resp.Header, nil
}

// opServerPort: the gateway's own port (env PORT, default 20128).
func opServerPort() int {
	if v := os.Getenv("PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 && p < 65536 {
			return p
		}
	}
	return 20128
}

// opProviderUsage returns registry transport.usage for a provider.
func opProviderUsage(providerID string) map[string]any {
	p, ok := providers.Get(providerID)
	if !ok {
		return nil
	}
	return opMap(opMap(p.Raw, "transport"), "usage")
}

// opProviderOAuth returns the registry oauth block for a provider.
func opProviderOAuth(providerID string) map[string]any {
	p, ok := providers.Get(providerID)
	if !ok {
		return nil
	}
	return opMap(p.Raw, "oauth")
}

// opUsageApikeyProviders: registry features.usageApikey (USAGE_APIKEY_PROVIDERS).
func opUsageApikeyProviders() map[string]bool {
	out := map[string]bool{}
	for _, p := range providers.All() {
		if opBool(opMap(p.Raw, "features"), "usageApikey") {
			out[p.ID] = true
		}
	}
	return out
}

// opBuildProviderInfo mirrors internal/app.buildProviderInfo (unexported
// there) for direct executor calls from the translator routes.
func opBuildProviderInfo(providerID string) *executors.ProviderInfo {
	p, ok := providers.Get(providerID)
	if !ok {
		return &executors.ProviderInfo{ID: providerID, Format: "openai"}
	}
	info := &executors.ProviderInfo{
		ID:          p.ID,
		BaseURL:     p.Transport.BaseURL,
		Format:      p.Transport.Format,
		URLSuffix:   p.Transport.URLSuffix,
		Headers:     p.Transport.Headers,
		ForceStream: p.Transport.ForceStream,
		NoAuth:      p.Category == "noauth",
		Raw:         p.Raw,
	}
	if info.Format == "" {
		info.Format = "openai"
	}
	traw := opMap(p.Raw, "transport")
	if list, ok := traw["baseUrls"].([]any); ok {
		for _, u := range list {
			if s, ok := u.(string); ok {
				info.BaseURLs = append(info.BaseURLs, s)
			}
		}
	}
	if authRaw := traw["auth"]; authRaw != nil {
		if b, err := json.Marshal(authRaw); err == nil {
			var spec executors.AuthSpec
			if json.Unmarshal(b, &spec) == nil {
				info.Auth = &spec
			}
		}
	}
	if q := opMap(traw, "quirks"); q != nil {
		info.Quirks = q
	}
	if oauth := opMap(p.Raw, "oauth"); oauth != nil {
		info.ClientID = opStr(oauth, "clientId")
		info.ClientSecret = opStr(oauth, "clientSecret")
		info.TokenURL = opStr(oauth, "tokenUrl")
	}
	return info
}

// opCredFromConnection builds an executors.Credential from a db
// connection record (mirrors the JS credentials object).
func opCredFromConnection(conn db.Record) executors.Credential {
	psd := opMap(conn, "providerSpecificData")
	cred := executors.Credential{
		ConnectionID: opStr(conn, "id"),
		APIKey:       opStr(conn, "apiKey"),
		AccessToken:  opStr(conn, "accessToken"),
		RefreshToken: opStr(conn, "refreshToken"),
		ProjectID:    opStr(conn, "projectId"),
		Specific:     psd,
	}
	if psd != nil {
		cred.CopilotToken = opStr(psd, "copilotToken")
		cred.BaseURL = opStr(psd, "baseUrl")
	}
	if exp := opStr(conn, "expiresAt"); exp != "" {
		if t, err := time.Parse(time.RFC3339, exp); err == nil {
			cred.ExpiresAt = t
		}
	} else if exp := opStr(conn, "tokenExpiresAt"); exp != "" {
		if t, err := time.Parse(time.RFC3339, exp); err == nil {
			cred.ExpiresAt = t
		}
	}
	return cred
}

// opRefreshConnection ports refreshAndUpdateCredentials (usage
// [connectionId]/route.js): ask the provider executor's Refresher for
// new credentials and persist the rotated fields. Returns the updated
// connection record. When refresh is impossible but an access token
// exists, the JS proceeds with the existing token — mirrored here.
func opRefreshConnection(ctx context.Context, deps Deps, conn db.Record, force bool) (db.Record, error) {
	if latest, err := deps.Store.GetProviderConnectionByID(opStr(conn, "id")); err == nil && latest != nil {
		conn = latest
	}
	provider := opStr(conn, "provider")
	refresher, ok := executors.For(provider).(executors.Refresher)
	if !ok {
		if opStr(conn, "accessToken") != "" {
			return conn, nil
		}
		return conn, errors.New("Failed to refresh credentials. Please re-authorize the connection.")
	}
	cred := opCredFromConnection(conn)
	newCred, err := refresher.RefreshCredentials(ctx, opBuildProviderInfo(provider), cred)
	if err != nil {
		if opStr(conn, "accessToken") != "" {
			return conn, nil
		}
		return conn, err
	}
	if newCred == nil {
		if opStr(conn, "accessToken") != "" {
			return conn, nil
		}
		return conn, errors.New("Failed to refresh credentials. Please re-authorize the connection.")
	}
	updates := db.Record{"updatedAt": time.Now().UTC().Format(time.RFC3339)}
	if newCred.AccessToken != "" {
		updates["accessToken"] = newCred.AccessToken
	}
	if newCred.RefreshToken != "" {
		updates["refreshToken"] = newCred.RefreshToken
	}
	if !newCred.ExpiresAt.IsZero() {
		updates["expiresAt"] = newCred.ExpiresAt.UTC().Format(time.RFC3339)
	}
	psdUpdates := map[string]any{}
	for k, v := range newCred.Specific {
		psdUpdates[k] = v
	}
	if newCred.CopilotToken != "" {
		psdUpdates["copilotToken"] = newCred.CopilotToken
	}
	if len(psdUpdates) > 0 {
		merged := map[string]any{}
		for k, v := range opMap(conn, "providerSpecificData") {
			merged[k] = v
		}
		for k, v := range psdUpdates {
			merged[k] = v
		}
		updates["providerSpecificData"] = merged
	}
	if _, err := deps.Store.UpdateProviderConnection(opStr(conn, "id"), updates); err != nil {
		return conn, err
	}
	updated := db.Record{}
	for k, v := range conn {
		updated[k] = v
	}
	for k, v := range updates {
		updated[k] = v
	}
	return updated, nil
}

// ---------- usage: db-backed routes ----------

var opValidPeriods = map[string]bool{
	"today": true, "24h": true, "7d": true, "30d": true, "60d": true, "all": true,
}

func opUsageStats(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		period := r.URL.Query().Get("period")
		if period == "" {
			period = "7d"
		}
		if !opValidPeriods[period] {
			Err(w, http.StatusBadRequest, "Invalid period")
			return
		}
		stats, err := deps.Store.GetUsageStats(period)
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to fetch usage stats")
			return
		}
		WriteJSON(w, http.StatusOK, stats)
	}
}

func opUsageChart(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		period := r.URL.Query().Get("period")
		if period == "" {
			period = "7d"
		}
		if !opValidPeriods[period] {
			Err(w, http.StatusBadRequest, "Invalid period")
			return
		}
		data, err := deps.Store.GetChartData(period)
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to fetch chart data")
			return
		}
		if data == nil {
			data = []db.Record{}
		}
		WriteJSON(w, http.StatusOK, data)
	}
}

func opUsageHistory(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stats, err := deps.Store.GetUsageStats("")
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to fetch usage stats")
			return
		}
		WriteJSON(w, http.StatusOK, stats)
	}
}

func opUsageProviders(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ids, err := deps.Store.GetDistinctProviders()
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to fetch providers")
			return
		}
		nodeNames := map[string]string{}
		if nodes, err := deps.Store.GetProviderNodes(db.NodeFilter{}); err == nil {
			for _, n := range nodes {
				if opStr(n, "id") != "" {
					nodeNames[opStr(n, "id")] = opStr(n, "name")
				}
			}
		}
		out := make([]db.Record, 0, len(ids))
		for _, id := range ids {
			name := id
			if n, ok := nodeNames[id]; ok && n != "" {
				name = n
			} else if p, ok := providers.Get(id); ok && p.Display.Name != "" {
				name = p.Display.Name
			}
			out = append(out, db.Record{"id": id, "name": name})
		}
		WriteJSON(w, http.StatusOK, db.Record{"providers": out})
	}
}

func opUsageLogs(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logs, err := deps.Store.GetRecentLogs(200)
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to fetch logs")
			return
		}
		if logs == nil {
			logs = []string{}
		}
		WriteJSON(w, http.StatusOK, logs)
	}
}

func opUsageRequestDetails(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		page := 1
		if v := q.Get("page"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				page = n
			}
		}
		pageSize := 20
		if v := q.Get("pageSize"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				pageSize = n
			}
		}
		if page < 1 {
			Err(w, http.StatusBadRequest, "Page must be >= 1")
			return
		}
		if pageSize < 1 || pageSize > 100 {
			Err(w, http.StatusBadRequest, "PageSize must be between 1 and 100")
			return
		}
		filter := db.RequestDetailsFilter{
			Provider:     q.Get("provider"),
			Model:        q.Get("model"),
			ConnectionID: q.Get("connectionId"),
			Status:       q.Get("status"),
			StartDate:    q.Get("startDate"),
			EndDate:      q.Get("endDate"),
			Page:         page,
			PageSize:     pageSize,
		}
		result, err := deps.Store.GetRequestDetails(filter)
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to fetch request details")
			return
		}
		// Redact conversation payloads (route.js): keep metadata only.
		details := make([]db.Record, 0, len(result.Details))
		for _, d := range result.Details {
			redacted := db.Record{}
			for k, v := range d {
				redacted[k] = v
			}
			for _, key := range []string{"request", "providerRequest", "providerResponse", "response"} {
				if _, ok := redacted[key]; ok {
					redacted[key] = db.Record{"redacted": true}
				}
			}
			details = append(details, redacted)
		}
		WriteJSON(w, http.StatusOK, db.Record{
			"details":    details,
			"pagination": result.Pagination,
		})
	}
}

// opUsageStream: SSE live stats. The JS subscribes to a statsEmitter;
// the Go db layer has no emitter, so this polls every 2s and pushes
// when the payload changes, with the same 25s `: ping` keepalive and
// the same merge of getActiveRequests() into the cached stats.
func opUsageStream(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			Err(w, http.StatusInternalServerError, "Streaming unsupported")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		fl.Flush()

		ctx := r.Context()
		var cached db.Record
		var lastSent string
		send := func(full bool) {
			if full || cached == nil {
				if stats, err := deps.Store.GetUsageStats(""); err == nil && stats != nil {
					cached = stats
				}
			}
			if cached == nil {
				return
			}
			payload := db.Record{}
			for k, v := range cached {
				payload[k] = v
			}
			if active, err := deps.Store.GetActiveRequests(); err == nil && active != nil {
				for _, k := range []string{"activeRequests", "recentRequests", "errorProvider"} {
					if v, ok := active[k]; ok {
						payload[k] = v
					}
				}
			}
			raw, _ := json.Marshal(payload)
			if string(raw) == lastSent {
				return
			}
			lastSent = string(raw)
			fmt.Fprintf(w, "data: %s\n\n", raw)
			fl.Flush()
		}
		send(true)
		poll := time.NewTicker(2 * time.Second)
		ping := time.NewTicker(25 * time.Second)
		defer poll.Stop()
		defer ping.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-poll.C:
				send(true)
			case <-ping.C:
				fmt.Fprintf(w, ": ping\n\n")
				fl.Flush()
			}
		}
	}
}

// ---------- usage: provider fetchers (open-sse/services/usage) ----------

var errOpUsageNotPorted = errors.New("usage fetcher not ported")

// opUsageHandlersKnown mirrors USAGE_HANDLERS keys in usage.js.
var opUsageHandlersKnown = map[string]bool{
	"github": true, "gemini-cli": true, "antigravity": true, "claude": true,
	"codex": true, "kiro": true, "qoder": true, "qoder-cn": true,
	"iflow": true, "ollama": true, "glm": true, "glm-cn": true,
	"minimax": true, "minimax-cn": true, "minimax-code": true,
	"minimax-code-global": true, "vercel-ai-gateway": true,
	"codebuddy-cn": true, "codebuddy-intl": true, "grok-cli": true,
	"kimi": true, "opencode-go": true, "opencode-zen": true,
	"deepseek": true, "groq": true, "zed": true, "xiaomi-mimo": true,
	"commandcode": true, "cursor": true,
}

// opUsagePluginFetcher is the signature Phase-3 plugin fetchers
// register with: the full connection record + force flag, exactly what
// getUsageForProvider's handlers receive in JS. Plugin fetchers live in
// their own files (usage_fetch_*.go) and register via init() so teams
// never edit this dispatch.
type opUsagePluginFetcher func(ctx context.Context, conn db.Record, force bool) (db.Record, error)

var opUsagePluginFetchers = map[string]opUsagePluginFetcher{}

func opRegisterUsageFetcher(provider string, fn opUsagePluginFetcher) {
	opUsagePluginFetchers[provider] = fn
}

// opFetchUsageForProvider ports getUsageForProvider's dispatch.
func opFetchUsageForProvider(ctx context.Context, conn db.Record, force bool) (db.Record, error) {
	provider := opStr(conn, "provider")
	switch provider {
	case "claude":
		return opClaudeUsage(ctx, opStr(conn, "accessToken"), force)
	case "codex":
		return opCodexUsage(ctx, opStr(conn, "accessToken"))
	case "github":
		return opGithubUsage(ctx, opStr(conn, "accessToken"))
	case "groq":
		return opGroqUsage(ctx, opStr(conn, "apiKey"))
	}
	if fn, ok := opUsagePluginFetchers[provider]; ok {
		return fn(ctx, conn, force)
	}
	if opUsageHandlersKnown[provider] {
		return nil, fmt.Errorf("%w for provider %s", errOpUsageNotPorted, provider)
	}
	return db.Record{"message": fmt.Sprintf("Usage API not implemented for %s", provider)}, nil
}

var opAuthExpiredPatterns = []string{"expired", "authentication", "unauthorized", "401", "re-authorize"}

func opIsAuthExpiredMessage(usage db.Record) bool {
	msg := strings.ToLower(opStr(usage, "message"))
	if msg == "" {
		return false
	}
	for _, p := range opAuthExpiredPatterns {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
}

func opUsageConnection(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		connectionID := r.PathValue("connectionId")
		force := r.URL.Query().Get("force") == "1"
		conn, err := deps.Store.GetProviderConnectionByID(connectionID)
		if err != nil || conn == nil {
			Err(w, http.StatusNotFound, "Connection not found")
			return
		}
		authType := opStr(conn, "authType")
		isOAuth := authType == "oauth"
		isApikeyAuth := authType == "apikey" || authType == "api_key"
		isApikeyEligible := isApikeyAuth && opUsageApikeyProviders()[opStr(conn, "provider")]
		if !isOAuth && !isApikeyEligible {
			WriteJSON(w, http.StatusOK, db.Record{"message": "Usage not available for this connection"})
			return
		}
		ctx := r.Context()
		if isOAuth {
			refreshed, rerr := opRefreshConnection(ctx, deps, conn, false)
			if rerr != nil {
				Err(w, http.StatusUnauthorized, "Credential refresh failed: "+rerr.Error())
				return
			}
			conn = refreshed
		}
		usage, ferr := opFetchUsageForProvider(ctx, conn, force)
		if ferr != nil {
			if errors.Is(ferr, errOpUsageNotPorted) {
				Err(w, http.StatusNotImplemented, ferr.Error())
				return
			}
			Err(w, http.StatusInternalServerError, ferr.Error())
			return
		}
		if isOAuth && opIsAuthExpiredMessage(usage) && opStr(conn, "refreshToken") != "" {
			if refreshed, rerr := opRefreshConnection(ctx, deps, conn, true); rerr == nil {
				conn = refreshed
				if retry, ferr2 := opFetchUsageForProvider(ctx, conn, force); ferr2 == nil {
					usage = retry
				}
			}
		}
		WriteJSON(w, http.StatusOK, usage)
	}
}

// ----- Claude (usage/claude.js) -----

const (
	opAnthropicAPIVersion = "2023-06-01" // ANTHROPIC_API_VERSION
	opClaudeUA            = "claude-cli/2.1.280 (external, cli)"
)

var (
	opClaudeCooldownMu sync.Mutex
	opClaudeCooldown   = map[string]time.Time{}
	opClaudeCacheMu    sync.Mutex
	opClaudeCache      = map[string]struct {
		result    db.Record
		expiresAt time.Time
	}{}
)

func opClaudeHeaders(token string) map[string]string {
	return map[string]string{
		"Authorization":     "Bearer " + token,
		"anthropic-beta":    "oauth-2025-04-20",
		"anthropic-version": opAnthropicAPIVersion,
		"User-Agent":        opClaudeUA,
	}
}

func opClaudeUsage(ctx context.Context, accessToken string, force bool) (db.Record, error) {
	if !force && accessToken != "" {
		opClaudeCacheMu.Lock()
		hit, ok := opClaudeCache[accessToken]
		opClaudeCacheMu.Unlock()
		if ok && time.Now().Before(hit.expiresAt) {
			return hit.result, nil
		}
	}
	result := opClaudeUsageRaw(ctx, accessToken)
	if accessToken != "" && result != nil {
		if _, hasQuotas := result["quotas"]; hasQuotas {
			opClaudeCacheMu.Lock()
			opClaudeCache[accessToken] = struct {
				result    db.Record
				expiresAt time.Time
			}{result, time.Now().Add(300 * time.Second)}
			opClaudeCacheMu.Unlock()
			return result, nil
		}
		// Soft failure: prefer the last good read.
		opClaudeCacheMu.Lock()
		if hit, ok := opClaudeCache[accessToken]; ok && hit.result != nil {
			opClaudeCacheMu.Unlock()
			return hit.result, nil
		}
		opClaudeCacheMu.Unlock()
	}
	return result, nil
}

func opClaudeQuotaObject(window map[string]any) db.Record {
	used := opNum(window, "utilization")
	remaining := math.Max(0, 100-used)
	return db.Record{
		"used":                used,
		"total":               float64(100),
		"remaining":           remaining,
		"remainingPercentage": remaining,
		"resetAt":             opParseResetTime(window["resets_at"]),
		"unlimited":           false,
	}
}

func opClaudeHasUtilization(window map[string]any) bool {
	if window == nil {
		return false
	}
	_, ok := window["utilization"].(float64)
	return ok
}

func opClaudeUsageRaw(ctx context.Context, accessToken string) db.Record {
	u := opProviderUsage("claude")
	opClaudeCooldownMu.Lock()
	cooling := false
	if until, ok := opClaudeCooldown[accessToken]; ok && time.Now().Before(until) {
		cooling = true
	}
	opClaudeCooldownMu.Unlock()
	if cooling {
		return opClaudeUsageLegacy(ctx, accessToken)
	}
	status, data, _, err := opFetchJSON(ctx, "GET", opStr(u, "oauthUrl")+"?cedar_ember=1", opClaudeHeaders(accessToken), nil)
	if err != nil {
		return db.Record{"message": "Claude connected. Unable to fetch usage: " + err.Error()}
	}
	if status >= 200 && status < 300 && data != nil {
		quotas := db.Record{}
		if opClaudeHasUtilization(opMap(data, "five_hour")) {
			quotas["session (5h)"] = opClaudeQuotaObject(opMap(data, "five_hour"))
		}
		if opClaudeHasUtilization(opMap(data, "seven_day")) {
			quotas["weekly (7d)"] = opClaudeQuotaObject(opMap(data, "seven_day"))
		}
		for key, value := range data {
			if strings.HasPrefix(key, "seven_day_") && key != "seven_day" {
				if win, ok := value.(map[string]any); ok && opClaudeHasUtilization(win) {
					quotas["weekly "+strings.TrimPrefix(key, "seven_day_")+" (7d)"] = opClaudeQuotaObject(win)
				}
			}
		}
		if limits, ok := data["limits"].([]any); ok {
			for _, lv := range limits {
				limit, _ := lv.(map[string]any)
				if limit == nil || opStr(limit, "kind") != "weekly_scoped" {
					continue
				}
				modelName := strings.ToLower(strings.TrimSpace(opStr(opMap(opMap(limit, "scope"), "model"), "display_name")))
				if modelName == "" {
					continue
				}
				if _, ok := limit["percent"].(float64); !ok {
					continue
				}
				percent := math.Max(0, math.Min(100, opNum(limit, "percent")))
				quotas["weekly "+modelName+" (7d)"] = opClaudeQuotaObject(map[string]any{
					"utilization": percent,
					"resets_at":   limit["resets_at"],
				})
			}
		}
		var extraUsage any
		if v, ok := data["extra_usage"]; ok {
			extraUsage = v
		}
		return db.Record{
			"plan":         "Claude Code",
			"extraUsage":   extraUsage,
			"resetCredits": opParseClaudeResetGrants(opMap(data, "cedar_ember")),
			"quotas":       quotas,
		}
	}
	if status == 429 {
		opClaudeCooldownMu.Lock()
		opClaudeCooldown[accessToken] = time.Now().Add(180 * time.Second)
		opClaudeCooldownMu.Unlock()
	}
	return opClaudeUsageLegacy(ctx, accessToken)
}

func opClaudeUsageLegacy(ctx context.Context, accessToken string) db.Record {
	u := opProviderUsage("claude")
	headers := map[string]string{
		"Authorization":     "Bearer " + accessToken,
		"anthropic-version": opAnthropicAPIVersion,
	}
	status, settings, _, err := opFetchJSON(ctx, "GET", opStr(u, "settingsUrl"), headers, nil)
	if err != nil {
		return db.Record{"message": "Claude connected. Unable to fetch usage: " + err.Error()}
	}
	if status >= 200 && status < 300 && settings != nil {
		plan := opStr(settings, "plan")
		if plan == "" {
			plan = "Unknown"
		}
		org := settings["organization_name"]
		if orgID := opStr(settings, "organization_id"); orgID != "" {
			usageURL := strings.Replace(opStr(u, "orgUrl"), "{org_id}", orgID, 1)
			ustatus, usage, _, uerr := opFetchJSON(ctx, "GET", usageURL, headers, nil)
			if uerr == nil && ustatus >= 200 && ustatus < 300 && usage != nil {
				return db.Record{"plan": plan, "organization": org, "quotas": usage}
			}
		}
		return db.Record{
			"plan":         plan,
			"organization": org,
			"message":      "Claude connected. Usage details require admin access.",
		}
	}
	return db.Record{"message": "Claude connected. Usage API requires admin permissions."}
}

// opParseClaudeResetGrants ports parseClaudeResetGrants.
func opParseClaudeResetGrants(block map[string]any) any {
	if block == nil || !opBool(block, "eligible") {
		return nil
	}
	grantsRaw, ok := block["grants"].([]any)
	if !ok {
		return nil
	}
	var usable []map[string]any
	var all []db.Record
	for _, gv := range grantsRaw {
		g, _ := gv.(map[string]any)
		if g == nil || opStr(g, "id") == "" {
			continue
		}
		clears := g["clears"]
		if _, ok := clears.([]any); !ok {
			clears = []any{}
		}
		all = append(all, db.Record{
			"id":               opStr(g, "id"),
			"label":            opStr(g, "label"),
			"resetsLeft":       opFinite(g["resets_left"], 0),
			"resetsTotal":      opFinite(g["resets_total"], 0),
			"startsAt":         g["starts_at"],
			"endsAt":           g["ends_at"],
			"clears":           clears,
			"paused":           opBool(g, "paused"),
			"usableNow":        opBool(g, "usable_now"),
			"useRequiresLimit": g["use_requires_limit"] != false,
		})
		if !opBool(g, "paused") && opFinite(g["resets_left"], 0) > 0 {
			usable = append(usable, g)
		}
	}
	var next map[string]any
	for _, g := range usable {
		if opStr(g, "id") == opStr(block, "next_grant_id") {
			next = g
			break
		}
	}
	if next == nil && len(usable) > 0 {
		next = usable[0]
	}
	available := 0.0
	for _, g := range usable {
		available += opFinite(g["resets_left"], 0)
	}
	var nextID, expiresAt, clears any
	if next != nil {
		nextID = opStr(next, "id")
		expiresAt = next["ends_at"]
		clears = next["clears"]
		if _, ok := clears.([]any); !ok {
			clears = []any{}
		}
	}
	return db.Record{
		"availableCount": available,
		"nextGrantId":    nextID,
		"expiresAt":      expiresAt,
		"clears":         clears,
		"cooldownUntil":  block["cooldown_until"],
		"weeklyResetsAt": block["weekly_resets_at"],
		"grants":         all,
	}
}

var opGrantIDRe = regexp.MustCompile(`^[a-z0-9_-]{1,40}$`)

// opConsumeClaudeResetGrant ports consumeClaudeResetGrant.
func opConsumeClaudeResetGrant(ctx context.Context, accessToken, grantID string) (db.Record, error) {
	if accessToken == "" {
		return nil, errors.New("No Claude access token available. Please re-authorize the connection.")
	}
	if !opGrantIDRe.MatchString(grantID) {
		return nil, errors.New("Invalid reset grant id.")
	}
	u := opProviderUsage("claude")
	headers := opClaudeHeaders(accessToken)
	headers["Content-Type"] = "application/json"
	pstatus, profile, _, err := opFetchJSON(ctx, "GET", opStr(u, "profileUrl"), headers, nil)
	if err != nil {
		return nil, err
	}
	orgID := opStr(opMap(profile, "organization"), "uuid")
	if pstatus < 200 || pstatus >= 300 || orgID == "" {
		return nil, fmt.Errorf("Cannot resolve Claude organization (%d).", pstatus)
	}
	resetURL := strings.Replace(opStr(u, "resetUrl"), "{org_id}", orgID, 1)
	body, _ := json.Marshal(map[string]any{
		"program":    "cedar_ember",
		"grant_id":   grantID,
		"request_id": opUUID(),
	})
	status, data, _, err := opFetchJSON(ctx, "POST", resetURL, headers, body)
	if err != nil {
		return nil, err
	}
	opClaudeCacheMu.Lock()
	delete(opClaudeCache, accessToken)
	opClaudeCacheMu.Unlock()
	var message any
	if data != nil {
		message = opMap(data, "error")["message"]
	}
	return db.Record{
		"ok":         status >= 200 && status < 300 && opStr(data, "result") == "reset",
		"status":     status,
		"result":     dataStrOrNil(data, "result"),
		"reason":     dataStrOrNil(data, "reason"),
		"resetsLeft": dataAnyOrNil(data, "resets_left"),
		"message":    message,
	}, nil
}

func dataStrOrNil(m map[string]any, k string) any {
	if m == nil {
		return nil
	}
	if v, ok := m[k]; ok {
		return v
	}
	return nil
}

func dataAnyOrNil(m map[string]any, k string) any { return dataStrOrNil(m, k) }

func opUsageClaudeReset(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		connectionID := r.PathValue("connectionId")
		body, _ := ReadBodyJSON(r)
		grantID := Str(body, "grantId")
		conn, err := deps.Store.GetProviderConnectionByID(connectionID)
		if err != nil || conn == nil {
			Err(w, http.StatusNotFound, "Connection not found")
			return
		}
		if opStr(conn, "provider") != "claude" || opStr(conn, "authType") != "oauth" {
			Err(w, http.StatusBadRequest, "Limit reset is only available for Claude OAuth connections.")
			return
		}
		ctx := r.Context()
		refreshed, rerr := opRefreshConnection(ctx, deps, conn, false)
		if rerr != nil {
			Err(w, http.StatusInternalServerError, rerr.Error())
			return
		}
		conn = refreshed
		result, cerr := opConsumeClaudeResetGrant(ctx, opStr(conn, "accessToken"), grantID)
		if cerr != nil {
			Err(w, http.StatusInternalServerError, cerr.Error())
			return
		}
		if opBool(result, "ok") {
			WriteJSON(w, http.StatusOK, result)
			return
		}
		status := int(opNum(result, "status"))
		if status < 400 || status >= 500 {
			status = 409
		}
		msg := opStr(result, "message")
		if msg == "" {
			reason := opStr(result, "reason")
			if reason == "" {
				reason = opStr(result, "result")
			}
			if reason == "" {
				reason = "unknown"
			}
			msg = "Reset not applied: " + reason
		}
		out := db.Record{}
		for k, v := range result {
			out[k] = v
		}
		out["message"] = msg
		WriteJSON(w, status, out)
	}
}

// ----- Codex (usage/codex.js) -----

func opCodexRateLimitBody(snapshot map[string]any) map[string]any {
	if snapshot == nil {
		return nil
	}
	if rl := opMap(snapshot, "rate_limit"); rl != nil {
		return rl
	}
	return snapshot
}

func opCodexWindow(window map[string]any) db.Record {
	raw := window["used_percent"]
	if raw == nil {
		raw = window["percent_used"]
	}
	used := opFinite(raw, 0)
	if used < 0 {
		used = 0
	}
	if used > 100 {
		used = 100
	}
	reset := window["reset_at"]
	if reset == nil {
		reset = window["resets_at"]
	}
	if reset == nil {
		reset = window["resetAt"]
	}
	return db.Record{
		"used":      used,
		"total":     float64(100),
		"remaining": math.Max(0, 100-used),
		"resetAt":   opParseResetTime(reset),
		"unlimited": false,
	}
}

func opCodexAppendWindows(quotas db.Record, prefix string, snapshot map[string]any) bool {
	rateLimit := opCodexRateLimitBody(snapshot)
	if rateLimit == nil {
		return false
	}
	primary := opMap(rateLimit, "primary_window")
	if primary == nil {
		primary = opMap(rateLimit, "primary")
	}
	if primary == nil {
		primary = opMap(snapshot, "primary_window")
	}
	if primary == nil {
		primary = opMap(snapshot, "primary")
	}
	secondary := opMap(rateLimit, "secondary_window")
	if secondary == nil {
		secondary = opMap(rateLimit, "secondary")
	}
	if secondary == nil {
		secondary = opMap(snapshot, "secondary_window")
	}
	if secondary == nil {
		secondary = opMap(snapshot, "secondary")
	}
	added := false
	if primary != nil {
		key := "session"
		if prefix != "" {
			key = prefix + "_session"
		}
		quotas[key] = opCodexWindow(primary)
		added = true
	}
	if secondary != nil {
		key := "weekly"
		if prefix != "" {
			key = prefix + "_weekly"
		}
		quotas[key] = opCodexWindow(secondary)
		added = true
	}
	return added
}

func opCodexNamedRateLimit(data map[string]any, directKeys []string, byIDKeys []string, match func(id string) bool) map[string]any {
	for _, k := range directKeys {
		if v := opMap(data, k); v != nil {
			return v
		}
	}
	if byID := opMap(data, "rate_limits_by_limit_id"); byID != nil {
		for _, k := range byIDKeys {
			if v := opMap(byID, k); v != nil {
				return v
			}
		}
	}
	if additional, ok := data["additional_rate_limits"].([]any); ok {
		for _, ev := range additional {
			entry, _ := ev.(map[string]any)
			if entry == nil {
				continue
			}
			id := strings.ToLower(opStr(entry, "limit_name"))
			if id == "" {
				id = strings.ToLower(opStr(entry, "metered_feature"))
			}
			if id == "" {
				id = strings.ToLower(opStr(entry, "id"))
			}
			if match(id) {
				return entry
			}
		}
	}
	return nil
}

func opCodexUsage(ctx context.Context, accessToken string) (db.Record, error) {
	u := opProviderUsage("codex")
	status, data, _, err := opFetchJSON(ctx, "GET", opStr(u, "url"), map[string]string{
		"Authorization": "Bearer " + accessToken,
		"Accept":        "application/json",
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch Codex usage: %v", err)
	}
	if status < 200 || status >= 300 || data == nil {
		return db.Record{"message": fmt.Sprintf("Codex connected. Usage API temporarily unavailable (%d).", status)}, nil
	}
	normal := opMap(data, "rate_limit")
	if normal == nil {
		normal = opMap(data, "rate_limits")
	}
	if normal == nil {
		normal = opMap(opMap(data, "rate_limits_by_limit_id"), "codex")
	}
	if normal == nil {
		normal = db.Record{}
	}
	review := opCodexNamedRateLimit(data,
		[]string{"code_review_rate_limit", "review_rate_limit"},
		[]string{"code_review", "codex_review", "review"},
		func(id string) bool {
			return id == "code_review" || id == "codex_review" || id == "review" || strings.Contains(id, "review")
		})
	spark := opCodexNamedRateLimit(data,
		[]string{"spark_rate_limit", "gpt_5_3_codex_spark_rate_limit"},
		[]string{"gpt-5.3-codex-spark", "gpt_5_3_codex_spark", "spark"},
		func(id string) bool {
			return strings.Contains(id, "spark") || strings.Contains(id, "5.3-codex-spark")
		})
	availableReset := math.Max(0, opFinite(opMap(data, "rate_limit_reset_credits")["available_count"], 0))
	quotas := db.Record{}
	opCodexAppendWindows(quotas, "", normal)
	opCodexAppendWindows(quotas, "review", review)
	opCodexAppendWindows(quotas, "spark", spark)
	plan := opStr(data, "plan_type")
	if plan == "" {
		plan = opStr(opMap(data, "summary"), "plan")
	}
	if plan == "" {
		plan = "unknown"
	}
	limitReached := func(snap map[string]any) bool {
		body := opCodexRateLimitBody(snap)
		if body == nil {
			return false
		}
		return opBool(body, "limit_reached")
	}
	return db.Record{
		"plan":               plan,
		"limitReached":       limitReached(normal),
		"reviewLimitReached": limitReached(review),
		"sparkLimitReached":  limitReached(spark),
		"resetCredits":       db.Record{"availableCount": availableReset},
		"quotas":             quotas,
	}, nil
}

func opCodexAccountID(psd map[string]any) string {
	for _, k := range []string{"workspaceId", "accountId", "chatgptAccountId"} {
		if v := opStr(psd, k); v != "" {
			return v
		}
	}
	return ""
}

func opCodexErrorMessage(data map[string]any, fallback string) string {
	if data == nil {
		return fallback
	}
	for _, k := range []string{"message", "error", "detail"} {
		switch v := data[k].(type) {
		case string:
			if v != "" {
				return v
			}
		case map[string]any:
			if m := opStr(v, "message"); m != "" {
				return m
			}
			b, _ := json.Marshal(v)
			return string(b)
		}
	}
	return fallback
}

// opCodexResetCreditsList ports getCodexRateLimitResetCredits.
func opCodexResetCreditsList(ctx context.Context, accessToken string, psd map[string]any) (db.Record, error) {
	if accessToken == "" {
		return nil, errors.New("No Codex access token available. Please re-authorize the connection.")
	}
	u := opProviderUsage("codex")
	headers := map[string]string{
		"Authorization": "Bearer " + accessToken,
		"Accept":        "application/json",
		"OpenAI-Beta":   "codex-1",
		"originator":    "codex_cli_rs",
	}
	if accountID := opCodexAccountID(psd); accountID != "" {
		headers["ChatGPT-Account-ID"] = accountID
	}
	status, data, _, err := opFetchJSON(ctx, "GET", opStr(u, "resetCreditsUrl"), headers, nil)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, errors.New(opCodexErrorMessage(data, fmt.Sprintf("Codex reset credits API unavailable (%d).", status)))
	}
	credits := []db.Record{}
	if arr, ok := data["credits"].([]any); ok {
		for _, cv := range arr {
			credit, _ := cv.(map[string]any)
			if credit == nil {
				continue
			}
			st := opStr(credit, "status")
			if st == "" {
				st = "unknown"
			}
			granted := credit["granted_at"]
			if granted == nil {
				granted = credit["grantedAt"]
			}
			expires := credit["expires_at"]
			if expires == nil {
				expires = credit["expiresAt"]
			}
			credits = append(credits, db.Record{
				"status":    st,
				"grantedAt": opToISO(granted),
				"expiresAt": opToISO(expires),
			})
		}
	}
	available := data["available_count"]
	if available == nil {
		available = data["availableCount"]
	}
	return db.Record{
		"availableCount": math.Max(0, opFinite(available, 0)),
		"credits":        credits,
	}, nil
}

// opCodexResetCreditsConsume ports consumeCodexRateLimitResetCredit.
func opCodexResetCreditsConsume(ctx context.Context, accessToken, redeemRequestID string) (db.Record, error) {
	if accessToken == "" {
		return nil, errors.New("No Codex access token available. Please re-authorize the connection.")
	}
	if redeemRequestID == "" {
		return nil, errors.New("A redeem request id is required to consume a Codex reset credit.")
	}
	u := opProviderUsage("codex")
	body, _ := json.Marshal(map[string]any{"redeem_request_id": redeemRequestID})
	status, data, _, err := opFetchJSON(ctx, "POST", opStr(u, "resetCreditsConsumeUrl"), map[string]string{
		"Authorization": "Bearer " + accessToken,
		"Accept":        "application/json",
		"Content-Type":  "application/json",
	}, body)
	if err != nil {
		return nil, fmt.Errorf("Failed to consume Codex reset credit: %v", err)
	}
	code := dataStrOrNil(data, "code")
	windowsReset := opFinite(data["windows_reset"], 0)
	okStatus := status >= 200 && status < 300
	success := okStatus && (opStr(data, "code") == "reset" || windowsReset > 0)
	return db.Record{
		"ok":           success,
		"noCredit":     okStatus && opStr(data, "code") == "no_credit",
		"status":       status,
		"code":         code,
		"windowsReset": windowsReset,
		"message":      dataStrOrNil(data, "message"),
		"raw":          data,
	}, nil
}

// opCodexResetGuard resolves + validates a codex connection (route.js
// getCodexConnection). ok=false → response already written.
func opCodexResetGuard(w http.ResponseWriter, deps Deps, connectionID string) (db.Record, bool, bool) {
	conn, err := deps.Store.GetProviderConnectionByID(connectionID)
	if err != nil || conn == nil {
		Err(w, http.StatusNotFound, "Connection not found")
		return nil, false, false
	}
	if opStr(conn, "provider") != "codex" {
		Err(w, http.StatusBadRequest, "Codex reset credits are only available for Codex connections.")
		return nil, false, false
	}
	isOAuth := opStr(conn, "authType") == "oauth"
	isAccessToken := opStr(conn, "authType") == "access_token"
	if !isOAuth && !isAccessToken {
		Err(w, http.StatusBadRequest, "Codex reset credits require an OAuth or access-token connection.")
		return nil, false, false
	}
	return conn, isOAuth, true
}

func opCodexIsAuthExpiredResult(result db.Record) bool {
	candidates := []string{opStr(result, "message"), opStr(result, "code")}
	if raw := opMap(result, "raw"); raw != nil {
		candidates = append(candidates, opStr(raw, "detail"))
		if e, ok := raw["error"].(string); ok {
			candidates = append(candidates, e)
		}
	}
	for _, v := range candidates {
		lv := strings.ToLower(v)
		for _, p := range opAuthExpiredPatterns {
			if strings.Contains(lv, p) {
				return true
			}
		}
	}
	return false
}

func opUsageCodexResetCreditsGet(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, isOAuth, ok := opCodexResetGuard(w, deps, r.PathValue("connectionId"))
		if !ok {
			return
		}
		ctx := r.Context()
		if isOAuth {
			refreshed, rerr := opRefreshConnection(ctx, deps, conn, false)
			if rerr != nil {
				Err(w, http.StatusUnauthorized, "Credential refresh failed: "+rerr.Error())
				return
			}
			conn = refreshed
		}
		psd := opMap(conn, "providerSpecificData")
		result, ferr := opCodexResetCreditsList(ctx, opStr(conn, "accessToken"), psd)
		if ferr != nil {
			if isOAuth && opStr(conn, "refreshToken") != "" && opCodexIsAuthExpiredResult(db.Record{"message": ferr.Error()}) {
				if refreshed, rerr := opRefreshConnection(ctx, deps, conn, true); rerr == nil {
					conn = refreshed
					result, ferr = opCodexResetCreditsList(ctx, opStr(conn, "accessToken"), opMap(conn, "providerSpecificData"))
				}
			}
			if ferr != nil {
				Err(w, http.StatusInternalServerError, ferr.Error())
				return
			}
		}
		WriteJSON(w, http.StatusOK, result)
	}
}

func opUsageCodexResetCreditsPost(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, isOAuth, ok := opCodexResetGuard(w, deps, r.PathValue("connectionId"))
		if !ok {
			return
		}
		body, _ := ReadBodyJSON(r)
		redeemRequestID := Str(body, "redeemRequestId")
		if redeemRequestID == "" {
			redeemRequestID = Str(body, "redeem_request_id")
		}
		if redeemRequestID == "" {
			redeemRequestID = opUUID()
		}
		ctx := r.Context()
		if isOAuth {
			refreshed, rerr := opRefreshConnection(ctx, deps, conn, false)
			if rerr != nil {
				Err(w, http.StatusUnauthorized, "Credential refresh failed: "+rerr.Error())
				return
			}
			conn = refreshed
		}
		result, ferr := opCodexResetCreditsConsume(ctx, opStr(conn, "accessToken"), redeemRequestID)
		if ferr != nil && isOAuth && opStr(conn, "refreshToken") != "" && opCodexIsAuthExpiredResult(db.Record{"message": ferr.Error()}) {
			if refreshed, rerr := opRefreshConnection(ctx, deps, conn, true); rerr == nil {
				conn = refreshed
				result, ferr = opCodexResetCreditsConsume(ctx, opStr(conn, "accessToken"), redeemRequestID)
			}
		}
		if ferr != nil {
			Err(w, http.StatusInternalServerError, ferr.Error())
			return
		}
		opWriteCodexConsumeResult(w, result, redeemRequestID)
	}
}

// opWriteCodexConsumeResult ports getResponseForConsumeResult.
func opWriteCodexConsumeResult(w http.ResponseWriter, result db.Record, redeemRequestID string) {
	if opBool(result, "ok") {
		var credit any
		if raw := opMap(result, "raw"); raw != nil {
			credit = raw["credit"]
		}
		WriteJSON(w, http.StatusOK, db.Record{
			"code":            result["code"],
			"reset":           true,
			"windows_reset":   result["windowsReset"],
			"redeemRequestId": redeemRequestID,
			"credit":          credit,
		})
		return
	}
	if opBool(result, "noCredit") {
		WriteJSON(w, http.StatusConflict, db.Record{
			"code":          "no_credit",
			"reset":         false,
			"windows_reset": result["windowsReset"],
			"message":       "No Codex reset credits available.",
		})
		return
	}
	code := opStr(result, "code")
	if code == "" {
		code = "unknown_response"
	}
	msg := opStr(result, "message")
	if msg == "" {
		msg = "Codex reset credit consume returned an unexpected response."
	}
	status := int(opNum(result, "status"))
	if status < 400 || status >= 500 {
		status = 502
	}
	WriteJSON(w, status, db.Record{
		"code":          code,
		"reset":         false,
		"windows_reset": result["windowsReset"],
		"message":       msg,
	})
}

// ----- GitHub (usage/github.js) -----

func opGithubQuotaSnapshot(quota map[string]any) db.Record {
	if quota == nil {
		return db.Record{"used": float64(0), "total": float64(0), "unlimited": true}
	}
	entitlement := opNum(quota, "entitlement")
	remaining := opNum(quota, "remaining")
	return db.Record{
		"used":      entitlement - remaining,
		"total":     entitlement,
		"remaining": remaining,
		"unlimited": opBool(quota, "unlimited"),
	}
}

func opGithubUsage(ctx context.Context, accessToken string) (db.Record, error) {
	if accessToken == "" {
		return nil, fmt.Errorf("Failed to fetch GitHub usage: No GitHub access token available. Please re-authorize the connection.")
	}
	oauth := opProviderOAuth("github")
	u := opProviderUsage("github")
	req, err := http.NewRequestWithContext(ctx, "GET", opStr(u, "url"), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-GitHub-Api-Version", opStr(oauth, "apiVersion"))
	req.Header.Set("User-Agent", opStr(oauth, "userAgent"))
	req.Header.Set("Editor-Version", "vscode/1.100.0")
	req.Header.Set("Editor-Plugin-Version", "copilot-chat/0.26.7")
	resp, err := opHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch GitHub usage: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("Failed to fetch GitHub usage: GitHub API error: %s", string(raw))
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("Failed to fetch GitHub usage: %v", err)
	}
	if snapshots := opMap(data, "quota_snapshots"); snapshots != nil {
		resetAt := opParseResetTime(data["quota_reset_date"])
		withReset := func(q map[string]any) db.Record {
			out := opGithubQuotaSnapshot(q)
			out["resetAt"] = resetAt
			return out
		}
		return db.Record{
			"plan":      data["copilot_plan"],
			"resetDate": data["quota_reset_date"],
			"quotas": db.Record{
				"chat":                 withReset(opMap(snapshots, "chat")),
				"completions":          withReset(opMap(snapshots, "completions")),
				"premium_interactions": withReset(opMap(snapshots, "premium_interactions")),
			},
		}, nil
	}
	if data["monthly_quotas"] != nil || data["limited_user_quotas"] != nil {
		monthly := opMap(data, "monthly_quotas")
		used := opMap(data, "limited_user_quotas")
		resetAt := opParseResetTime(data["limited_user_reset_date"])
		plan := data["copilot_plan"]
		if plan == nil {
			plan = data["access_type_sku"]
		}
		return db.Record{
			"plan":      plan,
			"resetDate": data["limited_user_reset_date"],
			"quotas": db.Record{
				"chat": db.Record{
					"used": opNum(used, "chat"), "total": opNum(monthly, "chat"),
					"unlimited": false, "resetAt": resetAt,
				},
				"completions": db.Record{
					"used": opNum(used, "completions"), "total": opNum(monthly, "completions"),
					"unlimited": false, "resetAt": resetAt,
				},
			},
		}, nil
	}
	return db.Record{"message": "GitHub Copilot connected. Unable to parse quota data."}, nil
}

// ----- Groq (usage/groq.js) -----

var opGroqDurationRe = regexp.MustCompile(`(\d+(?:\.\d+)?)(ms|s|m|h)`)

func opGroqResetAt(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	matches := opGroqDurationRe.FindAllStringSubmatch(value, -1)
	if len(matches) == 0 {
		return nil
	}
	var totalMs float64
	for _, m := range matches {
		amount, _ := strconv.ParseFloat(m[1], 64)
		switch m[2] {
		case "h":
			totalMs += amount * 3600000
		case "m":
			totalMs += amount * 60000
		case "ms":
			totalMs += amount
		default:
			totalMs += amount * 1000
		}
	}
	return time.Now().Add(time.Duration(totalMs * float64(time.Millisecond))).UTC().Format("2006-01-02T15:04:05.000Z")
}

func opGroqQuota(headers http.Header, limitKey, remainingKey, resetKey string) db.Record {
	limitRaw, remainingRaw := headers.Get(limitKey), headers.Get(remainingKey)
	if limitRaw == "" || remainingRaw == "" {
		return nil
	}
	limit, err1 := strconv.ParseFloat(limitRaw, 64)
	remaining, err2 := strconv.ParseFloat(remainingRaw, 64)
	if err1 != nil || err2 != nil {
		return nil
	}
	return db.Record{
		"used":      math.Max(0, limit-remaining),
		"total":     limit,
		"resetAt":   opGroqResetAt(headers.Get(resetKey)),
		"unlimited": false,
	}
}

func opGroqUsage(ctx context.Context, apiKey string) (db.Record, error) {
	if strings.TrimSpace(apiKey) == "" {
		return db.Record{"message": "Groq API key not available. Add a key to view usage."}, nil
	}
	u := opProviderUsage("groq")
	req, err := http.NewRequestWithContext(ctx, "GET", opStr(u, "url"), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.Trim(apiKey, " "))
	req.Header.Set("Accept", "application/json")
	resp, err := opHTTPClient.Do(req)
	if err != nil {
		return db.Record{"message": "Groq error: " + err.Error()}, nil
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return db.Record{"plan": "Groq", "message": "Groq authentication failed. Check the API key."}, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := fmt.Sprintf("Groq usage API error (%d)", resp.StatusCode)
		if len(raw) > 0 {
			text := string(raw)
			if len(text) > 120 {
				text = text[:120]
			}
			msg += ": " + text
		}
		return db.Record{"plan": "Groq", "message": msg}, nil
	}
	requests := opGroqQuota(resp.Header, "x-ratelimit-limit-requests", "x-ratelimit-remaining-requests", "x-ratelimit-reset-requests")
	tokens := opGroqQuota(resp.Header, "x-ratelimit-limit-tokens", "x-ratelimit-remaining-tokens", "x-ratelimit-reset-tokens")
	if requests == nil && tokens == nil {
		return db.Record{
			"plan":    "Groq",
			"message": "Groq connected. No rate-limit data reported for this key yet.",
			"quotas":  db.Record{},
		}, nil
	}
	quotas := db.Record{}
	if requests != nil {
		quotas["Requests"] = requests
	}
	if tokens != nil {
		quotas["Tokens"] = tokens
	}
	return db.Record{"plan": "Groq", "quotas": quotas}, nil
}

// ---------- translator ----------

var opTranslatorFiles = map[string]bool{
	"1_req_client.json": true, "2_req_source.json": true,
	"3_req_openai.json": true, "4_req_target.json": true,
	"5_res_provider.txt": true, "6_res_openai.txt": true,
	"7_res_client.txt": true, "7_res_client.json": true,
}

func opTranslatorLogsDir() string {
	return filepath.Join(db.DataDir(), "logs", "translator")
}

func opTranslatorLoad(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		if file == "" {
			WriteJSON(w, http.StatusBadRequest, db.Record{"success": false, "error": "File parameter required"})
			return
		}
		if !opTranslatorFiles[file] {
			WriteJSON(w, http.StatusBadRequest, db.Record{"success": false, "error": "Invalid file name"})
			return
		}
		raw, err := os.ReadFile(filepath.Join(opTranslatorLogsDir(), file))
		if err != nil {
			WriteJSON(w, http.StatusNotFound, db.Record{"success": false, "error": "File not found"})
			return
		}
		WriteJSON(w, http.StatusOK, db.Record{"success": true, "content": string(raw)})
	}
}

func opTranslatorSave(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ReadBodyJSON(r)
		if err != nil {
			WriteJSON(w, http.StatusBadRequest, db.Record{"success": false, "error": err.Error()})
			return
		}
		file := Str(body, "file")
		content, hasContent := body["content"]
		if file == "" || !hasContent {
			WriteJSON(w, http.StatusBadRequest, db.Record{"success": false, "error": "File and content required"})
			return
		}
		if !opTranslatorFiles[file] {
			WriteJSON(w, http.StatusBadRequest, db.Record{"success": false, "error": "Invalid file name"})
			return
		}
		text, ok := content.(string)
		if !ok {
			raw, _ := json.Marshal(content)
			text = string(raw)
		}
		dir := opTranslatorLogsDir()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			WriteJSON(w, http.StatusInternalServerError, db.Record{"success": false, "error": err.Error()})
			return
		}
		if err := os.WriteFile(filepath.Join(dir, file), []byte(text), 0o644); err != nil {
			WriteJSON(w, http.StatusInternalServerError, db.Record{"success": false, "error": err.Error()})
			return
		}
		WriteJSON(w, http.StatusOK, db.Record{"success": true})
	}
}

// opTargetFormat: registry transport.format for the provider
// (services/provider.js getTargetFormat's common path).
func opTargetFormat(providerID string) string {
	if strings.HasPrefix(providerID, "openai-compatible-") {
		return "openai"
	}
	if strings.HasPrefix(providerID, "anthropic-compatible-") {
		return "claude"
	}
	if p, ok := providers.Get(providerID); ok && p.Transport.Format != "" {
		return p.Transport.Format
	}
	return "openai"
}

func opResolveAlias(deps Deps) func(string) string {
	aliases, _ := deps.Store.GetModelAliases()
	return func(model string) string {
		if aliases != nil {
			if v := opStr(aliases, model); v != "" {
				return v
			}
		}
		return model
	}
}

func opFirstActiveConnection(deps Deps, provider string) (db.Record, bool) {
	conns, err := deps.Store.GetProviderConnections(db.ConnectionFilter{Provider: provider})
	if err != nil {
		return nil, false
	}
	for _, c := range conns {
		if v, ok := c["isActive"].(bool); !ok || v {
			return c, true
		}
	}
	return nil, false
}

func opTranslatorTranslate(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ReadBodyJSON(r)
		if err != nil {
			WriteJSON(w, http.StatusBadRequest, db.Record{"success": false, "error": err.Error()})
			return
		}
		stepRaw, hasStep := body["step"]
		inner, hasBody := body["body"]
		if !hasStep || !hasBody {
			WriteJSON(w, http.StatusBadRequest, db.Record{"success": false, "error": "Step and body required"})
			return
		}
		step := int(opNum(body, "step"))
		_ = stepRaw
		innerMap, _ := inner.(map[string]any)
		clientBody := innerMap
		if nested := opMap(innerMap, "body"); nested != nil {
			clientBody = nested
		}
		if clientBody == nil {
			clientBody = map[string]any{}
		}
		fail := func(status int, msg string) {
			WriteJSON(w, status, db.Record{"success": false, "error": msg})
		}
		switch step {
		case 1:
			info := chatcore.ParseModelString(opStr(clientBody, "model"), opResolveAlias(deps))
			WriteJSON(w, http.StatusOK, db.Record{
				"success": true,
				"result": db.Record{
					"provider":     info.Provider,
					"model":        info.Model,
					"sourceFormat": chatcore.DetectFormat(clientBody),
					"targetFormat": opTargetFormat(info.Provider),
				},
			})
		case 2:
			info := chatcore.ParseModelString(opStr(clientBody, "model"), opResolveAlias(deps))
			sourceFormat := chatcore.DetectFormat(clientBody)
			result, terr := translator.TranslateRequest(sourceFormat, "openai", translator.Body(clientBody))
			if terr != nil {
				fail(http.StatusInternalServerError, terr.Error())
				return
			}
			delete(result, "_toolNameMap")
			_ = info
			WriteJSON(w, http.StatusOK, db.Record{
				"success": true,
				"result":  db.Record{"body": result},
			})
		case 3:
			provider := opStr(innerMap, "provider")
			model := opStr(innerMap, "model")
			if provider == "" || model == "" {
				fail(http.StatusBadRequest, "provider and model required")
				return
			}
			targetFormat := opTargetFormat(provider)
			stream := clientBody["stream"] != false
			translated, terr := translator.TranslateRequest("openai", targetFormat, translator.Body(clientBody))
			if terr != nil {
				fail(http.StatusInternalServerError, terr.Error())
				return
			}
			delete(translated, "_toolNameMap")
			conn, found := opFirstActiveConnection(deps, provider)
			if !found {
				fail(http.StatusBadRequest, fmt.Sprintf("No active connection for provider: %s", provider))
				return
			}
			cred := opCredFromConnection(conn)
			info := opBuildProviderInfo(provider)
			// Compat-node providers resolve to the node id; executor
			// URL/header building keys off the node prefix.
			info.ID = provider
			url := opBuildURLPreview(info, cred, model, stream)
			headers := opBuildHeadersPreview(info, cred, stream)
			finalBody := translated
			finalBody["model"] = model
			WriteJSON(w, http.StatusOK, db.Record{
				"success": true,
				"result":  db.Record{"url": url, "headers": headers, "body": finalBody},
			})
		default:
			fail(http.StatusBadRequest, "Invalid step (1-3)")
		}
	}
}

// opBuildURLPreview replicates DefaultExecutor.buildURL (default.js)
// for the translator step-3 preview (pure; no upstream call).
func opBuildURLPreview(info *executors.ProviderInfo, cred executors.Credential, model string, stream bool) string {
	if strings.HasPrefix(info.ID, "openai-compatible-") {
		base := cred.BaseURL
		if base == "" {
			base = "https://api.openai.com/v1"
		}
		path := "/chat/completions"
		if opStr(cred.Specific, "apiType") == "responses" {
			path = "/responses"
		}
		return strings.TrimSuffix(base, "/") + path
	}
	if strings.HasPrefix(info.ID, "anthropic-compatible-") {
		base := cred.BaseURL
		if base == "" {
			base = "https://api.anthropic.com/v1"
		}
		return strings.TrimSuffix(base, "/") + "/messages"
	}
	if info.Format == "gemini" {
		action := "generateContent"
		if stream {
			action = "streamGenerateContent?alt=sse"
		}
		return info.BaseURL + "/" + model + ":" + action
	}
	if info.URLSuffix != "" {
		return info.BaseURL + info.URLSuffix
	}
	u := info.BaseURL
	if strings.Contains(u, "{accountId}") {
		u = strings.Replace(u, "{accountId}", cred.SpecificString("accountId"), 1)
	}
	return u
}

// opBuildHeadersPreview replicates DefaultExecutor.buildHeaders +
// applyAuth for the common (non-hook) providers.
func opBuildHeadersPreview(info *executors.ProviderInfo, cred executors.Credential, stream bool) map[string]string {
	headers := map[string]string{"Content-Type": "application/json"}
	for k, v := range info.Headers {
		headers[k] = v
	}
	setAuth := func(header, scheme, token string) {
		if header == "" {
			header = "Authorization"
		}
		if strings.EqualFold(scheme, "bearer") {
			headers[header] = "Bearer " + token
		} else {
			headers[header] = token
		}
	}
	desc := info.Auth
	if desc == nil {
		// resolveAuthDescriptor defaults by format.
		switch info.Format {
		case "claude":
			if cred.APIKey != "" {
				setAuth("x-api-key", "raw", cred.APIKey)
			} else if cred.AccessToken != "" {
				setAuth("Authorization", "bearer", cred.AccessToken)
			}
			if headers["anthropic-version"] == "" {
				headers["anthropic-version"] = opAnthropicAPIVersion
			}
		case "gemini":
			if cred.APIKey != "" {
				setAuth("x-goog-api-key", "raw", cred.APIKey)
			} else if cred.AccessToken != "" {
				setAuth("Authorization", "bearer", cred.AccessToken)
			}
		default:
			token := cred.APIKey
			if token == "" {
				token = cred.AccessToken
			}
			if token != "" {
				setAuth("Authorization", "bearer", token)
			}
		}
	} else if desc.Combined {
		token := cred.APIKey
		if token == "" {
			token = cred.AccessToken
		}
		if token == "" {
			token = "undefined"
		}
		setAuth(desc.Header, desc.Scheme, token)
		if desc.AnthropicVersion && headers["anthropic-version"] == "" {
			headers["anthropic-version"] = opAnthropicAPIVersion
		}
	} else {
		if cred.APIKey != "" && desc.APIKey != nil {
			setAuth(desc.APIKey.Header, desc.APIKey.Scheme, cred.APIKey)
		} else if cred.AccessToken != "" && desc.OAuth != nil {
			setAuth(desc.OAuth.Header, desc.OAuth.Scheme, cred.AccessToken)
		}
		if desc.AnthropicVersion && headers["anthropic-version"] == "" {
			headers["anthropic-version"] = opAnthropicAPIVersion
		}
	}
	if stream {
		headers["Accept"] = "text/event-stream"
	}
	return headers
}

func opTranslatorSend(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ReadBodyJSON(r)
		if err != nil {
			WriteJSON(w, http.StatusBadRequest, db.Record{"success": false, "error": err.Error()})
			return
		}
		provider := Str(body, "provider")
		model := Str(body, "model")
		inner, hasInner := body["body"].(map[string]any)
		if provider == "" || model == "" || !hasInner {
			WriteJSON(w, http.StatusBadRequest, db.Record{"success": false, "error": "provider, model, and body required"})
			return
		}
		conn, found := opFirstActiveConnection(deps, provider)
		if !found {
			WriteJSON(w, http.StatusBadRequest, db.Record{"success": false, "error": fmt.Sprintf("No active connection for provider: %s", provider)})
			return
		}
		cred := opCredFromConnection(conn)
		info := opBuildProviderInfo(provider)
		info.ID = provider
		executor := executors.For(provider)
		rawBody, _ := json.Marshal(inner)
		ctx := r.Context()
		result, execErr := executor.Execute(ctx, info, cred, rawBody)
		if execErr != nil {
			WriteJSON(w, http.StatusInternalServerError, db.Record{"success": false, "error": execErr.Error()})
			return
		}
		resp := result.Response
		// Auto-refresh on 401/403 and retry once (send/route.js).
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			if refresher, ok := executor.(executors.Refresher); ok {
				if newCred, rerr := refresher.RefreshCredentials(ctx, info, cred); rerr == nil && newCred != nil &&
					(newCred.AccessToken != "" || newCred.CopilotToken != "") {
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					merged := cred
					if newCred.AccessToken != "" {
						merged.AccessToken = newCred.AccessToken
					}
					if newCred.RefreshToken != "" {
						merged.RefreshToken = newCred.RefreshToken
					}
					if newCred.CopilotToken != "" {
						merged.CopilotToken = newCred.CopilotToken
					}
					if _, uerr := deps.Store.UpdateProviderConnection(opStr(conn, "id"), db.Record{
						"accessToken":  merged.AccessToken,
						"refreshToken": merged.RefreshToken,
					}); uerr == nil {
					}
					if retry, rerr2 := executor.Execute(ctx, info, merged, rawBody); rerr2 == nil {
						result = retry
						resp = retry.Response
					}
				}
			}
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			errText, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			WriteJSON(w, resp.StatusCode, db.Record{
				"success": false,
				"error":   fmt.Sprintf("Provider error: %d", resp.StatusCode),
				"details": string(errText),
			})
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)
		fl, _ := w.(http.Flusher)
		buf := make([]byte, 32*1024)
		for {
			n, rerr := resp.Body.Read(buf)
			if n > 0 {
				_, _ = w.Write(buf[:n])
				if fl != nil {
					fl.Flush()
				}
			}
			if rerr != nil {
				return
			}
		}
	}
}

// ---------- translator console logs (lib/consoleLogBuffer.js) ----------

const opConsoleLogCap = 500

var (
	opConsoleMu   sync.Mutex
	opConsoleLogs []string
	opConsoleSubs = map[chan string]struct{}{}
	opConsoleSeq  uint64
)

type opConsoleEvent struct {
	Kind  string // "line" | "lines" | "clear"
	Line  string
	Lines []string
}

var (
	opConsoleEventMu   sync.Mutex
	opConsoleEventSubs = map[chan opConsoleEvent]struct{}{}
)

// AddConsoleLog appends a line to the translator console-log ring
// buffer and broadcasts it to stream subscribers. Exported so other Go
// packages can feed the dashboard's translator console (the JS
// captures console.* process-wide; the Go port cannot, so services
// log through this hook explicitly).
func AddConsoleLog(line string) {
	opConsoleMu.Lock()
	opConsoleLogs = append(opConsoleLogs, line)
	if len(opConsoleLogs) > opConsoleLogCap {
		opConsoleLogs = opConsoleLogs[len(opConsoleLogs)-opConsoleLogCap:]
	}
	opConsoleMu.Unlock()
	opBroadcastConsole(opConsoleEvent{Kind: "line", Line: line})
}

func opBroadcastConsole(ev opConsoleEvent) {
	opConsoleEventMu.Lock()
	defer opConsoleEventMu.Unlock()
	for ch := range opConsoleEventSubs {
		select {
		case ch <- ev:
		default: // slow subscriber: drop (JS emitter has no backpressure either)
		}
	}
}

func opGetConsoleLogs() []string {
	opConsoleMu.Lock()
	defer opConsoleMu.Unlock()
	out := make([]string, len(opConsoleLogs))
	copy(out, opConsoleLogs)
	return out
}

func opTranslatorConsoleLogsGet(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logs := opGetConsoleLogs()
		if logs == nil {
			logs = []string{}
		}
		WriteJSON(w, http.StatusOK, db.Record{"success": true, "logs": logs})
	}
}

func opTranslatorConsoleLogsDelete(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		opConsoleMu.Lock()
		opConsoleLogs = nil
		opConsoleMu.Unlock()
		opBroadcastConsole(opConsoleEvent{Kind: "clear"})
		WriteJSON(w, http.StatusOK, db.Record{"success": true})
	}
}

func opTranslatorConsoleLogsStream(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			Err(w, http.StatusInternalServerError, "Streaming unsupported")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		ch := make(chan opConsoleEvent, 64)
		opConsoleEventMu.Lock()
		opConsoleEventSubs[ch] = struct{}{}
		opConsoleEventMu.Unlock()
		defer func() {
			opConsoleEventMu.Lock()
			delete(opConsoleEventSubs, ch)
			opConsoleEventMu.Unlock()
		}()
		if logs := opGetConsoleLogs(); len(logs) > 0 {
			payload, _ := json.Marshal(db.Record{"type": "init", "logs": logs})
			fmt.Fprintf(w, "data: %s\n\n", payload)
			fl.Flush()
		}
		ping := time.NewTicker(25 * time.Second)
		defer ping.Stop()
		ctx := r.Context()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ping.C:
				fmt.Fprintf(w, ": ping\n\n")
				fl.Flush()
			case ev := <-ch:
				var payload []byte
				switch ev.Kind {
				case "line":
					payload, _ = json.Marshal(db.Record{"type": "line", "line": ev.Line})
				case "lines":
					payload, _ = json.Marshal(db.Record{"type": "lines", "lines": ev.Lines})
				case "clear":
					payload, _ = json.Marshal(db.Record{"type": "clear"})
				}
				if payload != nil {
					fmt.Fprintf(w, "data: %s\n\n", payload)
					fl.Flush()
				}
			}
		}
	}
}

// ---------- media-providers: TTS voices ----------

// Intl.DisplayNames stand-ins: the JS resolves language/region display
// names via ICU; Go's stdlib has no equivalent, so common codes are
// mapped here and unknown codes fall back to the code itself (the JS
// also falls back to the code when ICU throws).
var opLangNames = map[string]string{
	"en": "English", "vi": "Vietnamese", "ja": "Japanese", "ko": "Korean",
	"zh": "Chinese", "es": "Spanish", "fr": "French", "de": "German",
	"it": "Italian", "pt": "Portuguese", "ru": "Russian", "hi": "Hindi",
	"th": "Thai", "id": "Indonesian", "ms": "Malay", "fil": "Filipino",
	"nl": "Dutch", "pl": "Polish", "tr": "Turkish", "ar": "Arabic",
	"sv": "Swedish", "da": "Danish", "no": "Norwegian", "fi": "Finnish",
	"cs": "Czech", "el": "Greek", "he": "Hebrew", "uk": "Ukrainian",
	"ro": "Romanian", "hu": "Hungarian", "bg": "Bulgarian", "hr": "Croatian",
	"sk": "Slovak", "sl": "Slovenian", "lt": "Lithuanian", "lv": "Latvian",
	"et": "Estonian", "ca": "Catalan", "ta": "Tamil", "te": "Telugu",
	"bn": "Bengali", "ur": "Urdu", "fa": "Persian", "my": "Burmese",
	"km": "Khmer", "lo": "Lao", "ne": "Nepali", "si": "Sinhala",
}

var opRegionNames = map[string]string{
	"US": "United States", "GB": "United Kingdom", "VN": "Vietnam",
	"JP": "Japan", "KR": "South Korea", "CN": "China", "TW": "Taiwan",
	"HK": "Hong Kong", "IN": "India", "AU": "Australia", "CA": "Canada",
	"FR": "France", "DE": "Germany", "ES": "Spain", "MX": "Mexico",
	"BR": "Brazil", "PT": "Portugal", "IT": "Italy", "RU": "Russia",
	"TH": "Thailand", "ID": "Indonesia", "MY": "Malaysia", "PH": "Philippines",
	"SG": "Singapore", "NL": "Netherlands", "PL": "Poland", "TR": "Turkey",
	"SA": "Saudi Arabia", "AE": "United Arab Emirates", "EG": "Egypt",
	"SE": "Sweden", "DK": "Denmark", "NO": "Norway", "FI": "Finland",
	"CZ": "Czechia", "GR": "Greece", "IL": "Israel", "UA": "Ukraine",
	"RO": "Romania", "HU": "Hungary", "BG": "Bulgaria", "HR": "Croatia",
	"SK": "Slovakia", "SI": "Slovenia", "LT": "Lithuania", "LV": "Latvia",
	"EE": "Estonia", "IE": "Ireland", "NZ": "New Zealand", "ZA": "South Africa",
	"NG": "Nigeria", "KE": "Kenya", "AR": "Argentina", "CL": "Chile",
	"CO": "Colombia", "PE": "Peru", "VE": "Venezuela",
}

func opLangName(code string) string {
	if n, ok := opLangNames[code]; ok {
		return n
	}
	return code
}

func opCountryName(code string) string {
	if n, ok := opRegionNames[code]; ok {
		return n
	}
	return code
}

type opVoiceGroup struct {
	Code   string      `json:"code"`
	Name   string      `json:"name"`
	Voices []db.Record `json:"voices"`
}

// opLangGroups builds {languages, byLang} from grouped voices, sorted
// by language name like the JS routes.
func opLangGroups(byLang map[string]*opVoiceGroup) ([]*opVoiceGroup, map[string]*opVoiceGroup) {
	langs := make([]*opVoiceGroup, 0, len(byLang))
	for _, g := range byLang {
		langs = append(langs, g)
	}
	sort.Slice(langs, func(i, j int) bool { return langs[i].Name < langs[j].Name })
	return langs, byLang
}

func opGroupFor(byLang map[string]*opVoiceGroup, code string) *opVoiceGroup {
	g, ok := byLang[code]
	if !ok {
		g = &opVoiceGroup{Code: code, Name: opLangName(code), Voices: []db.Record{}}
		byLang[code] = g
	}
	return g
}

func opFirstConnectionAPIKey(deps Deps, provider string) string {
	conns, err := deps.Store.GetProviderConnections(db.ConnectionFilter{Provider: provider, IsActive: boolPtrOp(true)})
	if err != nil || len(conns) == 0 {
		return ""
	}
	return opStr(conns[0], "apiKey")
}

func boolPtrOp(b bool) *bool { return &b }

// fetchElevenLabsVoices (ttsProviders/elevenlabs.js).
func opFetchElevenLabsVoices(ctx context.Context, apiKey string) ([]map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.elevenlabs.io/v1/voices", nil)
	if err != nil {
		return nil, err
	}
	if apiKey != "" {
		req.Header.Set("xi-api-key", apiKey)
	}
	resp, err := opHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ElevenLabs API %d: %s", resp.StatusCode, string(raw))
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, err
	}
	var voices []map[string]any
	if arr, ok := data["voices"].([]any); ok {
		for _, v := range arr {
			if m, ok := v.(map[string]any); ok {
				voices = append(voices, m)
			}
		}
	}
	return voices, nil
}

// opElevenLabsGrouped: the elevenlabs route's byLang grouping (shared
// by the dedicated route and the generic route's eleven shape).
func opElevenLabsGrouped(voices []map[string]any) map[string]*opVoiceGroup {
	byLang := map[string]*opVoiceGroup{}
	add := func(code string, v map[string]any) {
		g := opGroupFor(byLang, code)
		id := opStr(v, "voice_id")
		for _, existing := range g.Voices {
			if opStr(existing, "id") == id {
				return
			}
		}
		labels := opMap(v, "labels")
		g.Voices = append(g.Voices, db.Record{
			"id":                 id,
			"name":               opStr(v, "name"),
			"gender":             opStr(labels, "gender"),
			"lang":               code,
			"free_users_allowed": opStr(v, "category") == "premade" || opBool(v, "is_owner"),
		})
	}
	for _, v := range voices {
		labels := opMap(v, "labels")
		primary := opStr(labels, "language")
		if primary == "" {
			primary = "en"
		}
		add(primary, v)
		if arr, ok := v["verified_languages"].([]any); ok {
			for _, lv := range arr {
				m, _ := lv.(map[string]any)
				if m == nil {
					continue
				}
				if lang := opStr(m, "language"); lang != "" && lang != primary {
					add(lang, v)
				}
			}
		}
	}
	return byLang
}

func opVoicesElevenlabs(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := opFirstConnectionAPIKey(deps, "elevenlabs")
		if apiKey == "" {
			Err(w, http.StatusBadRequest, "No ElevenLabs connection found")
			return
		}
		voices, err := opFetchElevenLabsVoices(r.Context(), apiKey)
		if err != nil {
			Err(w, http.StatusBadGateway, err.Error())
			return
		}
		byLang := opElevenLabsGrouped(voices)
		if langFilter := r.URL.Query().Get("lang"); langFilter != "" {
			var out []db.Record
			if g, ok := byLang[langFilter]; ok {
				out = g.Voices
			}
			if out == nil {
				out = []db.Record{}
			}
			WriteJSON(w, http.StatusOK, db.Record{"voices": out})
			return
		}
		langs, groups := opLangGroups(byLang)
		WriteJSON(w, http.StatusOK, db.Record{"languages": langs, "byLang": groups})
	}
}

func opVoicesDeepgram(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := opFirstConnectionAPIKey(deps, "deepgram")
		if apiKey == "" {
			Err(w, http.StatusBadRequest, "No Deepgram connection found")
			return
		}
		status, data, _, err := opFetchJSON(r.Context(), "GET", "https://api.deepgram.com/v1/models",
			map[string]string{"Authorization": "Token " + apiKey}, nil)
		if err != nil {
			Err(w, http.StatusBadGateway, err.Error())
			return
		}
		if status < 200 || status >= 300 {
			Err(w, http.StatusBadGateway, fmt.Sprintf("Deepgram API %d: Failed", status))
			return
		}
		byLang := map[string]*opVoiceGroup{}
		if models, ok := data["tts"].([]any); ok {
			for _, mv := range models {
				m, _ := mv.(map[string]any)
				if m == nil {
					continue
				}
				langs := opStrSlice(m, "languages")
				if len(langs) == 0 {
					cn := opStr(m, "canonical_name")
					parts := strings.Split(cn, "-")
					last := "en"
					if len(parts) > 0 && parts[len(parts)-1] != "" {
						last = parts[len(parts)-1]
					}
					langs = []string{last}
				}
				voiceID := opStr(m, "canonical_name")
				if voiceID == "" {
					voiceID = opStr(m, "name")
				}
				gender := ""
				if tags, ok := opMap(m, "metadata")["tags"].([]any); ok {
					for _, t := range tags {
						if s, _ := t.(string); s == "masculine" || s == "feminine" {
							gender = s
						}
					}
				}
				name := opStr(m, "name")
				if name == "" {
					name = voiceID
				}
				for _, code := range langs {
					g := opGroupFor(byLang, code)
					dup := false
					for _, existing := range g.Voices {
						if opStr(existing, "id") == voiceID {
							dup = true
						}
					}
					if !dup {
						g.Voices = append(g.Voices, db.Record{
							"id": voiceID, "name": name, "gender": gender, "lang": code,
						})
					}
				}
			}
		}
		if langFilter := r.URL.Query().Get("lang"); langFilter != "" {
			var out []db.Record
			if g, ok := byLang[langFilter]; ok {
				out = g.Voices
			}
			if out == nil {
				out = []db.Record{}
			}
			WriteJSON(w, http.StatusOK, db.Record{"voices": out})
			return
		}
		langs, groups := opLangGroups(byLang)
		WriteJSON(w, http.StatusOK, db.Record{"languages": langs, "byLang": groups})
	}
}

func opVoicesInworld(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := opFirstConnectionAPIKey(deps, "inworld")
		if apiKey == "" {
			Err(w, http.StatusBadRequest, "No Inworld connection found")
			return
		}
		status, data, _, err := opFetchJSON(r.Context(), "GET", "https://api.inworld.ai/tts/v1/voices",
			map[string]string{"Authorization": "Basic " + apiKey}, nil)
		if err != nil {
			Err(w, http.StatusBadGateway, err.Error())
			return
		}
		if status < 200 || status >= 300 {
			Err(w, http.StatusBadGateway, fmt.Sprintf("Inworld API %d: Failed", status))
			return
		}
		byLang := map[string]*opVoiceGroup{}
		if arr, ok := data["voices"].([]any); ok {
			for _, vv := range arr {
				v, _ := vv.(map[string]any)
				if v == nil {
					continue
				}
				langs := opStrSlice(v, "languages")
				if len(langs) == 0 {
					langs = []string{"en"}
				}
				id := opStr(v, "voiceId")
				name := opStr(v, "displayName")
				if name == "" {
					name = id
				}
				for _, code := range langs {
					g := opGroupFor(byLang, code)
					dup := false
					for _, existing := range g.Voices {
						if opStr(existing, "id") == id {
							dup = true
						}
					}
					if !dup {
						g.Voices = append(g.Voices, db.Record{
							"id": id, "name": name, "gender": opStr(v, "gender"), "lang": code,
						})
					}
				}
			}
		}
		if langFilter := r.URL.Query().Get("lang"); langFilter != "" {
			var out []db.Record
			if g, ok := byLang[langFilter]; ok {
				out = g.Voices
			}
			if out == nil {
				out = []db.Record{}
			}
			WriteJSON(w, http.StatusOK, db.Record{"voices": out})
			return
		}
		langs, groups := opLangGroups(byLang)
		WriteJSON(w, http.StatusOK, db.Record{"languages": langs, "byLang": groups})
	}
}

var opMinimaxGroups = []struct{ key, label string }{
	{"system_voice", "System"}, {"voice_cloning", "Cloned"},
	{"voice_generation", "Generated"}, {"music_generation", "Music"},
}

func opMinimaxInferLang(voiceID string) string {
	v := strings.TrimSpace(voiceID)
	if !strings.Contains(v, "_") {
		return "Custom"
	}
	first := strings.SplitN(v, "_", 2)[0]
	if first == "" {
		return "Custom"
	}
	return first
}

func opVoicesMinimax(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provider := "minimax"
		if r.URL.Query().Get("provider") == "minimax-cn" {
			provider = "minimax-cn"
		}
		voiceType := r.URL.Query().Get("voice_type")
		if voiceType == "" {
			voiceType = "all"
		}
		apiKey := opFirstConnectionAPIKey(deps, provider)
		if apiKey == "" {
			Err(w, http.StatusBadRequest, fmt.Sprintf("No %s connection found", provider))
			return
		}
		endpoint := "https://api.minimax.io/v1/get_voice"
		if provider == "minimax-cn" {
			endpoint = "https://api.minimaxi.com/v1/get_voice"
		}
		body, _ := json.Marshal(map[string]any{"voice_type": voiceType})
		status, data, _, err := opFetchJSON(r.Context(), "POST", endpoint, map[string]string{
			"Authorization": "Bearer " + apiKey,
			"Content-Type":  "application/json",
		}, body)
		if err != nil {
			Err(w, http.StatusBadGateway, err.Error())
			return
		}
		if status < 200 || status >= 300 {
			Err(w, http.StatusBadGateway, fmt.Sprintf("MiniMax API %d: Failed", status))
			return
		}
		if baseResp := opMap(data, "base_resp"); baseResp != nil {
			if code := opNum(baseResp, "status_code"); code != 0 {
				Err(w, http.StatusBadGateway, fmt.Sprintf("MiniMax API error %d: %s", int(code), opStr(baseResp, "status_msg")))
				return
			}
		}
		byLang := map[string]*opVoiceGroup{}
		add := func(code string, voice db.Record) {
			g, ok := byLang[code]
			if !ok {
				g = &opVoiceGroup{Code: code, Name: code, Voices: []db.Record{}}
				byLang[code] = g
			}
			for _, existing := range g.Voices {
				if opStr(existing, "id") == opStr(voice, "id") {
					return
				}
			}
			g.Voices = append(g.Voices, voice)
		}
		for _, grp := range opMinimaxGroups {
			arr, _ := data[grp.key].([]any)
			for _, iv := range arr {
				item, _ := iv.(map[string]any)
				if item == nil {
					continue
				}
				voiceID := opStr(item, "voice_id")
				if voiceID == "" {
					voiceID = opStr(item, "voiceId")
				}
				if voiceID == "" {
					continue
				}
				voiceName := opStr(item, "voice_name")
				if voiceName == "" {
					voiceName = opStr(item, "voiceName")
				}
				if voiceName == "" {
					voiceName = voiceID
				}
				lang := "Custom"
				name := voiceName + " · " + grp.label
				if grp.key == "system_voice" {
					lang = opMinimaxInferLang(voiceID)
					name = voiceName
				}
				add(lang, db.Record{
					"id": voiceID, "name": name, "lang": lang, "category": grp.key,
				})
			}
		}
		langs := make([]*opVoiceGroup, 0, len(byLang))
		for _, g := range byLang {
			sort.Slice(g.Voices, func(i, j int) bool { return opStr(g.Voices[i], "name") < opStr(g.Voices[j], "name") })
			langs = append(langs, g)
		}
		sort.Slice(langs, func(i, j int) bool {
			if langs[i].Code == "Custom" {
				return false
			}
			if langs[j].Code == "Custom" {
				return true
			}
			return langs[i].Name < langs[j].Name
		})
		if langFilter := r.URL.Query().Get("lang"); langFilter != "" {
			var out []db.Record
			if g, ok := byLang[langFilter]; ok {
				out = g.Voices
			}
			if out == nil {
				out = []db.Record{}
			}
			WriteJSON(w, http.StatusOK, db.Record{"voices": out})
			return
		}
		WriteJSON(w, http.StatusOK, db.Record{"languages": langs, "byLang": byLang})
	}
}

// ----- generic voices route (tts/voices/route.js) -----

var (
	opEdgeVoicesCache   []map[string]any
	opEdgeVoicesCacheAt time.Time
	opEdgeVoicesMu      sync.Mutex
)

func opFetchEdgeVoices(ctx context.Context) ([]map[string]any, error) {
	opEdgeVoicesMu.Lock()
	defer opEdgeVoicesMu.Unlock()
	if opEdgeVoicesCache != nil && time.Since(opEdgeVoicesCacheAt) < 10*time.Minute {
		return opEdgeVoicesCache, nil
	}
	req, err := http.NewRequestWithContext(ctx, "GET",
		"https://speech.platform.bing.com/consumer/speech/synthesize/readaloud/voices/list?trustedclienttoken=6A5AA1D4EAFF4E9FB37E23D68491D6F4", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36")
	resp, err := opHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("Edge TTS voices fetch failed: %d", resp.StatusCode)
	}
	var voices []map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&voices); err != nil {
		return nil, err
	}
	opEdgeVoicesCache = voices
	opEdgeVoicesCacheAt = time.Now()
	return voices, nil
}

var opGeminiPrebuiltVoices = []struct{ id, gender string }{
	{"Zephyr", "Female"}, {"Puck", "Male"}, {"Charon", "Male"}, {"Kore", "Female"},
	{"Fenrir", "Male"}, {"Leda", "Female"}, {"Orus", "Male"}, {"Aoede", "Female"},
	{"Callirrhoe", "Female"}, {"Autonoe", "Female"}, {"Enceladus", "Male"},
	{"Iapetus", "Male"}, {"Umbriel", "Male"}, {"Algieba", "Male"}, {"Despina", "Female"},
	{"Erinome", "Female"}, {"Algenib", "Male"}, {"Rasalgethi", "Male"},
	{"Laomedeia", "Female"}, {"Achernar", "Female"}, {"Alnilam", "Male"},
	{"Schedar", "Male"}, {"Gacrux", "Female"}, {"Pulcherrima", "Female"},
	{"Achird", "Male"}, {"Zubenelgenubi", "Male"}, {"Vindemiatrix", "Female"},
	{"Sadachbia", "Male"}, {"Sadaltager", "Male"}, {"Sulafat", "Female"},
}

func opFetchLocalDeviceVoices() ([]map[string]any, error) {
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("say", "-v", "?").Output()
		if err != nil {
			return nil, err
		}
		re := regexp.MustCompile(`^(\S.*?)\s{2,}([a-z]{2}_[A-Z]{2})`)
		var voices []map[string]any
		for _, line := range strings.Split(string(out), "\n") {
			m := re.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			locale := m[2]
			parts := strings.SplitN(locale, "_", 2)
			voices = append(voices, map[string]any{
				"id": m[1], "name": strings.TrimSpace(m[1]), "locale": locale,
				"lang": parts[0], "country": parts[1], "gender": "",
			})
		}
		return voices, nil
	case "windows":
		script := "Add-Type -AssemblyName System.Speech; $s = New-Object System.Speech.Synthesis.SpeechSynthesizer; $s.GetInstalledVoices() | ForEach-Object { $v = $_.VoiceInfo; [PSCustomObject]@{ Name=$v.Name; Culture=$v.Culture.Name; Gender=$v.Gender } } | ConvertTo-Json -Compress"
		out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script).Output()
		if err != nil {
			return nil, err
		}
		trimmed := strings.TrimSpace(string(out))
		if trimmed == "" {
			return nil, nil
		}
		var raw []map[string]any
		if strings.HasPrefix(trimmed, "{") {
			var single map[string]any
			if err := json.Unmarshal([]byte(trimmed), &single); err == nil {
				raw = []map[string]any{single}
			}
		} else if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
			return nil, err
		}
		var voices []map[string]any
		for _, v := range raw {
			culture := opStr(v, "Culture")
			lang := culture
			country := ""
			if parts := strings.SplitN(culture, "-", 2); len(parts) == 2 {
				lang, country = parts[0], parts[1]
			}
			gender := ""
			if g, ok := v["Gender"].(float64); ok {
				if g == 1 {
					gender = "Female"
				} else if g == 2 {
					gender = "Male"
				}
			}
			voices = append(voices, map[string]any{
				"id": opStr(v, "Name"), "name": opStr(v, "Name"), "locale": culture,
				"lang": lang, "country": country, "gender": gender,
			})
		}
		return voices, nil
	default:
		return nil, nil
	}
}

func opVoicesGeneric(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		provider := q.Get("provider")
		if provider == "" {
			provider = "edge-tts"
		}
		langFilter := q.Get("lang")
		apiKey := q.Get("apiKey")
		ctx := r.Context()
		var voices []db.Record
		switch provider {
		case "edge-tts":
			raw, err := opFetchEdgeVoices(ctx)
			if err != nil {
				Err(w, http.StatusBadGateway, err.Error())
				return
			}
			for _, v := range raw {
				locale := opStr(v, "Locale")
				parts := strings.SplitN(locale, "-", 2)
				lang := parts[0]
				country := ""
				if len(parts) == 2 {
					country = parts[1]
				}
				name := opStr(v, "FriendlyName")
				if name == "" {
					name = opStr(v, "ShortName")
				}
				name = strings.Replace(name, "Microsoft ", "", 1)
				name = strings.ReplaceAll(name, " Online (Natural) - ", " (")
				voices = append(voices, db.Record{
					"id": opStr(v, "ShortName"), "name": name, "locale": locale,
					"lang": lang, "country": country,
					"countryName": opCountryName(firstNonEmptyOp(country, lang)),
					"langName":    opLangName(lang),
					"gender":      opStr(v, "Gender"),
				})
			}
		case "elevenlabs", "gemini":
			var raw []map[string]any
			var err error
			if provider == "elevenlabs" {
				raw, err = opFetchElevenLabsVoices(ctx, apiKey)
			} else {
				for _, pv := range opGeminiPrebuiltVoices {
					raw = append(raw, map[string]any{
						"voice_id": pv.id, "name": pv.id,
						"labels": map[string]any{"language": "en", "gender": pv.gender},
					})
				}
			}
			if err != nil {
				Err(w, http.StatusBadGateway, err.Error())
				return
			}
			for _, v := range raw {
				labels := opMap(v, "labels")
				locale := opStr(labels, "language")
				if locale == "" {
					locale = "en"
				}
				lang := strings.SplitN(locale, "-", 2)[0]
				voices = append(voices, db.Record{
					"id": opStr(v, "voice_id"), "name": opStr(v, "name"), "locale": locale,
					"lang": lang, "country": "", "countryName": "",
					"langName": opLangName(lang),
					"gender":   opStr(labels, "gender"),
					"category": v["category"],
				})
			}
		case "local-device":
			raw, err := opFetchLocalDeviceVoices()
			if err != nil {
				Err(w, http.StatusBadGateway, err.Error())
				return
			}
			for _, v := range raw {
				locale := strings.Replace(opStr(v, "locale"), "_", "-", 1)
				voices = append(voices, db.Record{
					"id": opStr(v, "id"), "name": opStr(v, "name"), "locale": locale,
					"lang": opStr(v, "lang"), "country": opStr(v, "country"),
					"countryName": opCountryName(opStr(v, "country")),
					"langName":    opLangName(opStr(v, "lang")),
					"gender":      opStr(v, "gender"),
				})
			}
		default:
			Err(w, http.StatusBadRequest, fmt.Sprintf("Provider '%s' does not support voice listing", provider))
			return
		}
		if voices == nil {
			voices = []db.Record{}
		}
		if langFilter != "" {
			filtered := []db.Record{}
			for _, v := range voices {
				if opStr(v, "lang") == langFilter {
					filtered = append(filtered, v)
				}
			}
			voices = filtered
		}
		byLang := map[string]*opVoiceGroup{}
		for _, v := range voices {
			lang := opStr(v, "lang")
			g, ok := byLang[lang]
			if !ok {
				g = &opVoiceGroup{Code: lang, Name: opStr(v, "langName"), Voices: []db.Record{}}
				byLang[lang] = g
			}
			g.Voices = append(g.Voices, v)
		}
		langs, groups := opLangGroups(byLang)
		WriteJSON(w, http.StatusOK, db.Record{"voices": voices, "languages": langs, "byLang": groups})
	}
}

func firstNonEmptyOp(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// ---------- MCP stdio↔SSE bridge (lib/mcp/stdioSseBridge.js) ----------

type opMcpPlugin struct {
	name    string
	command string
	args    []string
}

var opMcpPlugins = []opMcpPlugin{
	{name: "browsermcp", command: "npx", args: []string{"-y", "@browsermcp/mcp@latest"}},
}

func opMcpFindPlugin(name string) *opMcpPlugin {
	for i := range opMcpPlugins {
		if opMcpPlugins[i].name == name {
			return &opMcpPlugins[i]
		}
	}
	return nil
}

const (
	opMcpMaxTextChars      = 50000
	opMcpCollapseThreshold = 30
	opMcpCollapseHead      = 10
	opMcpCollapseTail      = 5
)

var opMcpSiblingRe = regexp.MustCompile(`^(\s*)-\s*([a-zA-Z]+)\b`)

// opMcpSmartFilterText ports smartFilterText.
func opMcpSmartFilterText(text string) string {
	if len(text) < 2000 {
		return text
	}
	out := regexp.MustCompile(`(?m)^\s*-\s*generic:?\s*$`).ReplaceAllString(text, "")
	out = regexp.MustCompile(`(?m)^\s*-\s*text:\s*""\s*$`).ReplaceAllString(out, "")
	out = opMcpCollapseRepeated(out)
	if len(out) > opMcpMaxTextChars {
		head := out[:opMcpMaxTextChars-300]
		out = fmt.Sprintf("%s\n\n... [truncated %d chars by 9router bridge. Page is large; ask user to scroll/navigate to a specific section, or click an element with the refs shown above]",
			head, len(text)-len(head))
	}
	return out
}

func opMcpSiblingMatch(line string) (string, string, bool) {
	m := opMcpSiblingRe.FindStringSubmatch(line)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

func opMcpFindNthSiblingEnd(lines []string, start int, indent, role string, n int) int {
	count := 0
	for k := start; k < len(lines); k++ {
		if ind, r, ok := opMcpSiblingMatch(lines[k]); ok && ind == indent && r == role {
			count++
			if count > n {
				return k
			}
		}
	}
	return len(lines)
}

func opMcpFindLastNSiblingStart(lines []string, end int, indent, role string, n int) int {
	var positions []int
	for k := 0; k < end && k < len(lines); k++ {
		if ind, r, ok := opMcpSiblingMatch(lines[k]); ok && ind == indent && r == role {
			positions = append(positions, k)
		}
	}
	if len(positions) > n {
		return positions[len(positions)-n]
	}
	return end
}

// opMcpCollapseRepeated ports collapseRepeated.
func opMcpCollapseRepeated(text string) string {
	lines := strings.Split(text, "\n")
	var out []string
	i := 0
	for i < len(lines) {
		indent, role, ok := opMcpSiblingMatch(lines[i])
		if !ok {
			out = append(out, lines[i])
			i++
			continue
		}
		j := i
		for j < len(lines) {
			ln := lines[j]
			if ind, r, ok2 := opMcpSiblingMatch(ln); ok2 && ind == indent && r == role {
				j++
				continue
			}
			if strings.HasPrefix(ln, indent+" ") || strings.HasPrefix(ln, indent+"\t") {
				j++
				continue
			}
			break
		}
		groupLen := j - i
		if groupLen >= opMcpCollapseThreshold {
			headEnd := opMcpFindNthSiblingEnd(lines, i, indent, role, opMcpCollapseHead)
			tailStart := opMcpFindLastNSiblingStart(lines, j, indent, role, opMcpCollapseTail)
			for k := i; k < headEnd && k < len(lines); k++ {
				out = append(out, lines[k])
			}
			out = append(out, fmt.Sprintf("%s... [%d similar %q items omitted by 9router bridge]",
				indent, groupLen-opMcpCollapseHead-opMcpCollapseTail, role))
			for k := tailStart; k < j && k < len(lines); k++ {
				out = append(out, lines[k])
			}
		} else {
			for k := i; k < j; k++ {
				out = append(out, lines[k])
			}
		}
		i = j
	}
	return strings.Join(out, "\n")
}

// opMcpFilterFrame ports filterFrame.
func opMcpFilterFrame(line string) string {
	var msg map[string]any
	if err := json.Unmarshal([]byte(line), &msg); err != nil {
		return line
	}
	content, ok := opMap(msg, "result")["content"].([]any)
	if !ok {
		return line
	}
	mutated := false
	for _, item := range content {
		m, _ := item.(map[string]any)
		if m == nil || opStr(m, "type") != "text" {
			continue
		}
		if text, ok := m["text"].(string); ok {
			filtered := opMcpSmartFilterText(text)
			if filtered != text {
				m["text"] = filtered
				mutated = true
			}
		}
	}
	if !mutated {
		return line
	}
	raw, err := json.Marshal(msg)
	if err != nil {
		return line
	}
	return string(raw)
}

type opMcpEntry struct {
	cmd      *exec.Cmd
	stdin    io.WriteCloser
	sessions map[string]func(string)
	mu       sync.Mutex
}

var (
	opMcpMu      sync.Mutex
	opMcpEntries = map[string]*opMcpEntry{}
)

func opMcpGetOrSpawn(name string) (*opMcpEntry, error) {
	opMcpMu.Lock()
	defer opMcpMu.Unlock()
	if entry, ok := opMcpEntries[name]; ok && entry.cmd != nil && entry.cmd.ProcessState == nil {
		return entry, nil
	}
	plugin := opMcpFindPlugin(name)
	if plugin == nil {
		return nil, fmt.Errorf("Unknown local plugin: %s", name)
	}
	cmd := exec.Command(plugin.command, plugin.args...)
	cmd.Env = os.Environ()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	entry := &opMcpEntry{cmd: cmd, stdin: stdin, sessions: map[string]func(string){}}
	opMcpEntries[name] = entry
	go func() {
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 64*1024), 4<<20)
		for sc.Scan() {
			AddConsoleLog(fmt.Sprintf("[mcp:%s] %s", name, strings.TrimSpace(sc.Text())))
		}
	}()
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 64*1024), 16<<20)
		for sc.Scan() {
			raw := strings.TrimSpace(sc.Text())
			if raw == "" {
				continue
			}
			line := opMcpFilterFrame(raw)
			chunk := "event: message\ndata: " + line + "\n\n"
			entry.mu.Lock()
			sends := make([]func(string), 0, len(entry.sessions))
			for _, s := range entry.sessions {
				sends = append(sends, s)
			}
			entry.mu.Unlock()
			for _, send := range sends {
				func() {
					defer func() { _ = recover() }()
					send(chunk)
				}()
			}
		}
	}()
	go func() {
		_ = cmd.Wait()
		opMcpMu.Lock()
		if cur, ok := opMcpEntries[name]; ok && cur == entry {
			delete(opMcpEntries, name)
		}
		opMcpMu.Unlock()
	}()
	return entry, nil
}

func opMcpRegisterSession(name string, send func(string)) (string, error) {
	entry, err := opMcpGetOrSpawn(name)
	if err != nil {
		return "", err
	}
	sid := opUUID()
	entry.mu.Lock()
	entry.sessions[sid] = send
	entry.mu.Unlock()
	return sid, nil
}

func opMcpUnregisterSession(name, sid string) {
	opMcpMu.Lock()
	entry, ok := opMcpEntries[name]
	opMcpMu.Unlock()
	if !ok || entry == nil {
		return
	}
	entry.mu.Lock()
	delete(entry.sessions, sid)
	empty := len(entry.sessions) == 0
	entry.mu.Unlock()
	if empty {
		opMcpMu.Lock()
		if cur, ok := opMcpEntries[name]; ok && cur == entry {
			delete(opMcpEntries, name)
		}
		opMcpMu.Unlock()
		if entry.cmd != nil && entry.cmd.Process != nil {
			_ = entry.cmd.Process.Kill()
		}
	}
}

func opMcpSendToChild(name string, jsonRPC map[string]any) error {
	opMcpMu.Lock()
	entry, ok := opMcpEntries[name]
	opMcpMu.Unlock()
	if !ok || entry == nil || entry.stdin == nil {
		return fmt.Errorf("Bridge not running: %s", name)
	}
	raw, err := json.Marshal(jsonRPC)
	if err != nil {
		return err
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	_, err = entry.stdin.Write(append(raw, '\n'))
	return err
}

func opMcpSSE(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		plugin := r.PathValue("plugin")
		if opMcpFindPlugin(plugin) == nil {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, "Unknown plugin: %s", plugin)
			return
		}
		fl, ok := w.(http.Flusher)
		if !ok {
			Err(w, http.StatusInternalServerError, "Streaming unsupported")
			return
		}
		ch := make(chan string, 32)
		var sendMu sync.Mutex
		send := func(chunk string) {
			sendMu.Lock()
			defer sendMu.Unlock()
			select {
			case ch <- chunk:
			default:
			}
		}
		sid, err := opMcpRegisterSession(plugin, send)
		if err != nil {
			Err(w, http.StatusInternalServerError, err.Error())
			return
		}
		defer opMcpUnregisterSession(plugin, sid)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache, no-transform")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "event: endpoint\ndata: /api/mcp/%s/message?sessionId=%s\n\n", plugin, sid)
		fl.Flush()
		ctx := r.Context()
		for {
			select {
			case <-ctx.Done():
				return
			case chunk := <-ch:
				fmt.Fprint(w, chunk)
				fl.Flush()
			}
		}
	}
}

func opMcpMessage(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		plugin := r.PathValue("plugin")
		if opMcpFindPlugin(plugin) == nil {
			Err(w, http.StatusNotFound, fmt.Sprintf("Unknown plugin: %s", plugin))
			return
		}
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := opMcpSendToChild(plugin, body); err != nil {
			Err(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}
}

// ---------- tunnel routes (src/app/api/tunnel) ----------

var (
	opTunnelCacheMu sync.Mutex
	opTunnelCache   db.Record
	opTunnelCacheAt time.Time
)

// opTunnelStatus ports tunnel/status: probes cached 3s, download live.
func opTunnelStatus(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		opTunnelCacheMu.Lock()
		if opTunnelCache == nil || time.Since(opTunnelCacheAt) >= 3*time.Second {
			tun, err := tunnel.GetTunnelStatus(deps.Store)
			if err != nil {
				opTunnelCacheMu.Unlock()
				Err(w, http.StatusInternalServerError, err.Error())
				return
			}
			ts, err := tunnel.GetTailscaleStatus(deps.Store)
			if err != nil {
				opTunnelCacheMu.Unlock()
				Err(w, http.StatusInternalServerError, err.Error())
				return
			}
			opTunnelCache = db.Record{"tunnel": tun, "tailscale": ts}
			opTunnelCacheAt = time.Now()
		}
		probes := opTunnelCache
		opTunnelCacheMu.Unlock()
		out := db.Record{}
		for k, v := range probes {
			out[k] = v
		}
		out["download"] = tunnel.GetDownloadStatus()
		WriteJSON(w, http.StatusOK, out)
	}
}

func opTunnelEnable(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result, err := tunnel.EnableTunnel(deps.Store, opServerPort())
		if err != nil {
			Err(w, http.StatusInternalServerError, err.Error())
			return
		}
		// DNS warmup wait (route-level in the JS).
		time.Sleep(8 * time.Second)
		WriteJSON(w, http.StatusOK, result)
	}
}

func opTunnelDisable(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result, err := tunnel.DisableTunnel(deps.Store)
		if err != nil {
			Err(w, http.StatusInternalServerError, err.Error())
			return
		}
		WriteJSON(w, http.StatusOK, result)
	}
}

func opTailscaleEnable(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result, err := tunnel.EnableTailscale(deps.Store, opServerPort())
		if err != nil {
			Err(w, http.StatusInternalServerError, err.Error())
			return
		}
		WriteJSON(w, http.StatusOK, result)
	}
}

func opTailscaleDisable(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result, err := tunnel.DisableTailscale(deps.Store)
		if err != nil {
			Err(w, http.StatusInternalServerError, err.Error())
			return
		}
		WriteJSON(w, http.StatusOK, result)
	}
}

func opPlatformName() string {
	if runtime.GOOS == "windows" {
		return "win32"
	}
	return runtime.GOOS
}

func opHasBrew() bool {
	_, err := exec.LookPath("brew")
	return err == nil
}

// opTailscaleCheck ports tunnel/tailscale-check.
func opTailscaleCheck(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		installed := tunnel.IsTailscaleInstalled()
		platform := opPlatformName()
		brewAvailable := platform == "darwin" && opHasBrew()
		var customDaemon, systemDaemon bool
		if installed {
			customDaemon = tunnel.IsDaemonAlive()
			systemDaemon = tunnel.IsSystemDaemonRunning()
		}
		daemonRunning := customDaemon || systemDaemon
		loggedIn := false
		if daemonRunning {
			loggedIn = tunnel.IsTailscaleLoggedIn()
		}
		hasCachedPassword := mitm.GetCachedPassword() != ""
		if !hasCachedPassword {
			if p, _ := mitm.LoadEncryptedPassword(); p != "" {
				hasCachedPassword = true
			}
		}
		WriteJSON(w, http.StatusOK, db.Record{
			"installed":           installed,
			"loggedIn":            loggedIn,
			"platform":            platform,
			"brewAvailable":       brewAvailable,
			"daemonRunning":       daemonRunning,
			"customDaemonRunning": customDaemon,
			"systemDaemonRunning": systemDaemon,
			"hasCachedPassword":   hasCachedPassword,
		})
	}
}

// opTailscaleInstall ports tunnel/tailscale-install (SSE progress).
func opTailscaleInstall(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := ReadBodyJSON(r)
		platform := opPlatformName()
		isWindows := platform == "win32"
		isBrew := platform == "darwin" && opHasBrew()
		needsPassword := !isWindows && !isBrew
		sudoPassword := Str(body, "sudoPassword")
		if sudoPassword == "" {
			sudoPassword = mitm.GetCachedPassword()
		}
		if sudoPassword == "" {
			sudoPassword, _ = mitm.LoadEncryptedPassword()
		}
		if needsPassword && strings.TrimSpace(sudoPassword) == "" {
			Err(w, http.StatusBadRequest, "Sudo password is required")
			return
		}
		hostname := ""
		if state := tunnel.LoadState(); state != nil {
			hostname = opStr(state, "shortId")
		}
		if hostname == "" {
			hostname = tunnel.GenerateShortId()
		}
		fl, ok := w.(http.Flusher)
		if !ok {
			Err(w, http.StatusInternalServerError, "Streaming unsupported")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)
		send := func(event string, data db.Record) {
			payload, _ := json.Marshal(data)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, payload)
			fl.Flush()
		}
		result, err := tunnel.InstallTailscale(sudoPassword, hostname, func(msg string) {
			send("progress", db.Record{"message": msg})
		})
		if err != nil {
			msg := err.Error()
			if strings.Contains(msg, "incorrect password") || strings.Contains(msg, "Sorry") {
				msg = "Wrong sudo password"
			}
			send("error", db.Record{"error": msg})
			return
		}
		var authURL any
		if result != nil && result.AuthURL != "" {
			authURL = result.AuthURL
		}
		send("done", db.Record{"success": true, "authUrl": authURL})
	}
}

// ---------- headroom (lib/headroom detect.js + process.js) ----------

const opHrDefaultURL = "http://localhost:8787"

type opCodedError struct {
	code string
	msg  string
}

func (e *opCodedError) Error() string { return e.msg }

func opHrDir() string { return filepath.Join(db.DataDir(), "headroom") }
func opHrPidFile() string {
	return filepath.Join(opHrDir(), "proxy.pid")
}
func opHrLogFile() string { return filepath.Join(opHrDir(), "proxy.log") }
func opHrInstallLogFile() string {
	return filepath.Join(opHrDir(), "install.log")
}

func opExtendedPATH() string {
	extra := "/usr/local/bin:/opt/homebrew/bin:/usr/sbin:/usr/bin:/bin:/snap/bin"
	if runtime.GOOS == "windows" {
		return os.Getenv("PATH")
	}
	return extra + ":" + os.Getenv("PATH")
}

func opLookPath(name string) string {
	env := os.Environ()
	for i, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			env[i] = "PATH=" + opExtendedPATH()
		}
	}
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("where", name)
	} else {
		cmd = exec.Command("which", name)
	}
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 {
		return ""
	}
	return strings.TrimSpace(lines[0])
}

func opHrFindBinary() string { return opLookPath("headroom") }

var opHrPythonCandidates = []string{"python3.13", "python3.12", "python3.11", "python3.10", "python3", "python"}

func opHrPythonVersion(py string) (int, int, bool) {
	out, err := exec.Command(py, "--version").CombinedOutput()
	if err != nil {
		return 0, 0, false
	}
	m := regexp.MustCompile(`(\d+)\.(\d+)`).FindStringSubmatch(string(out))
	if m == nil {
		return 0, 0, false
	}
	maj, _ := strconv.Atoi(m[1])
	min, _ := strconv.Atoi(m[2])
	return maj, min, true
}

// opHrFindPython ports findPython310 (prefers an interpreter that has
// headroom-ai installed, else the first ≥3.10).
func opHrFindPython() string {
	var fallback string
	for _, cand := range opHrPythonCandidates {
		py := opLookPath(cand)
		if py == "" {
			continue
		}
		maj, min, ok := opHrPythonVersion(py)
		if !ok || !(maj > 3 || (maj == 3 && min >= 10)) {
			continue
		}
		if fallback == "" {
			fallback = py
		}
		if err := exec.Command(py, "-m", "pip", "show", "headroom-ai").Run(); err == nil {
			return py
		}
	}
	return fallback
}

var opHrExtraMarkers = map[string][]string{
	"code": {"tree-sitter", "tree-sitter-language-pack"},
	"ml":   {"torch", "huggingface-hub"},
}

var opHrExtrasList = []string{"code", "ml"}

// opHrExtrasStatus ports getInstalledHeadroomExtras.
func opHrExtrasStatus(py string) db.Record {
	none := db.Record{"installed": false, "version": nil, "extras": db.Record{"code": false, "ml": false}}
	if py == "" {
		py = opHrFindPython()
	}
	if py == "" {
		return none
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, py, "-m", "pip", "list", "--format=json", "--disable-pip-version-check").Output()
	if err != nil {
		return none
	}
	var pkgs []map[string]any
	if err := json.Unmarshal(out, &pkgs); err != nil {
		return none
	}
	names := map[string]bool{}
	var version any
	for _, p := range pkgs {
		name := strings.ToLower(opStr(p, "name"))
		names[name] = true
		if name == "headroom-ai" {
			version = p["version"]
		}
	}
	if !names["headroom-ai"] {
		return none
	}
	extras := db.Record{}
	for _, extra := range opHrExtrasList {
		has := false
		for _, marker := range opHrExtraMarkers[extra] {
			if names[marker] {
				has = true
			}
		}
		extras[extra] = has
	}
	return db.Record{"installed": true, "version": version, "extras": extras}
}

func opHrIsLoopback(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.Trim(u.Hostname(), "[]")
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func opHrProbeRunning(rawURL string) bool {
	if rawURL == "" {
		return false
	}
	base := strings.TrimSuffix(rawURL, "/")
	client := &http.Client{Timeout: 1500 * time.Millisecond}
	resp, err := client.Get(base + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func opHrSettingsURL(deps Deps) string {
	settings, err := deps.Store.GetSettings()
	if err == nil {
		if u := opStr(settings, "headroomUrl"); u != "" {
			return u
		}
	}
	if v := os.Getenv("HEADROOM_URL"); v != "" {
		return v
	}
	return opHrDefaultURL
}

// opHrStatus ports getHeadroomStatus + the status route additions.
func opHrStatus(deps Deps) db.Record {
	rawURL := opHrSettingsURL(deps)
	path := opHrFindBinary()
	python := opHrFindPython()
	installed := path != ""
	localURL := opHrIsLoopback(rawURL)
	extras := db.Record{"installed": false, "version": nil, "extras": db.Record{"code": false, "ml": false}}
	if installed {
		extras = opHrExtrasStatus(python)
	}
	var pathVal, pythonVal, versionVal any
	if installed {
		pathVal = path
	}
	if python != "" {
		pythonVal = python
	}
	versionVal = extras["version"]
	return db.Record{
		"installed":  installed,
		"path":       pathVal,
		"running":    opHrProbeRunning(rawURL),
		"python":     pythonVal,
		"localUrl":   localURL,
		"canStart":   installed && localURL,
		"version":    versionVal,
		"extras":     extras["extras"],
		"url":        rawURL,
		"managedPid": opHrManagedPid(),
	}
}

func opPidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	if runtime.GOOS == "windows" {
		out, err := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/NH").CombinedOutput()
		return err == nil && strings.Contains(string(out), strconv.Itoa(pid))
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscallSignal0()) == nil
}

func opHrManagedPid() any {
	raw, err := os.ReadFile(opHrPidFile())
	if err != nil {
		return nil
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || !opPidAlive(pid) {
		return nil
	}
	return pid
}

func opHrReadPid() int {
	if v, ok := opHrManagedPid().(int); ok {
		return v
	}
	return 0
}

func opHrWritePid(pid int) {
	_ = os.MkdirAll(opHrDir(), 0o755)
	_ = os.WriteFile(opHrPidFile(), []byte(strconv.Itoa(pid)), 0o644)
}

func opHrClearPid() { _ = os.Remove(opHrPidFile()) }

var (
	opHrMu    sync.Mutex
	opHrProcs = map[int]*exec.Cmd{}
)

// opHrStart ports startHeadroomProxy.
func opHrStart(port int, codeAware bool, kompress bool) (db.Record, error) {
	if port <= 0 || port >= 65536 {
		port = 8787
	}
	binary := opHrFindBinary()
	if binary == "" {
		return nil, &opCodedError{code: "NOT_INSTALLED", msg: "Headroom CLI not installed"}
	}
	if existing := opHrReadPid(); existing > 0 {
		return db.Record{"pid": existing, "alreadyRunning": true}, nil
	}
	_ = os.MkdirAll(opHrDir(), 0o755)
	logFile, err := os.OpenFile(opHrLogFile(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	defer logFile.Close()
	args := []string{"proxy", "--port", strconv.Itoa(port)}
	if codeAware {
		args = append(args, "--code-aware")
	}
	if !kompress {
		args = append(args, "--disable-kompress")
	}
	cmd := exec.Command(binary, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = sysProcDetached()
	if err := cmd.Start(); err != nil {
		return nil, &opCodedError{code: "SPAWN_FAILED", msg: "Failed to spawn headroom proxy"}
	}
	pid := cmd.Process.Pid
	opHrMu.Lock()
	opHrProcs[pid] = cmd
	opHrMu.Unlock()
	opHrWritePid(pid)
	exitCh := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		opHrMu.Lock()
		delete(opHrProcs, pid)
		opHrMu.Unlock()
		exitCh <- err
	}()
	select {
	case err := <-exitCh:
		opHrClearPid()
		code := 0
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		}
		return nil, &opCodedError{code: "EARLY_EXIT", msg: fmt.Sprintf("headroom proxy exited early (code=%d) — see proxy.log", code)}
	case <-time.After(8 * time.Second):
		if !opPidAlive(pid) {
			return nil, errors.New("headroom proxy exited during startup — see proxy.log")
		}
	}
	return db.Record{"pid": pid, "alreadyRunning": false}, nil
}

// opHrStop ports stopHeadroomProxy.
func opHrStop() (db.Record, error) {
	pid := opHrReadPid()
	if pid == 0 {
		return db.Record{"stopped": false, "reason": "not_running"}, nil
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		opHrClearPid()
		return nil, &opCodedError{code: "STOP_FAILED", msg: "Failed to stop headroom proxy: " + err.Error()}
	}
	_ = proc.Signal(syscallSIGTERM())
	go func() {
		time.Sleep(2 * time.Second)
		if opPidAlive(pid) {
			if p, err := os.FindProcess(pid); err == nil {
				_ = p.Kill()
			}
		}
	}()
	opHrClearPid()
	return db.Record{"stopped": true, "pid": pid}, nil
}

// opHrRestart ports restartHeadroomProxy.
func opHrRestart(port int, codeAware bool, kompress bool) (db.Record, error) {
	if pid := opHrReadPid(); pid > 0 {
		if proc, err := os.FindProcess(pid); err == nil {
			_ = proc.Signal(syscallSIGTERM())
		}
		for i := 0; i < 30 && opPidAlive(pid); i++ {
			time.Sleep(100 * time.Millisecond)
		}
		if opPidAlive(pid) {
			if proc, err := os.FindProcess(pid); err == nil {
				_ = proc.Kill()
			}
		}
		opHrClearPid()
	}
	return opHrStart(port, codeAware, kompress)
}

func opHrParsePort(rawURL string) int {
	u, err := url.Parse(rawURL)
	if err != nil {
		return 0
	}
	if p, err := strconv.Atoi(u.Port()); err == nil && p > 0 && p < 65536 {
		return p
	}
	return 0
}

func opHeadroomStatus(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		WriteJSON(w, http.StatusOK, opHrStatus(deps))
	}
}

func opHeadroomStart(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rawURL := opHrSettingsURL(deps)
		if !opHrIsLoopback(rawURL) {
			WriteJSON(w, http.StatusBadRequest, db.Record{
				"error": "External Headroom proxies must be started outside 9Router",
				"code":  "EXTERNAL_PROXY",
			})
			return
		}
		settings, _ := deps.Store.GetSettings()
		port := opHrParsePort(rawURL)
		if port == 0 {
			port = 8787
		}
		result, err := opHrStart(port, opBool(settings, "headroomCodeAware"), !opSettingsFalse(settings, "headroomKompress"))
		opWriteHrResult(w, result, err)
	}
}

func opSettingsFalse(settings db.Record, key string) bool {
	if settings == nil {
		return false
	}
	v, ok := settings[key].(bool)
	return ok && !v
}

func opWriteHrResult(w http.ResponseWriter, result db.Record, err error) {
	if err != nil {
		status := http.StatusInternalServerError
		code := any(nil)
		if ce, ok := err.(*opCodedError); ok {
			code = ce.code
			if ce.code == "NOT_INSTALLED" || ce.code == "NO_PYTHON" || ce.code == "INVALID_EXTRAS" {
				status = http.StatusBadRequest
			}
		}
		WriteJSON(w, status, db.Record{"error": err.Error(), "code": code})
		return
	}
	out := db.Record{"success": true}
	for k, v := range result {
		out[k] = v
	}
	WriteJSON(w, http.StatusOK, out)
}

func opHeadroomStop(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result, err := opHrStop()
		if err != nil {
			opWriteHrResult(w, nil, err)
			return
		}
		status := http.StatusOK
		if !opBool(result, "stopped") {
			status = http.StatusConflict
		}
		WriteJSON(w, status, result)
	}
}

func opHeadroomRestart(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rawURL := opHrSettingsURL(deps)
		if !opHrIsLoopback(rawURL) {
			WriteJSON(w, http.StatusBadRequest, db.Record{
				"error": "External Headroom proxies must be started outside 9Router",
				"code":  "EXTERNAL_PROXY",
			})
			return
		}
		settings, _ := deps.Store.GetSettings()
		port := opHrParsePort(rawURL)
		if port == 0 {
			port = 8787
		}
		result, err := opHrRestart(port, opBool(settings, "headroomCodeAware"), !opSettingsFalse(settings, "headroomKompress"))
		opWriteHrResult(w, result, err)
	}
}

func opHrInstallLogTail(maxLines int) string {
	raw, err := os.ReadFile(opHrInstallLogFile())
	if err != nil {
		return ""
	}
	var lines []string
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.TrimRight(l, "\r") != "" {
			lines = append(lines, strings.TrimRight(l, "\r"))
		}
	}
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return strings.Join(lines, "\n")
}

func opHrFilterExtras(body map[string]any) []string {
	var out []string
	if arr, ok := body["extras"].([]any); ok {
		for _, v := range arr {
			if s, ok := v.(string); ok && (s == "code" || s == "ml") {
				out = append(out, s)
			}
		}
	}
	return out
}

func opHrRunPip(py string, args []string) int {
	_ = os.MkdirAll(opHrDir(), 0o755)
	logFile, err := os.OpenFile(opHrInstallLogFile(), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return -1
	}
	defer logFile.Close()
	cmd := exec.Command(py, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		return -1
	}
	return 0
}

func opHeadroomExtrasGet(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("log") == "1" {
			WriteJSON(w, http.StatusOK, db.Record{"log": opHrInstallLogTail(15)})
			return
		}
		py := opHrFindPython()
		status := opHrExtrasStatus(py)
		WriteJSON(w, http.StatusOK, db.Record{
			"available": opHrExtrasList,
			"installed": status["installed"],
			"version":   status["version"],
			"extras":    status["extras"],
		})
	}
}

func opHeadroomExtrasPost(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := ReadBodyJSON(r)
		requested := opHrFilterExtras(body)
		py := opHrFindPython()
		if py == "" {
			opWriteHrResult(w, nil, &opCodedError{code: "NO_PYTHON", msg: "Python >= 3.10 not found"})
			return
		}
		if opHrFindBinary() == "" {
			opWriteHrResult(w, nil, &opCodedError{code: "NOT_INSTALLED", msg: "headroom-ai not installed (run `pip install headroom-ai[proxy]` first)"})
			return
		}
		spec := "headroom-ai[proxy"
		if len(requested) > 0 {
			spec += "," + strings.Join(requested, ",")
		}
		spec += "]"
		code := opHrRunPip(py, []string{"-m", "pip", "install", "--upgrade", spec})
		if code != 0 {
			opWriteHrResult(w, nil, &opCodedError{code: "INSTALL_FAILED", msg: fmt.Sprintf("pip install exited with code=%d — see headroom/install.log", code)})
			return
		}
		status := opHrExtrasStatus(py)
		// JS spreads the extras status last, so its `extras` object
		// replaces the requested list in the response.
		WriteJSON(w, http.StatusOK, db.Record{
			"success": true, "code": 0, "spec": spec,
			"installed": status["installed"], "version": status["version"], "extras": status["extras"],
		})
	}
}

func opHeadroomExtrasDelete(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := ReadBodyJSON(r)
		requested := opHrFilterExtras(body)
		py := opHrFindPython()
		if py == "" {
			opWriteHrResult(w, nil, &opCodedError{code: "NO_PYTHON", msg: "Python >= 3.10 not found"})
			return
		}
		seen := map[string]bool{}
		var pkgs []string
		for _, e := range requested {
			for _, p := range opHrExtraMarkers[e] {
				if !seen[p] {
					seen[p] = true
					pkgs = append(pkgs, p)
				}
			}
		}
		if len(pkgs) == 0 {
			opWriteHrResult(w, nil, &opCodedError{code: "INVALID_EXTRAS", msg: "No valid extras to remove"})
			return
		}
		args := append([]string{"-m", "pip", "uninstall", "-y"}, pkgs...)
		code := opHrRunPip(py, args)
		if code != 0 {
			opWriteHrResult(w, nil, &opCodedError{code: "UNINSTALL_FAILED", msg: fmt.Sprintf("pip uninstall exited with code=%d — see headroom/install.log", code)})
			return
		}
		status := opHrExtrasStatus(py)
		WriteJSON(w, http.StatusOK, db.Record{
			"success": true, "code": 0, "removed": pkgs,
			"installed": status["installed"], "version": status["version"], "extras": status["extras"],
		})
	}
}

// ---------- headroom proxy route ----------

var opHopByHop = map[string]bool{
	"connection": true, "keep-alive": true, "proxy-authenticate": true,
	"proxy-authorization": true, "te": true, "trailer": true,
	"transfer-encoding": true, "upgrade": true,
}

// opHrRewriteDashboard ports rewriteDashboardHtml: fetch('/stats…'),
// fetch('/health…'), fetch('/stats-history…') and
// fetch('/transformations/feed…') in the headroom dashboard HTML are
// re-pointed at the proxy prefix. RE2 has no lookahead, so this is a
// manual scan (same fix class as Team I's TOML regex).
func opHrRewriteDashboard(html string) string {
	prefixes := []string{"/stats", "/health", "/stats-history", "/transformations/feed"}
	var b strings.Builder
	rest := html
	for {
		idx := strings.Index(rest, "fetch('")
		if idx < 0 {
			b.WriteString(rest)
			break
		}
		after := rest[idx+len("fetch('"):]
		matched := false
		for _, p := range prefixes {
			if strings.HasPrefix(after, p) {
				matched = true
				break
			}
		}
		if matched {
			b.WriteString(rest[:idx])
			b.WriteString("fetch('/api/headroom/proxy")
			rest = after
		} else {
			b.WriteString(rest[:idx+len("fetch('")])
			rest = after
		}
	}
	return b.String()
}

func opHeadroomProxy(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rawURL := opHrSettingsURL(deps)
		base, err := url.Parse(rawURL)
		if err != nil || (base.Scheme != "http" && base.Scheme != "https") {
			Err(w, http.StatusInternalServerError, "Headroom URL must use http or https")
			return
		}
		path := r.PathValue("path")
		target := *base
		target.Path = "/" + path
		target.RawPath = ""
		target.RawQuery = r.URL.RawQuery
		var body io.Reader
		if r.Method != "GET" && r.Method != "HEAD" {
			body = r.Body
		}
		outReq, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), body)
		if err != nil {
			Err(w, http.StatusInternalServerError, err.Error())
			return
		}
		loopback := opHrIsLoopback(target.String())
		for k, vs := range r.Header {
			lk := strings.ToLower(k)
			if opHopByHop[lk] || lk == "host" {
				continue
			}
			if !loopback && (lk == "cookie" || lk == "authorization") {
				continue
			}
			for _, v := range vs {
				outReq.Header.Add(k, v)
			}
		}
		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		resp, err := client.Do(outReq)
		if err != nil {
			Err(w, http.StatusInternalServerError, err.Error())
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			if opHopByHop[strings.ToLower(k)] {
				continue
			}
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		if path == "dashboard" && strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
			rewritten := opHrRewriteDashboard(string(raw))
			w.Header().Del("Content-Length")
			w.WriteHeader(resp.StatusCode)
			_, _ = io.WriteString(w, rewritten)
			return
		}
		w.WriteHeader(resp.StatusCode)
		fl, _ := w.(http.Flusher)
		buf := make([]byte, 32*1024)
		for {
			n, rerr := resp.Body.Read(buf)
			if n > 0 {
				_, _ = w.Write(buf[:n])
				if fl != nil {
					fl.Flush()
				}
			}
			if rerr != nil {
				return
			}
		}
	}
}

// ---------- pxpipe (lib/pxpipe) ----------
//
// pxpipe-proxy is loaded in-process by the JS server
// (lib/pxpipe/loader.js). The Go port cannot import a JS library, but
// the package ships a standalone server entry (bin/cli.js), so
// internal/pxpipe supervises it as a managed child process — start /
// stop / restart / running are real, with PXPIPE_LOG pointed at the
// events.jsonl below. Everything filesystem-shaped (npm install,
// events, stats, logs) is real. See internal/pxpipe for the full
// investigation notes and the documented divergence (the Go chat
// pipeline does not route through the child proxy).

func opPxDir() string { return filepath.Join(db.DataDir(), "pxpipe") }
func opPxPackageRoot() string {
	return filepath.Join(opPxDir(), "node_modules", "pxpipe-proxy")
}
func opPxLibraryEntry() string {
	return filepath.Join(opPxPackageRoot(), "dist", "core", "library.js")
}
func opPxInstallLogFile() string { return filepath.Join(opPxDir(), "install.log") }

func opPxInstallInfo() db.Record {
	pkgJSON := filepath.Join(opPxPackageRoot(), "package.json")
	if _, err := os.Stat(pkgJSON); err != nil {
		return db.Record{"installed": false, "version": nil, "path": nil}
	}
	if _, err := os.Stat(opPxLibraryEntry()); err != nil {
		return db.Record{"installed": false, "version": nil, "path": nil}
	}
	raw, err := os.ReadFile(pkgJSON)
	if err != nil {
		return db.Record{"installed": false, "version": nil, "path": nil}
	}
	var pkg map[string]any
	_ = json.Unmarshal(raw, &pkg)
	var version any
	if v := opStr(pkg, "version"); v != "" {
		version = v
	}
	return db.Record{"installed": true, "version": version, "path": opPxPackageRoot()}
}

var (
	opPxInstallMu       sync.Mutex
	opPxInstalling      bool
	opPxInstallDone     chan struct{}
	opPxInstallErr      error
	opPxInstallErrCoded string
)

func opPxIsInstalling() bool {
	opPxInstallMu.Lock()
	defer opPxInstallMu.Unlock()
	return opPxInstalling
}

// opPxInstall runs (or joins) the serialized npm install.
func opPxInstall() (db.Record, error) {
	opPxInstallMu.Lock()
	if opPxInstalling {
		done := opPxInstallDone
		opPxInstallMu.Unlock()
		<-done
		opPxInstallMu.Lock()
		err := opPxInstallErr
		opPxInstallMu.Unlock()
		if err != nil {
			return nil, err
		}
		return opPxInstallInfo(), nil
	}
	opPxInstalling = true
	opPxInstallDone = make(chan struct{})
	opPxInstallMu.Unlock()

	err := opPxRunInstall()
	opPxInstallMu.Lock()
	opPxInstallErr = err
	opPxInstalling = false
	close(opPxInstallDone)
	opPxInstallMu.Unlock()
	if err != nil {
		return nil, err
	}
	return opPxInstallInfo(), nil
}

func opPxRunInstall() error {
	npm := opLookPath("npm")
	if npm == "" {
		return &opCodedError{code: "NPM_NOT_FOUND", msg: "npm not found in PATH. Install Node.js to use PXPIPE."}
	}
	_ = os.MkdirAll(opPxDir(), 0o755)
	hostPkg := filepath.Join(opPxDir(), "package.json")
	if _, err := os.Stat(hostPkg); err != nil {
		_ = os.WriteFile(hostPkg, []byte("{\n  \"name\": \"9router-pxpipe-host\",\n  \"private\": true\n}\n"), 0o644)
	}
	logFile, err := os.OpenFile(opPxInstallLogFile(), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer logFile.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, npm, "install", "pxpipe-proxy@latest", "--no-audit", "--no-fund", "--omit=dev")
	cmd.Dir = opPxDir()
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("npm install exited with code %d — see install.log", exitErr.ExitCode())
		}
		return err
	}
	return nil
}

func opPxInstallLogTail(maxLines int) string {
	raw, err := os.ReadFile(opPxInstallLogFile())
	if err != nil {
		return ""
	}
	var lines []string
	for _, l := range strings.Split(string(raw), "\n") {
		lines = append(lines, strings.TrimRight(l, "\r"))
	}
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return strings.Join(lines, "\n")
}

func opPxStatus(deps Deps) db.Record {
	info := opPxInstallInfo()
	// "running" in the Go port = the managed pxpipe child process is
	// alive and its port answers (internal/pxpipe). loadedAt/uptimeMs
	// describe the child, mirroring the JS module loadedAt/uptimeMs.
	var loadedAt any
	uptimeMs := float64(0)
	st, running := pxpipe.Running(opPxDir())
	if running {
		loadedAt = st.StartedAt
		if up := time.Now().UnixMilli() - st.StartedAt; up > 0 {
			uptimeMs = float64(up)
		}
	}
	return db.Record{
		"installed":    info["installed"],
		"installing":   opPxIsInstalling(),
		"version":      info["version"],
		"path":         info["path"],
		"running":      running,
		"loadedAt":     loadedAt,
		"uptimeMs":     uptimeMs,
		"npmAvailable": opLookPath("npm") != "",
		"mode":         "library",
	}
}

// opPxHealth ports runHealthCheck. The JS loads the module in-process
// and self-tests it; the Go port checks the same facts from outside:
// package entry points present + a Node runtime to load them, then the
// exact JS self-test (synthetic transform) in a one-shot node process
// via internal/pxpipe.
func opPxHealth() db.Record {
	info := opPxInstallInfo()
	installed := opBool(info, "installed")
	var detail any
	if v, ok := info["version"].(string); ok && v != "" {
		detail = "v" + v
	}
	checks := []db.Record{
		{"id": "installed", "label": "PXPIPE installed", "ok": installed, "detail": detail},
	}
	if !installed {
		return db.Record{"healthy": false, "checks": checks, "error": "pxpipe not installed"}
	}
	dir := opPxDir()
	moduleOK := pxpipe.FindNode() != ""
	moduleDetail := detail
	if !moduleOK {
		moduleDetail = "Node.js runtime not found in PATH (required to load the pxpipe package)"
	} else if _, err := os.Stat(pxpipe.LibraryEntry(dir)); err != nil {
		moduleOK = false
		moduleDetail = "dist/core/library.js missing — reinstall PXPIPE"
	}
	checks = append(checks, db.Record{
		"id": "module", "label": "Transform module loads", "ok": moduleOK, "detail": moduleDetail,
	})
	if !moduleOK {
		return db.Record{"healthy": false, "checks": checks, "error": "Cannot load module: " + fmt.Sprint(moduleDetail)}
	}
	test, err := pxpipe.SelfTest(dir, 30*time.Second)
	if err != nil {
		checks = append(checks, db.Record{
			"id": "transform", "label": "Test request transforms", "ok": false, "detail": err.Error(),
		})
		return db.Record{"healthy": false, "checks": checks, "error": "Self-test failed: " + err.Error()}
	}
	checks = append(checks, db.Record{
		"id": "transform", "label": "Test request transforms", "ok": true,
		"detail": fmt.Sprintf("%dms (%s)", test.DurationMs, test.Reason),
	})
	return db.Record{"healthy": true, "checks": checks, "error": nil}
}

func opPxReadEvents(limit int) []db.Record {
	var events []db.Record
	for _, file := range []string{opPxDir() + "/events.jsonl.1", opPxDir() + "/events.jsonl"} {
		raw, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var ev db.Record
			if err := json.Unmarshal([]byte(line), &ev); err == nil && ev != nil {
				events = append(events, ev)
			}
		}
	}
	sort.SliceStable(events, func(i, j int) bool {
		return opNum(events[i], "ts") < opNum(events[j], "ts")
	})
	if limit > 0 && len(events) > limit {
		events = events[len(events)-limit:]
	}
	return events
}

type opPxTotals struct {
	Requests          float64 `json:"requests"`
	Compressed        float64 `json:"compressed"`
	Bypassed          float64 `json:"bypassed"`
	Errors            float64 `json:"errors"`
	TokensBeforeEst   float64 `json:"tokensBeforeEst"`
	TokensAfterEst    float64 `json:"tokensAfterEst"`
	TokensSavedEst    float64 `json:"tokensSavedEst"`
	SavedPct          float64 `json:"savedPct"`
	ImagesGenerated   float64 `json:"imagesGenerated"`
	CompressionTimeMs float64 `json:"compressionTimeMs"`
	AvgCompressionMs  float64 `json:"avgCompressionMs"`
}

func opPxAccumulate(t *opPxTotals, ev db.Record) {
	t.Requests++
	if opBool(ev, "applied") {
		t.Compressed++
		t.TokensBeforeEst += opNum(ev, "tokensBeforeEst")
		t.TokensAfterEst += opNum(ev, "tokensAfterEst")
		t.TokensSavedEst += opNum(ev, "tokensSavedEst")
		t.ImagesGenerated += opNum(ev, "imageCount")
		t.CompressionTimeMs += opNum(ev, "durationMs")
	} else if reason := opStr(ev, "reason"); reason == "transform_error" || reason == "timeout" {
		t.Errors++
	} else {
		t.Bypassed++
	}
}

func opPxFinalize(t *opPxTotals) {
	if t.TokensBeforeEst > 0 {
		t.SavedPct = math.Round((t.TokensSavedEst/t.TokensBeforeEst)*100*100) / 100
	}
	if t.Compressed > 0 {
		t.AvgCompressionMs = math.Round(t.CompressionTimeMs / t.Compressed)
	}
}

// opPxStats ports getPxpipeStats.
func opPxStats(recentLimit int) db.Record {
	events := opPxReadEvents(0)
	now := time.Now()
	startOfToday := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).UnixMilli()
	dayMs := float64(24 * time.Hour / time.Millisecond)
	windows := map[string]*opPxTotals{
		"all": {}, "today": {}, "yesterday": {}, "last7d": {}, "last30d": {},
	}
	type bucket struct {
		Date           string  `json:"date"`
		TokensSavedEst float64 `json:"tokensSavedEst"`
		Compressed     float64 `json:"compressed"`
		Requests       float64 `json:"requests"`
	}
	var timeline []*bucket
	byDate := map[string]*bucket{}
	for i := 29; i >= 0; i-- {
		day := time.UnixMilli(startOfToday - int64(i)*int64(dayMs))
		key := day.Format("2006-01-02")
		b := &bucket{Date: key}
		timeline = append(timeline, b)
		byDate[key] = b
	}
	nowMs := float64(now.UnixMilli())
	for _, ev := range events {
		ts := opNum(ev, "ts")
		opPxAccumulate(windows["all"], ev)
		if ts >= float64(startOfToday) {
			opPxAccumulate(windows["today"], ev)
		} else if ts >= float64(startOfToday)-dayMs {
			opPxAccumulate(windows["yesterday"], ev)
		}
		if ts >= nowMs-7*dayMs {
			opPxAccumulate(windows["last7d"], ev)
		}
		if ts >= nowMs-30*dayMs {
			opPxAccumulate(windows["last30d"], ev)
		}
		key := time.UnixMilli(int64(ts)).Format("2006-01-02")
		if b, ok := byDate[key]; ok {
			b.Requests++
			if opBool(ev, "applied") {
				b.Compressed++
				b.TokensSavedEst += opNum(ev, "tokensSavedEst")
			}
		}
	}
	for _, t := range windows {
		opPxFinalize(t)
	}
	recent := events
	if len(recent) > recentLimit {
		recent = recent[len(recent)-recentLimit:]
	}
	reversed := make([]db.Record, 0, len(recent))
	for i := len(recent) - 1; i >= 0; i-- {
		reversed = append(reversed, recent[i])
	}
	if reversed == nil {
		reversed = []db.Record{}
	}
	return db.Record{
		"windows":  windows,
		"timeline": timeline,
		"recent":   reversed,
	}
}

func opPxLimitParam(r *http.Request) int {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 500 {
		limit = 500
	}
	return limit
}

// opPxStatusPayload is getPxpipeStatus() + the settings fields the
// status route merges in; start/stop/restart return the same shape in
// the JS, so all four handlers share it.
func opPxStatusPayload(deps Deps) db.Record {
	settings, _ := deps.Store.GetSettings()
	out := opPxStatus(deps)
	out["enabled"] = opBool(settings, "pxpipeEnabled")
	out["autoInstall"] = opBool(settings, "pxpipeAutoInstall")
	out["minChars"] = settings["pxpipeMinChars"]
	out["timeoutMs"] = settings["pxpipeTimeoutMs"]
	return out
}

func opPxpipeStatus(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		WriteJSON(w, http.StatusOK, opPxStatusPayload(deps))
	}
}

func opPxpipeHealth(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		WriteJSON(w, http.StatusOK, opPxHealth())
	}
}

func opPxWriteCoded(w http.ResponseWriter, status int, err error) {
	code := any(nil)
	if ce, ok := err.(*opCodedError); ok {
		code = ce.code
	}
	if ce, ok := err.(*pxpipe.CodedError); ok {
		code = ce.Code
	}
	WriteJSON(w, status, db.Record{"error": err.Error(), "code": code})
}

func opPxpipeStart(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !opBool(opPxInstallInfo(), "installed") {
			settings, _ := deps.Store.GetSettings()
			if !opBool(settings, "pxpipeAutoInstall") {
				WriteJSON(w, http.StatusConflict, db.Record{"error": "PXPIPE is not installed", "code": "NOT_INSTALLED"})
				return
			}
			if _, err := opPxInstall(); err != nil {
				opPxWriteCoded(w, http.StatusInternalServerError, err)
				return
			}
		}
		// loadPxpipe() — in the Go port this starts the managed child
		// process running the package's standalone entry (see header).
		if _, _, err := pxpipe.Start(opPxDir(), pxpipe.DefaultPort); err != nil {
			opPxWriteCoded(w, http.StatusInternalServerError, err)
			return
		}
		WriteJSON(w, http.StatusOK, opPxStatusPayload(deps))
	}
}

func opPxpipeStop(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stopped, err := pxpipe.Stop(opPxDir())
		if err != nil {
			opPxWriteCoded(w, http.StatusInternalServerError, err)
			return
		}
		out := opPxStatusPayload(deps)
		out["stopped"] = stopped // JS: wasLoaded
		WriteJSON(w, http.StatusOK, out)
	}
}

func opPxpipeRestart(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := pxpipe.Restart(opPxDir(), pxpipe.DefaultPort); err != nil {
			opPxWriteCoded(w, http.StatusInternalServerError, err)
			return
		}
		WriteJSON(w, http.StatusOK, opPxStatusPayload(deps))
	}
}

func opPxpipeInstall(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info, err := opPxInstall()
		if err != nil {
			opPxWriteCoded(w, http.StatusInternalServerError, err)
			return
		}
		out := db.Record{}
		for k, v := range info {
			out[k] = v
		}
		out["health"] = opPxHealth()
		WriteJSON(w, http.StatusOK, out)
	}
}

func opPxpipeStats(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		WriteJSON(w, http.StatusOK, opPxStats(opPxLimitParam(r)))
	}
}

func opPxpipeLogs(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		events := opPxReadEvents(opPxLimitParam(r))
		reversed := make([]db.Record, 0, len(events))
		for i := len(events) - 1; i >= 0; i-- {
			reversed = append(reversed, events[i])
		}
		if reversed == nil {
			reversed = []db.Record{}
		}
		WriteJSON(w, http.StatusOK, db.Record{
			"installLog": opPxInstallLogTail(200),
			"events":     reversed,
		})
	}
}

// ---------- platform helpers (headroom process control) ----------

// The packaged server targets unix hosts (the JS uses POSIX signals
// for the managed headroom proxy the same way).
func syscallSignal0() os.Signal { return syscall.Signal(0) }
func syscallSIGTERM() os.Signal { return syscall.SIGTERM }

// sysProcDetached lives in ops_detach_unix.go / ops_detach_windows.go
// (SysProcAttr fields differ per platform).
