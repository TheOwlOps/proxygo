package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/proxy"

	"9router-go/internal/db"
	"9router-go/internal/selfupdate"
)

// RegisterAuth — Team E. Ports src/app/api auth/*, settings/*, keys/*,
// pricing, version/*, shutdown, health, init, locale (oidc/* and saml/*
// belong to Team G and are deliberately NOT registered here).
func RegisterAuth(mux *http.ServeMux, deps Deps) {
	// auth
	mux.HandleFunc("POST /api/auth/login", authLogin(deps))
	mux.HandleFunc("POST /api/auth/logout", Wrap(deps, authLogout))
	mux.HandleFunc("GET /api/auth/status", Wrap(deps, authStatus(deps)))
	mux.HandleFunc("POST /api/auth/reset-password", authResetPassword(deps))

	// settings
	mux.HandleFunc("GET /api/settings", Wrap(deps, settingsGet(deps)))
	mux.HandleFunc("PATCH /api/settings", Wrap(deps, settingsPatch(deps)))
	mux.HandleFunc("GET /api/settings/require-login", Wrap(deps, settingsRequireLogin(deps)))
	mux.HandleFunc("GET /api/settings/database", Wrap(deps, settingsDatabaseExport(deps)))
	mux.HandleFunc("POST /api/settings/database", Wrap(deps, settingsDatabaseImport(deps)))
	mux.HandleFunc("POST /api/settings/proxy-test", Wrap(deps, settingsProxyTest))

	// keys
	mux.HandleFunc("GET /api/keys", Wrap(deps, keysList(deps)))
	mux.HandleFunc("POST /api/keys", Wrap(deps, keysCreate(deps)))
	mux.HandleFunc("GET /api/keys/{id}", Wrap(deps, keyGet(deps)))
	mux.HandleFunc("PUT /api/keys/{id}", Wrap(deps, keyUpdate(deps)))
	mux.HandleFunc("DELETE /api/keys/{id}", Wrap(deps, keyDelete(deps)))

	// pricing
	mux.HandleFunc("GET /api/pricing", Wrap(deps, pricingGet(deps)))
	mux.HandleFunc("PATCH /api/pricing", Wrap(deps, pricingPatch(deps)))
	mux.HandleFunc("DELETE /api/pricing", Wrap(deps, pricingDelete(deps)))

	// version + lifecycle
	mux.HandleFunc("GET /api/version", Wrap(deps, versionGet))
	mux.HandleFunc("POST /api/version/shutdown", Wrap(deps, versionShutdown))
	mux.HandleFunc("POST /api/version/update", Wrap(deps, versionUpdate))
	mux.HandleFunc("POST /api/shutdown", Wrap(deps, shutdown))

	// misc public routes
	mux.HandleFunc("GET /api/health", apiHealth)
	mux.HandleFunc("OPTIONS /api/health", apiHealthOptions)
	mux.HandleFunc("GET /api/init", apiInit)
	mux.HandleFunc("POST /api/locale", Wrap(deps, localeSet))

	// Quota AutoPing: initializeApp.js starts the scheduler at boot;
	// configure from the persisted settings (starts only when some
	// account opted in or has a schedule). Settings PATCH reconfigures.
	if deps.Store != nil {
		if settings, err := deps.Store.GetSettings(); err == nil && settings != nil {
			configureQuotaAutoPing(deps, map[string]any(settings))
		}
	}
}

// ---------- shared small helpers ----------

func boolSetting(settings db.Record, key string, def bool) bool {
	if v, ok := settings[key].(bool); ok {
		return v
	}
	return def
}

func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

// scheduleExit mirrors the JS `setTimeout(() => process.exit(0), 500)`.
func scheduleExit() {
	time.AfterFunc(500*time.Millisecond, func() { os.Exit(0) })
}

// ---------- login limiter (port of src/lib/auth/loginLimiter.js) ----------

const (
	loginMaxFails   = 5
	loginFailWindow = time.Hour
)

var loginLockSteps = []time.Duration{30 * time.Second, 2 * time.Minute, 10 * time.Minute, 30 * time.Minute}

type loginEntry struct {
	fails     int
	lockUntil time.Time
	lockLevel int
	lastFail  time.Time
}

var (
	loginMu       sync.Mutex
	loginAttempts = map[string]*loginEntry{}
)

func loginGetEntry(ip string) *loginEntry {
	e := loginAttempts[ip]
	if e == nil {
		return nil
	}
	if !e.lastFail.IsZero() && time.Since(e.lastFail) > loginFailWindow &&
		(e.lockUntil.IsZero() || !time.Now().Before(e.lockUntil)) {
		delete(loginAttempts, ip)
		return nil
	}
	return e
}

// checkLock returns (locked, retryAfterSeconds).
func checkLock(ip string) (bool, int) {
	loginMu.Lock()
	defer loginMu.Unlock()
	e := loginGetEntry(ip)
	if e == nil || e.lockUntil.IsZero() {
		return false, 0
	}
	remaining := time.Until(e.lockUntil)
	if remaining <= 0 {
		return false, 0
	}
	return true, int((remaining + time.Second - 1) / time.Second)
}

// recordFail returns remainingBeforeLock.
func recordFail(ip string) int {
	loginMu.Lock()
	defer loginMu.Unlock()
	e := loginGetEntry(ip)
	if e == nil {
		e = &loginEntry{}
	}
	e.fails++
	e.lastFail = time.Now()
	if e.fails >= loginMaxFails {
		step := loginLockSteps[min(e.lockLevel, len(loginLockSteps)-1)]
		e.lockUntil = time.Now().Add(step)
		e.lockLevel++
		e.fails = 0
	}
	loginAttempts[ip] = e
	remaining := loginMaxFails - e.fails
	if remaining < 0 {
		remaining = 0
	}
	return remaining
}

func recordSuccess(ip string) {
	loginMu.Lock()
	delete(loginAttempts, ip)
	loginMu.Unlock()
}

// getClientIp ports getClientIp (loginLimiter.js) + trustedPeer.js:
// the x-9r-real-ip header counts only when the per-process peer token
// proves custom-server stamped it; otherwise TRUST_PROXY XFF; otherwise
// a single shared bucket so spoofed XFF cannot escape the limiter.
func getClientIp(r *http.Request) string {
	if tok := os.Getenv("NINEROUTER_PEER_TOKEN"); tok != "" && r.Header.Get("x-9r-peer-token") == tok {
		if ip := r.Header.Get("x-9r-real-ip"); ip != "" {
			return ip
		}
	}
	if os.Getenv("TRUST_PROXY") == "true" {
		if xff := r.Header.Get("x-forwarded-for"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	return "unknown"
}

const loginResetHint = "Forgot password? Reset to default via 9Router CLI → Settings → Reset Password to Default."

func loginLockedResponse(w http.ResponseWriter, retryAfter int) {
	w.Header().Set("Retry-After", fmt.Sprint(retryAfter))
	WriteJSON(w, http.StatusTooManyRequests, map[string]any{
		"error":      fmt.Sprintf("Too many failed attempts. Try again in %ds. %s", retryAfter, loginResetHint),
		"retryAfter": retryAfter,
		"resetHint":  loginResetHint,
	})
}

// isTunnelRequest: Host matches the configured tunnel/tailscale hostname.
func isTunnelRequest(r *http.Request, settings db.Record) bool {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)
	for _, key := range []string{"tunnelUrl", "tailscaleUrl"} {
		raw := Str(settings, key)
		if raw == "" {
			continue
		}
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" &&
			strings.ToLower(u.Hostname()) == host {
			return true
		}
	}
	return false
}

// OIDC/SAML "configured" checks (lib/auth/oidc.js, lib/auth/saml.js) —
// settings-shape only; the flows themselves are Team G's.
func oidcConfigured(settings db.Record) bool {
	return strings.TrimRight(Str(settings, "oidcIssuerUrl"), "/") != "" &&
		strings.TrimSpace(Str(settings, "oidcClientId")) != "" &&
		strings.TrimSpace(Str(settings, "oidcClientSecret")) != ""
}

func samlConfigured(settings db.Record) bool {
	return Str(settings, "samlEntryPoint") != "" && Str(settings, "samlCert") != ""
}

// ---------- auth routes ----------

func authLogin(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIp(r)
		if locked, retryAfter := checkLock(ip); locked {
			loginLockedResponse(w, retryAfter)
			return
		}
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, http.StatusInternalServerError, err.Error())
			return
		}
		password := Str(body, "password")
		settings, _ := deps.Store.GetSettings()
		if settings == nil {
			settings = db.Record{}
		}

		// Block login via tunnel/tailscale if dashboard access is disabled
		if isTunnelRequest(r, settings) && settings["tunnelDashboardAccess"] != true {
			Err(w, http.StatusForbidden, "Dashboard access via tunnel is disabled")
			return
		}

		if mode := Str(settings, "authMode"); mode == "sso" || mode == "saml" || mode == "oidc" {
			ssoType := Str(settings, "ssoType")
			if ssoType == "" {
				if mode == "saml" {
					ssoType = "saml"
				} else {
					ssoType = "oidc"
				}
			}
			if ssoType == "saml" && samlConfigured(settings) {
				Err(w, http.StatusForbidden, "Password login is disabled. Use SAML SSO sign in.")
				return
			}
			if ssoType == "oidc" && oidcConfigured(settings) {
				Err(w, http.StatusForbidden, "Password login is disabled. Use OIDC sign in.")
				return
			}
		}

		if VerifyPassword(deps.Store, password) {
			recordSuccess(ip)
			// Default password still in use on a remote client → force a
			// change first; deliberately NO session is issued (see JS
			// route comment: CVE-2026-56679 class).
			mustChangePassword := Str(settings, "password") == "" &&
				os.Getenv("INITIAL_PASSWORD") == "" && !IsLocalRequest(r)
			noStore(w)
			if mustChangePassword {
				WriteJSON(w, http.StatusForbidden, map[string]any{
					"success":            false,
					"error":              "Default password must be changed before remote access. Change it from the local machine (or set INITIAL_PASSWORD).",
					"mustChangePassword": true,
				})
				return
			}
			SetSessionCookie(w, r, deps.Store)
			WriteJSON(w, http.StatusOK, map[string]any{"success": true, "mustChangePassword": false})
			return
		}

		remaining := recordFail(ip)
		if locked, retryAfter := checkLock(ip); locked {
			loginLockedResponse(w, retryAfter)
			return
		}
		WriteJSON(w, http.StatusUnauthorized, map[string]any{
			"error":               fmt.Sprintf("Invalid password. %d attempt(s) left before lockout.", remaining),
			"remainingBeforeLock": remaining,
		})
	}
}

func authLogout(w http.ResponseWriter, r *http.Request) {
	ClearSessionCookie(w)
	for _, name := range []string{"oidc_state", "oidc_nonce", "oidc_code_verifier"} {
		http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1})
	}
	noStore(w)
	WriteJSON(w, http.StatusOK, map[string]any{"success": true})
}

// sessionClaims decodes the JWT payload after signature verification
// (getDashboardAuthSession returns the full payload in the JS).
func sessionClaims(deps Deps, r *http.Request) map[string]any {
	token := SessionToken(r)
	if token == "" || !VerifySessionToken(deps.Store, token) {
		return nil
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var payload map[string]any
	if json.Unmarshal(raw, &payload) != nil {
		return nil
	}
	return payload
}

func claimStr(claims map[string]any, key string) string {
	if claims == nil {
		return ""
	}
	return strings.TrimSpace(Str(claims, key))
}

func claimBool(claims map[string]any, key string) bool {
	if claims == nil {
		return false
	}
	v, _ := claims[key].(bool)
	return v
}

func authStatus(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings, err := deps.Store.GetSettings()
		if err != nil || settings == nil {
			// JS catch branch: static defaults object.
			WriteJSON(w, http.StatusOK, map[string]any{
				"requireLogin": true, "authMode": "password", "ssoType": "oidc",
				"oidcConfigured": false, "oidcLoginLabel": "Sign in with OIDC",
				"samlConfigured": false, "samlLoginLabel": "Sign in with SAML SSO",
				"hasPassword": false, "displayName": "Password user", "loginMethod": "Password",
				"authenticated": false, "oidcName": nil, "oidcEmail": nil, "oidcLogin": false,
				"samlName": nil, "samlEmail": nil, "samlLogin": false,
			})
			return
		}
		session := sessionClaims(deps, r)
		oidcName, oidcEmail := claimStr(session, "oidcName"), claimStr(session, "oidcEmail")
		samlName, samlEmail := claimStr(session, "samlName"), claimStr(session, "samlEmail")
		isSAML, isOIDC := claimBool(session, "saml"), claimBool(session, "oidc")

		displayName := "Password user"
		for _, cand := range []struct {
			val string
			ok  bool
		}{{samlName, samlName != ""}, {samlEmail, samlEmail != ""}, {oidcName, oidcName != ""}, {oidcEmail, oidcEmail != ""}} {
			if cand.ok {
				displayName = cand.val
				break
			}
		}
		if displayName == "Password user" {
			if isSAML {
				displayName = "SAML user"
			} else if isOIDC {
				displayName = "OIDC user"
			}
		}
		loginMethod := "Password"
		if isSAML {
			loginMethod = "SAML"
		} else if isOIDC {
			loginMethod = "OIDC"
		}
		authMode := Str(settings, "authMode")
		if authMode == "" {
			authMode = "password"
		}
		ssoType := Str(settings, "ssoType")
		if ssoType == "" {
			ssoType = "oidc"
		}
		oidcLabel := strings.TrimSpace(Str(settings, "oidcLoginLabel"))
		if oidcLabel == "" {
			oidcLabel = "Sign in with OIDC"
		}
		samlLabel := strings.TrimSpace(Str(settings, "samlLoginLabel"))
		if samlLabel == "" {
			samlLabel = "Sign in with SAML SSO"
		}
		nilOr := func(s string) any {
			if s == "" {
				return nil
			}
			return s
		}
		WriteJSON(w, http.StatusOK, map[string]any{
			"requireLogin":   boolSetting(settings, "requireLogin", true),
			"authMode":       authMode,
			"ssoType":        ssoType,
			"oidcConfigured": oidcConfigured(settings),
			"oidcLoginLabel": oidcLabel,
			"samlConfigured": samlConfigured(settings),
			"samlLoginLabel": samlLabel,
			"hasPassword":    Str(settings, "password") != "",
			"displayName":    displayName,
			"loginMethod":    loginMethod,
			"authenticated":  session != nil,
			"oidcName":       nilOr(oidcName),
			"oidcEmail":      nilOr(oidcEmail),
			"oidcLogin":      isOIDC,
			"samlName":       nilOr(samlName),
			"samlEmail":      nilOr(samlEmail),
			"samlLogin":      isSAML,
		})
	}
}

// cliToken ports the machineId-based CLI token (dashboardGuard.js):
// getConsistentMachineId("9r-cli-auth") = sha256(rawId + salt + cliSecret)[:16].
func cliToken() string {
	dir := db.DataDir()
	raw := ""
	if b, err := os.ReadFile(filepath.Join(dir, "machine-id")); err == nil {
		raw = strings.TrimSpace(string(b))
	}
	if raw == "" {
		buf := make([]byte, 16)
		_, _ = rand.Read(buf)
		raw = hex.EncodeToString(buf)
		_ = os.MkdirAll(dir, 0o755)
		_ = os.WriteFile(filepath.Join(dir, "machine-id"), []byte(raw), 0o600)
	}
	secret := ""
	secretFile := filepath.Join(dir, "auth", "cli-secret")
	if b, err := os.ReadFile(secretFile); err == nil {
		secret = strings.TrimSpace(string(b))
	}
	if secret == "" {
		buf := make([]byte, 32)
		_, _ = rand.Read(buf)
		secret = hex.EncodeToString(buf)
		_ = os.MkdirAll(filepath.Join(dir, "auth"), 0o755)
		_ = os.WriteFile(secretFile, []byte(secret), 0o600)
	}
	sum := sha256.Sum256([]byte(raw + "9r-cli-auth" + secret))
	return hex.EncodeToString(sum[:])[:16]
}

func hasValidCliToken(r *http.Request) bool {
	tok := r.Header.Get("x-9r-cli-token")
	return tok != "" && tok == cliToken()
}

// localOnly enforces the dashboardGuard LOCAL_ONLY_PATHS gate used by
// /api/auth/reset-password: CLI token, or loopback + authenticated
// (a valid session, or requireLogin disabled).
func localOnly(deps Deps, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hasValidCliToken(r) {
			h(w, r)
			return
		}
		authed := VerifySessionToken(deps.Store, SessionToken(r))
		if !authed {
			if settings, err := deps.Store.GetSettings(); err == nil && settings != nil {
				authed = settings["requireLogin"] == false
			}
		}
		if IsLocalRequest(r) && authed {
			h(w, r)
			return
		}
		Err(w, http.StatusForbidden, "Local only: CLI token required")
	}
}

func authResetPassword(deps Deps) http.HandlerFunc {
	return localOnly(deps, func(w http.ResponseWriter, r *http.Request) {
		if _, err := deps.Store.UpdateSettings(db.Record{"password": nil}); err != nil {
			Err(w, http.StatusInternalServerError, err.Error())
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"success": true})
	})
}

// ---------- settings routes ----------

// safeSettings strips secrets exactly like the JS settings route and adds
// oidcConfigured.
func safeSettings(settings db.Record) map[string]any {
	out := map[string]any{}
	for k, v := range settings {
		if k == "password" || k == "oidcClientSecret" {
			continue
		}
		out[k] = v
	}
	out["oidcConfigured"] = Str(settings, "oidcIssuerUrl") != "" &&
		Str(settings, "oidcClientId") != "" && Str(settings, "oidcClientSecret") != ""
	return out
}

func settingsGet(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings, err := deps.Store.GetSettings()
		if err != nil {
			Err(w, http.StatusInternalServerError, err.Error())
			return
		}
		out := safeSettings(settings)
		out["enableRequestLogs"] = os.Getenv("ENABLE_REQUEST_LOGS") == "true"
		out["enableTranslator"] = os.Getenv("ENABLE_TRANSLATOR") == "true"
		out["hasPassword"] = Str(settings, "password") != ""
		noStore(w)
		WriteJSON(w, http.StatusOK, out)
	}
}

var proxyEnvBadChars = regexp.MustCompile("[\n\r`$]")

// applyOutboundProxyEnv ports lib/network/outboundProxy.js.
func applyOutboundProxyEnv(settings db.Record) {
	enabled := boolSetting(settings, "outboundProxyEnabled", false)
	proxyURL := strings.TrimSpace(Str(settings, "outboundProxyUrl"))
	noProxy := strings.TrimSpace(Str(settings, "outboundNoProxy"))

	if !enabled {
		if os.Getenv("NINE_ROUTER_PROXY_MANAGED") == "1" {
			for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
				"NINE_ROUTER_PROXY_MANAGED", "NINE_ROUTER_PROXY_URL", "NINE_ROUTER_NO_PROXY"} {
				_ = os.Unsetenv(k)
			}
		}
		return
	}
	wasManaged := os.Getenv("NINE_ROUTER_PROXY_MANAGED") == "1"
	if wasManaged {
		if proxyURL == "" {
			for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NINE_ROUTER_PROXY_URL"} {
				_ = os.Unsetenv(k)
			}
		}
		if noProxy == "" {
			_ = os.Unsetenv("NO_PROXY")
			_ = os.Unsetenv("NINE_ROUTER_NO_PROXY")
		}
	}
	managed := false
	if proxyURL != "" {
		if validated := validateProxyURL(proxyURL); validated != "" {
			_ = os.Setenv("HTTP_PROXY", validated)
			_ = os.Setenv("HTTPS_PROXY", validated)
			_ = os.Setenv("ALL_PROXY", validated)
			_ = os.Setenv("NINE_ROUTER_PROXY_URL", validated)
			managed = true
		}
	}
	if noProxy != "" {
		_ = os.Setenv("NO_PROXY", noProxy)
		_ = os.Setenv("NINE_ROUTER_NO_PROXY", noProxy)
		managed = true
	}
	if managed {
		_ = os.Setenv("NINE_ROUTER_PROXY_MANAGED", "1")
	} else if wasManaged {
		_ = os.Unsetenv("NINE_ROUTER_PROXY_MANAGED")
	}
}

func validateProxyURL(raw string) string {
	if raw == "" || proxyEnvBadChars.MatchString(raw) {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks4", "socks5h", "socks4a":
		return u.String()
	}
	return ""
}

func settingsPatch(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, http.StatusInternalServerError, err.Error())
			return
		}
		// Secrets must never be mass-assigned (CWE-915).
		delete(body, "password")
		delete(body, "mitmSudoEncrypted")

		if _, hasNew := body["newPassword"]; hasNew {
			settings, _ := deps.Store.GetSettings()
			currentHash := ""
			if settings != nil {
				currentHash = Str(settings, "password")
			}
			if currentHash != "" {
				current, present := body["currentPassword"]
				if !present {
					Err(w, http.StatusBadRequest, "Current password required")
					return
				}
				cs, _ := current.(string)
				if bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(cs)) != nil {
					Err(w, http.StatusUnauthorized, "Invalid current password")
					return
				}
			} else {
				// First time setting a password: empty or the default.
				if cur := Str(body, "currentPassword"); cur != "" && cur != "123456" {
					Err(w, http.StatusUnauthorized, "Invalid current password")
					return
				}
			}
			hash, herr := HashPassword(Str(body, "newPassword"))
			if herr != nil {
				Err(w, http.StatusInternalServerError, herr.Error())
				return
			}
			body["password"] = hash
			delete(body, "newPassword")
			delete(body, "currentPassword")
		}

		if v, present := body["oidcClientSecret"]; present {
			if s, _ := v.(string); strings.TrimSpace(s) == "" {
				delete(body, "oidcClientSecret")
			}
		}

		settings, err := deps.Store.UpdateSettings(db.Record(body))
		if err != nil {
			Err(w, http.StatusInternalServerError, err.Error())
			return
		}

		if _, ok := body["outboundProxyEnabled"]; ok {
			applyOutboundProxyEnv(settings)
		} else if _, ok := body["outboundProxyUrl"]; ok {
			applyOutboundProxyEnv(settings)
		} else if _, ok := body["outboundNoProxy"]; ok {
			applyOutboundProxyEnv(settings)
		}
		// Side effects, mirroring the JS settings route (independent
		// key-presence checks, exactly like the JS hasOwnProperty chain):
		// - combo strategy settings changes invalidate the in-memory
		//   combo rotation state (resetComboRotation() — all combos).
		if _, ok := body["comboStrategy"]; ok {
			if deps.Chat != nil {
				deps.Chat.ResetAllComboRotation()
			}
		}
		if _, ok := body["comboStickyRoundRobinLimit"]; ok {
			if deps.Chat != nil {
				deps.Chat.ResetAllComboRotation()
			}
		}
		if _, ok := body["comboStrategies"]; ok {
			if deps.Chat != nil {
				deps.Chat.ResetAllComboRotation()
			}
		}
		// - claudeAutoPing/codexAutoPing changes reconfigure the quota
		//   auto-ping scheduler (configureQuotaAutoPing — autoping.go).
		if _, ok := body["claudeAutoPing"]; ok {
			configureQuotaAutoPing(deps, map[string]any(settings))
		}
		if _, ok := body["codexAutoPing"]; ok {
			configureQuotaAutoPing(deps, map[string]any(settings))
		}

		noStore(w)
		WriteJSON(w, http.StatusOK, safeSettings(settings))
	}
}

func settingsRequireLogin(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings, err := deps.Store.GetSettings()
		if err != nil || settings == nil {
			WriteJSON(w, http.StatusOK, map[string]any{"requireLogin": true})
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{
			"requireLogin":          boolSetting(settings, "requireLogin", true),
			"tunnelDashboardAccess": boolSetting(settings, "tunnelDashboardAccess", true),
			"tunnelUrl":             Str(settings, "tunnelUrl"),
			"tailscaleUrl":          Str(settings, "tailscaleUrl"),
		})
	}
}

func settingsDatabaseExport(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// CLI token requests are trusted; others re-auth with the password.
		if r.Header.Get("x-9r-cli-token") == "" &&
			!VerifyPassword(deps.Store, r.Header.Get("x-9r-password")) {
			Err(w, http.StatusUnauthorized, "Invalid password")
			return
		}
		payload, err := deps.Store.ExportDB()
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to export database")
			return
		}
		WriteJSON(w, http.StatusOK, payload)
	}
}

func settingsDatabaseImport(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, http.StatusBadRequest, err.Error())
			return
		}
		password := Str(body, "password")
		delete(body, "password")
		if r.Header.Get("x-9r-cli-token") == "" && !VerifyPassword(deps.Store, password) {
			Err(w, http.StatusUnauthorized, "Invalid password")
			return
		}
		if _, err := deps.Store.ImportDB(db.Record(body)); err != nil {
			Err(w, http.StatusBadRequest, err.Error())
			return
		}
		if settings, serr := deps.Store.GetSettings(); serr == nil && settings != nil {
			applyOutboundProxyEnv(settings)
		}
		WriteJSON(w, http.StatusOK, map[string]any{"success": true})
	}
}

// testProxyURL ports lib/network/proxyTest.js (HEAD through the proxy).
func settingsProxyTest(w http.ResponseWriter, r *http.Request) {
	body, err := ReadBodyJSON(r)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "deadline") || strings.Contains(msg, "timeout") {
			msg = "Proxy test timed out"
		}
		WriteJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": msg})
		return
	}
	proxyRaw := strings.TrimSpace(Str(body, "proxyUrl"))
	if proxyRaw == "" {
		WriteJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "proxyUrl is required"})
		return
	}
	testURL := strings.TrimSpace(Str(body, "testUrl"))
	if testURL == "" {
		testURL = "https://google.com/"
	}
	timeout := 8 * time.Second
	if v, ok := body["timeoutMs"].(float64); ok && v > 0 {
		timeout = time.Duration(v) * time.Millisecond
		if timeout > 30*time.Second {
			timeout = 30 * time.Second
		}
	}
	proxyURL, err := url.Parse(proxyRaw)
	if err != nil || proxyURL.Scheme == "" || proxyURL.Host == "" {
		msg := "invalid proxy URL"
		if err != nil {
			msg = err.Error()
		}
		WriteJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid proxy URL: " + msg})
		return
	}
	transport := &http.Transport{}
	switch proxyURL.Scheme {
	case "http", "https":
		transport.Proxy = http.ProxyURL(proxyURL)
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if proxyURL.User != nil {
			pw, _ := proxyURL.User.Password()
			auth = &proxy.Auth{User: proxyURL.User.Username(), Password: pw}
		}
		dialer, derr := proxy.SOCKS5("tcp", proxyURL.Host, auth, proxy.Direct)
		if derr != nil {
			WriteJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid proxy URL: " + derr.Error()})
			return
		}
		if cd, ok := dialer.(proxy.ContextDialer); ok {
			transport.DialContext = cd.DialContext
		} else {
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			}
		}
	default:
		WriteJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid proxy URL: unsupported scheme " + proxyURL.Scheme})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, testURL, nil)
	if err != nil {
		WriteJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	req.Header.Set("User-Agent", "9Router")
	start := time.Now()
	resp, err := (&http.Client{Transport: transport}).Do(req)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		msg := err.Error()
		if ctx.Err() == context.DeadlineExceeded {
			msg = "Proxy test timed out"
		}
		WriteJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": msg})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		WriteJSON(w, http.StatusOK, map[string]any{
			"ok": true, "status": resp.StatusCode, "statusText": resp.Status,
			"url": testURL, "elapsedMs": elapsed,
		})
		return
	}
	WriteJSON(w, resp.StatusCode, map[string]any{"ok": false, "error": "Proxy test failed"})
}

// ---------- machine id (port of shared/utils/machineId.js) ----------

var (
	machineIDOnce sync.Once
	machineIDVal  string
)

// consistentMachineID = sha256(rawMachineId + salt)[:16]; the raw id is
// persisted at $DATA_DIR/machine-id so CLI/server/middleware agree.
func consistentMachineID() string {
	machineIDOnce.Do(func() {
		dir := db.DataDir()
		raw := ""
		if b, err := os.ReadFile(filepath.Join(dir, "machine-id")); err == nil {
			raw = strings.TrimSpace(string(b))
		}
		if raw == "" {
			buf := make([]byte, 16)
			_, _ = rand.Read(buf)
			raw = hex.EncodeToString(buf)
			_ = os.MkdirAll(dir, 0o755)
			_ = os.WriteFile(filepath.Join(dir, "machine-id"), []byte(raw), 0o600)
		}
		salt := os.Getenv("MACHINE_ID_SALT")
		if salt == "" {
			salt = "endpoint-proxy-salt"
		}
		sum := sha256.Sum256([]byte(raw + salt))
		machineIDVal = hex.EncodeToString(sum[:])[:16]
	})
	return machineIDVal
}

// ---------- keys routes ----------

func keysList(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		keys, err := deps.Store.GetAPIKeys()
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to fetch keys")
			return
		}
		if keys == nil {
			keys = []db.Record{}
		}
		WriteJSON(w, http.StatusOK, map[string]any{"keys": keys})
	}
}

func keysCreate(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to create key")
			return
		}
		name := Str(body, "name")
		if name == "" {
			Err(w, http.StatusBadRequest, "Name is required")
			return
		}
		rec, err := deps.Store.CreateAPIKey(name, consistentMachineID())
		if err != nil || rec == nil {
			Err(w, http.StatusInternalServerError, "Failed to create key")
			return
		}
		WriteJSON(w, http.StatusCreated, map[string]any{
			"key": rec["key"], "name": rec["name"], "id": rec["id"], "machineId": rec["machineId"],
		})
	}
}

func keyGet(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec, err := deps.Store.GetAPIKeyByID(r.PathValue("id"))
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to fetch key")
			return
		}
		if rec == nil {
			Err(w, http.StatusNotFound, "Key not found")
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"key": rec})
	}
}

// validateKeyAccessInput ports shared/utils/keyAccess.js (reject, not repair).
func validateKeyAccessInput(input any) (map[string]any, string) {
	m, ok := input.(map[string]any)
	if !ok {
		return nil, "access must be an object { restricted, allow }"
	}
	var extra []string
	for k := range m {
		if k != "restricted" && k != "allow" {
			extra = append(extra, k)
		}
	}
	if len(extra) > 0 {
		return nil, "access: unexpected field(s) " + strings.Join(extra, ", ")
	}
	restricted, ok := m["restricted"].(bool)
	if !ok {
		return nil, "access.restricted must be a boolean"
	}
	var allowRaw []any
	if v, present := m["allow"]; present && v != nil {
		arr, isArr := v.([]any)
		if !isArr {
			return nil, "access.allow must be an array of strings"
		}
		for _, e := range arr {
			if _, isStr := e.(string); !isStr {
				return nil, "access.allow must be an array of strings"
			}
		}
		allowRaw = arr
	}
	if len(allowRaw) > 200 {
		return nil, "access.allow has more than 200 entries"
	}
	for _, e := range allowRaw {
		if len(strings.TrimSpace(e.(string))) > 256 {
			return nil, "access.allow entries must be at most 256 characters"
		}
	}
	// normalizeAllowList: strings only, trimmed, dedupe case-insensitively.
	seen := map[string]bool{}
	allow := []any{}
	for _, e := range allowRaw {
		entry := strings.TrimSpace(e.(string))
		if entry == "" {
			continue
		}
		k := strings.ToLower(entry)
		if seen[k] {
			continue
		}
		seen[k] = true
		allow = append(allow, entry)
	}
	return map[string]any{"restricted": restricted, "allow": allow}, ""
}

func keyUpdate(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to update key")
			return
		}
		existing, err := deps.Store.GetAPIKeyByID(id)
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to update key")
			return
		}
		if existing == nil {
			Err(w, http.StatusNotFound, "Key not found")
			return
		}
		update := db.Record{}
		if v, present := body["isActive"]; present {
			update["isActive"] = v
		}
		if v, present := body["access"]; present {
			checked, errMsg := validateKeyAccessInput(v)
			if errMsg != "" {
				Err(w, http.StatusBadRequest, errMsg)
				return
			}
			update["access"] = checked
		}
		updated, err := deps.Store.UpdateAPIKey(id, update)
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to update key")
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"key": updated})
	}
}

func keyDelete(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		deleted, err := deps.Store.DeleteAPIKey(r.PathValue("id"))
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to delete key")
			return
		}
		if !deleted {
			Err(w, http.StatusNotFound, "Key not found")
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"message": "Key deleted successfully"})
	}
}

// ---------- pricing routes ----------

func pricingGet(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pricing, err := deps.Store.GetPricing()
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to fetch pricing")
			return
		}
		WriteJSON(w, http.StatusOK, pricing)
	}
}

var pricingValidFields = map[string]bool{
	"input": true, "output": true, "cached": true, "reasoning": true, "cache_creation": true,
}

func pricingPatch(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to update pricing")
			return
		}
		if body == nil {
			Err(w, http.StatusBadRequest, "Invalid pricing data format")
			return
		}
		for provider, modelsAny := range body {
			models, ok := modelsAny.(map[string]any)
			if !ok {
				Err(w, http.StatusBadRequest, "Invalid pricing for provider: "+provider)
				return
			}
			for model, pricingAny := range models {
				pricing, ok := pricingAny.(map[string]any)
				if !ok {
					Err(w, http.StatusBadRequest, fmt.Sprintf("Invalid pricing for model: %s/%s", provider, model))
					return
				}
				for field, value := range pricing {
					if !pricingValidFields[field] {
						Err(w, http.StatusBadRequest, fmt.Sprintf("Invalid pricing field: %s for %s/%s", field, provider, model))
						return
					}
					num, isNum := value.(float64)
					if !isNum || num < 0 {
						Err(w, http.StatusBadRequest, fmt.Sprintf("Invalid pricing value for %s in %s/%s: must be non-negative number", field, provider, model))
						return
					}
				}
			}
		}
		updated, err := deps.Store.UpdatePricing(db.Record(body))
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to update pricing")
			return
		}
		WriteJSON(w, http.StatusOK, updated)
	}
}

func pricingDelete(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provider := r.URL.Query().Get("provider")
		model := r.URL.Query().Get("model")
		var err error
		switch {
		case provider != "" && model != "":
			_, err = deps.Store.ResetPricing(provider, model)
		case provider != "":
			_, err = deps.Store.ResetPricing(provider, "")
		default:
			_, err = deps.Store.ResetAllPricing()
		}
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to reset pricing")
			return
		}
		pricing, err := deps.Store.GetPricing()
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to reset pricing")
			return
		}
		WriteJSON(w, http.StatusOK, pricing)
	}
}

// ---------- version + lifecycle ----------

// currentVersion mirrors package.json of the source repo (v0.5.104).
const currentVersion = "0.5.104"

var (
	versionMu        sync.Mutex
	versionCacheVal  string
	versionFetchedAt time.Time
)

func fetchLatestVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://registry.npmjs.org/9router/latest", nil)
	if err != nil {
		return ""
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var out map[string]any
	if json.NewDecoder(resp.Body).Decode(&out) != nil {
		return ""
	}
	return Str(out, "version")
}

func latestVersionCached() string {
	versionMu.Lock()
	defer versionMu.Unlock()
	if versionCacheVal != "" && time.Since(versionFetchedAt) < time.Hour {
		return versionCacheVal
	}
	latest := fetchLatestVersion()
	if latest != "" {
		versionCacheVal = latest
		versionFetchedAt = time.Now()
	}
	return latest
}

func compareVersions(a, b string) int {
	parse := func(s string) [3]int {
		var out [3]int
		for i, part := range strings.SplitN(s, ".", 3) {
			if i > 2 {
				break
			}
			fmt.Sscanf(part, "%d", &out[i])
		}
		return out
	}
	pa, pb := parse(a), parse(b)
	for i := 0; i < 3; i++ {
		if pa[i] > pb[i] {
			return 1
		}
		if pa[i] < pb[i] {
			return -1
		}
	}
	return 0
}

func versionGet(w http.ResponseWriter, r *http.Request) {
	latest := latestVersionCached()
	var latestVal any
	hasUpdate := false
	if latest != "" {
		latestVal = latest
		hasUpdate = compareVersions(latest, currentVersion) > 0
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"currentVersion": currentVersion,
		"latestVersion":  latestVal,
		"hasUpdate":      hasUpdate,
	})
}

func versionShutdown(w http.ResponseWriter, r *http.Request) {
	// killAppProcesses (lib/appUpdater) is not ported — best effort only.
	scheduleExit()
	WriteJSON(w, http.StatusOK, map[string]any{"success": true, "message": "Shutting down for manual update..."})
}

func versionUpdate(w http.ResponseWriter, r *http.Request) {
	if os.Getenv("NODE_ENV") != "production" {
		WriteJSON(w, http.StatusForbidden, map[string]any{
			"success": false,
			"message": "Update is only available in production build (9router CLI)",
		})
		return
	}
	// SELF-UPDATE (Feature F5 — supersedes the earlier divergence
	// note): the JS spawns a detached Node updater that runs
	// `npm install -g 9router` and relaunches via npx. A standalone
	// Go binary has no npm package, so the update channel is the
	// project's GitHub Releases feed via internal/selfupdate: when
	// the latest release is newer AND ships an asset for this
	// platform (9router-go-<GOOS>-<GOARCH>[.exe], sha256-verified
	// against the release's checksums.txt when present), the new
	// binary is downloaded and swapped over os.Executable(), then
	// this process exits — the external supervisor / CLI launcher
	// relaunches the swapped binary (that relaunch is what makes the
	// new version take effect, on Windows too: the swap renames the
	// running exe aside first). Upstream releases currently ship no
	// Go assets, so until they do this route reports
	// selfUpdate:"no-compatible-asset" and keeps the old semantics
	// (success response + exit for a supervisor-driven swap).
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	selfupdate.CurrentVersion = currentVersion
	info, checkErr := selfupdate.Check(ctx)
	if checkErr == nil && info.UpdateAvailable && info.Compatible {
		if err := selfupdate.Apply(ctx, info, ""); err != nil {
			WriteJSON(w, http.StatusBadGateway, map[string]any{
				"success":    false,
				"message":    "Self-update failed: " + err.Error(),
				"selfUpdate": "apply-failed",
			})
			return
		}
		scheduleExit()
		WriteJSON(w, http.StatusOK, map[string]any{
			"success":    true,
			"message":    "Update " + info.Version + " downloaded. This app will exit shortly; the supervisor/CLI relaunches the new binary.",
			"selfUpdate": "applied",
			"version":    info.Version,
		})
		return
	}
	scheduleExit()
	WriteJSON(w, http.StatusOK, map[string]any{
		"success":    true,
		"message":    "Updater started. This app will exit shortly.",
		"selfUpdate": "no-compatible-asset",
	})
}

func shutdown(w http.ResponseWriter, r *http.Request) {
	if os.Getenv("NODE_ENV") == "production" {
		WriteJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Not allowed in production"})
		return
	}
	secret := os.Getenv("SHUTDOWN_SECRET")
	if secret == "" || r.Header.Get("Authorization") != "Bearer "+secret {
		WriteJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "Unauthorized"})
		return
	}
	scheduleExit()
	WriteJSON(w, http.StatusOK, map[string]any{"success": true, "message": "Shutting down..."})
}

// ---------- misc public routes ----------

var healthCORS = map[string]string{
	"Access-Control-Allow-Origin":  "*",
	"Access-Control-Allow-Methods": "GET, OPTIONS",
	"Access-Control-Allow-Headers": "*",
}

func apiHealth(w http.ResponseWriter, r *http.Request) {
	for k, v := range healthCORS {
		w.Header().Set(k, v)
	}
	WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func apiHealthOptions(w http.ResponseWriter, r *http.Request) {
	for k, v := range healthCORS {
		w.Header().Set(k, v)
	}
	w.WriteHeader(http.StatusNoContent)
}

func apiInit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Initialized"))
}

var supportedLocales = map[string]bool{
	"en": true, "vi": true, "zh-CN": true, "zh-TW": true, "ja": true,
	"pt-BR": true, "pt-PT": true, "ko": true, "es": true, "de": true,
	"fr": true, "he": true, "ar": true, "ru": true, "pl": true,
	"cs": true, "nl": true, "tr": true, "uk": true, "tl": true,
	"id": true, "km": true, "th": true, "hi": true, "bn": true,
	"ur": true, "ro": true, "sv": true, "it": true, "el": true,
	"hu": true, "fi": true, "da": true, "no": true, "fa": true,
}

// normalizeLocale ports i18n/config.js (explicit chain; default "en").
func normalizeLocale(locale string) string {
	if locale == "zh" {
		return "zh-CN"
	}
	if supportedLocales[locale] {
		return locale
	}
	return "en"
}

func localeSet(w http.ResponseWriter, r *http.Request) {
	body, err := ReadBodyJSON(r)
	if err != nil {
		Err(w, http.StatusInternalServerError, "Failed to set locale")
		return
	}
	locale := Str(body, "locale")
	if locale == "" || !supportedLocales[locale] {
		Err(w, http.StatusBadRequest, "Invalid locale")
		return
	}
	normalized := normalizeLocale(locale)
	http.SetCookie(w, &http.Cookie{
		Name: "locale", Value: normalized, Path: "/", MaxAge: 60 * 60 * 24 * 365,
	})
	WriteJSON(w, http.StatusOK, map[string]any{"success": true, "locale": normalized})
}
