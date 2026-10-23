// Package api hosts the dashboard management APIs (port of
// src/app/api/*, 173 Next routes). Shared framework lives here
// (parent-owned); each domain registrar is one team-owned file.
package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"proxygo/internal/chatcore"
	"proxygo/internal/db"
)

// Deps are the shared dependencies every registrar receives.
type Deps struct {
	Store *db.Store
	Chat  *chatcore.Service
}

// RegisterAll mounts every domain registrar on the mux.
func RegisterAll(mux *http.ServeMux, deps Deps) {
	RegisterAuth(mux, deps)
	RegisterProviders(mux, deps)
	RegisterOAuth(mux, deps)
	RegisterOps(mux, deps)
	RegisterCLITools(mux, deps)
	// Feature Pack 1+3 management APIs.
	RegisterCacheAPI(mux, deps)
	RegisterBreakerAPI(mux, deps)
	RegisterKeyLimitsAPI(mux, deps)
	RegisterDashboardChat(mux, deps)
}

// ---------- JSON helpers ----------

func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Err writes the common {"error": msg} shape.
func Err(w http.ResponseWriter, status int, msg string) {
	WriteJSON(w, status, map[string]any{"error": msg})
}

func ReadBodyJSON(r *http.Request) (map[string]any, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return map[string]any{}, nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func Str(r map[string]any, k string) string {
	if s, ok := r[k].(string); ok {
		return s
	}
	return ""
}

// ---------- Session (port of src/lib/auth/dashboardSession.js) ----------

var (
	secretOnce sync.Once
	secretVal  []byte
)

func jwtSecret(store *db.Store) []byte {
	secretOnce.Do(func() {
		if s := os.Getenv("JWT_SECRET"); s != "" {
			secretVal = []byte(s)
			return
		}
		dir := db.DataDir()
		file := filepath.Join(dir, "jwt-secret")
		if raw, err := os.ReadFile(file); err == nil && strings.TrimSpace(string(raw)) != "" {
			secretVal = []byte(strings.TrimSpace(string(raw)))
			return
		}
		_ = os.MkdirAll(dir, 0o755)
		buf := make([]byte, 32)
		_, _ = rand.Read(buf)
		gen := hex.EncodeToString(buf)
		_ = os.WriteFile(file, []byte(gen), 0o600)
		secretVal = []byte(gen)
	})
	return secretVal
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// CreateSessionToken mints the HS256 dashboard JWT ({authenticated:true}, 24h).
func CreateSessionToken(store *db.Store) string {
	return CreateSessionTokenWithClaims(store, nil)
}

// CreateSessionTokenWithClaims mints the session JWT with extra claims
// merged over {authenticated:true} — port of createDashboardAuthToken's
// `{authenticated: true, ...claims}` (src/lib/auth/dashboardSession.js).
// The OIDC callback stamps {oidc, oidcSub, oidcEmail, oidcName} and the
// SAML ACS stamps {saml, samlEmail, samlName}; authStatus surfaces them.
func CreateSessionTokenWithClaims(store *db.Store, extra map[string]any) string {
	header, _ := json.Marshal(map[string]any{"alg": "HS256", "typ": "JWT"})
	now := time.Now()
	payload := map[string]any{
		"authenticated": true,
		"iat":           now.Unix(),
		"exp":           now.Add(24 * time.Hour).Unix(),
	}
	for k, v := range extra {
		payload[k] = v
	}
	raw, _ := json.Marshal(payload)
	msg := b64(header) + "." + b64(raw)
	mac := hmac.New(sha256.New, jwtSecret(store))
	mac.Write([]byte(msg))
	return msg + "." + b64(mac.Sum(nil))
}

// VerifySessionToken validates signature + expiry.
func VerifySessionToken(store *db.Store, token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	mac := hmac.New(sha256.New, jwtSecret(store))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, mac.Sum(nil)) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var payload map[string]any
	if json.Unmarshal(raw, &payload) != nil {
		return false
	}
	if exp, ok := payload["exp"].(float64); ok && time.Now().Unix() > int64(exp) {
		return false
	}
	return payload["authenticated"] == true
}

// SessionToken extracts the token from the auth_token cookie or Bearer.
func SessionToken(r *http.Request) string {
	if c, err := r.Cookie("auth_token"); err == nil && c.Value != "" {
		return c.Value
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}

// SetSessionCookie sets the auth_token cookie like setDashboardAuthCookie.
func SetSessionCookie(w http.ResponseWriter, r *http.Request, store *db.Store) {
	SetSessionCookieWithClaims(w, r, store, nil)
}

// SetSessionCookieWithClaims is setDashboardAuthCookie(cookieStore,
// request, claims): the cookie carries a session token minted with the
// given extra claims (SSO identity stamps).
func SetSessionCookieWithClaims(w http.ResponseWriter, r *http.Request, store *db.Store, extra map[string]any) {
	secure := os.Getenv("AUTH_COOKIE_SECURE") == "true" || r.Header.Get("x-forwarded-proto") == "https"
	http.SetCookie(w, &http.Cookie{
		Name: "auth_token", Value: CreateSessionTokenWithClaims(store, extra),
		Path: "/", MaxAge: 24 * 60 * 60, HttpOnly: true,
		Secure: secure, SameSite: http.SameSiteLaxMode,
	})
}

// ClearSessionCookie removes the auth_token cookie.
func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "auth_token", Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
}

// VerifyPassword ports verifyDashboardPassword: bcrypt against
// settings.password when set, else INITIAL_PASSWORD env or "123456".
func VerifyPassword(store *db.Store, pw string) bool {
	if pw == "" {
		return false
	}
	if settings, err := store.GetSettings(); err == nil && settings != nil {
		if hash := Str(settings, "password"); hash != "" {
			return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
		}
	}
	initial := os.Getenv("INITIAL_PASSWORD")
	if initial == "" {
		initial = "123456"
	}
	return pw == initial
}

// HashPassword bcrypt-hashes a new dashboard password (settings writes).
func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(b), err
}

// ---------- Guard (port of src/dashboardGuard.js, API subset) ----------

var publicPaths = map[string]bool{
	"/api/health": true, "/api/init": true, "/api/locale": true,
	"/api/auth/login": true, "/api/auth/logout": true, "/api/auth/status": true,
	"/api/version": true, "/api/settings/require-login": true,
}

var alwaysProtected = []string{
	"/api/shutdown", "/api/settings/database", "/api/version/shutdown", "/api/version/update",
	"/api/oauth/cursor/auto-import", "/api/oauth/kiro/auto-import", "/api/oauth/zed/auto-import",
}

var protectedPrefixes = []string{
	"/api/settings", "/api/keys", "/api/providers", "/api/provider-nodes",
	"/api/proxy-pools", "/api/combos", "/api/models", "/api/usage",
	"/api/oauth", "/api/media-providers", "/api/pricing", "/api/tags",
	"/api/cli-tools", "/api/mcp", "/api/translator", "/api/tunnel",
}

func hasPrefixAny(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// RequireAuth wraps a handler with the dashboard guard rules.
func RequireAuth(deps Deps, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if publicPaths[path] || strings.HasPrefix(path, "/api/auth/oidc") || strings.HasPrefix(path, "/api/auth/saml") {
			h(w, r)
			return
		}
		authed := VerifySessionToken(deps.Store, SessionToken(r))
		if hasPrefixAny(path, alwaysProtected) {
			if !authed {
				Err(w, http.StatusUnauthorized, "Unauthorized")
				return
			}
			h(w, r)
			return
		}
		if hasPrefixAny(path, protectedPrefixes) {
			requireLogin := true
			if settings, err := deps.Store.GetSettings(); err == nil && settings != nil {
				if v, ok := settings["requireLogin"].(bool); ok {
					requireLogin = v
				}
			}
			if requireLogin && !authed {
				Err(w, http.StatusUnauthorized, "Unauthorized")
				return
			}
		}
		h(w, r)
	}
}

// IsLocalRequest reports whether the request originates from loopback
// (custom-server.js derives the client IP from the socket; the Go server
// trusts RemoteAddr the same way).
func IsLocalRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Wrap is shorthand for RequireAuth + handler registration used by teams:
//
//	mux.HandleFunc("GET /api/keys", api.Wrap(deps, listKeys))
func Wrap(deps Deps, h http.HandlerFunc) http.HandlerFunc { return RequireAuth(deps, h) }
