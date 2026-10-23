package executors

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"time"
)

// MimoFreeExecutor ports open-sse/executors/mimo-free.js: Xiaomi's free MiMo
// chat endpoint, gated by two anti-abuse mechanisms —
//
//  1. a short-lived JWT obtained from a bootstrap endpoint (POST
//     {client: <device fingerprint sha256>}) and cached in-process until
//     5 minutes before its `exp`; a 401/403 from the chat endpoint
//     invalidates the cache and retries exactly once with a fresh JWT;
//  2. a system message carrying the exact MiMoCode signature marker,
//     injected (idempotently) at the head of messages, plus a Chrome-like
//     User-Agent (the endpoint 403s "Illegal access" without one) and a
//     per-executor x-session-affinity id (ses_ + 24 chars).
//
// Registry note: the JS provider is hidden ("MiMo free API service has
// ended") — the protocol is ported faithfully regardless.
//
// Live-unverified: the real bootstrap/chat endpoints (no live call made) —
// the flow is exercised against httptest fixtures in mimo_free_test.go.
type MimoFreeExecutor struct {
	*Base
	mimoSessionID string
}

// NewMimoFreeExecutor builds the mimo-free executor (JS constructor
// generates the session-affinity id per executor instance).
func NewMimoFreeExecutor() *MimoFreeExecutor {
	m := &MimoFreeExecutor{mimoSessionID: mimoFreeGenerateSessionID()}
	m.Base = &Base{ProviderID: "mimo-free", Hooks: Hooks{
		BuildURL: func(b *Base, req *Request, urlIndex int) (string, error) {
			return mimoFreeChatURL(req.Provider), nil
		},
		BuildHeaders: func(b *Base, req *Request, url string) (map[string]string, error) {
			return m.mimoBuildHeaders(req.Stream), nil
		},
		TransformBody: func(b *Base, req *Request) (map[string]any, error) {
			if req.Body == nil {
				return nil, nil
			}
			return mimoFreeInjectSystemMarker(req.Body), nil
		},
	}}
	return m
}

// mimoFreeDefaultChatURL is PROVIDERS["mimo-free"].baseUrl (registry
// transport); ProviderInfo.BaseURL carries it when the parent wires one.
const mimoFreeDefaultChatURL = "https://api.xiaomimimo.com/api/free-ai/openai/chat"

// mimoFreeBootstrapURL is the JS BOOTSTRAP_URL. A var (not const) purely as
// a test seam so tests can point bootstrap at an httptest server.
var mimoFreeBootstrapURL = "https://api.xiaomimimo.com/api/free-ai/bootstrap"

const (
	mimoFreeSessionAffinityPrefix = "ses_"
	mimoFreeSessionIDLength       = 24
	mimoFreeJWTFallbackTTL        = 3000 * time.Second
	mimoFreeJWTExpiryBuffer       = 300 * time.Second
	mimoFreeSessionChars          = "abcdefghijklmnopqrstuvwxyz0123456789"
)

// mimoFreeSystemMarker is the JS MIMO_SYSTEM_MARKER: the free chat endpoint
// returns 403 "Illegal access" unless a system message contains this exact
// substring.
const mimoFreeSystemMarker = "You are MiMoCode, an interactive CLI tool that helps users with software engineering tasks."

// mimoFreeUserAgents is the JS USER_AGENTS list (Chrome-like UA gate).
var mimoFreeUserAgents = []string{
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
}

func mimoFreeRandomUA() string {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(mimoFreeUserAgents))))
	if err != nil {
		return mimoFreeUserAgents[0]
	}
	return mimoFreeUserAgents[n.Int64()]
}

func mimoFreeChatURL(p *ProviderInfo) string {
	if p != nil && p.BaseURL != "" {
		return p.BaseURL
	}
	return mimoFreeDefaultChatURL
}

// mimoBuildHeaders ports buildHeaders(credentials, stream).
func (m *MimoFreeExecutor) mimoBuildHeaders(stream bool) map[string]string {
	accept := "application/json"
	if stream {
		accept = "text/event-stream"
	}
	return map[string]string{
		"Content-Type":       "application/json",
		"X-Mimo-Source":      "mimocode-cli-free",
		"User-Agent":         mimoFreeRandomUA(),
		"x-session-affinity": m.mimoSessionID,
		"Accept":             accept,
	}
}

// mimoFreeGenerateSessionID ports generateSessionId.
func mimoFreeGenerateSessionID() string {
	var sb strings.Builder
	sb.WriteString(mimoFreeSessionAffinityPrefix)
	buf := make([]byte, mimoFreeSessionIDLength)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failure is effectively unreachable; fall back to time.
		n := time.Now().UnixNano()
		for i := range buf {
			buf[i] = byte(n >> (8 * (i % 8)))
		}
	}
	for _, b := range buf {
		sb.WriteByte(mimoFreeSessionChars[int(b)%len(mimoFreeSessionChars)])
	}
	return sb.String()
}

// mimoFreeGenerateFingerprint ports generateFingerprint: sha256 of
// hostname|platform|arch|cpu|username. Go's stdlib has no CPU-model API;
// on Linux the first "model name" from /proc/cpuinfo is used (matching
// os.cpus()[0].model there), elsewhere "unknown-cpu" (the JS fallback).
func mimoFreeGenerateFingerprint() string {
	username := "unknown-user"
	if u, err := user.Current(); err == nil && u.Username != "" {
		username = u.Username
	}
	cpu := mimoFreeCPUModel()
	hostname, err := os.Hostname()
	if err != nil {
		hostname = ""
	}
	seed := fmt.Sprintf("%s|%s|%s|%s|%s", hostname, runtime.GOOS, runtime.GOARCH, cpu, username)
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}

func mimoFreeCPUModel() string {
	if runtime.GOOS == "linux" {
		if raw, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			for _, line := range strings.Split(string(raw), "\n") {
				if strings.HasPrefix(line, "model name") {
					if i := strings.Index(line, ":"); i >= 0 {
						if model := strings.TrimSpace(line[i+1:]); model != "" {
							return model
						}
					}
				}
			}
		}
	}
	return "unknown-cpu"
}

// mimoFreeParseJWTExp ports parseJwtExp: expiry from the JWT `exp` claim,
// falling back to a fixed TTL when unparseable.
func mimoFreeParseJWTExp(jwt string) time.Time {
	parts := strings.Split(jwt, ".")
	if len(parts) >= 2 {
		if payloadRaw, err := mimoFreeBase64URLDecode(parts[1]); err == nil {
			var payload map[string]any
			if err := json.Unmarshal(payloadRaw, &payload); err == nil {
				if exp := getFloat(payload, "exp"); exp > 0 {
					return time.Unix(int64(exp), 0)
				}
			}
		}
	}
	return time.Now().Add(mimoFreeJWTFallbackTTL)
}

func mimoFreeBase64URLDecode(s string) ([]byte, error) {
	if raw, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return raw, nil
	}
	// Padded / standard-alphabet fallback (Node's base64 decoder is lenient).
	if pad := len(s) % 4; pad != 0 {
		s += strings.Repeat("=", 4-pad)
	}
	return base64.URLEncoding.DecodeString(s)
}

// mimoFreeInjectSystemMarker ports injectSystemMarker (idempotent).
func mimoFreeInjectSystemMarker(body map[string]any) map[string]any {
	messages, ok := body["messages"].([]any)
	if !ok {
		return body
	}
	for _, raw := range messages {
		m, _ := raw.(map[string]any)
		if m != nil && m["role"] == "system" {
			if content, _ := m["content"].(string); strings.Contains(content, mimoFreeSystemMarker) {
				return body
			}
		}
	}
	out := cloneMap(body)
	out["messages"] = append([]any{map[string]any{"role": "system", "content": mimoFreeSystemMarker}}, messages...)
	return out
}

// --- In-process JWT cache (JS cachedJwt / jwtExpiresAt module state) ---

var (
	mimoFreeCacheMu       sync.Mutex
	mimoFreeCachedJWT     string
	mimoFreeJWTExpiresAt  time.Time
	mimoFreeBootstrapFunc = mimoFreeBootstrapHTTP // test seam if needed
)

// mimoFreeResetJWTCache ports resetJwtCache.
func mimoFreeResetJWTCache() {
	mimoFreeCacheMu.Lock()
	defer mimoFreeCacheMu.Unlock()
	mimoFreeCachedJWT = ""
	mimoFreeJWTExpiresAt = time.Time{}
}

// mimoFreeBootstrapJWT ports bootstrapJwt: return the cached JWT while it is
// valid beyond the expiry buffer, else POST the bootstrap endpoint.
func mimoFreeBootstrapJWT(ctx context.Context) (string, error) {
	mimoFreeCacheMu.Lock()
	if mimoFreeCachedJWT != "" && time.Now().Before(mimoFreeJWTExpiresAt.Add(-mimoFreeJWTExpiryBuffer)) {
		jwt := mimoFreeCachedJWT
		mimoFreeCacheMu.Unlock()
		return jwt, nil
	}
	mimoFreeCacheMu.Unlock()
	return mimoFreeBootstrapFunc(ctx)
}

func mimoFreeBootstrapHTTP(ctx context.Context) (string, error) {
	payload, _ := json.Marshal(map[string]any{"client": mimoFreeGenerateFingerprint()})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, mimoFreeBootstrapURL, strings.NewReader(string(payload)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", mimoFreeRandomUA())
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("MiMo bootstrap failed: %d", resp.StatusCode)
	}
	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}
	jwt := getStr(data, "jwt")
	if jwt == "" {
		return "", fmt.Errorf("MiMo bootstrap returned no JWT")
	}
	mimoFreeCacheMu.Lock()
	mimoFreeCachedJWT = jwt
	mimoFreeJWTExpiresAt = mimoFreeParseJWTExp(jwt)
	mimoFreeCacheMu.Unlock()
	return jwt, nil
}

// Execute ports MimoFreeExecutor.execute: bootstrap → POST chat → on
// 401/403 reset the JWT cache, re-bootstrap and retry exactly once.
func (m *MimoFreeExecutor) Execute(ctx context.Context, p *ProviderInfo, cred Credential, body []byte) (*ExecResult, error) {
	if p == nil {
		p = &ProviderInfo{ID: "mimo-free"}
	}
	bodyMap := BodyMap(body)
	stream := StreamRequested(bodyMap)
	payload := body
	if bodyMap != nil {
		transformed := mimoFreeInjectSystemMarker(bodyMap)
		raw, err := json.Marshal(transformed)
		if err != nil {
			return nil, err
		}
		payload = raw
	}

	jwt, err := mimoFreeBootstrapJWT(ctx)
	if err != nil {
		return nil, err
	}
	url := mimoFreeChatURL(p)
	headers := m.mimoBuildHeaders(stream)
	headers["Authorization"] = "Bearer " + jwt

	resp, err := doPost(ctx, url, headers, payload, connectTimeout(p))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		drainClose(resp)
		mimoFreeResetJWTCache()
		fresh, berr := mimoFreeBootstrapJWT(ctx)
		if berr != nil {
			return nil, berr
		}
		headers["Authorization"] = "Bearer " + fresh
		resp, err = doPost(ctx, url, headers, payload, connectTimeout(p))
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
	}
	return &ExecResult{Response: resp, URL: url, Headers: headers, TransformedBody: payload}, nil
}
