package oauthsvc

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Port of src/lib/oauth/utils/server.js — the loopback OAuth callback proxy
// servers + in-memory session stores for the providers whose flows complete
// through a local redirect (codex, xai, trae, windsurf, zed, xiaomi-mimo).
//
// The JS completions exchange tokens and save the connection inside the
// callback handler. In Go that part belongs to the api layer, so the
// handler delegates to OnCallbackComplete (set by internal/api's
// RegisterOAuth); without a hook it simply records the callback params as
// the session result.

// ProxySession is one in-flight callback-proxy login session.
type ProxySession struct {
	State         string
	Provider      string
	Status        string // pending | done | error
	Result        map[string]any
	Error         string
	CodeVerifier  string
	RedirectURI   string
	PrivateKeyDER []byte // xiaomi-mimo ECDH private key
	CreatedAt     time.Time
}

var proxySessions sync.Map // state -> *ProxySession

// RegisterProxySession stores a session (registerOAuthSession).
func RegisterProxySession(s *ProxySession) {
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now()
	}
	if s.Status == "" {
		s.Status = "pending"
	}
	proxySessions.Store(s.State, s)
}

// GetProxySession reads a session (getOAuthSession).
func GetProxySession(state string) *ProxySession {
	if v, ok := proxySessions.Load(state); ok {
		return v.(*ProxySession)
	}
	return nil
}

// ClearProxySession removes a session (clearOAuthSession).
func ClearProxySession(state string) { proxySessions.Delete(state) }

// CompleteProxySession marks a session done with a result.
func CompleteProxySession(state string, result map[string]any) {
	if s := GetProxySession(state); s != nil {
		s.Status = "done"
		s.Result = result
	}
}

// FailProxySession marks a session errored.
func FailProxySession(state, msg string) {
	if s := GetProxySession(state); s != nil {
		s.Status = "error"
		s.Error = msg
	}
}

// pendingSessionFor returns the single pending session for a provider
// (loopback callbacks for some providers arrive without a state param).
func pendingSessionFor(provider string) *ProxySession {
	var found *ProxySession
	count := 0
	proxySessions.Range(func(_, v any) bool {
		s := v.(*ProxySession)
		if s.Provider == provider && s.Status == "pending" {
			found = s
			count++
		}
		return true
	})
	if count == 1 {
		return found
	}
	return nil
}

// OnCallbackComplete is invoked by the callback handler after a session is
// matched. It should perform the provider exchange + connection save and
// return the result stored on the session. Set by internal/api.
var OnCallbackComplete func(ctx context.Context, sess *ProxySession, params url.Values) (map[string]any, error)

type callbackServer struct {
	provider string
	port     int
	server   *http.Server
	ln       net.Listener
}

var (
	callbackMu      sync.Mutex
	callbackServers = map[string]*callbackServer{}
)

// DefaultCallbackPort mirrors the JS per-provider port choices.
func DefaultCallbackPort(provider string) int {
	switch provider {
	case "codex":
		return 1455
	case "xai":
		return 56121
	case "zed":
		return 58443
	case "xiaomi-mimo":
		return XiaomiProxyPort
	}
	return 0 // ephemeral
}

// CallbackPort returns the running callback port for a provider (0 = down).
func CallbackPort(provider string) int {
	callbackMu.Lock()
	defer callbackMu.Unlock()
	if cs, ok := callbackServers[provider]; ok {
		return cs.port
	}
	return 0
}

// StartCallbackServer starts (or reports) the loopback callback server for
// a provider. appPort > 0 pins the port; 0 uses the provider default.
func StartCallbackServer(provider string, appPort int) (port int, alreadyRunning bool, err error) {
	callbackMu.Lock()
	defer callbackMu.Unlock()
	if cs, ok := callbackServers[provider]; ok {
		return cs.port, true, nil
	}
	port = appPort
	if port == 0 {
		port = DefaultCallbackPort(provider)
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil && provider == "zed" && appPort == 0 {
		// Zed falls back to the next free port like the JS does.
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		return 0, false, err
	}
	actual := ln.Addr().(*net.TCPAddr).Port
	cs := &callbackServer{provider: provider, port: actual, ln: ln}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleCallback(provider, w, r)
	})
	cs.server = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	callbackServers[provider] = cs
	go func() { _ = cs.server.Serve(ln) }()
	return actual, false, nil
}

// StopCallbackServer stops a provider's callback server (stopProxyServer).
func StopCallbackServer(provider string) {
	callbackMu.Lock()
	defer callbackMu.Unlock()
	if cs, ok := callbackServers[provider]; ok {
		_ = cs.server.Close()
		delete(callbackServers, provider)
	}
}

const callbackDoneHTML = `<!doctype html><html><body style="font-family:sans-serif;text-align:center;padding-top:3rem"><h3>Login complete</h3><p>You can close this tab and return to 9Router.</p></body></html>`

func isLoopbackOrigin(origin string) bool {
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := u.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func handleCallback(provider string, w http.ResponseWriter, r *http.Request) {
	// Loopback Origin guard from utils/server.js.
	if origin := r.Header.Get("Origin"); origin != "" && !isLoopbackOrigin(origin) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	params := r.URL.Query()
	state := params.Get("state")
	sess := (*ProxySession)(nil)
	if state != "" {
		sess = GetProxySession(state)
	}
	if sess == nil {
		sess = pendingSessionFor(provider)
	}
	if sess == nil {
		http.Error(w, "Unknown or expired login session", http.StatusBadRequest)
		return
	}
	if cbErr := firstStr(params.Get("error_description"), params.Get("error")); cbErr != "" && params.Get("code") == "" && provider != "xiaomi-mimo" {
		FailProxySession(sess.State, cbErr)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(callbackDoneHTML))
		return
	}
	// Xiaomi completes by decrypting the `u` param right here (the JS proxy
	// does the same); the api layer's poll-status turns it into a connection.
	if provider == "xiaomi-mimo" && params.Get("u") != "" {
		decrypted, err := XiaomiDecryptCallback(sess.PrivateKeyDER, params.Get("u"))
		if err != nil {
			FailProxySession(sess.State, err.Error())
		} else {
			CompleteProxySession(sess.State, decrypted)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(callbackDoneHTML))
		return
	}
	if OnCallbackComplete != nil {
		result, err := OnCallbackComplete(r.Context(), sess, params)
		if err != nil {
			FailProxySession(sess.State, err.Error())
		} else {
			CompleteProxySession(sess.State, result)
		}
	} else {
		result := map[string]any{}
		for k := range params {
			result[k] = params.Get(k)
		}
		CompleteProxySession(sess.State, result)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(callbackDoneHTML))
}

// IdleSessionsCleanup drops sessions older than the JS 10-minute TTL.
func IdleSessionsCleanup() {
	cutoff := time.Now().Add(-10 * time.Minute)
	proxySessions.Range(func(k, v any) bool {
		if v.(*ProxySession).CreatedAt.Before(cutoff) {
			proxySessions.Delete(k)
		}
		return true
	})
}

var _ = strings.TrimSpace
