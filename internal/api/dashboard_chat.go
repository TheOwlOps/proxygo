package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"proxygo/internal/chatcore"
)

// dashboard_chat.go — POST /api/dashboard/chat/completions.
//
// The dashboard's Basic Chat page posts here with the dashboard
// session cookie instead of an API key. Upstream v0.5.104 ships the
// page but no server route for this path (verified against the JS
// source: no route file, rewrite or middleware maps it), so this Go
// implementation defines the contract from the page's own fetch:
// {model, messages, stream} in, the chat pipeline's response
// (SSE for streams) out, {error} JSON on failure.
//
// Auth: a valid dashboard session is required (self-enforced like
// the cache API — /api/dashboard is not in the guard's protected
// prefixes). The chat itself runs under the first active dashboard
// API key, so the requireApiKey gate, per-key access control, rate
// limits and usage attribution all behave exactly as for a /v1 call.
// With no API key on the instance the route answers 400 with the
// remedy instead of failing obscurely downstream.
func RegisterDashboardChat(mux *http.ServeMux, deps Deps) {
	mux.HandleFunc("POST /api/dashboard/chat/completions", Wrap(deps, dashboardChatCompletions(deps)))
}

func dashboardChatCompletions(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps.Store == nil || !VerifySessionToken(deps.Store, SessionToken(r)) {
			Err(w, http.StatusUnauthorized, "Unauthorized")
			return
		}
		if deps.Chat == nil {
			Err(w, http.StatusServiceUnavailable, "Chat service unavailable")
			return
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			Err(w, http.StatusBadRequest, "Failed to read body")
			return
		}
		var body map[string]any
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &body); err != nil {
				Err(w, http.StatusBadRequest, "Invalid JSON body")
				return
			}
		}
		if body == nil {
			body = map[string]any{}
		}

		key := firstActiveAPIKey(deps)
		if key == "" {
			Err(w, http.StatusBadRequest, "No API key available — create one on the Endpoint & Key page first; Basic Chat runs under your first active key.")
			return
		}

		headers := map[string]string{}
		for k, vs := range r.Header {
			if len(vs) > 0 {
				headers[strings.ToLower(k)] = vs[0]
			}
		}
		resp, err := deps.Chat.HandleChat(r.Context(), chatcore.ChatRequest{
			Body:      body,
			Endpoint:  "/v1/chat/completions",
			Headers:   headers,
			APIKey:    key,
			UserAgent: r.UserAgent(),
		})
		if err != nil {
			Err(w, http.StatusInternalServerError, err.Error())
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
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

// firstActiveAPIKey returns the key string of the first API key
// record that is not disabled, in dashboard list order.
func firstActiveAPIKey(deps Deps) string {
	if deps.Store == nil {
		return ""
	}
	keys, err := deps.Store.GetAPIKeys()
	if err != nil {
		return ""
	}
	for _, k := range keys {
		if b, ok := k["isActive"].(bool); ok && !b {
			continue // explicitly disabled
		}
		if s, _ := k["key"].(string); s != "" {
			return s
		}
	}
	return ""
}
