// Package server is the HTTP surface of the Go port: the OpenAI-compatible
// /v1/* endpoints wired to chatcore, /health, and the React dashboard
// served as static files (WEB_DIR) — all logic in Go, UI unchanged.
package server

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"proxygo/internal/api"
	"proxygo/internal/app"
	"proxygo/internal/chatcore"
	"proxygo/internal/db"
	"proxygo/internal/providers"
	"proxygo/internal/respcache"
)

// New builds the root handler.
func New(store *db.Store) http.Handler {
	svc := app.NewService(store)
	// Feature Pack F1: response cache reads its settings live on every
	// request, so dashboard changes take effect without a restart.
	respcache.Configure(func() (bool, int, int) {
		rec, err := store.GetSettings()
		if err != nil || rec == nil {
			return false, 300, 500
		}
		enabled, _ := rec["responseCacheEnabled"].(bool)
		ttl, maxEntries := 300, 500
		if v, ok := rec["responseCacheTTLSeconds"].(float64); ok && v > 0 {
			ttl = int(v)
		}
		if v, ok := rec["responseCacheMaxEntries"].(float64); ok && v > 0 {
			maxEntries = int(v)
		}
		return enabled, ttl, maxEntries
	})
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "engine": "go"})
	})

	mux.HandleFunc("GET /v1/models", func(w http.ResponseWriter, r *http.Request) {
		data := []map[string]any{}
		for _, e := range providers.Models() {
			data = append(data, map[string]any{
				"id":       e.ProviderID + "/" + e.Model.ID,
				"object":   "model",
				"owned_by": e.ProviderID,
				"name":     e.Model.Name,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": data})
	})

	chat := func(w http.ResponseWriter, r *http.Request) { handleChat(w, r, svc) }
	chatHandler := CacheMiddleware(http.HandlerFunc(chat))
	mux.Handle("POST /v1/chat/completions", chatHandler)
	mux.Handle("POST /v1/messages", chatHandler)
	mux.Handle("POST /v1/responses", chatHandler)

	// Feature Pack F4: embedded playground page (client-side vs /v1).
	mux.Handle("GET /playground", PlaygroundHandler())

	// Dashboard management APIs (Phase 2, internal/api registrars).
	api.RegisterAll(mux, api.Deps{Store: store, Chat: svc})

	// Dashboard: static React build (WEB_DIR), SPA fallback to index.html.
	if dir := os.Getenv("WEB_DIR"); dir != "" {
		fs := http.FileServer(http.Dir(dir))
		mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := filepath.Join(dir, filepath.Clean("/"+r.URL.Path))
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				fs.ServeHTTP(w, r)
				return
			}
			http.ServeFile(w, r, filepath.Join(dir, "index.html"))
		}))
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				writeJSON(w, http.StatusOK, map[string]any{
					"service": "proxygo", "dashboard": "set WEB_DIR to the built React dashboard",
					"api": "/v1",
				})
				return
			}
			http.NotFound(w, r)
		})
	}
	return mux
}

func handleChat(w http.ResponseWriter, r *http.Request, svc *chatcore.Service) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("Failed to read body"))
		return
	}
	var body map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody("Invalid JSON body"))
			return
		}
	}
	headers := map[string]string{}
	for k, vs := range r.Header {
		if len(vs) > 0 {
			headers[strings.ToLower(k)] = vs[0]
		}
	}
	apiKey := ""
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		apiKey = strings.TrimPrefix(auth, "Bearer ")
	}
	if apiKey == "" {
		apiKey = r.Header.Get("x-api-key")
	}
	resp, err := svc.HandleChat(r.Context(), chatcore.ChatRequest{
		Body:      body,
		Endpoint:  r.URL.Path,
		Headers:   headers,
		APIKey:    apiKey,
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func errBody(msg string) map[string]any {
	return map[string]any{"error": map[string]any{"message": msg, "type": "invalid_request_error"}}
}
