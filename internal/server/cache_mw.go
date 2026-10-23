package server

import (
	"bytes"
	"io"
	"net/http"
	"strings"

	"proxygo/internal/respcache"
)

// cache_mw.go — Feature Pack F1: byte-level response cache for the
// three chat POST endpoints, implemented as middleware so the chat
// handler itself is untouched. Parent wires it in New():
//
//	chatHandler := CacheMiddleware(http.HandlerFunc(chat))
//	mux.Handle("POST /v1/chat/completions", chatHandler) // etc.
//
// Behavior (docs/FEATURE_PACK_13.md F1):
//   - Only POST /v1/chat/completions, /v1/messages, /v1/responses.
//   - Fully opt-in: when respcache.Config() reports disabled (the
//     default until Configure is wired to settings), every request
//     passes through untouched.
//   - Header `x-proxygo-no-cache: 1` bypasses both lookup and store.
//   - On a hit the stored status/headers/body are replayed verbatim
//     plus `x-proxygo-cache: hit`. On a miss the response is tee'd
//     while streaming to the client and stored after completion —
//     ONLY for status 200 and bodies up to 4MB — so SSE streams are
//     cached as their raw byte stream and replayed byte for byte.

// maxCacheBodyBytes caps a stored response body at 4MB; larger
// responses stream through uncached.
const maxCacheBodyBytes = 4 << 20

var cacheablePaths = map[string]bool{
	"/v1/chat/completions": true,
	"/v1/messages":         true,
	"/v1/responses":        true,
}

// CacheMiddleware wraps next with the response cache described above.
func CacheMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !cacheablePaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		enabled, _, _ := respcache.Config()
		if !enabled || r.Header.Get("x-proxygo-no-cache") == "1" {
			next.ServeHTTP(w, r)
			return
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			// Unreadable body: hand the request on as-is; the chat
			// handler produces its own read error.
			next.ServeHTTP(w, r)
			return
		}
		// Restore the body for the downstream handler.
		r.Body = io.NopCloser(bytes.NewReader(raw))
		r.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(raw)), nil
		}

		key, ok := respcache.KeyFor(r.URL.Path, raw, cacheAPIKey(r))
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		if ent, hit := respcache.Get(key); hit {
			for k, vs := range ent.Header {
				for _, v := range vs {
					w.Header().Add(k, v)
				}
			}
			w.Header().Set("x-proxygo-cache", "hit")
			w.WriteHeader(ent.Status)
			_, _ = w.Write(ent.Body)
			return
		}

		cw := &captureWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(cw, r)
		if cw.status == http.StatusOK && !cw.overflow {
			respcache.Put(key, respcache.Entry{
				Status: cw.status,
				Header: cw.Header().Clone(),
				Body:   cw.buf.Bytes(),
			})
		}
	})
}

// cacheAPIKey extracts the caller's API key the same way handleChat
// does (Authorization: Bearer, else x-api-key).
func cacheAPIKey(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return r.Header.Get("x-api-key")
}

// captureWriter tees the response into a bounded buffer while it is
// written to the client, so streaming (SSE) responses are captured
// without delaying or altering a single byte.
type captureWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
	buf         bytes.Buffer
	overflow    bool
}

func (c *captureWriter) WriteHeader(status int) {
	if !c.wroteHeader {
		c.status = status
		c.wroteHeader = true
	}
	c.ResponseWriter.WriteHeader(status)
}

func (c *captureWriter) Write(p []byte) (int, error) {
	if !c.wroteHeader {
		c.WriteHeader(http.StatusOK)
	}
	n, err := c.ResponseWriter.Write(p)
	if n > 0 {
		if c.buf.Len()+n <= maxCacheBodyBytes {
			c.buf.Write(p[:n])
		} else {
			c.overflow = true
		}
	}
	return n, err
}

// Flush forwards streaming flushes to the client (SSE).
func (c *captureWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (c *captureWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }
