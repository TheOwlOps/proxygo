package mitm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// In-process port of server.js: where the JS spawns a Node child
// process, the Go port serves the MITM listener from a goroutine in the
// same binary (identical wire behaviour: SNI-based leaf certs,
// passthrough via public-DNS resolution, chat interception to the
// router). Port: LOCAL_PORT 443 (env MITM_PORT override for tests).

func mitmPort() int {
	if v := os.Getenv("MITM_PORT"); v != "" {
		var p int
		if _, err := fmt.Sscanf(v, "%d", &p); err == nil && p > 0 {
			return p
		}
	}
	return 443
}

type ipCacheEntry struct {
	ip string
	at time.Time
}

var (
	ipCache   = map[string]ipCacheEntry{}
	ipCacheMu sync.Mutex
	publicDNS = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}
)

// resolveTargetIP (server.js): public-DNS lookup with a 5-min cache.
func resolveTargetIP(hostname string) (string, error) {
	ipCacheMu.Lock()
	if e, ok := ipCache[hostname]; ok && time.Since(e.at) < 5*time.Minute {
		ipCacheMu.Unlock()
		return e.ip, nil
	}
	ipCacheMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := publicDNS.LookupIPAddr(ctx, hostname)
	if err != nil || len(ips) == 0 {
		// OS resolver fallback (hosts file would loop back to us).
		ips2, err2 := net.DefaultResolver.LookupIPAddr(ctx, hostname)
		if err2 != nil || len(ips2) == 0 {
			if err != nil {
				return "", err
			}
			return "", fmt.Errorf("no addresses for %s", hostname)
		}
		ips = ips2
	}
	ip := ips[0].IP.String()
	ipCacheMu.Lock()
	ipCache[hostname] = ipCacheEntry{ip: ip, at: time.Now()}
	ipCacheMu.Unlock()
	return ip, nil
}

type mitmServer struct {
	httpSrv *http.Server
	ln      net.Listener
	apiKey  string
	base    string
	leafMu  sync.Mutex
	leafs   map[string]*tls.Certificate
}

func (s *mitmServer) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := hello.ServerName
	ca, err := LoadRootCA()
	if err != nil {
		return nil, err
	}
	if domain == "" {
		// Default: serve the root CA pair (server.js SNICallback default).
		cert, err := tls.X509KeyPair([]byte(ca.pem), mustKeyPEM())
		if err != nil {
			return nil, err
		}
		return &cert, nil
	}
	s.leafMu.Lock()
	defer s.leafMu.Unlock()
	if c, ok := s.leafs[domain]; ok {
		return c, nil
	}
	certPEM, keyPEM, err := GenerateLeafCert(domain)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair([]byte(certPEM+"\n"+ca.pem), []byte(keyPEM))
	if err != nil {
		return nil, err
	}
	s.leafs[domain] = &cert
	return &cert, nil
}

func mustKeyPEM() []byte {
	raw, _ := os.ReadFile(rootCAKeyPath())
	return raw
}

var stripRouterHeaders = map[string]bool{
	"host": true, "content-length": true, "connection": true,
	"transfer-encoding": true, "content-type": true, "authorization": true,
}

// fetchRouter (handlers/base.js): POST JSON to the router, return the
// raw response for streaming back.
func (s *mitmServer) fetchRouter(body []byte, path string, client http.Header) (*http.Response, error) {
	req, err := http.NewRequest("POST", strings.TrimRight(s.base, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, vs := range client {
		if stripRouterHeaders[strings.ToLower(k)] {
			continue
		}
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("Content-Type", "application/json")
	if s.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.apiKey)
	}
	return http.DefaultClient.Do(req)
}

// pipeRouterResponse streams a router response back (base.js pipeSSE).
func pipeRouterResponse(resp *http.Response, w http.ResponseWriter) {
	defer resp.Body.Close()
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/json"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	if strings.Contains(ct, "text/event-stream") {
		w.Header().Set("X-Accel-Buffering", "no")
	}
	w.WriteHeader(resp.StatusCode)
	fl, _ := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			_, _ = w.Write(buf[:n])
			if fl != nil {
				fl.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

func writeMitmError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(500)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{"message": msg, "type": "mitm_error"},
	})
}

func (s *mitmServer) interceptAntigravity(w http.ResponseWriter, r *http.Request, body []byte) {
	isStream := strings.Contains(r.URL.String(), ":streamGenerateContent")
	fail := func(err error) {
		if isStream {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(200)
			payload, _ := json.Marshal(map[string]any{"error": map[string]any{"message": err.Error()}})
			fmt.Fprintf(w, "data: %s\r\n\r\n", payload)
			return
		}
		writeMitmError(w, err.Error())
	}
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		fail(err)
		return
	}
	if m, ok := parsed["model"].(string); ok && m != "" {
		parsed["model"] = GetMappedModel(m, "antigravity")
	}
	out, _ := json.Marshal(parsed)
	resp, err := s.fetchRouter(out, "/v1/chat/completions", r.Header)
	if err != nil {
		fail(err)
		return
	}
	pipeRouterResponse(resp, w)
}

var copilotURLMap = []struct{ pattern, path string }{
	{"/chat/completions", "/v1/chat/completions"},
	{"/v1/messages", "/v1/messages"},
	{"/responses", "/v1/responses"},
}

func (s *mitmServer) interceptCopilot(w http.ResponseWriter, r *http.Request, body []byte) {
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		writeMitmError(w, err.Error())
		return
	}
	if m, ok := parsed["model"].(string); ok {
		parsed["model"] = GetMappedModel(m, "copilot")
	}
	routerPath := "/v1/chat/completions"
	for _, m := range copilotURLMap {
		if strings.Contains(r.URL.String(), m.pattern) {
			routerPath = m.path
			break
		}
	}
	out, _ := json.Marshal(parsed)
	resp, err := s.fetchRouter(out, routerPath, r.Header)
	if err != nil {
		writeMitmError(w, err.Error())
		return
	}
	pipeRouterResponse(resp, w)
}

func (s *mitmServer) interceptCursor(w http.ResponseWriter, r *http.Request) {
	// handlers/cursor.js — verbatim behaviour.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(501)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"message": "Cursor MITM support is coming soon.",
			"type":    "not_implemented",
		},
	})
}

func (s *mitmServer) passthrough(w http.ResponseWriter, r *http.Request, body []byte, host string) {
	upstreamHost := host
	if rw, ok := HostRewrite[host]; ok {
		upstreamHost = rw
	}
	ip, err := resolveTargetIP(upstreamHost)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, "MITM proxy error: %v", err)
		return
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: upstreamHost, MinVersion: tls.VersionTLS12},
		DialContext:     (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := &tls.Dialer{Config: &tls.Config{ServerName: upstreamHost, MinVersion: tls.VersionTLS12}}
			return d.DialContext(ctx, network, net.JoinHostPort(ip, "443"))
		},
	}
	target := "https://" + upstreamHost + r.URL.RequestURI()
	outReq, err := http.NewRequest(r.Method, target, bytes.NewReader(body))
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	for k, vs := range r.Header {
		lk := strings.ToLower(k)
		if lk == "host" || lk == "content-length" || lk == "connection" {
			continue
		}
		for _, v := range vs {
			outReq.Header.Add(k, v)
		}
	}
	outReq.Host = upstreamHost
	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, "MITM proxy error: %v", err)
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

func (s *mitmServer) handle(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	body, _ := io.ReadAll(r.Body)
	// Anti-loop (server.js): requests originating from ProxyGo itself
	// carry x-request-source: local and are never intercepted.
	if r.Header.Get("x-request-source") == "local" {
		s.passthrough(w, r, body, host)
		return
	}
	tool := ToolForHost(host)
	headerMap := map[string]string{}
	for k := range r.Header {
		headerMap[strings.ToLower(k)] = r.Header.Get(k)
	}
	if tool != "" && IsChatRequest(tool, r.URL.String(), headerMap) {
		switch tool {
		case "antigravity":
			s.interceptAntigravity(w, r, body)
			return
		case "copilot":
			s.interceptCopilot(w, r, body)
			return
		case "cursor":
			s.interceptCursor(w, r)
			return
		case "kiro":
			// server.js: intercept only when the request's model
			// resolves through the alias map; otherwise passthrough
			// to the real Kiro endpoint unmapped.
			if mapped := kiroMappedModel(body); mapped != "" {
				s.interceptKiro(w, r, body, mapped)
				return
			}
		}
	}
	s.passthrough(w, r, body, host)
}

// startListener binds 443 (or MITM_PORT) and serves until stopped.
func (s *mitmServer) startListener() error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", mitmPort()))
	if err != nil {
		return err
	}
	s.ln = ln
	s.httpSrv = &http.Server{
		Handler: http.HandlerFunc(s.handle),
		TLSConfig: &tls.Config{
			GetCertificate: s.getCertificate,
			MinVersion:     tls.VersionTLS12,
		},
	}
	go func() {
		_ = s.httpSrv.ServeTLS(ln, "", "")
	}()
	return nil
}

func (s *mitmServer) stop() {
	if s.httpSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.httpSrv.Shutdown(ctx)
	}
	if s.ln != nil {
		_ = s.ln.Close()
	}
}
