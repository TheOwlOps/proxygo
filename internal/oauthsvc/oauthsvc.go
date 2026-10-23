// Package oauthsvc is the Go port of src/lib/oauth/ (constants, providers,
// services, utils) from 9Router v0.5.104.
//
// Provider OAuth configuration data is NOT hand-copied: it is read from the
// Phase-1 registry port (internal/providers, Provider.Raw["oauth"]), which
// is exactly where the JS constants/oauth.js reads it from too
// (PROVIDER_OAUTH). The few configs the JS keeps outside the registry
// (xai constants, trae/windsurf/nous/xiaomi/zed constants, the Google and
// Antigravity desktop OAuth clients from open-sse/providers/shared.js) are
// reproduced in providers.go from those source files.
package oauthsvc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"9router-go/internal/providers"
)

// HTTPClient performs every upstream OAuth call. Tests replace it (and the
// endpoint URLs inside provider configs) to run against httptest servers.
var HTTPClient = &http.Client{Timeout: 30 * time.Second}

// Config is one provider's OAuth config block (registry `oauth` object plus
// the JS-side constants merged in). Values keep their JSON shapes.
type Config map[string]any

// Str reads a string config value.
func (c Config) Str(k string) string {
	if s, ok := c[k].(string); ok {
		return s
	}
	return ""
}

// StrOr reads a string config value with a fallback.
func (c Config) StrOr(k, def string) string {
	if s := c.Str(k); s != "" {
		return s
	}
	return def
}

// StrList reads a scopes value that may be []any, a single string, or
// space/comma separated.
func (c Config) StrList(k string) []string {
	switch v := c[k].(type) {
	case []any:
		out := []string{}
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if strings.TrimSpace(v) == "" {
			return nil
		}
		return strings.Fields(strings.ReplaceAll(v, ",", " "))
	}
	return nil
}

// ScopeString joins the provider's scopes the way its JS buildAuthUrl does:
// registry `scope` (string) wins, else `scopes` joined with spaces.
func (c Config) ScopeString() string {
	if s := c.Str("scope"); s != "" {
		return s
	}
	return strings.Join(c.StrList("scopes"), " ")
}

// RegistryOAuth returns the raw registry oauth block for a provider id.
func RegistryOAuth(id string) Config {
	p, ok := providers.Get(id)
	if !ok || p.Raw == nil {
		return Config{}
	}
	if m, ok := p.Raw["oauth"].(map[string]any); ok {
		return Config(m)
	}
	return Config{}
}

// RegistryRaw returns a provider's full registry object (or nil).
func RegistryRaw(id string) map[string]any {
	p, ok := providers.Get(id)
	if !ok {
		return nil
	}
	return p.Raw
}

// ---- shared HTTP helpers (the JS uses fetch with these shapes) ----

// PostForm POSTs application/x-www-form-urlencoded and parses a JSON body.
// It returns the HTTP status and the parsed body (error bodies included —
// OAuth endpoints report errors as JSON). A non-JSON body becomes
// {"error":"invalid_response","error_description":<text>}.
func PostForm(ctx context.Context, endpoint string, form url.Values, headers map[string]string) (int, map[string]any, error) {
	return doReq(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()),
		"application/x-www-form-urlencoded", headers)
}

// PostJSON POSTs a JSON body and parses a JSON response (same error shape
// policy as PostForm).
func PostJSON(ctx context.Context, endpoint string, payload any, headers map[string]string) (int, map[string]any, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	return doReq(ctx, http.MethodPost, endpoint, bytes.NewReader(raw), "application/json", headers)
}

// GetJSON GETs and parses a JSON response.
func GetJSON(ctx context.Context, endpoint string, headers map[string]string) (int, map[string]any, error) {
	return doReq(ctx, http.MethodGet, endpoint, nil, "", headers)
}

// Raw performs a request and returns status + raw body text.
func Raw(ctx context.Context, method, endpoint string, body io.Reader, contentType string, headers map[string]string) (int, string, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return 0, "", nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return resp.StatusCode, "", resp.Header, err
	}
	return resp.StatusCode, string(raw), resp.Header, nil
}

func doReq(ctx context.Context, method, endpoint string, body io.Reader, contentType string, headers map[string]string) (int, map[string]any, error) {
	status, text, _, err := Raw(ctx, method, endpoint, body, contentType, headers)
	if err != nil {
		return 0, nil, err
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(text), &out); err != nil || out == nil {
		out = map[string]any{"error": "invalid_response", "error_description": text}
	}
	return status, out, nil
}

// TokenError mirrors the JS `throw new Error("Token exchange failed: …")`.
func TokenError(prefix string, status int, body map[string]any, raw string) error {
	if raw != "" {
		return fmt.Errorf("%s: %s", prefix, raw)
	}
	if msg := strOf(body, "error_description"); msg != "" {
		return fmt.Errorf("%s: %s", prefix, msg)
	}
	if msg := strOf(body, "error"); msg != "" {
		return fmt.Errorf("%s: %s", prefix, msg)
	}
	return fmt.Errorf("%s: HTTP %d", prefix, status)
}

func strOf(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	if s, ok := m[k].(string); ok {
		return s
	}
	return ""
}

func numOf(m map[string]any, k string) (float64, bool) {
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

// SetIf sets dst[k]=v when v is a non-empty string.
func SetIf(dst map[string]any, k, v string) {
	if v != "" {
		dst[k] = v
	}
}

// NumPair carries a (value, present) pair for SetNumIf call sites.
type NumPair struct {
	V  float64
	Ok bool
}

// NumPairOf reads a numeric map value as a NumPair.
func NumPairOf(m map[string]any, k string) NumPair {
	v, ok := numOf(m, k)
	return NumPair{V: v, Ok: ok}
}

// SetNumIf sets dst[k]=p.V when p.Ok.
func SetNumIf(dst map[string]any, k string, p NumPair) {
	if p.Ok {
		dst[k] = p.V
	}
}
