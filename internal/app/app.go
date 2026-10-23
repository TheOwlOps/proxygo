// Package app wires the ported packages together: providers (registry) +
// db (SQLite store) + translator + executors behind the narrow interfaces
// chatcore defines. This is the parent's integration layer.
package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"time"

	"9router-go/internal/chatcore"
	"9router-go/internal/db"
	"9router-go/internal/executors"
	"9router-go/internal/modelcatalog"
	"9router-go/internal/providers"
	"9router-go/internal/translator"
)

// ---------- helpers on db.Record ----------

func str(r db.Record, k string) string {
	if s, ok := r[k].(string); ok {
		return s
	}
	return ""
}
func toMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return nil
}
func parseTime(v any) time.Time {
	switch t := v.(type) {
	case string:
		if t == "" {
			return time.Time{}
		}
		if ts, err := time.Parse(time.RFC3339, t); err == nil {
			return ts
		}
		if n, err := time.Parse("2006-01-02T15:04:05.000Z07:00", t); err == nil {
			return n
		}
	case float64:
		if t > 1e12 {
			return time.UnixMilli(int64(t))
		}
		return time.Unix(int64(t), 0)
	}
	return time.Time{}
}

// ---------- ProviderSource ----------

type providerSource struct{ store *db.Store }

func (ps providerSource) Provider(idOrAlias string) (chatcore.ProviderInfo, bool) {
	// Custom provider nodes (services/provider.js getProviderConfig):
	// openai-compatible-* clones the openai config, anthropic-compatible-*
	// the claude one; the endpoint lives on the connection, not the registry.
	if strings.HasPrefix(idOrAlias, "openai-compatible-") {
		return chatcore.ProviderInfo{ID: idOrAlias, Format: "openai"}, true
	}
	if strings.HasPrefix(idOrAlias, "anthropic-compatible-") {
		return chatcore.ProviderInfo{ID: idOrAlias, Format: "claude"}, true
	}
	p, ok := providers.Get(idOrAlias)
	if !ok {
		return chatcore.ProviderInfo{}, false
	}
	format := p.Transport.Format
	if format == "" {
		format = "openai"
	}
	noAuth := p.Category == "noauth"
	if v, ok := p.Raw["noAuth"].(bool); ok {
		noAuth = v
	}
	return chatcore.ProviderInfo{ID: p.ID, Format: format, ForceStream: p.Transport.ForceStream, NoAuth: noAuth}, true
}

func (ps providerSource) ResolveProviderAlias(alias string) string {
	if p, ok := providers.Get(alias); ok {
		return p.ID
	}
	return alias
}

func (ps providerSource) ResolveModelAlias(alias string) (string, string, bool) {
	if ps.store != nil {
		if aliases, err := ps.store.GetModelAliases(); err == nil {
			if target, ok := aliases[alias].(string); ok && target != "" {
				if prov, model, found := strings.Cut(target, "/"); found {
					return prov, model, true
				}
				return "", target, true
			}
		}
	}
	return "", "", false
}

func (ps providerSource) ModelMeta(providerID, model string) chatcore.ModelMeta {
	// Phase 2 — Team K (flagged minimal change): consult the extracted
	// PROVIDER_MODELS catalogue (internal/modelcatalog) first — it carries
	// target/supported formats, upstream ids and types that the registry
	// alone does not surface to chatcore. The phase-1 registry-Kind
	// fallback below is unchanged for models the catalogue doesn't know.
	if cm := modelcatalog.ModelMeta(providerID, model); cm.Found || cm.TargetFormat != "" || cm.SupportedFormats != nil {
		meta := chatcore.ModelMeta{
			TargetFormat:     cm.TargetFormat,
			SupportedFormats: cm.SupportedFormats,
			UpstreamID:       cm.UpstreamID,
		}
		switch cm.Type {
		case "image":
			meta.Type = "imageGen"
		case "tts":
			meta.Type = "tts"
		}
		return meta
	}
	p, ok := providers.Get(providerID)
	if !ok {
		return chatcore.ModelMeta{}
	}
	for _, m := range p.Models {
		if m.ID == model {
			meta := chatcore.ModelMeta{}
			switch m.Kind {
			case "image":
				meta.Type = "imageGen"
			case "tts":
				meta.Type = "tts"
			}
			return meta
		}
	}
	return chatcore.ModelMeta{}
}

func (ps providerSource) TargetFormat(providerID string, cred chatcore.Credential) string {
	if cred.RuntimeTransport != nil && cred.RuntimeTransport.Format != "" {
		return cred.RuntimeTransport.Format
	}
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

func (ps providerSource) TransportFor(providerID, format string) *chatcore.TransportOption {
	if strings.HasPrefix(providerID, "openai-compatible-") && format == "openai" {
		return &chatcore.TransportOption{Format: "openai"}
	}
	if strings.HasPrefix(providerID, "anthropic-compatible-") && format == "claude" {
		return &chatcore.TransportOption{Format: "claude"}
	}
	p, ok := providers.Get(providerID)
	if !ok {
		return nil
	}
	// Multi-transport registries keep alternatives in Raw["transports"].
	if list, ok := p.Raw["transports"].([]any); ok {
		for _, item := range list {
			m := toMap(item)
			if m == nil {
				continue
			}
			if f, _ := m["format"].(string); f == format {
				return &chatcore.TransportOption{
					Format:    f,
					BaseURL:   str(m2r(m), "baseUrl"),
					URLSuffix: str(m2r(m), "urlSuffix"),
					Headers:   strMap(m["headers"]),
					Auth:      m["auth"],
				}
			}
		}
	}
	if format == p.Transport.Format || (format == "openai" && p.Transport.Format == "") {
		return &chatcore.TransportOption{
			Format:    format,
			BaseURL:   p.Transport.BaseURL,
			URLSuffix: p.Transport.URLSuffix,
			Headers:   p.Transport.Headers,
			Auth:      transportRaw(p)["auth"],
		}
	}
	return nil
}

func m2r(m map[string]any) db.Record { return db.Record(m) }

func strMap(v any) map[string]string {
	m := toMap(v)
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, val := range m {
		if s, ok := val.(string); ok {
			out[k] = s
		}
	}
	return out
}

func transportRaw(p *providers.Provider) map[string]any {
	return toMap(p.Raw["transport"])
}

func (ps providerSource) Combo(name string) ([]string, bool) {
	if ps.store == nil {
		return nil, false
	}
	rec, err := ps.store.GetComboByName(name)
	if err != nil || rec == nil {
		return nil, false
	}
	var out []string
	switch v := rec["models"].(type) {
	case []any:
		for _, item := range v {
			switch m := item.(type) {
			case string:
				out = append(out, m)
			case map[string]any:
				if s := str(db.Record(m), "model"); s != "" {
					out = append(out, s)
				}
			}
		}
	case string:
		if v != "" {
			out = []string{v}
		}
	}
	return out, len(out) > 0
}

// ---------- Accounts (over db connections repo) ----------

type accounts struct {
	store     *db.Store
	refresher chatcore.TokenRefresher
	mu        sync.Mutex
	cooldown  map[string]time.Time
}

func (a *accounts) Next(provider string, exclude map[string]bool, model, requestedModel string) (chatcore.Credential, *chatcore.AllRateLimited, error) {
	active := true
	conns, err := a.store.GetProviderConnections(db.ConnectionFilter{Provider: provider, IsActive: &active})
	if err != nil {
		return chatcore.Credential{}, nil, err
	}
	now := time.Now()
	var lastRL *chatcore.AllRateLimited
	for _, c := range conns {
		id := str(c, "id")
		if exclude[id] {
			continue
		}
		if until := parseTime(c["rateLimitedUntil"]); !until.IsZero() && until.After(now) {
			lastRL = &chatcore.AllRateLimited{RetryAfter: until}
			continue
		}
		a.mu.Lock()
		cd := a.cooldown[id]
		a.mu.Unlock()
		if cd.After(now) {
			lastRL = &chatcore.AllRateLimited{RetryAfter: cd}
			continue
		}
		psd := toMap(c["providerSpecificData"])
		cred := chatcore.Credential{
			ConnectionID:   id,
			ConnectionName: str(c, "name"),
			APIKey:         str(c, "apiKey"),
			AccessToken:    str(c, "accessToken"),
			RefreshToken:   str(c, "refreshToken"),
			ProjectID:      str(c, "projectId"),
			Specific:       psd,
		}
		if psd != nil {
			cred.BaseURL = str(db.Record(psd), "baseUrl")
		}
		if exp := parseTime(c["expiresAt"]); !exp.IsZero() {
			cred.ExpiresAt = exp
		}
		if p, ok := providers.Get(provider); ok && p.Category == "noauth" {
			cred.NoAuth = true
		}
		return cred, nil, nil
	}
	if len(conns) > 0 && lastRL != nil {
		return chatcore.Credential{}, lastRL, nil
	}
	return chatcore.Credential{}, nil, nil
}

func (a *accounts) RefreshIfNeeded(ctx context.Context, provider string, cred chatcore.Credential) (chatcore.Credential, error) {
	if a.refresher == nil || cred.RefreshToken == "" {
		return cred, nil
	}
	if !cred.ExpiresAt.IsZero() && time.Until(cred.ExpiresAt) > 5*time.Minute {
		return cred, nil
	}
	refreshed, err := a.refresher.Refresh(ctx, provider, cred)
	if err != nil || refreshed == nil {
		return cred, nil // non-fatal, like the JS
	}
	_ = a.PersistRefreshed(cred, *refreshed)
	return *refreshed, nil
}

func (a *accounts) MarkUnavailable(cred chatcore.Credential, status int, errText, provider, model string, resetsAt time.Time) bool {
	until := resetsAt
	if until.IsZero() {
		d := 30 * time.Second
		if status == 429 {
			d = 60 * time.Second
		}
		until = time.Now().Add(d)
	}
	a.mu.Lock()
	if a.cooldown == nil {
		a.cooldown = map[string]time.Time{}
	}
	a.cooldown[cred.ConnectionID] = until
	a.mu.Unlock()
	if cred.ConnectionID != "" {
		_, _ = a.store.UpdateProviderConnection(cred.ConnectionID, db.Record{
			"lastError": errText, "lastErrorAt": time.Now().Format(time.RFC3339),
			"rateLimitedUntil": until.Format(time.RFC3339),
		})
	}
	return true
}

func (a *accounts) ClearError(cred chatcore.Credential, model string) {
	a.mu.Lock()
	delete(a.cooldown, cred.ConnectionID)
	a.mu.Unlock()
}

func (a *accounts) PersistRefreshed(cred chatcore.Credential, refreshed chatcore.Credential) error {
	if cred.ConnectionID == "" {
		return nil
	}
	upd := db.Record{}
	if refreshed.AccessToken != "" {
		upd["accessToken"] = refreshed.AccessToken
	}
	if refreshed.RefreshToken != "" {
		upd["refreshToken"] = refreshed.RefreshToken
	}
	if !refreshed.ExpiresAt.IsZero() {
		upd["expiresAt"] = refreshed.ExpiresAt.Format(time.RFC3339)
	}
	if len(upd) == 0 {
		return nil
	}
	_, err := a.store.UpdateProviderConnection(cred.ConnectionID, upd)
	return err
}

// ---------- Translator adapter ----------

type translatorAdapter struct{}

func (translatorAdapter) TranslateRequest(from, to string, body map[string]any) (map[string]any, error) {
	return translator.TranslateRequest(from, to, body)
}
func (translatorAdapter) TranslateResponseBody(from, to string, body map[string]any) (map[string]any, error) {
	return translator.TranslateResponse(from, to, body)
}
func (translatorAdapter) NeedsTranslation(from, to string) bool {
	return translator.NeedsTranslation(from, to)
}

// WrapStream translates an SSE stream chunk-by-chunk using Team A's
// TranslateStreamChunk. Non-SSE input passes through untouched.
func (translatorAdapter) WrapStream(r io.Reader, from, to string) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		state := translator.NewStreamState(from)
		br := bufio.NewReader(r)
		emit := func(chunks []translator.Body) {
			for _, c := range chunks {
				b, err := json.Marshal(c)
				if err != nil {
					continue
				}
				_, _ = pw.Write([]byte("data: "))
				_, _ = pw.Write(b)
				_, _ = pw.Write([]byte("\n\n"))
			}
		}
		for {
			line, err := br.ReadString('\n')
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "data:") {
				payload := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
				if payload == "[DONE]" {
					emit(mustChunks(translator.TranslateStreamChunk(from, to, nil, state)))
					_, _ = pw.Write([]byte("data: [DONE]\n\n"))
				} else if payload != "" {
					var chunk translator.Body
					if json.Unmarshal([]byte(payload), &chunk) == nil {
						emit(mustChunks(translator.TranslateStreamChunk(from, to, chunk, state)))
					} else {
						_, _ = pw.Write([]byte(line))
					}
				}
			} else if trimmed != "" {
				_, _ = pw.Write([]byte(line))
			}
			if err != nil {
				emit(mustChunks(translator.TranslateStreamChunk(from, to, nil, state)))
				return
			}
		}
	}()
	return pr
}

func mustChunks(chunks []translator.Body, err error) []translator.Body {
	if err != nil {
		return nil
	}
	return chunks
}

// ---------- Executor adapter ----------

type executorAdapter struct{}

func buildProviderInfo(providerID string) *executors.ProviderInfo {
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
	traw := transportRaw(p)
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
	if q := toMap(traw["quirks"]); q != nil {
		info.Quirks = q
	}
	if oauth := toMap(p.Raw["oauth"]); oauth != nil {
		info.ClientID = str(db.Record(oauth), "clientId")
		info.ClientSecret = str(db.Record(oauth), "clientSecret")
		info.TokenURL = str(db.Record(oauth), "tokenUrl")
	}
	return info
}

func toExecCred(cred chatcore.Credential) executors.Credential {
	ec := executors.Credential{
		ConnectionID: cred.ConnectionID, ConnectionName: cred.ConnectionName,
		APIKey: cred.APIKey, AccessToken: cred.AccessToken, RefreshToken: cred.RefreshToken,
		CopilotToken: cred.CopilotToken, BaseURL: cred.BaseURL, ProjectID: cred.ProjectID,
		ExpiresAt: cred.ExpiresAt, NoAuth: cred.NoAuth, Specific: cred.Specific,
		RawHeaders: cred.RawHeaders, OverrideHeaders: cred.OverrideHeaders,
	}
	if cred.RuntimeTransport != nil {
		rt := &executors.TransportOverride{
			BaseURL: cred.RuntimeTransport.BaseURL, URLSuffix: cred.RuntimeTransport.URLSuffix,
			Format: cred.RuntimeTransport.Format, Headers: cred.RuntimeTransport.Headers,
		}
		if b, err := json.Marshal(cred.RuntimeTransport.Auth); err == nil {
			var spec executors.AuthSpec
			if json.Unmarshal(b, &spec) == nil {
				rt.Auth = &spec
			}
		}
		ec.RuntimeTransport = rt
	}
	return ec
}

func (executorAdapter) Execute(ctx context.Context, provider string, info chatcore.ProviderInfo, cred chatcore.Credential, body []byte) (*chatcore.ExecResult, error) {
	pInfo := buildProviderInfo(provider)
	if info.Format != "" {
		pInfo.Format = info.Format
	}
	if info.ForceStream {
		pInfo.ForceStream = true
	}
	res, err := executors.For(provider).Execute(ctx, pInfo, toExecCred(cred), body)
	if err != nil {
		return nil, err
	}
	return &chatcore.ExecResult{
		Response: res.Response, URL: res.URL, Headers: res.Headers,
		TransformedBody: res.TransformedBody, ResponseFormat: res.ResponseFormat,
	}, nil
}

func (executorAdapter) ParseError(provider string, status int, bodyText string) *chatcore.ParsedErrorLike {
	ex := executors.For(provider)
	ep, ok := ex.(executors.ErrorParser)
	if !ok {
		return nil
	}
	pe := ep.ParseError(status, bodyText)
	if pe == nil {
		return nil
	}
	return &chatcore.ParsedErrorLike{Status: pe.Status, Message: pe.Message, ResetsAt: pe.ResetsAt}
}

// ---------- TokenRefresher adapter ----------

type refresherAdapter struct{}

func (refresherAdapter) Refresh(ctx context.Context, provider string, cred chatcore.Credential) (*chatcore.Credential, error) {
	ex := executors.For(provider)
	rf, ok := ex.(executors.Refresher)
	if !ok {
		return nil, nil
	}
	out, err := rf.RefreshCredentials(ctx, buildProviderInfo(provider), toExecCred(cred))
	if err != nil || out == nil {
		return nil, err
	}
	c := cred
	c.AccessToken = out.AccessToken
	c.RefreshToken = out.RefreshToken
	c.CopilotToken = out.CopilotToken
	c.ExpiresAt = out.ExpiresAt
	return &c, nil
}

// ---------- Settings / Keys ----------

type settingsSource struct{ store *db.Store }

func (ss settingsSource) Settings() chatcore.Settings {
	rec, err := ss.store.GetSettings()
	if err != nil || rec == nil {
		return chatcore.Settings{}
	}
	out := chatcore.Settings{}
	if v, ok := rec["requireApiKey"].(bool); ok {
		out.RequireAPIKey = v
	}
	if v, ok := rec["rtkEnabled"].(bool); ok {
		out.RTKEnabled = v
	}
	if v, ok := rec["piiRedactionEnabled"].(bool); ok {
		out.PIIRedactionEnabled = v
	}
	out.ComboStrategy = str(rec, "comboStrategy")
	return out
}

type keysValidator struct{ store *db.Store }

func (kv keysValidator) ValidAPIKey(key string) bool {
	ok, err := kv.store.ValidateAPIKey(key)
	return err == nil && ok
}

// ---------- Service builder ----------

// NewService builds the fully wired chatcore.Service over the store.
func NewService(store *db.Store) *chatcore.Service {
	acc := &accounts{store: store, cooldown: map[string]time.Time{}}
	ref := refresherAdapter{}
	acc.refresher = ref
	svc := chatcore.NewService(chatcore.Service{
		Providers:  providerSource{store: store},
		Translator: translatorAdapter{},
		Executor:   executorAdapter{},
		Accounts:   acc,
		Refresher:  ref,
		TokenSaver: TokenSaverImpl(), // internal/rtk port (see rtk.go)
		Settings:   settingsSource{store: store},
		Keys:       keysValidator{store: store},
	})
	// Feature Pack 1+3 hooks — all opt-in via settings, no-op when off:
	// PII redaction (BodyGuard; the national-ID opt-in is captured at
	// wire time), per-key limits (always attached; keys without limits
	// are unlimited and the limiter fails open), circuit breaker (only
	// attached when circuitBreakerEnabled, thresholds read now).
	nationalID := false
	if rec, err := store.GetSettings(); err == nil && rec != nil {
		if v, ok := rec["piiRedactNationalId"].(bool); ok {
			nationalID = v
		}
		WireBreaker(svc, rec)
	}
	svc.BodyGuard = NewPIIGuard(nationalID)
	svc.KeyLimiter = KeyLimiterImpl(store)
	return svc
}

// Ensure bytes import is used even if helpers change.
var _ = bytes.MinRead
