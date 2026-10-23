package executors

// Port of open-sse/services/cursorModels.js — the live Cursor model
// catalog (AgentService GetUsableModels) used to resolve the "Auto
// (Server Picks)" / "default" alias to a real agent-capable model.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// agent.v1.ModelDetails / GetUsableModelsResponse field numbers.
const (
	modelDetailsID            = 1
	modelDetailsDisplayID     = 3
	modelDetailsDisplayName   = 4
	modelDetailsDisplayShort  = 5
	usableModelsField         = 1
	availableModelsField      = 2
	availableModelName        = 1
	availableModelDefaultOn   = 2
	availableModelIsChatOnly  = 4
	availableModelSupportsAgt = 5
	availableModelIsHidden    = 35
)

const (
	cursorCatalogFetchTimeout = 10 * time.Second
	cursorCatalogCacheTTL     = 5 * time.Minute
)

// CursorCatalogModel is one catalog entry: {id, name} plus the
// AvailableModels picker flags once merged.
type CursorCatalogModel struct {
	ID            string
	Name          string
	DefaultOn     bool
	IsChatOnly    bool
	SupportsAgent bool
	IsHidden      bool
	HasFlags      bool
}

// ParseCursorUsableModels ports parseCursorUsableModels(): repeated
// ModelDetails under response field 1.
func ParseCursorUsableModels(payload []byte) []CursorCatalogModel {
	response := pbDecodeMessage(payload)
	seen := map[string]bool{}
	var models []CursorCatalogModel
	for _, entry := range response.get(usableModelsField) {
		if entry.Bytes == nil {
			continue
		}
		detail := pbDecodeMessage(entry.Bytes)
		id := strings.TrimSpace(detail.firstString(modelDetailsID))
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		name := detail.firstString(modelDetailsDisplayName)
		if name == "" {
			name = detail.firstString(modelDetailsDisplayShort)
		}
		if name == "" {
			name = detail.firstString(modelDetailsDisplayID)
		}
		if name == "" {
			name = id
		}
		models = append(models, CursorCatalogModel{ID: id, Name: strings.TrimSpace(name)})
	}
	return models
}

// ParseCursorAvailableModels ports parseCursorAvailableModels():
// repeated AvailableModels under response field 2.
func ParseCursorAvailableModels(payload []byte) []CursorCatalogModel {
	response := pbDecodeMessage(payload)
	seen := map[string]bool{}
	var models []CursorCatalogModel
	for _, entry := range response.get(availableModelsField) {
		if entry.Bytes == nil {
			continue
		}
		fields := pbDecodeMessage(entry.Bytes)
		id := strings.TrimSpace(fields.firstString(availableModelName))
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		models = append(models, CursorCatalogModel{
			ID:            id,
			DefaultOn:     fields.firstVarint(availableModelDefaultOn) == 1,
			IsChatOnly:    fields.firstVarint(availableModelIsChatOnly) == 1,
			SupportsAgent: fields.firstVarint(availableModelSupportsAgt) == 1,
			IsHidden:      fields.firstVarint(availableModelIsHidden) == 1,
			HasFlags:      true,
		})
	}
	return models
}

// MergeCursorModelFlags ports mergeCursorModelFlags().
func MergeCursorModelFlags(models []CursorCatalogModel, payload []byte) []CursorCatalogModel {
	available := ParseCursorAvailableModels(payload)
	if len(available) == 0 || models == nil {
		return models
	}
	flagsByID := map[string]CursorCatalogModel{}
	for _, m := range available {
		flagsByID[m.ID] = m
	}
	out := make([]CursorCatalogModel, len(models))
	for i, m := range models {
		out[i] = m
		if flags, ok := flagsByID[m.ID]; ok {
			out[i].DefaultOn = flags.DefaultOn
			out[i].IsChatOnly = flags.IsChatOnly
			out[i].SupportsAgent = flags.SupportsAgent
			out[i].IsHidden = flags.IsHidden
			out[i].HasFlags = true
		}
	}
	return out
}

// ResolveAutoModelSelection ports resolveAutoModelSelection(): prefer
// the picker's defaultOn model among usable agent models, else the
// first usable one. Returns ("", false) when nothing is usable.
func ResolveAutoModelSelection(models []CursorCatalogModel) (string, bool) {
	if len(models) == 0 {
		return "", false
	}
	var usable []CursorCatalogModel
	for _, m := range models {
		if m.SupportsAgent && !m.IsChatOnly && !m.IsHidden {
			usable = append(usable, m)
		}
	}
	if len(usable) == 0 {
		return "", false
	}
	for _, m := range usable {
		if m.DefaultOn {
			return m.ID, true
		}
	}
	return usable[0].ID, true
}

// ---------- live fetch (cached) ----------

type cursorCatalogCacheEntry struct {
	expiresAt time.Time
	models    []CursorCatalogModel
}

var (
	cursorCatalogCacheMu sync.Mutex
	cursorCatalogCache   = map[string]cursorCatalogCacheEntry{}
)

// ClearCursorModelCache ports clearCursorModelCache().
func ClearCursorModelCache() {
	cursorCatalogCacheMu.Lock()
	defer cursorCatalogCacheMu.Unlock()
	cursorCatalogCache = map[string]cursorCatalogCacheEntry{}
}

func cursorCatalogCacheKey(cred Credential) string {
	seed := cred.SpecificString("machineId") + ":" + cred.AccessToken
	if seed == ":" {
		return "cursor-anonymous"
	}
	sum := sha256.Sum256([]byte("cursor:" + seed))
	return hex.EncodeToString(sum[:])
}

// cursorModelsURL builds the GetUsableModels URL from the provider's
// oauth config (agentEndpoint + modelsEndpoint), like getCursorModelsUrl.
func cursorModelsURL(p *ProviderInfo) string {
	endpoint := cursorOAuthString(p, "agentEndpoint")
	modelsEndpoint := cursorOAuthString(p, "modelsEndpoint")
	if endpoint == "" || modelsEndpoint == "" {
		return ""
	}
	return strings.TrimSuffix(endpoint, "/") + modelsEndpoint
}

// ResolveCursorModels ports resolveCursorModels(): returns the live
// catalog or nil on any failure so callers fall back to static models.
func ResolveCursorModels(ctx context.Context, p *ProviderInfo, cred Credential) []CursorCatalogModel {
	if cred.AccessToken == "" || cred.SpecificString("machineId") == "" {
		return nil
	}
	key := cursorCatalogCacheKey(cred)
	now := time.Now()
	cursorCatalogCacheMu.Lock()
	if entry, ok := cursorCatalogCache[key]; ok && entry.expiresAt.After(now) {
		models := entry.models
		cursorCatalogCacheMu.Unlock()
		return models
	}
	cursorCatalogCacheMu.Unlock()

	models, err := fetchCursorCatalog(ctx, p, cred)
	if err != nil || len(models) == 0 {
		return nil
	}
	cursorCatalogCacheMu.Lock()
	cursorCatalogCache[key] = cursorCatalogCacheEntry{
		expiresAt: now.Add(cursorCatalogCacheTTL),
		models:    models,
	}
	cursorCatalogCacheMu.Unlock()
	return models
}

// fetchCursorCatalog posts the unary GetUsableModels RPC
// (unframed protobuf body, application/proto) over HTTP/2.
func fetchCursorCatalog(ctx context.Context, p *ProviderInfo, cred Credential) ([]CursorCatalogModel, error) {
	url := cursorModelsURL(p)
	if url == "" {
		return nil, nil
	}
	headers := BuildCursorHeaders(cred.AccessToken, cred.SpecificString("machineId"),
		cred.SpecificString("ghostMode") != "false")
	// Connect unary calls use an unframed protobuf body.
	headers["accept"] = "application/proto"
	headers["content-type"] = "application/proto"
	delete(headers, "connect-accept-encoding")
	delete(headers, "connect-protocol-version")

	reqCtx, cancel := context.WithTimeout(ctx, cursorCatalogFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(nil))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := cursorHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := readAllBody(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, &cursorHTTPError{status: resp.StatusCode}
	}
	return MergeCursorModelFlags(ParseCursorUsableModels(body), body), nil
}

type cursorHTTPError struct{ status int }

func (e *cursorHTTPError) Error() string {
	return "Cursor GetUsableModels returned " + strconv.Itoa(e.status)
}
