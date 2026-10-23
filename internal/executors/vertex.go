package executors

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// VertexExecutor ports open-sse/executors/vertex.js: Google Vertex AI.
//   - "vertex": Gemini models via regional/global Vertex endpoints.
//   - "vertex-partner": partner models via the global OpenAI-compatible
//     endpoint (project_id required in the path).
//
// Auth flows ported: service-account JSON (stored as the connection's
// apiKey) → RS256 JWT assertion → access token (minted + cached here, as
// the JS does in tokenRefresh.js); ADC authorized_user JSON → OAuth
// refresh; pre-set accessToken; raw API key via ?key= (with project
// auto-resolution probe for vertex-partner).
type VertexExecutor struct {
	*Base
	providerID string
}

type vertexSA struct {
	Type        string `json:"type"`
	ProjectID   string `json:"project_id"`
	PrivateKey  string `json:"private_key"`
	ClientEmail string `json:"client_email"`
}

type vertexADC struct {
	Type         string `json:"type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
	QuotaProject string `json:"quota_project_id"`
}

func parseVertexSA(apiKey string) *vertexSA {
	if !strings.HasPrefix(strings.TrimSpace(apiKey), "{") {
		return nil
	}
	var sa vertexSA
	if json.Unmarshal([]byte(apiKey), &sa) != nil {
		return nil
	}
	if sa.Type != "service_account" || sa.ClientEmail == "" || sa.PrivateKey == "" {
		return nil
	}
	return &sa
}

func parseVertexADC(apiKey string) *vertexADC {
	if !strings.HasPrefix(strings.TrimSpace(apiKey), "{") {
		return nil
	}
	var adc vertexADC
	if json.Unmarshal([]byte(apiKey), &adc) != nil {
		return nil
	}
	if adc.Type != "authorized_user" || adc.ClientID == "" || adc.ClientSecret == "" || adc.RefreshToken == "" {
		return nil
	}
	return &adc
}

var (
	vertexTokenCacheMu sync.Mutex
	vertexTokenCache   = map[string]vertexCachedToken{}
)

type vertexCachedToken struct {
	token  string
	expiry time.Time
}

// mintVertexSAToken exchanges a service-account JWT assertion for an
// access token (services/tokenRefresh.js refreshVertexToken), cached
// until ~1 minute before expiry.
func mintVertexSAToken(ctx context.Context, sa *vertexSA) (string, error) {
	cacheKey := sa.ClientEmail
	vertexTokenCacheMu.Lock()
	if ct, ok := vertexTokenCache[cacheKey]; ok && time.Until(ct.expiry) > time.Minute {
		vertexTokenCacheMu.Unlock()
		return ct.token, nil
	}
	vertexTokenCacheMu.Unlock()

	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return "", errors.New("vertex: SA private_key is not PEM")
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		if k, err2 := x509.ParsePKCS1PrivateKey(block.Bytes); err2 == nil {
			keyAny = k
		} else {
			return "", fmt.Errorf("vertex: parse SA private key: %w", err)
		}
	}
	rsaKey, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return "", errors.New("vertex: SA private key is not RSA")
	}
	now := time.Now()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{
		"iss":   sa.ClientEmail,
		"scope": "https://www.googleapis.com/auth/cloud-platform",
		"aud":   "https://oauth2.googleapis.com/token",
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
	})
	signingInput := header + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	assertion := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("vertex: token exchange failed: %s", resp.Status)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.AccessToken == "" {
		return "", errors.New("vertex: token exchange returned no access_token")
	}
	ttl := out.ExpiresIn
	if ttl <= 0 {
		ttl = 3600
	}
	vertexTokenCacheMu.Lock()
	vertexTokenCache[cacheKey] = vertexCachedToken{token: out.AccessToken, expiry: now.Add(time.Duration(ttl) * time.Second)}
	vertexTokenCacheMu.Unlock()
	return out.AccessToken, nil
}

// refreshGoogleToken ports services/tokenRefresh.js refreshGoogleToken
// (ADC user credentials → access token).
func refreshGoogleToken(ctx context.Context, adc *vertexADC) (string, error) {
	res, err := postRefreshForm(ctx, "https://oauth2.googleapis.com/token", map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": adc.RefreshToken,
		"client_id":     adc.ClientID,
		"client_secret": adc.ClientSecret,
	}, nil)
	if err != nil || res == nil {
		return "", err
	}
	return res.AccessToken, nil
}

func NewVertexExecutor(providerID string) *VertexExecutor {
	if providerID == "" {
		providerID = "vertex"
	}
	v := &VertexExecutor{providerID: providerID}
	v.Base = &Base{ProviderID: providerID}
	return v
}

// buildURL ports VertexExecutor.buildUrl.
func (v *VertexExecutor) buildURL(p *ProviderInfo, cred Credential, model string, stream bool) (string, error) {
	sa := parseVertexSA(cred.APIKey)
	adc := parseVertexADC(cred.APIKey)
	usesOAuth := sa != nil || adc != nil || cred.AccessToken != ""
	var rawKey string
	if !usesOAuth {
		rawKey = cred.APIKey
	}
	projectID := cred.SpecificString("projectId")
	if sa != nil && sa.ProjectID != "" {
		projectID = sa.ProjectID
	}
	if adc != nil && adc.QuotaProject != "" && cred.SpecificString("projectId") == "" {
		projectID = adc.QuotaProject
	}
	if cred.ProjectID != "" {
		projectID = cred.ProjectID
	}

	if v.providerID == "vertex-partner" {
		if projectID == "" {
			return "", errors.New("Vertex partner models require a project_id. Add it in providerSpecificData or use Service Account JSON.")
		}
		u := fmt.Sprintf("https://aiplatform.googleapis.com/v1/projects/%s/locations/global/endpoints/openapi/chat/completions", projectID)
		if rawKey != "" {
			u += "?key=" + rawKey
		}
		return u, nil
	}

	action := "generateContent"
	if stream {
		action = "streamGenerateContent"
	}
	if usesOAuth {
		if projectID == "" {
			return "", errors.New("Vertex OAuth/ADC requires a project_id. Add quota_project_id to your ADC JSON or set providerSpecificData.projectId.")
		}
		location := cred.SpecificString("location")
		if location == "" {
			location = "us-central1"
		}
		u := fmt.Sprintf("https://aiplatform.googleapis.com/v1/projects/%s/locations/%s/publishers/google/models/%s:%s",
			projectID, location, model, action)
		if stream {
			u += "?alt=sse"
		}
		return u, nil
	}
	location := cred.SpecificString("location")
	if location == "" {
		location = "global"
	}
	var u string
	if projectID != "" {
		u = fmt.Sprintf("https://aiplatform.googleapis.com/v1/projects/%s/locations/%s/publishers/google/models/%s:%s",
			projectID, location, model, action)
	} else {
		u = fmt.Sprintf("https://aiplatform.googleapis.com/v1/publishers/google/models/%s:%s", model, action)
	}
	if stream {
		u += "?alt=sse"
	}
	if rawKey != "" {
		if stream {
			u += "&key=" + rawKey
		} else {
			u += "?key=" + rawKey
		}
	}
	return u, nil
}

// resolveVertexProjectID ports resolveProjectId: dummy probe request; the
// error message names projects/{id}. Cached per API key.
var vertexProjectCache sync.Map // apiKey -> projectId

func (v *VertexExecutor) resolveVertexProjectID(ctx context.Context, apiKey string) (string, error) {
	if cached, ok := vertexProjectCache.Load(apiKey); ok {
		return cached.(string), nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://aiplatform.googleapis.com/v1/publishers/google/models/__probe__:generateContent?key="+apiKey,
		strings.NewReader("{}"))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var parsed map[string]any
	_ = unmarshalJSON(raw, &parsed)
	msg := ""
	if arr, ok := parsed["error"].(map[string]any); ok {
		msg = getStr(arr, "message")
	}
	if msg == "" {
		if arr, ok := parsed["0"]; ok {
			_ = arr
		}
		msg = string(raw)
	}
	if idx := strings.Index(msg, "projects/"); idx >= 0 {
		rest := msg[idx+len("projects/"):]
		if end := strings.Index(rest, "/"); end > 0 {
			projectID := rest[:end]
			vertexProjectCache.Store(apiKey, projectID)
			return projectID, nil
		}
	}
	return "", nil
}

// Execute ports VertexExecutor.execute: mint/refresh the Bearer token for
// SA / ADC credentials first, auto-resolve the project for partner raw
// keys, then a plain POST (no base-class fallback loop — the JS overrides
// execute entirely).
func (v *VertexExecutor) Execute(ctx context.Context, p *ProviderInfo, cred Credential, body []byte) (*ExecResult, error) {
	if p == nil {
		p = &ProviderInfo{ID: v.providerID}
	}
	bodyMap, _ := decodeBody(body)
	model := ModelOf(bodyMap)
	stream := StreamRequested(bodyMap) || p.ForceStream

	if sa := parseVertexSA(cred.APIKey); sa != nil {
		token, err := mintVertexSAToken(ctx, sa)
		if err != nil || token == "" {
			return nil, errors.New("Vertex: failed to mint access token from Service Account JSON")
		}
		cred.AccessToken = token
	} else if adc := parseVertexADC(cred.APIKey); adc != nil {
		token, err := refreshGoogleToken(ctx, adc)
		if err != nil || token == "" {
			return nil, errors.New("Vertex: failed to refresh access token from ADC JSON (authorized_user)")
		}
		cred.AccessToken = token
	}

	if v.providerID == "vertex-partner" && parseVertexSA(cred.APIKey) == nil &&
		parseVertexADC(cred.APIKey) == nil && cred.SpecificString("projectId") == "" && cred.ProjectID == "" {
		projectID, err := v.resolveVertexProjectID(ctx, cred.APIKey)
		if err != nil || projectID == "" {
			return nil, errors.New("Vertex: could not resolve project_id from API key. Please add it manually in provider settings.")
		}
		specific := map[string]any{}
		for k, val := range cred.Specific {
			specific[k] = val
		}
		specific["projectId"] = projectID
		cred.Specific = specific
	}

	urlStr, err := v.buildURL(p, cred, model, stream)
	if err != nil {
		return nil, err
	}
	headers := map[string]string{"Content-Type": "application/json"}
	if cred.AccessToken != "" {
		headers["Authorization"] = "Bearer " + cred.AccessToken
	}
	if stream {
		headers["Accept"] = "text/event-stream"
	}
	payload := body
	if bodyMap != nil {
		if raw, err := marshalJSON(bodyMap); err == nil {
			payload = raw
		}
	}
	resp, err := doPost(ctx, urlStr, headers, payload, connectTimeout(p))
	if err != nil {
		return nil, err
	}
	return &ExecResult{Response: resp, URL: urlStr, Headers: headers, TransformedBody: payload}, nil
}
