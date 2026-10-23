package executors

import (
	"context"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// GeminiCLIExecutor ports open-sse/executors/gemini-cli.js: Google Cloud
// Code Assist (v1internal) — the Gemini body is wrapped as
// {project, model, request} and the action hangs off the base URL with a
// colon (:streamGenerateContent?alt=sse / :generateContent).
type GeminiCLIExecutor struct{ *Base }

func NewGeminiCLIExecutor() *GeminiCLIExecutor {
	g := &GeminiCLIExecutor{}
	g.Base = &Base{ProviderID: "gemini-cli", Hooks: Hooks{
		BuildURL:      g.buildURL,
		BuildHeaders:  g.buildHeaders,
		TransformBody: g.transformBody,
		ParseError:    g.parseError,
		Refresh:       refreshGeminiCLI,
	}}
	return g
}

func (g *GeminiCLIExecutor) buildURL(b *Base, req *Request, urlIndex int) (string, error) {
	action := "generateContent"
	if req.Stream {
		action = "streamGenerateContent?alt=sse"
	}
	return req.Provider.BaseURL + ":" + action, nil
}

// geminiCLIUserAgent ports config/appConstants.js geminiCLIUserAgent:
// GeminiCLI/<version>/<model> (<os>; <arch>; terminal). The CLI version is
// registry data (transport.cliVersion) — carried in Raw by the adapter.
func geminiCLIUserAgent(p *ProviderInfo, model string) string {
	version := p.RawString("cliVersion")
	if version == "" {
		version = "0.0.0"
	}
	if model == "" {
		model = "unknown"
	}
	return fmt.Sprintf("GeminiCLI/%s/%s (%s; %s; terminal)", version, model, runtime.GOOS, runtime.GOARCH)
}

func (g *GeminiCLIExecutor) buildHeaders(b *Base, req *Request, url string) (map[string]string, error) {
	accept := "application/json"
	if req.Stream {
		accept = "text/event-stream"
	}
	headers := map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Bearer " + req.Cred.AccessToken,
		"User-Agent":    geminiCLIUserAgent(req.Provider, req.Model),
		"Accept":        accept,
	}
	if client := req.Provider.RawString("apiClient"); client != "" {
		headers["X-Goog-Api-Client"] = client
	}
	return headers, nil
}

// transformBody ports transformRequest: wrap {project, model, request}
// unless the body is already wrapped.
func (g *GeminiCLIExecutor) transformBody(b *Base, req *Request) (map[string]any, error) {
	body := req.Body
	if body == nil {
		return nil, nil
	}
	if _, hasReq := body["request"]; hasReq {
		if _, hasModel := body["model"]; hasModel {
			return body, nil // already wrapped
		}
	}
	project := req.Cred.ProjectID
	if project == "" {
		project = getStr(body, "project")
	}
	return map[string]any{
		"project": project,
		"model":   req.Model,
		"request": body,
	}, nil
}

// parseError ports GeminiCLIExecutor.parseError: on a 429, surface Google's
// RetryInfo.retryDelay as the retry hint.
func (g *GeminiCLIExecutor) parseError(status int, bodyText string) *ParsedError {
	if status != 429 || bodyText == "" {
		return nil
	}
	var parsed map[string]any
	if unmarshalJSON([]byte(bodyText), &parsed) != nil {
		return nil
	}
	errObj, _ := parsed["error"].(map[string]any)
	details, _ := errObj["details"].([]any)
	for _, raw := range details {
		d, _ := raw.(map[string]any)
		if d != nil && d["@type"] == "type.googleapis.com/google.rpc.RetryInfo" {
			if delay := getStr(d, "retryDelay"); delay != "" {
				return &ParsedError{Status: status, Message: bodyText, RetryAfter: delay}
			}
		}
	}
	return nil
}

// refreshGeminiCLI ports refreshCredentials: form grant against Google's
// token endpoint with the registry client id/secret.
func refreshGeminiCLI(ctx context.Context, b *Base, p *ProviderInfo, cred Credential) (*Credential, error) {
	if cred.RefreshToken == "" {
		return nil, nil
	}
	tokenURL := p.TokenURL
	if tokenURL == "" {
		tokenURL = "https://oauth2.googleapis.com/token"
	}
	res, err := postRefreshForm(ctx, tokenURL, map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": cred.RefreshToken,
		"client_id":     p.ClientID,
		"client_secret": p.ClientSecret,
	}, nil)
	if err != nil || res == nil {
		return nil, err
	}
	out := cred
	out.AccessToken = res.AccessToken
	if res.RefreshToken != "" {
		out.RefreshToken = res.RefreshToken
	}
	return &out, nil
}

// AntigravityExecutor ports open-sse/executors/antigravity.js at the
// executor level: v1internal URL + wrap {project, model, request},
// Bearer auth, and quota-error parsing (ErrorInfo quotaResetTimeStamp /
// RetryInfo retryDelay → precise resetsAt, used by the account loop's
// antigravity strike handling).
//
// TODO (report): the deep Gemini-content normalisation inside the JS
// transform (thought-signature backfill, tool-schema sanitising, prompt
// rewrites, generationConfig caps) belongs to the translator layer and is
// not ported here; the request body passes through wrapped but otherwise
// unchanged.
type AntigravityExecutor struct{ *Base }

func NewAntigravityExecutor() *AntigravityExecutor {
	a := &AntigravityExecutor{}
	a.Base = &Base{ProviderID: "antigravity", Hooks: Hooks{
		BuildURL:      a.buildURL,
		BuildHeaders:  a.buildHeaders,
		TransformBody: a.transformBody,
		ParseError:    a.parseError,
	}}
	return a
}

func (a *AntigravityExecutor) buildURL(b *Base, req *Request, urlIndex int) (string, error) {
	urls := req.Provider.BaseURLsList()
	base := req.Provider.BaseURL
	if urlIndex < len(urls) {
		base = urls[urlIndex]
	}
	action := "generateContent"
	if req.Stream && !isImageModelName(req.Model) {
		action = "streamGenerateContent?alt=sse"
	}
	return base + "/v1internal:" + action, nil
}

func isImageModelName(model string) bool {
	lower := strings.ToLower(model)
	return strings.Contains(lower, "image") || strings.Contains(lower, "imagen")
}

func (a *AntigravityExecutor) buildHeaders(b *Base, req *Request, url string) (map[string]string, error) {
	headers := map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Bearer " + req.Cred.AccessToken,
	}
	if ua := req.Provider.Headers["User-Agent"]; ua != "" {
		headers["User-Agent"] = ua
	}
	return headers, nil
}

func (a *AntigravityExecutor) transformBody(b *Base, req *Request) (map[string]any, error) {
	body := req.Body
	if body == nil {
		return nil, nil
	}
	if !req.Stream {
		// Google generateContent rejects stream_options on non-streaming
		// calls (antigravity.js transformRequest).
		delete(body, "stream_options")
	}
	if _, hasReq := body["request"]; hasReq {
		if _, hasModel := body["model"]; hasModel {
			return body, nil
		}
	}
	project := req.Cred.ProjectID
	if project == "" {
		project = getStr(body, "project")
	}
	inner, _ := body["request"].(map[string]any)
	if inner == nil {
		inner = body
	}
	return map[string]any{
		"project":     project,
		"model":       req.Model,
		"userAgent":   "antigravity",
		"requestType": "agent",
		"requestId":   newUUID(),
		"request":     inner,
	}, nil
}

// parseError ports AntigravityExecutor.parseError (429/409 quota resets).
func (a *AntigravityExecutor) parseError(status int, bodyText string) *ParsedError {
	if (status != 429 && status != 409) || bodyText == "" {
		return nil
	}
	var parsed map[string]any
	if unmarshalJSON([]byte(bodyText), &parsed) != nil {
		return nil
	}
	errObj, _ := parsed["error"].(map[string]any)
	if errObj == nil {
		return nil
	}
	details, _ := errObj["details"].([]any)
	for _, raw := range details {
		d, _ := raw.(map[string]any)
		if d == nil {
			continue
		}
		if meta, ok := d["metadata"].(map[string]any); ok {
			if ts := getStr(meta, "quotaResetTimeStamp"); ts != "" {
				if t, err := time.Parse(time.RFC3339Nano, ts); err == nil && t.After(time.Now()) {
					return &ParsedError{Status: status, Message: firstNonEmpty(getStr(errObj, "message"), bodyText), ResetsAt: t}
				}
			}
		}
		if delay := getStr(d, "retryDelay"); delay != "" {
			// Google durations look like "123.456s".
			if secs, err := strconv.ParseFloat(strings.TrimSuffix(delay, "s"), 64); err == nil && secs > 0 {
				return &ParsedError{Status: status, Message: firstNonEmpty(getStr(errObj, "message"), bodyText),
					ResetsAt: time.Now().Add(time.Duration(secs * float64(time.Second)))}
			}
		}
	}
	return nil
}
