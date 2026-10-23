package executors

import (
	"context"
	"net/http"
	"regexp"
	"strings"
)

// OpenAIToClaudeTranslator, when wired by the parent from Team A's
// translator, enables the GithubExecutor's Claude-model route: Copilot's
// Anthropic-native /v1/messages shim needs a Claude-format body, which the
// JS executor produces by calling translateRequest(openai→claude) itself
// (executors/github.js executeWithMessagesEndpoint). When nil, Claude
// models fall back to the /chat/completions path.
var OpenAIToClaudeTranslator func(body map[string]any, model string) (map[string]any, error)

// GithubExecutor ports open-sse/executors/github.js: GitHub Copilot.
// Ported: Copilot identity headers, message sanitising for
// /chat/completions, max_tokens → max_completion_tokens for gpt-5/o-series,
// Claude-model routing to /v1/messages (via the wired translator), and the
// Copilot token exchange refresh.
//
// TODO (report): the /responses endpoint route for Responses-shaped bodies
// (executeWithResponsesEndpoint) — chatcore's target-format resolution
// sends Responses bodies to the default buildUrl path here.
type GithubExecutor struct{ *Base }

var copilotMaxCompletionRe = regexp.MustCompile(`(?i)gpt-5|o[134]-`)

func NewGithubExecutor() *GithubExecutor {
	g := &GithubExecutor{}
	g.Base = &Base{ProviderID: "github", Hooks: Hooks{
		BuildURL:      g.buildURL,
		BuildHeaders:  g.buildHeaders,
		TransformBody: g.transformBody,
		Refresh:       g.refresh,
	}}
	return g
}

func isCopilotClaudeModel(model string) bool {
	return strings.Contains(strings.ToLower(model), "claude")
}

func (g *GithubExecutor) buildURL(b *Base, req *Request, urlIndex int) (string, error) {
	return req.Provider.BaseURL, nil
}

func (g *GithubExecutor) buildHeaders(b *Base, req *Request, url string) (map[string]string, error) {
	token := req.Cred.CopilotToken
	if token == "" {
		token = req.Cred.AccessToken
	}
	// Copilot editor identity constants live in the registry Raw
	// (config/appConstants.js GITHUB_COPILOT, derived from registry
	// github.transport.copilot); defaults match the JS values' shape.
	vscodeVersion := firstNonEmpty(req.Provider.RawString("vscodeVersion"), "1.96.0")
	copilotVersion := firstNonEmpty(req.Provider.RawString("copilotChatVersion"), "0.24.0")
	userAgent := firstNonEmpty(req.Provider.RawString("copilotUserAgent"), "GitHubCopilotChat/0.24.0")
	apiVersion := firstNonEmpty(req.Provider.RawString("githubApiVersion"), "2025-04-01")
	accept := "application/json"
	if req.Stream {
		accept = "text/event-stream"
	}
	return map[string]string{
		"Authorization":                       "Bearer " + token,
		"Content-Type":                        "application/json",
		"copilot-integration-id":              "vscode-chat",
		"editor-version":                      "vscode/" + vscodeVersion,
		"editor-plugin-version":               "copilot-chat/" + copilotVersion,
		"user-agent":                          userAgent,
		"openai-intent":                       "conversation-panel",
		"x-github-api-version":                apiVersion,
		"x-request-id":                        newUUID(),
		"x-vscode-user-agent-library-version": "electron-fetch",
		"X-Initiator":                         "user",
		"anthropic-version":                   anthropicAPIVersion,
		"Accept":                              accept,
	}, nil
}

// transformBody ports transformRequest: sanitise messages for the chat
// completions endpoint + rename max_tokens for newer models.
func (g *GithubExecutor) transformBody(b *Base, req *Request) (map[string]any, error) {
	body := req.Body
	if body == nil {
		return nil, nil
	}
	if copilotMaxCompletionRe.MatchString(req.Model) {
		if _, has := body["max_tokens"]; has {
			body["max_completion_tokens"] = body["max_tokens"]
			delete(body, "max_tokens")
		}
	}
	if msgs, ok := body["messages"].([]any); ok {
		for i, raw := range msgs {
			msg, ok := raw.(map[string]any)
			if !ok || msg["content"] == nil {
				continue
			}
			if _, isStr := msg["content"].(string); isStr {
				continue
			}
			parts, ok := msg["content"].([]any)
			if !ok {
				continue
			}
			// Only text / image_url parts survive; tool_use, tool_result,
			// thinking etc. are serialised as text (github.js
			// sanitizeMessagesForChatCompletions).
			var clean []any
			for _, praw := range parts {
				part, _ := praw.(map[string]any)
				if part == nil {
					continue
				}
				switch part["type"] {
				case "text", "image_url":
					clean = append(clean, part)
				default:
					text := getStr(part, "text")
					if text == "" {
						text = getStr(part, "content")
					}
					if text == "" {
						rawJSON, _ := marshalJSON(part)
						text = string(rawJSON)
					}
					clean = append(clean, map[string]any{"type": "text", "text": text})
				}
			}
			var filtered []any
			for _, part := range clean {
				if pm, _ := part.(map[string]any); pm != nil && pm["type"] == "text" && getStr(pm, "text") == "" {
					continue
				}
				filtered = append(filtered, part)
			}
			if len(filtered) > 0 {
				msg["content"] = filtered
			} else {
				msg["content"] = nil
			}
			msgs[i] = msg
		}
		body["messages"] = msgs
	}
	return body, nil
}

// Execute routes Claude models to Copilot's /v1/messages shim when the
// translator is wired (see the package var), else uses the base flow.
func (g *GithubExecutor) Execute(ctx context.Context, p *ProviderInfo, cred Credential, body []byte) (*ExecResult, error) {
	if p == nil {
		p = &ProviderInfo{ID: "github"}
	}
	bodyMap, _ := decodeBody(body)
	model := ModelOf(bodyMap)
	messagesURL := p.RawString("messagesUrl")
	if isCopilotClaudeModel(model) && messagesURL != "" && OpenAIToClaudeTranslator != nil && bodyMap != nil {
		translated, err := OpenAIToClaudeTranslator(cloneMap(bodyMap), model)
		if err != nil {
			return nil, err
		}
		delete(translated, "_toolNameMap") // internal bookkeeping (github.js)
		translated["stream"] = true        // forced upstream streaming (github.js)
		payload, err := marshalJSON(translated)
		if err != nil {
			return nil, err
		}
		req := &Request{Provider: p, Cred: cred, Model: model, Stream: true, Body: translated, State: map[string]any{}}
		headers, err := g.buildHeaders(g.Base, req, messagesURL)
		if err != nil {
			return nil, err
		}
		resp, err := doPost(ctx, messagesURL, headers, payload, connectTimeout(p))
		if err != nil {
			return nil, err
		}
		return &ExecResult{Response: resp, URL: messagesURL, Headers: headers, TransformedBody: payload, ResponseFormat: "claude"}, nil
	}
	return g.Base.Execute(ctx, p, cred, body)
}

// refresh ports refreshCredentials: exchange the GitHub token for a
// short-lived Copilot token (GET copilot_internal/v2/token, `token …`
// auth scheme). The result rides back as Credential.CopilotToken —
// chatcore's refresh gate accepts accessToken OR copilotToken
// (chatCore.js: newCredentials?.accessToken || newCredentials?.copilotToken).
func (g *GithubExecutor) refresh(ctx context.Context, b *Base, p *ProviderInfo, cred Credential) (*Credential, error) {
	githubToken := cred.AccessToken
	if githubToken == "" {
		githubToken = cred.APIKey
	}
	if githubToken == "" {
		return nil, nil
	}
	tokenURL := "https://api.github.com/copilot_internal/v2/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+githubToken)
	req.Header.Set("Accept", "application/json")
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil
	}
	var out map[string]any
	if err := unmarshalJSON(readAllLimit(resp), &out); err != nil {
		return nil, err
	}
	token := getStr(out, "token")
	if token == "" {
		return nil, nil
	}
	refreshed := cred
	refreshed.CopilotToken = token
	return &refreshed, nil
}

func readAllLimit(resp *http.Response) []byte {
	if resp == nil || resp.Body == nil {
		return nil
	}
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 8192)
	for len(buf) < 1<<20 {
		n, err := resp.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
	}
	return buf
}
