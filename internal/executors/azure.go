package executors

import (
	"os"
	"strings"
)

// AzureExecutor ports open-sse/executors/azure.js: Azure OpenAI deployments
// URL + `api-key` header auth.
type AzureExecutor struct{ *DefaultExecutor }

func NewAzureExecutor() *AzureExecutor {
	a := &AzureExecutor{DefaultExecutor: NewDefaultExecutor("azure")}
	a.Base.Hooks.BuildURL = a.buildURL
	a.Base.Hooks.BuildHeaders = a.buildHeaders
	a.Base.Hooks.TransformBody = func(b *Base, req *Request) (map[string]any, error) {
		return req.Body, nil // JS transformRequest is identity
	}
	return a
}

func (a *AzureExecutor) buildURL(b *Base, req *Request, urlIndex int) (string, error) {
	cred := req.Cred
	endpoint := cred.SpecificString("azureEndpoint")
	if endpoint == "" {
		endpoint = os.Getenv("AZURE_ENDPOINT")
	}
	if endpoint == "" {
		endpoint = "https://api.openai.com"
	}
	apiVersion := cred.SpecificString("apiVersion")
	if apiVersion == "" {
		apiVersion = os.Getenv("AZURE_API_VERSION")
	}
	if apiVersion == "" {
		apiVersion = "2024-10-01-preview"
	}
	deployment := cred.SpecificString("deployment")
	if deployment == "" {
		deployment = req.Model
	}
	if deployment == "" {
		deployment = os.Getenv("AZURE_DEPLOYMENT")
	}
	if deployment == "" {
		deployment = "gpt-4"
	}
	return strings.TrimSuffix(endpoint, "/") + "/openai/deployments/" + deployment +
		"/chat/completions?api-version=" + apiVersion, nil
}

func (a *AzureExecutor) buildHeaders(b *Base, req *Request, url string) (map[string]string, error) {
	headers := map[string]string{"Content-Type": "application/json"}
	for k, v := range req.Provider.Headers {
		headers[k] = v
	}
	apiKey := req.Cred.APIKey
	if apiKey == "" {
		apiKey = req.Cred.AccessToken
	}
	if apiKey == "" {
		apiKey = os.Getenv("OPENAI_API_KEY")
	}
	if apiKey != "" {
		headers["api-key"] = apiKey
	}
	org := req.Cred.SpecificString("organization")
	if org == "" {
		org = os.Getenv("AZURE_ORGANIZATION")
	}
	if org != "" {
		headers["OpenAI-Organization"] = org
	}
	if req.Stream {
		headers["Accept"] = "text/event-stream"
	}
	return headers, nil
}
