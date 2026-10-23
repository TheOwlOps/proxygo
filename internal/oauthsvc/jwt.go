package oauthsvc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
)

// Port of src/lib/oauth/providerHelpers.js (JWT helpers + Kiro profile ARN)
// and the endpoint validation used by the xAI provider.

// DecodeJWTPayload decodes a JWT's payload segment without verifying the
// signature (the JS helpers do the same — display/identity extraction only).
func DecodeJWTPayload(jwt string) map[string]any {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// JS pads manually then uses standard base64.
		padded := parts[1]
		for len(padded)%4 != 0 {
			padded += "="
		}
		raw, err = base64.StdEncoding.DecodeString(strings.NewReplacer("-", "+", "_", "/").Replace(padded))
		if err != nil {
			return nil
		}
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}

// CodexAccountInfo mirrors extractCodexAccountInfo's return shape.
type CodexAccountInfo struct {
	Email            string
	ChatGPTAccountID string
	ChatGPTPlanType  string
}

// ExtractCodexAccountInfo reads email + ChatGPT account/plan claims from an
// OpenAI id_token (or access token carrying the same claims).
func ExtractCodexAccountInfo(idToken string) CodexAccountInfo {
	payload := DecodeJWTPayload(idToken)
	if payload == nil {
		return CodexAccountInfo{}
	}
	auth, _ := payload["https://api.openai.com/auth"].(map[string]any)
	info := CodexAccountInfo{Email: strOf(payload, "email")}
	info.ChatGPTAccountID = firstStr(strOf(auth, "chatgpt_account_id"), strOf(payload, "account_id"))
	info.ChatGPTPlanType = firstStr(strOf(auth, "chatgpt_plan_type"), strOf(payload, "plan_type"))
	return info
}

// ExtractEmailFromAccessToken returns email/preferred_username/sub from a JWT.
func ExtractEmailFromAccessToken(accessToken string) string {
	payload := DecodeJWTPayload(accessToken)
	if payload == nil {
		return ""
	}
	return firstStr(strOf(payload, "email"), strOf(payload, "preferred_username"), strOf(payload, "sub"))
}

// DecodeXaiIdTokenEmail is the xAI-specific alias of the same extraction.
func DecodeXaiIdTokenEmail(idToken string) string { return ExtractEmailFromAccessToken(idToken) }

func firstStr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// ValidateXaiOAuthEndpoint ports validateXaiOAuthEndpoint: discovery
// endpoints must be https on x.ai (SSRF guard).
func ValidateXaiOAuthEndpoint(rawURL, field string) (string, error) {
	value := strings.TrimSpace(rawURL)
	if value == "" {
		return "", errf("xai discovery %s is empty", field)
	}
	if !strings.HasPrefix(value, "https://") {
		return "", errf("xai discovery %s must use https: %s", field, value)
	}
	host := value[len("https://"):]
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host != "x.ai" && !strings.HasSuffix(host, ".x.ai") {
		return "", errf("xai discovery %s host %s is not on x.ai", field, host)
	}
	return value, nil
}

// FetchKiroProfileArn ports fetchKiroProfileArn: first profile ARN from
// ListAvailableProfiles, or "" when unavailable.
func FetchKiroProfileArn(ctx context.Context, accessToken string) string {
	if accessToken == "" {
		return ""
	}
	status, body, err := PostJSON(ctx, "https://codewhisperer.us-east-1.amazonaws.com/ListAvailableProfiles",
		map[string]any{"maxResults": 10},
		map[string]string{"Authorization": "Bearer " + accessToken})
	if err != nil || status != http.StatusOK {
		return ""
	}
	profiles, _ := body["profiles"].([]any)
	for _, p := range profiles {
		if m, ok := p.(map[string]any); ok {
			if arn := strings.TrimSpace(strOf(m, "arn")); arn != "" {
				return arn
			}
		}
	}
	return ""
}
