package oauthsvc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"
)

// Device-code providers: requestDeviceCode + pollToken ports from
// src/lib/oauth/providers/{github,kimi,kilocode,codebuddy-cn,
// codebuddy-intl,grok-cli,muse,nous,minimax-code-shared}.js.
// Kiro and Qoder have dedicated service files (kiro.go, qoder.go); GLM is
// in glm.go.

// KimiHeaders ports buildKimiHeaders from open-sse/config/appConstants.js.
func KimiHeaders(deviceID string) map[string]string {
	deviceModel := runtime.GOOS + " " + runtime.GOARCH
	switch runtime.GOOS {
	case "darwin":
		deviceModel = "macOS " + runtime.GOARCH
	case "windows":
		deviceModel = "Windows " + runtime.GOARCH
	case "linux":
		deviceModel = "Linux " + runtime.GOARCH
	}
	deviceName, err := os.Hostname()
	if err != nil || deviceName == "" {
		deviceName = "unknown"
	}
	resolved := strings.TrimSpace(deviceID)
	if resolved == "" {
		resolved = fmt.Sprintf("kimi-%d", time.Now().UnixMilli())
	}
	return map[string]string{
		"X-Msh-Platform":     "9router",
		"X-Msh-Version":      "0.5.104",
		"X-Msh-Device-Name":  deviceName,
		"X-Msh-Device-Model": deviceModel,
		"X-Msh-Device-Id":    resolved,
	}
}

const deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// requestDeviceCodeImpl dispatches per provider. options carries the
// route-level extras (kiro startUrl/region/authMethod).
func requestDeviceCodeImpl(ctx context.Context, name string, cfg Config, codeChallenge string, options map[string]any) (map[string]any, error) {
	switch name {
	case "github":
		form := url.Values{"client_id": {cfg.Str("clientId")}, "scope": {cfg.ScopeString()}}
		status, body, err := PostForm(ctx, cfg.Str("deviceCodeUrl"), form,
			map[string]string{"User-Agent": cfg.StrOr("userAgent", "ProxyGo")})
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, TokenError("Device code request failed", status, body, "")
		}
		return body, nil

	case "kimi":
		deviceID := "9router-" + newUUID()
		status, body, err := PostForm(ctx, cfg.Str("deviceCodeUrl"),
			url.Values{"client_id": {cfg.Str("clientId")}}, KimiHeaders(deviceID))
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, TokenError("Kimi device code request failed", status, body, "")
		}
		out := map[string]any{}
		for k, v := range body {
			out[k] = v
		}
		out["_kimiDeviceId"] = deviceID
		return out, nil

	case "kilocode":
		status, body, err := PostJSON(ctx, cfg.Str("initiateUrl"), map[string]any{}, nil)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, TokenError("Kilo Code device auth failed", status, body, "")
		}
		code := strOf(body, "code")
		return map[string]any{
			"device_code":      code,
			"user_code":        code,
			"verification_uri": strOf(body, "verificationUrl"),
			"expires_in":       numOr(body, "expiresIn", 600),
			"interval":         float64(5),
		}, nil

	case "codebuddy-cn", "codebuddy-intl":
		return codebuddyRequestDevice(ctx, cfg)

	case "grok-cli":
		status, body, err := PostJSON(ctx, cfg.Str("deviceCodeUrl"), map[string]any{
			"client_id": cfg.Str("clientId"),
			"scope":     cfg.ScopeString(),
			"referrer":  cfg.StrOr("referrer", "grok-cli"),
		}, nil)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, TokenError("Grok CLI device code request failed", status, body, "")
		}
		return body, nil

	case "muse":
		form := url.Values{"client_id": {cfg.Str("clientId")}}
		status, raw, _, err := Raw(ctx, http.MethodPost, cfg.Str("deviceCodeUrl"),
			strings.NewReader(form.Encode()), "application/x-www-form-urlencoded",
			map[string]string{"x-api-version": "1.0.0"})
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, errf("Muse Code device code request failed: %s", raw)
		}
		var body map[string]any
		if json.Unmarshal([]byte(raw), &body) != nil {
			return nil, errf("Muse Code device code request failed: invalid JSON")
		}
		return body, nil

	case "nous":
		status, body, err := PostJSON(ctx, cfg.Str("deviceCodeUrl"), map[string]any{
			"client_id": cfg.Str("clientId"),
		}, map[string]string{"User-Agent": "ProxyGo"})
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, TokenError("Nous device code request failed", status, body, "")
		}
		out := map[string]any{}
		for k, v := range body {
			out[k] = v
		}
		if _, ok := out["verification_uri"]; !ok {
			out["verification_uri"] = firstStr(strOf(body, "verification_url"), strOf(body, "verification_uri_complete"))
		}
		if _, ok := out["interval"]; !ok {
			out["interval"] = float64(5)
		}
		return out, nil

	case "minimax-code", "minimax-code-global":
		return minimaxRequestDevice(ctx, cfg, codeChallenge)

	case "kiro":
		return kiroRequestDevice(ctx, cfg, options)

	case "qoder", "qoder-cn":
		return QoderInitiateDeviceFlow(cfg), nil

	case "glm":
		return glmRequestDevice(ctx, cfg)
	}
	return nil, errf("provider %s does not support device code flow", name)
}

func numOr(m map[string]any, k string, def float64) float64 {
	if v, ok := numOf(m, k); ok {
		return v
	}
	return def
}

// ---- CodeBuddy ----

func codebuddyDomain(cfg Config) string {
	base := cfg.Str("baseUrl")
	if strings.Contains(base, "codebuddy.ai") {
		return "www.codebuddy.ai"
	}
	return "copilot.tencent.com"
}

func codebuddyHeaders(cfg Config) map[string]string {
	return map[string]string{
		"User-Agent": cfg.StrOr("userAgent", "CLI/2.63.2 CodeBuddy/2.63.2"),
		"X-Domain":   codebuddyDomain(cfg),
	}
}

func codebuddyRequestDevice(ctx context.Context, cfg Config) (map[string]any, error) {
	status, body, err := PostJSON(ctx, cfg.Str("stateUrl"), map[string]any{
		"platform": cfg.StrOr("platform", "cli"),
		"domain":   codebuddyDomain(cfg),
	}, codebuddyHeaders(cfg))
	if err != nil {
		return nil, err
	}
	data, _ := body["data"].(map[string]any)
	state := strOf(data, "state")
	authURL := firstStr(strOf(data, "authUrl"), strOf(data, "auth_url"))
	if status != http.StatusOK || state == "" {
		return nil, TokenError("CodeBuddy auth state request failed", status, body, "")
	}
	return map[string]any{
		"device_code":      state,
		"user_code":        state,
		"verification_uri": authURL,
		"state":            state,
		"expires_in":       float64(600),
		"interval":         float64(2),
	}, nil
}

// ---- poll implementations. Return (tokens, pendingError, fatal, err):
// tokens != nil on success; pendingError is the OAuth error code while the
// user has not finished ("" when not pending). ----

type pollOutcome struct {
	tokens  map[string]any
	pending string // authorization_pending | slow_down
	errCode string
	errDesc string
	fatal   bool
}

func pollImpl(ctx context.Context, name string, cfg Config, deviceCode, codeVerifier string, extra map[string]any) (*pollOutcome, error) {
	switch name {
	case "github":
		return pollGitHub(ctx, cfg, deviceCode)
	case "kimi":
		return pollKimi(ctx, cfg, deviceCode, extra)
	case "kilocode":
		return pollKilocode(ctx, cfg, deviceCode)
	case "codebuddy-cn", "codebuddy-intl":
		return pollCodebuddy(ctx, cfg, deviceCode)
	case "grok-cli":
		return pollGrokCLI(ctx, cfg, deviceCode)
	case "muse":
		return pollMuse(ctx, cfg, deviceCode)
	case "nous":
		return pollNous(ctx, cfg, deviceCode)
	case "minimax-code", "minimax-code-global":
		return pollMinimax(ctx, cfg, deviceCode, codeVerifier, extra)
	case "kiro":
		return pollKiro(ctx, cfg, deviceCode, extra)
	case "qoder", "qoder-cn":
		return pollQoder(ctx, cfg, deviceCode, codeVerifier, extra)
	case "glm":
		return pollGLM(ctx, cfg, deviceCode, extra)
	}
	return nil, errf("provider %s does not support device code polling", name)
}

func oauthErrOutcome(body map[string]any) *pollOutcome {
	code := strOf(body, "error")
	desc := strOf(body, "error_description")
	switch code {
	case "authorization_pending", "slow_down":
		return &pollOutcome{pending: code, errCode: code, errDesc: desc}
	}
	return &pollOutcome{errCode: firstStr(code, "unknown_error"), errDesc: desc}
}

func pollGitHub(ctx context.Context, cfg Config, deviceCode string) (*pollOutcome, error) {
	form := url.Values{
		"client_id":   {cfg.Str("clientId")},
		"device_code": {deviceCode},
		"grant_type":  {deviceGrantType},
	}
	status, body, err := PostForm(ctx, cfg.Str("tokenUrl"), form,
		map[string]string{"User-Agent": cfg.StrOr("userAgent", "ProxyGo")})
	if err != nil {
		return nil, err
	}
	if strOf(body, "error") != "" {
		return oauthErrOutcome(body), nil
	}
	if status != http.StatusOK {
		return nil, TokenError("GitHub token poll failed", status, body, "")
	}
	accessToken := strOf(body, "access_token")
	out := map[string]any{"accessToken": accessToken}
	SetIf(out, "refreshToken", strOf(body, "refresh_token"))
	SetNumIf(out, "expiresIn", NumPairOf(body, "expires_in"))
	SetIf(out, "scope", strOf(body, "scope"))
	// postExchange: Copilot token + user info (best effort).
	psd := map[string]any{"authMethod": "device_code"}
	if copilot := GitHubCopilotToken(ctx, cfg, accessToken); copilot != "" {
		psd["copilotToken"] = copilot
	}
	if cfg.Str("userInfoUrl") != "" {
		if s, user, err := GetJSON(ctx, cfg.Str("userInfoUrl"), map[string]string{
			"Authorization": "Bearer " + accessToken,
			"User-Agent":    cfg.StrOr("userAgent", "ProxyGo"),
		}); err == nil && s == http.StatusOK {
			SetIf(out, "email", strOf(user, "email"))
			SetIf(out, "displayName", firstStr(strOf(user, "name"), strOf(user, "login")))
			SetIf(psd, "login", strOf(user, "login"))
			if id, ok := numOf(user, "id"); ok {
				psd["githubId"] = id
			}
		}
	}
	out["providerSpecificData"] = psd
	return &pollOutcome{tokens: out}, nil
}

// GitHubCopilotToken exchanges a GitHub OAuth token for a Copilot token
// (getGitHubCopilotToken). Returns "" on failure.
func GitHubCopilotToken(ctx context.Context, cfg Config, accessToken string) string {
	endpoint := cfg.StrOr("copilotTokenUrl", "https://api.github.com/copilot_internal/v2/token")
	status, body, err := GetJSON(ctx, endpoint, map[string]string{
		"Authorization":         "token " + accessToken,
		"User-Agent":            cfg.StrOr("userAgent", "ProxyGo"),
		"Editor-Version":        cfg.StrOr("editorVersion", "vscode/1.95.0"),
		"Editor-Plugin-Version": cfg.StrOr("editorPluginVersion", "copilot-chat/0.22.0"),
	})
	if err != nil || status != http.StatusOK {
		return ""
	}
	return strOf(body, "token")
}

func pollKimi(ctx context.Context, cfg Config, deviceCode string, extra map[string]any) (*pollOutcome, error) {
	deviceID := ""
	if extra != nil {
		deviceID = strOf(extra, "_kimiDeviceId")
	}
	status, body, err := PostJSON(ctx, cfg.Str("tokenUrl"), map[string]any{
		"grant_type":  deviceGrantType,
		"device_code": deviceCode,
		"client_id":   cfg.Str("clientId"),
	}, KimiHeaders(deviceID))
	if err != nil {
		return nil, err
	}
	if strOf(body, "error") != "" {
		return oauthErrOutcome(body), nil
	}
	if status != http.StatusOK {
		return nil, TokenError("Kimi token poll failed", status, body, "")
	}
	out := map[string]any{}
	SetIf(out, "accessToken", strOf(body, "access_token"))
	SetIf(out, "refreshToken", strOf(body, "refresh_token"))
	SetNumIf(out, "expiresIn", NumPairOf(body, "expires_in"))
	SetIf(out, "scope", strOf(body, "scope"))
	if deviceID != "" {
		out["providerSpecificData"] = map[string]any{"deviceId": deviceID}
	}
	return &pollOutcome{tokens: out}, nil
}

func pollKilocode(ctx context.Context, cfg Config, deviceCode string) (*pollOutcome, error) {
	endpoint := strings.TrimRight(cfg.Str("pollUrlBase"), "/") + "/" + url.PathEscape(deviceCode)
	status, raw, _, err := Raw(ctx, http.MethodGet, endpoint, nil, "", nil)
	if err != nil {
		return nil, err
	}
	switch status {
	case 202:
		return &pollOutcome{pending: "authorization_pending", errCode: "authorization_pending"}, nil
	case 403:
		return &pollOutcome{errCode: "access_denied", errDesc: "User denied the request"}, nil
	case 410:
		return &pollOutcome{errCode: "expired_token", errDesc: "Device code expired"}, nil
	}
	if status != http.StatusOK {
		return nil, errf("Kilo Code poll failed: HTTP %d", status)
	}
	var body map[string]any
	if json.Unmarshal([]byte(raw), &body) != nil {
		return nil, errf("Kilo Code poll failed: invalid JSON")
	}
	token := firstStr(strOf(body, "token"), strOf(body, "accessToken"), strOf(body, "access_token"))
	if token == "" {
		return &pollOutcome{pending: "authorization_pending", errCode: "authorization_pending"}, nil
	}
	out := map[string]any{"accessToken": token}
	SetIf(out, "refreshToken", firstStr(strOf(body, "refreshToken"), strOf(body, "refresh_token")))
	// Best-effort profile for org id.
	if s, prof, err := GetJSON(ctx, strings.TrimRight(cfg.StrOr("apiBaseUrl", "https://api.kilo.ai"), "/")+"/api/profile",
		map[string]string{"Authorization": "Bearer " + token}); err == nil && s == http.StatusOK {
		SetIf(out, "email", strOf(prof, "email"))
		SetIf(out, "displayName", strOf(prof, "name"))
		psd := map[string]any{}
		SetIf(psd, "orgId", firstStr(strOf(prof, "organizationId"), strOf(prof, "orgId")))
		if len(psd) > 0 {
			out["providerSpecificData"] = psd
		}
	}
	return &pollOutcome{tokens: out}, nil
}

func pollCodebuddy(ctx context.Context, cfg Config, deviceCode string) (*pollOutcome, error) {
	endpoint := cfg.Str("tokenUrl") + "?state=" + url.QueryEscape(deviceCode)
	status, body, err := GetJSON(ctx, endpoint, codebuddyHeaders(cfg))
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, TokenError("CodeBuddy token poll failed", status, body, "")
	}
	codeF, _ := numOf(body, "code")
	data, _ := body["data"].(map[string]any)
	switch int(codeF) {
	case 0:
		if data == nil || strOf(data, "accessToken") == "" {
			return &pollOutcome{pending: "authorization_pending", errCode: "authorization_pending"}, nil
		}
		out := map[string]any{}
		SetIf(out, "accessToken", strOf(data, "accessToken"))
		SetIf(out, "refreshToken", strOf(data, "refreshToken"))
		if v, ok := numOf(data, "expiresIn"); ok {
			out["expiresIn"] = v
		} else {
			out["expiresIn"] = float64(86400)
		}
		out["providerSpecificData"] = map[string]any{}
		return &pollOutcome{tokens: out}, nil
	case 11217:
		return &pollOutcome{pending: "authorization_pending", errCode: "authorization_pending"}, nil
	}
	return &pollOutcome{errCode: "unknown_error", errDesc: strOf(body, "message")}, nil
}

func pollGrokCLI(ctx context.Context, cfg Config, deviceCode string) (*pollOutcome, error) {
	status, body, err := PostJSON(ctx, cfg.Str("tokenUrl"), map[string]any{
		"client_id":   cfg.Str("clientId"),
		"device_code": deviceCode,
		"grant_type":  deviceGrantType,
	}, nil)
	if err != nil {
		return nil, err
	}
	if strOf(body, "error") != "" {
		return oauthErrOutcome(body), nil
	}
	if status != http.StatusOK {
		return nil, TokenError("Grok CLI token poll failed", status, body, "")
	}
	out := map[string]any{}
	SetIf(out, "accessToken", strOf(body, "access_token"))
	if rt := strOf(body, "refresh_token"); rt != "" {
		out["refreshToken"] = rt
	} else {
		out["refreshToken"] = nil
	}
	SetNumIf(out, "expiresIn", NumPairOf(body, "expires_in"))
	SetIf(out, "scope", strOf(body, "scope"))
	email := ""
	if idToken := strOf(body, "id_token"); idToken != "" {
		email = DecodeXaiIdTokenEmail(idToken)
	}
	if email == "" {
		email = ExtractEmailFromAccessToken(strOf(body, "access_token"))
	}
	// Best-effort profile.
	var user map[string]any
	if s, u, err := GetJSON(ctx, "https://cli-chat-proxy.grok.com/v1/user",
		map[string]string{"Authorization": "Bearer " + strOf(body, "access_token")}); err == nil && s == http.StatusOK {
		user = u
		if email == "" {
			email = strOf(u, "email")
		}
	}
	if email != "" {
		out["email"] = email
	}
	if user != nil {
		displayName := strings.TrimSpace(firstStr(strOf(user, "firstName"), "") + " " + firstStr(strOf(user, "lastName"), ""))
		if displayName != "" {
			out["displayName"] = displayName
		}
	}
	psd := map[string]any{"authMethod": "device_code"}
	if idToken := strOf(body, "id_token"); idToken != "" {
		psd["idToken"] = idToken
	} else {
		psd["idToken"] = nil
	}
	if email != "" {
		psd["email"] = email
	} else {
		psd["email"] = nil
	}
	if user != nil {
		psd["userId"] = firstStr(strOf(user, "userId"), strOf(user, "principalId"))
		psd["hasGrokCodeAccess"] = user["hasGrokCodeAccess"]
		psd["subscriptionTier"] = user["subscriptionTier"]
	} else {
		psd["userId"] = nil
		psd["hasGrokCodeAccess"] = nil
		psd["subscriptionTier"] = nil
	}
	out["providerSpecificData"] = psd
	return &pollOutcome{tokens: out}, nil
}

func pollMuse(ctx context.Context, cfg Config, deviceCode string) (*pollOutcome, error) {
	form := url.Values{
		"client_id":   {cfg.Str("clientId")},
		"device_code": {deviceCode},
		"grant_type":  {deviceGrantType},
	}
	status, body, err := PostForm(ctx, cfg.Str("tokenUrl"), form, map[string]string{"x-api-version": "1.0.0"})
	if err != nil {
		return nil, err
	}
	if strOf(body, "error") != "" {
		return oauthErrOutcome(body), nil
	}
	if status != http.StatusOK {
		return nil, TokenError("Muse Code token poll failed", status, body, "")
	}
	deviceToken := strOf(body, "access_token")
	// postExchange: mint the Model API key (fatal on failure, with retries).
	var keyBody map[string]any
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		s, b, err := PostJSON(ctx, "https://api.meta.ai/muse-code/key", map[string]any{},
			map[string]string{"Authorization": "Bearer " + deviceToken})
		if err == nil && s == http.StatusOK && strOf(b, "api_key") != "" {
			keyBody = b
			lastErr = nil
			break
		}
		lastErr = errf("muse key mint failed: HTTP %d", s)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(attempt+1) * time.Second):
		}
	}
	if keyBody == nil {
		return &pollOutcome{errCode: "exchange_failed", errDesc: fmt.Sprint(lastErr), fatal: true}, nil
	}
	out := map[string]any{
		"accessToken":  strOf(keyBody, "api_key"),
		"refreshToken": nil,
		"expiresIn":    nil,
	}
	if email := strings.ToLower(strings.TrimSpace(strOf(keyBody, "user_email"))); email != "" {
		out["email"] = email
	}
	psd := map[string]any{
		"authMethod":       "device_code",
		"oauthAccessToken": deviceToken,
	}
	if tier := strOf(keyBody, "subs_tier_name"); tier != "" {
		psd["subscriptionTier"] = tier
	} else {
		psd["subscriptionTier"] = nil
	}
	out["providerSpecificData"] = psd
	return &pollOutcome{tokens: out}, nil
}

func pollNous(ctx context.Context, cfg Config, deviceCode string) (*pollOutcome, error) {
	status, body, err := PostJSON(ctx, cfg.Str("tokenUrl"), map[string]any{
		"device_code": deviceCode,
		"grant_type":  deviceGrantType,
	}, map[string]string{"User-Agent": "ProxyGo"})
	if err != nil {
		return nil, err
	}
	if strOf(body, "error") != "" {
		return oauthErrOutcome(body), nil
	}
	if status != http.StatusOK {
		return nil, TokenError("Nous token poll failed", status, body, "")
	}
	portalToken := strOf(body, "access_token")
	out := map[string]any{}
	SetIf(out, "accessToken", portalToken)
	SetIf(out, "refreshToken", strOf(body, "refresh_token"))
	SetNumIf(out, "expiresIn", NumPairOf(body, "expires_in"))
	SetIf(out, "scope", strOf(body, "scope"))
	// postExchange: mint an agent key (failure is NON-fatal in the JS).
	psd := map[string]any{"inferenceBaseUrl": cfg.StrOr("inferenceBaseUrl", "https://inference.nousresearch.com/v1")}
	if agentKeyURL := cfg.StrOr("agentKeyUrl", NousPortalBase+"/api/oauth/agent-key"); agentKeyURL != "" {
		if s, b, err := PostJSON(ctx, agentKeyURL, map[string]any{},
			map[string]string{"Authorization": "Bearer " + portalToken}); err == nil && s == http.StatusOK {
			if key := firstStr(strOf(b, "key"), strOf(b, "agent_key"), strOf(b, "api_key")); key != "" {
				out["apiKey"] = key
			}
			SetIf(psd, "agentKeyId", strOf(b, "id"))
			SetIf(psd, "agentKeyExpiresAt", strOf(b, "expires_at"))
		}
	}
	out["providerSpecificData"] = psd
	return &pollOutcome{tokens: out}, nil
}

// ---- MiniMax Code (shared factory port) ----

func minimaxRequestDevice(ctx context.Context, cfg Config, codeChallenge string) (map[string]any, error) {
	if codeChallenge == "" {
		return nil, errf("MiniMax Code sign-in requires a PKCE code challenge")
	}
	form := url.Values{
		"client_id":             {cfg.Str("clientId")},
		"scope":                 {cfg.ScopeString()},
		"audience":              {cfg.StrOr("audience", "agent-backend")},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}
	status, body, err := PostForm(ctx, cfg.Str("deviceUrl"), form, nil)
	if err != nil {
		return nil, err
	}
	userCode := strOf(body, "user_code")
	deviceCode := strOf(body, "device_code")
	uri := firstStr(strOf(body, "verification_uri_complete"), strOf(body, "verification_uri"), strOf(body, "verification_url"))
	if userCode == "" || uri == "" {
		return nil, errf("MiniMax device code response unusable (HTTP %d)", status)
	}
	pollByUser := deviceCode == ""
	expiresIn := numOr(body, "expires_in", 0)
	if expiresIn == 0 {
		if expiredIn, ok := numOf(body, "expired_in"); ok && expiredIn > 0 {
			if expiredIn < 1e12 {
				expiresIn = expiredIn
			} else {
				expiresIn = float64(int64((int64(expiredIn) - time.Now().UnixMilli()) / 1000))
				if expiresIn < 1 {
					expiresIn = 1
				}
			}
		}
	}
	if expiresIn == 0 {
		expiresIn = 600
	}
	interval := float64(5)
	if iv, ok := numOf(body, "interval"); ok && iv > 0 {
		interval = iv
		if pollByUser && interval >= 60 {
			interval = float64(int64(interval / 1000))
		}
	}
	dc := deviceCode
	if dc == "" {
		dc = userCode
	}
	return map[string]any{
		"device_code":        dc,
		"user_code":          userCode,
		"verification_uri":   uri,
		"expires_in":         expiresIn,
		"interval":           interval,
		"_minimaxPollByUser": pollByUser,
	}, nil
}

func pollMinimax(ctx context.Context, cfg Config, deviceCode, codeVerifier string, extra map[string]any) (*pollOutcome, error) {
	if deviceCode == "" {
		return &pollOutcome{pending: "authorization_pending", errCode: "authorization_pending"}, nil
	}
	form := url.Values{
		"grant_type":    {deviceGrantType},
		"client_id":     {cfg.Str("clientId")},
		"code_verifier": {codeVerifier},
	}
	if extra != nil {
		if byUser, _ := extra["_minimaxPollByUser"].(bool); byUser {
			form.Set("user_code", deviceCode)
		} else {
			form.Set("device_code", deviceCode)
		}
	} else {
		form.Set("device_code", deviceCode)
	}
	_, body, err := PostForm(ctx, cfg.Str("tokenUrl"), form, nil)
	if err != nil {
		return nil, err
	}
	switch s := strOf(body, "status"); s {
	case "pending":
		return &pollOutcome{pending: "authorization_pending", errCode: "authorization_pending"}, nil
	case "slow_down":
		return &pollOutcome{pending: "slow_down", errCode: "slow_down"}, nil
	case "denied", "access_denied":
		return &pollOutcome{errCode: "access_denied"}, nil
	case "expired", "expired_token":
		return &pollOutcome{errCode: "expired_token"}, nil
	case "":
		// fall through to standard OAuth shape
	default:
		return &pollOutcome{errCode: "unexpected_status:" + s}, nil
	}
	if strOf(body, "error") != "" {
		return oauthErrOutcome(body), nil
	}
	if strOf(body, "access_token") == "" {
		return &pollOutcome{errCode: "no_access_token"}, nil
	}
	out := map[string]any{}
	SetIf(out, "accessToken", strOf(body, "access_token"))
	if rt := strOf(body, "refresh_token"); rt != "" {
		out["refreshToken"] = rt
	} else {
		out["refreshToken"] = ""
	}
	if v, ok := numOf(body, "expires_in"); ok {
		out["expiresIn"] = v
	} else {
		out["expiresIn"] = float64(3600)
	}
	return &pollOutcome{tokens: out}, nil
}

// ---- Kiro / Qoder poll bridges ----

func kiroRequestDevice(ctx context.Context, cfg Config, options map[string]any) (map[string]any, error) {
	region := "us-east-1"
	startURL := cfg.StrOr("startUrl", "https://view.awsapps.com/start")
	if options != nil {
		if r := strOf(options, "region"); r != "" {
			region = r
		}
		if s := strOf(options, "startUrl"); s != "" {
			startURL = s
		}
	}
	r, err := AssertValidAWSRegion(region)
	if err != nil {
		return nil, err
	}
	region = r
	clientID, clientSecret, err := KiroRegisterClient(ctx, region)
	if err != nil {
		return nil, err
	}
	device, err := KiroStartDeviceAuthorization(ctx, clientID, region, startURL)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"device_code":               strOf(device, "deviceCode"),
		"user_code":                 strOf(device, "userCode"),
		"verification_uri":          strOf(device, "verificationUri"),
		"verification_uri_complete": strOf(device, "verificationUriComplete"),
		"expires_in":                numOr(device, "expiresIn", 600),
		"interval":                  numOr(device, "interval", 5),
		"clientId":                  clientID,
		"clientSecret":              clientSecret,
		"region":                    region,
	}, nil
}

func pollKiro(ctx context.Context, cfg Config, deviceCode string, extra map[string]any) (*pollOutcome, error) {
	clientID, clientSecret, region := "", "", "us-east-1"
	if extra != nil {
		clientID = strOf(extra, "clientId")
		clientSecret = strOf(extra, "clientSecret")
		if r := strOf(extra, "region"); r != "" {
			region = r
		}
	}
	if clientID == "" || clientSecret == "" {
		return nil, errf("Kiro poll requires clientId and clientSecret")
	}
	tokens, pending, err := KiroPollDeviceToken(ctx, clientID, clientSecret, deviceCode, region)
	if err != nil {
		return nil, err
	}
	if pending {
		return &pollOutcome{pending: "authorization_pending", errCode: "authorization_pending"}, nil
	}
	out := map[string]any{}
	SetIf(out, "accessToken", strOf(tokens, "accessToken"))
	SetIf(out, "refreshToken", strOf(tokens, "refreshToken"))
	SetNumIf(out, "expiresIn", NumPairOf(tokens, "expiresIn"))
	psd := map[string]any{
		"clientId":     clientID,
		"clientSecret": clientSecret,
		"region":       region,
		"authMethod":   "idc",
	}
	// Framework backfill: profileArn via ListAvailableProfiles.
	if arn := FetchKiroProfileArn(ctx, strOf(tokens, "accessToken")); arn != "" {
		psd["profileArn"] = arn
	}
	out["providerSpecificData"] = psd
	return &pollOutcome{tokens: out}, nil
}

func pollQoder(ctx context.Context, cfg Config, deviceCode, codeVerifier string, extra map[string]any) (*pollOutcome, error) {
	nonce := deviceCode
	if extra != nil {
		if n := strOf(extra, "nonce"); n != "" {
			nonce = n
		}
		if n := strOf(extra, "_qoderNonce"); n != "" {
			nonce = n
		}
	}
	res, err := QoderPollDeviceToken(ctx, cfg, nonce, codeVerifier)
	if err != nil {
		return nil, err
	}
	if res.Status == "pending" {
		return &pollOutcome{pending: "authorization_pending", errCode: "authorization_pending"}, nil
	}
	name, email, orgID := QoderFetchUserInfo(ctx, cfg, res.AccessToken)
	expiresIn := float64((res.ExpireTimeMs - time.Now().UnixMilli()) / 1000)
	if expiresIn < 0 {
		expiresIn = 0
	}
	out := map[string]any{
		"accessToken": res.AccessToken,
	}
	if res.RefreshToken != "" {
		out["refreshToken"] = res.RefreshToken
	} else {
		out["refreshToken"] = ""
	}
	out["expiresIn"] = expiresIn
	SetIf(out, "email", email)
	SetIf(out, "displayName", name)
	psd := map[string]any{}
	SetIf(psd, "userId", res.UserID)
	SetIf(psd, "organizationId", orgID)
	if extra != nil {
		SetIf(psd, "machineId", strOf(extra, "machineId"))
	}
	out["providerSpecificData"] = psd
	return &pollOutcome{tokens: out}, nil
}

func urlEscape(s string) string { return url.QueryEscape(s) }

func jsonUnmarshal(raw string, v any) error { return json.Unmarshal([]byte(raw), v) }
