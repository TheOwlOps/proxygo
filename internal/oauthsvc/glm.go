package oauthsvc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Port of src/lib/oauth/providers/glm.js — the ZCode CLI polling flow:
// init (poll token) → browser authorize → poll → business login →
// coding-plan API key resolution. The plan API key is the credential.

func glmRequestDevice(ctx context.Context, cfg Config) (map[string]any, error) {
	var raw [32]byte
	_, _ = rand.Read(raw[:])
	pollToken := hex.EncodeToString(raw[:])
	status, rawBody, _, err := Raw(ctx, http.MethodPost, cfg.Str("cliInitUrl"),
		strings.NewReader(mustJSON(map[string]any{"provider": cfg.StrOr("providerId", "zai")})),
		"application/json", map[string]string{"Authorization": "Bearer " + pollToken})
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, errf("ZCode OAuth init failed: %s", rawBody)
	}
	var payload map[string]any
	if jsonUnmarshal(rawBody, &payload) != nil || !glmSuccessCode(payload["code"]) {
		msg := strOf(payload, "msg")
		if msg == "" {
			msg = "ZCode OAuth init returned no data"
		}
		return nil, errf("%s", msg)
	}
	data, _ := payload["data"].(map[string]any)
	if data == nil || strOf(data, "flow_id") == "" || strOf(data, "authorize_url") == "" {
		return nil, errf("ZCode OAuth init response missing flow_id/authorize_url")
	}
	expiresIn := float64(300)
	if rel := glmRelativeSeconds(data["expires_at"]); rel > 0 {
		expiresIn = float64(rel)
	}
	return map[string]any{
		"device_code":      strOf(data, "flow_id"),
		"verification_uri": strOf(data, "authorize_url"),
		"expires_in":       expiresIn,
		"interval":         numOr(data, "poll_interval_sec", 3),
		"_zcodePollToken":  pollToken,
	}, nil
}

func pollGLM(ctx context.Context, cfg Config, deviceCode string, extra map[string]any) (*pollOutcome, error) {
	pollToken := ""
	if extra != nil {
		pollToken = strOf(extra, "_zcodePollToken")
	}
	if pollToken == "" {
		return &pollOutcome{errCode: "access_denied", errDesc: "Missing ZCode poll token — restart the login flow"}, nil
	}
	endpoint := strings.TrimRight(cfg.Str("cliPollUrl"), "/") + "/" + urlEscape(deviceCode)
	status, body, err := GetJSON(ctx, endpoint, map[string]string{"Authorization": "Bearer " + pollToken})
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return &pollOutcome{errCode: "access_denied", errDesc: fmt.Sprintf("ZCode poll failed (HTTP %d)", status)}, nil
	}
	if !glmSuccessCode(body["code"]) {
		desc := strOf(body, "msg")
		if desc == "" {
			desc = "ZCode poll failed"
		}
		return &pollOutcome{errCode: "access_denied", errDesc: desc}, nil
	}
	data, _ := body["data"].(map[string]any)
	if data == nil {
		data = map[string]any{}
	}
	switch strOf(data, "status") {
	case "pending":
		return &pollOutcome{pending: "authorization_pending", errCode: "authorization_pending"}, nil
	case "failed":
		return &pollOutcome{errCode: "access_denied", errDesc: "ZCode authorization failed or was cancelled"}, nil
	case "ready":
		// continue below
	default:
		return &pollOutcome{pending: "authorization_pending", errCode: "authorization_pending",
			errDesc: "Unknown status: " + strOf(data, "status")}, nil
	}
	providerID := cfg.StrOr("providerId", "zai")
	providerData, _ := data[providerID].(map[string]any)
	zaiToken := ""
	if providerData != nil {
		zaiToken = firstStr(strOf(providerData, "access_token"), strOf(providerData, "accessToken"))
	}
	if zaiToken == "" {
		zaiToken = firstStr(strOf(data, "accessToken"), strOf(data, "access_token"))
	}
	if zaiToken == "" {
		return &pollOutcome{errCode: "access_denied", errDesc: "ZCode poll response missing access token"}, nil
	}
	planKey, businessToken, err := glmResolveCodingPlanAPIKey(ctx, cfg, zaiToken)
	if err != nil {
		// JS resolveCodingPlanApiKey throws → framework marks exchange_failed/fatal.
		return &pollOutcome{errCode: "exchange_failed", errDesc: err.Error(), fatal: true}, nil
	}
	user, _ := data["user"].(map[string]any)
	zaiRefresh := ""
	if providerData != nil {
		zaiRefresh = firstStr(strOf(providerData, "refresh_token"), strOf(providerData, "refreshToken"))
	}
	if zaiRefresh == "" {
		zaiRefresh = firstStr(strOf(data, "refresh_token"), strOf(data, "refreshToken"))
	}
	out := map[string]any{
		"accessToken":  planKey,
		"refreshToken": nil,
	}
	email := ""
	displayName := ""
	if user != nil {
		email = strOf(user, "email")
		displayName = firstStr(strOf(user, "name"), email)
	}
	if email != "" {
		out["email"] = email
	} else {
		out["email"] = nil
	}
	if displayName != "" {
		out["displayName"] = displayName
	}
	psd := map[string]any{"authMethod": "cli_poll"}
	if user != nil {
		SetIf(psd, "username", strOf(user, "name"))
		SetIf(psd, "userId", strOf(user, "user_id"))
	}
	SetIf(psd, "zcodeJwtToken", strOf(data, "token"))
	SetIf(psd, "zaiBusinessToken", businessToken)
	SetIf(psd, "zaiRefreshToken", zaiRefresh)
	out["providerSpecificData"] = psd
	return &pollOutcome{tokens: out}, nil
}

func glmSuccessCode(code any) bool {
	switch v := code.(type) {
	case nil:
		return true
	case float64:
		return v == 0 || v == 200
	case string:
		return v == "0" || v == "200"
	}
	return false
}

func glmRelativeSeconds(expiresAt any) int64 {
	f, ok := expiresAt.(float64)
	if !ok || f <= 0 {
		return 0
	}
	ms := f
	if ms <= 1e12 {
		ms = ms * 1000
	}
	seconds := (int64(ms) - time.Now().UnixMilli()) / 1000
	if seconds > 0 {
		return seconds
	}
	return 0
}

// fetchBusinessJSON ports fetchBusinessJson: returns payload.data (or the
// payload itself) on business success.
func glmFetchBusiness(ctx context.Context, cfg Config, endpoint, method string, payload any, headers map[string]string, label string) (any, error) {
	var bodyReader *strings.Reader
	if payload != nil {
		bodyReader = strings.NewReader(mustJSON(payload))
	} else {
		bodyReader = strings.NewReader("")
	}
	status, raw, _, err := Raw(ctx, method, endpoint, bodyReader, "application/json", headers)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		text := raw
		if len(text) > 200 {
			text = text[:200]
		}
		return nil, errf("Z.ai %s request failed (HTTP %d): %s", label, status, text)
	}
	var parsed map[string]any
	if jsonUnmarshal(raw, &parsed) != nil {
		return nil, errf("Z.ai %s response is not valid JSON", label)
	}
	if !glmSuccessCode(parsed["code"]) {
		msg := strOf(parsed, "msg")
		if msg == "" {
			msg = fmt.Sprintf("Z.ai %s returned business error %v", label, parsed["code"])
		}
		return nil, errf("%s", msg)
	}
	if data, ok := parsed["data"]; ok && data != nil {
		return data, nil
	}
	return parsed, nil
}

func glmResolveCodingPlanAPIKey(ctx context.Context, cfg Config, zaiAccessToken string) (string, string, error) {
	// Business login.
	loginData, err := glmFetchBusiness(ctx, cfg, cfg.Str("businessLoginUrl"), http.MethodPost,
		map[string]any{"token": zaiAccessToken}, nil, "Z.ai business login")
	if err != nil {
		return "", "", err
	}
	businessToken := ""
	if m, ok := loginData.(map[string]any); ok {
		businessToken = strings.TrimSpace(firstStr(strOf(m, "access_token"), strOf(m, "accessToken")))
	}
	if businessToken == "" {
		return "", "", errf("Z.ai business login response is missing access_token")
	}
	authHeaders := map[string]string{"Authorization": "Bearer " + businessToken}

	apiBase := strings.TrimRight(cfg.Str("apiBaseUrl"), "/")
	customerInfoRaw, err := glmFetchBusiness(ctx, cfg, apiBase+"/api/biz/customer/getCustomerInfo",
		http.MethodGet, nil, authHeaders, "customer info")
	if err != nil {
		return "", "", err
	}
	customerInfo, _ := customerInfoRaw.(map[string]any)
	orgID, projectID := glmPickOrgProject(customerInfo)
	if orgID == "" || projectID == "" {
		return "", "", errf("Unable to resolve Z.ai organization and project for the coding plan")
	}
	listURL := apiBase + "/api/biz/v1/organization/" + orgID + "/projects/" + projectID + "/api_keys"
	keysRaw, err := glmFetchBusiness(ctx, cfg, listURL, http.MethodGet, nil, authHeaders, "api keys")
	if err != nil {
		return "", "", err
	}
	keyName := cfg.StrOr("planApiKeyName", "zcode-api-key")
	var keyEntry map[string]any
	if keys, ok := keysRaw.([]any); ok {
		for _, item := range keys {
			if m, ok := item.(map[string]any); ok && strOf(m, "name") == keyName {
				keyEntry = m
				break
			}
		}
	}
	if keyEntry == nil {
		created, err := glmFetchBusiness(ctx, cfg, listURL, http.MethodPost,
			map[string]any{"name": keyName}, authHeaders, "api key create")
		if err != nil {
			return "", "", err
		}
		keyEntry, _ = created.(map[string]any)
	}
	apiKey := ""
	if keyEntry != nil {
		apiKey = strings.TrimSpace(strOf(keyEntry, "apiKey"))
	}
	if apiKey == "" {
		return "", "", errf("Z.ai api_keys response is missing apiKey")
	}
	secretRaw, err := glmFetchBusiness(ctx, cfg, listURL+"/copy/"+urlEscape(apiKey),
		http.MethodGet, nil, authHeaders, "api key copy")
	if err != nil {
		return "", "", err
	}
	secretKey := ""
	if m, ok := secretRaw.(map[string]any); ok {
		secretKey = strings.TrimSpace(strOf(m, "secretKey"))
	}
	if secretKey == "" {
		return "", "", errf("Z.ai api key copy response is missing secretKey")
	}
	return apiKey + "." + secretKey, businessToken, nil
}

func glmPickOrgProject(customerInfo map[string]any) (string, string) {
	if customerInfo == nil {
		return "", ""
	}
	orgs, _ := customerInfo["organizations"].([]any)
	type orgProjects struct {
		org      map[string]any
		projects []map[string]any
	}
	var personal []orgProjects
	for _, o := range orgs {
		om, ok := o.(map[string]any)
		if !ok || strOf(om, "organizationId") == "" {
			continue
		}
		var projects []map[string]any
		if list, ok := om["projects"].([]any); ok {
			for _, p := range list {
				if pm, ok := p.(map[string]any); ok {
					if strings.TrimSpace(glmAnyStr(pm["projectType"])) != "2" {
						projects = append(projects, pm)
					}
				}
			}
		}
		if len(projects) > 0 {
			personal = append(personal, orgProjects{om, projects})
		}
	}
	if len(personal) == 0 {
		return "", ""
	}
	chosen := personal[0]
	for _, cand := range personal {
		if glmIsDefaultName(strOf(cand.org, "organizationName")) {
			chosen = cand
			break
		}
	}
	project := chosen.projects[0]
	for _, p := range chosen.projects {
		if glmIsDefaultName(strOf(p, "projectName")) {
			project = p
			break
		}
	}
	return strOf(chosen.org, "organizationId"), strOf(project, "projectId")
}

func glmAnyStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%v", t)
	}
	return ""
}

func glmIsDefaultName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	return strings.Contains(n, "默认机构") || strings.Contains(n, "默认项目") || n == "default"
}
