package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"9router-go/internal/db"
	"9router-go/internal/oauthsvc"
)

// RegisterOAuth wires the OAuth + SSO routes (port of src/app/api/oauth/**
// and src/app/api/auth/{oidc,saml}/**). Successful flows persist provider
// connections through the db connections repo with the same record shapes
// the JS writes.
func RegisterOAuth(mux *http.ServeMux, deps Deps) {
	// Loopback callback completions (utils/server.js in the JS): exchange
	// the code and save the connection.
	oauthsvc.OnCallbackComplete = func(ctx context.Context, sess *oauthsvc.ProxySession, params url.Values) (map[string]any, error) {
		return completeCallbackLogin(ctx, deps, sess, params)
	}

	mux.HandleFunc("GET /api/oauth/{provider}/{action}", Wrap(deps, deps.oauthGetAction))
	mux.HandleFunc("POST /api/oauth/{provider}/{action}", Wrap(deps, deps.oauthPostAction))

	mux.HandleFunc("POST /api/oauth/codex/bulk-import", Wrap(deps, deps.codexBulkImport))
	mux.HandleFunc("POST /api/oauth/codex/import-token", Wrap(deps, deps.codexImportToken))
	mux.HandleFunc("GET /api/oauth/cursor/auto-import", Wrap(deps, deps.cursorAutoImport))
	mux.HandleFunc("GET /api/oauth/cursor/import", Wrap(deps, cursorImportInstructions))
	mux.HandleFunc("POST /api/oauth/cursor/import", Wrap(deps, deps.cursorImport))
	mux.HandleFunc("POST /api/oauth/gitlab/pat", Wrap(deps, deps.gitlabPAT))
	mux.HandleFunc("POST /api/oauth/grok-cli/bulk-import", Wrap(deps, deps.grokBulkImport))
	mux.HandleFunc("POST /api/oauth/iflow/cookie", Wrap(deps, deps.iflowCookie))
	mux.HandleFunc("POST /api/oauth/kiro/api-key", Wrap(deps, deps.kiroAPIKey))
	mux.HandleFunc("GET /api/oauth/kiro/auto-import", Wrap(deps, deps.kiroAutoImport))
	mux.HandleFunc("POST /api/oauth/kiro/import-cli-proxy", Wrap(deps, deps.kiroImportCLIProxy))
	mux.HandleFunc("POST /api/oauth/kiro/import", Wrap(deps, deps.kiroImport))
	mux.HandleFunc("GET /api/oauth/kiro/social-authorize", Wrap(deps, kiroSocialAuthorize))
	mux.HandleFunc("POST /api/oauth/kiro/social-exchange", Wrap(deps, deps.kiroSocialExchange))
	mux.HandleFunc("POST /api/oauth/xiaomi-mimo/api-key", Wrap(deps, deps.xiaomiAPIKey))
	mux.HandleFunc("GET /api/oauth/xiaomi-mimo/auto-import", Wrap(deps, deps.xiaomiAutoImport))
	mux.HandleFunc("POST /api/oauth/xiaomi-mimo/login/start", Wrap(deps, xiaomiLoginStart))
	mux.HandleFunc("GET /api/oauth/xiaomi-mimo/login/status", Wrap(deps, xiaomiLoginStatus))
	mux.HandleFunc("GET /api/oauth/zed/auto-import", Wrap(deps, deps.zedAutoImport))
	mux.HandleFunc("POST /api/oauth/zed/import", Wrap(deps, deps.zedImport))

	mux.HandleFunc("GET /api/auth/oidc/start", deps.oidcStart)
	mux.HandleFunc("GET /api/auth/oidc/callback", deps.oidcCallback)
	mux.HandleFunc("POST /api/auth/oidc/test", deps.oidcTest)
	mux.HandleFunc("GET /api/auth/saml/start", deps.samlStart)
	mux.HandleFunc("POST /api/auth/saml/acs", deps.samlACS)
	mux.HandleFunc("GET /api/auth/saml/metadata", deps.samlMetadata)
	mux.HandleFunc("POST /api/auth/saml/test", deps.samlTest)
}

// ---------- shared helpers ----------

func connSummary(rec db.Record) map[string]any {
	out := map[string]any{"id": rec["id"], "provider": rec["provider"]}
	if v := rec["email"]; v != nil {
		out["email"] = v
	}
	if v := rec["displayName"]; v != nil {
		out["displayName"] = v
	} else if v := rec["name"]; v != nil {
		out["displayName"] = v
	}
	return out
}

// saveOAuthConnection builds the JS connection record from a mapped token
// map and persists it.
func (deps Deps) saveOAuthConnection(provider, authType string, tokens map[string]any) (db.Record, error) {
	rec := db.Record{"provider": provider, "authType": authType, "testStatus": "active", "isActive": true}
	copyStr := func(dst, src string) {
		if v, ok := tokens[src].(string); ok && v != "" {
			rec[dst] = v
		}
	}
	copyStr("accessToken", "accessToken")
	copyStr("refreshToken", "refreshToken")
	copyStr("apiKey", "apiKey")
	copyStr("email", "email")
	copyStr("displayName", "displayName")
	copyStr("name", "name")
	if rec["name"] == nil {
		if v := rec["displayName"]; v != nil {
			rec["name"] = v
		} else if v := rec["email"]; v != nil {
			rec["name"] = v
		}
	}
	if v, ok := tokens["expiresIn"].(float64); ok && v > 0 {
		rec["expiresAt"] = time.Now().Add(time.Duration(v) * time.Second).UTC().Format(time.RFC3339)
	}
	if v, ok := tokens["expiresAt"].(string); ok && v != "" {
		rec["expiresAt"] = v
	}
	if v := tokens["scope"]; v != nil {
		rec["scope"] = v
	}
	if v := tokens["providerSpecificData"]; v != nil {
		rec["providerSpecificData"] = v
	}
	if v := tokens["lastRefreshAt"]; v != nil {
		rec["lastRefreshAt"] = v
	}
	if v := tokens["projectId"]; v != nil {
		psd, _ := rec["providerSpecificData"].(map[string]any)
		if psd == nil {
			psd = map[string]any{}
			rec["providerSpecificData"] = psd
		}
		psd["projectId"] = v
	}
	return deps.Store.CreateProviderConnection(rec)
}

func successConnection(w http.ResponseWriter, rec db.Record) {
	WriteJSON(w, http.StatusOK, map[string]any{"success": true, "connection": connSummary(rec)})
}

// completeCallbackLogin is the loopback-callback completion hook: it runs
// the provider exchange for codex/xai/trae/windsurf/zed and saves the
// connection, mirroring the JS callback servers.
func completeCallbackLogin(ctx context.Context, deps Deps, sess *oauthsvc.ProxySession, params url.Values) (map[string]any, error) {
	provider := sess.Provider
	switch provider {
	case "codex", "xai":
		code := params.Get("code")
		if code == "" {
			return nil, fmt.Errorf("callback carries no code")
		}
		tokens, err := oauthsvc.ExchangeTokens(ctx, provider, code, sess.RedirectURI, sess.CodeVerifier, params.Get("state"), nil)
		if err != nil {
			return nil, err
		}
		rec, err := deps.saveOAuthConnection(provider, "oauth", tokens)
		if err != nil {
			return nil, err
		}
		return map[string]any{"connectionId": rec["id"], "email": rec["email"]}, nil
	case "trae":
		login, err := oauthsvc.ResolveTraeLoginResult("http://localhost/?" + params.Encode())
		if err != nil {
			return nil, err
		}
		tokens, err := oauthsvc.ExchangeTraeLoginResult(ctx, oauthsvc.ConfigFor("trae"), login)
		if err != nil {
			return nil, err
		}
		rec, err := deps.saveOAuthConnection("trae", "oauth", tokens)
		if err != nil {
			return nil, err
		}
		return map[string]any{"connectionId": rec["id"], "email": rec["email"]}, nil
	case "windsurf":
		token := params.Get("token")
		if token == "" {
			return nil, fmt.Errorf("callback carries no token")
		}
		tokens, err := oauthsvc.ExchangeWindsurfAuthCode(ctx, oauthsvc.ConfigFor("windsurf"), token)
		if err != nil {
			return nil, err
		}
		rec, err := deps.saveOAuthConnection("windsurf", "api_key", tokens)
		if err != nil {
			return nil, err
		}
		return map[string]any{"connectionId": rec["id"], "email": rec["email"]}, nil
	case "zed":
		token := params.Get("token")
		if token == "" {
			return nil, fmt.Errorf("callback carries no token")
		}
		systemID := ""
		if sess.Result != nil {
			systemID, _ = sess.Result["systemId"].(string)
		}
		tokens, err := oauthsvc.ExchangeZedCode(ctx, token, sess.CodeVerifier, systemID)
		if err != nil {
			return nil, err
		}
		rec, err := deps.saveOAuthConnection("zed", "oauth", tokens)
		if err != nil {
			return nil, err
		}
		return map[string]any{"connectionId": rec["id"], "email": rec["email"]}, nil
	}
	return map[string]any{"ok": true}, nil
}

// ---------- dynamic [provider]/[action] ----------

var oauthReservedQuery = map[string]bool{
	"redirect_uri": true, "redirectUri": true, "state": true, "app_port": true,
}

func queryMeta(r *http.Request) map[string]any {
	meta := map[string]any{}
	for k, vals := range r.URL.Query() {
		if oauthReservedQuery[k] || len(vals) == 0 {
			continue
		}
		meta[k] = vals[0]
	}
	return meta
}

func (deps Deps) oauthGetAction(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	action := r.PathValue("action")
	ctx := r.Context()

	switch action {
	case "authorize":
		redirectURI := r.URL.Query().Get("redirect_uri")
		if redirectURI == "" {
			redirectURI = r.URL.Query().Get("redirectUri")
		}
		if redirectURI == "" {
			redirectURI = "http://localhost:8080/callback"
		}
		if provider == "xiaomi-mimo" {
			authorizeXiaomi(w, r)
			return
		}
		if _, ok := oauthsvc.GetProvider(provider); !ok {
			Err(w, http.StatusNotFound, "Unknown provider: "+provider)
			return
		}
		meta := queryMeta(r)
		if provider == "zed" {
			if u, err := url.Parse(redirectURI); err == nil && u.Port() != "" {
				if p, perr := strconv.Atoi(u.Port()); perr == nil {
					meta["nativeAppPort"] = float64(p)
				}
			}
		}
		authData, err := oauthsvc.GenerateAuthData(ctx, provider, redirectURI, meta)
		if err != nil {
			Err(w, http.StatusInternalServerError, err.Error())
			return
		}
		if authData["authUrl"] == nil || authData["authUrl"] == "" {
			Err(w, http.StatusBadRequest, "Failed to generate auth URL")
			return
		}
		WriteJSON(w, http.StatusOK, authData)
		return

	case "device-code":
		def, ok := oauthsvc.GetProvider(provider)
		if !ok {
			Err(w, http.StatusNotFound, "Unknown provider: "+provider)
			return
		}
		if def.FlowType != oauthsvc.FlowDeviceCode {
			Err(w, http.StatusBadRequest, "Provider "+provider+" does not use device code flow")
			return
		}
		options := map[string]any{}
		q := r.URL.Query()
		if v := q.Get("startUrl"); v != "" {
			options["startUrl"] = v
		}
		if v := q.Get("region"); v != "" {
			options["region"] = v
		}
		if v := q.Get("authMethod"); v != "" {
			options["authMethod"] = v
		}
		data, err := oauthsvc.RequestDeviceCode(ctx, provider, options)
		if err != nil {
			Err(w, http.StatusInternalServerError, err.Error())
			return
		}
		WriteJSON(w, http.StatusOK, data)
		return

	case "start-proxy":
		startProxyAction(w, r, provider)
		return

	case "poll-status":
		pollStatusAction(w, r, provider)
		return

	case "stop-proxy":
		oauthsvc.StopCallbackServer(provider)
		WriteJSON(w, http.StatusOK, map[string]any{"success": true})
		return

	case "ide-status":
		ideStatusAction(w, provider)
		return
	}
	Err(w, http.StatusBadRequest, "Unknown action")
}

func authorizeXiaomi(w http.ResponseWriter, r *http.Request) {
	publicKey, privDER, err := oauthsvc.XiaomiGenerateKeyPair()
	if err != nil {
		Err(w, http.StatusInternalServerError, err.Error())
		return
	}
	port, _, err := oauthsvc.StartCallbackServer("xiaomi-mimo", 0)
	if err != nil {
		Err(w, http.StatusInternalServerError, err.Error())
		return
	}
	state := oauthsvc.GenerateState()
	redirectURI := fmt.Sprintf("http://localhost:%d/", port)
	oauthsvc.RegisterProxySession(&oauthsvc.ProxySession{
		State: state, Provider: "xiaomi-mimo", PrivateKeyDER: privDER, RedirectURI: redirectURI,
	})
	authURL := oauthsvc.XiaomiBuildAuthorizeURL(publicKey, redirectURI, oauthsvc.XiaomiKeyNameForMachine())
	WriteJSON(w, http.StatusOK, map[string]any{
		"authUrl": authURL, "state": state, "serverSide": true,
		"flowType": "authorization_code", "redirectUri": redirectURI,
	})
}

var proxyProviders = map[string]bool{
	"trae": true, "windsurf": true, "zed": true, "xiaomi-mimo": true, "codex": true, "xai": true,
}

func startProxyAction(w http.ResponseWriter, r *http.Request, provider string) {
	if !proxyProviders[provider] {
		Err(w, http.StatusBadRequest, "Provider "+provider+" does not use a callback proxy")
		return
	}
	appPort := 0
	if v := r.URL.Query().Get("app_port"); v != "" {
		appPort, _ = strconv.Atoi(v)
	}
	if (provider == "codex" || provider == "xai") && appPort == 0 {
		Err(w, http.StatusBadRequest, "app_port is required for "+provider)
		return
	}
	port, already, err := oauthsvc.StartCallbackServer(provider, appPort)
	if err != nil {
		Err(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := map[string]any{"success": true, "port": float64(port), "serverSide": true, "alreadyRunning": already}
	if state := r.URL.Query().Get("state"); state != "" {
		oauthsvc.RegisterProxySession(&oauthsvc.ProxySession{State: state, Provider: provider})
	}
	WriteJSON(w, http.StatusOK, resp)
}

func pollStatusAction(w http.ResponseWriter, r *http.Request, provider string) {
	state := r.URL.Query().Get("state")
	if state == "" {
		Err(w, http.StatusBadRequest, "Missing state parameter")
		return
	}
	if !proxyProviders[provider] {
		Err(w, http.StatusBadRequest, "Provider "+provider+" does not use a callback proxy")
		return
	}
	sess := oauthsvc.GetProxySession(state)
	if sess == nil {
		WriteJSON(w, http.StatusOK, map[string]any{"status": "error", "error": "Session not found or expired"})
		return
	}
	switch sess.Status {
	case "done":
		if provider == "xiaomi-mimo" {
			// The session result is the decrypted callback payload; the
			// connection is created by the exchange action (the JS clears
			// the xiaomi session there, not on poll-status done).
			WriteJSON(w, http.StatusOK, map[string]any{"status": "done", "result": sess.Result})
			return
		}
		result := sess.Result
		oauthsvc.ClearProxySession(state)
		WriteJSON(w, http.StatusOK, map[string]any{"status": "done", "result": result})
	case "error":
		msg := sess.Error
		oauthsvc.ClearProxySession(state)
		WriteJSON(w, http.StatusOK, map[string]any{"status": "error", "error": msg})
	default:
		WriteJSON(w, http.StatusOK, map[string]any{"status": "pending"})
	}
}

func ideStatusAction(w http.ResponseWriter, provider string) {
	if provider != "trae" && provider != "windsurf" {
		Err(w, http.StatusBadRequest, "ide-status is only available for trae and windsurf")
		return
	}
	home, _ := os.UserHomeDir()
	var candidates []string
	if provider == "trae" {
		candidates = []string{
			filepath.Join(home, ".config", "Trae"),
			filepath.Join(home, "Library", "Application Support", "Trae"),
			filepath.Join(os.Getenv("APPDATA"), "Trae"),
		}
	} else {
		candidates = []string{
			filepath.Join(home, ".config", "Windsurf"),
			filepath.Join(home, "Library", "Application Support", "Windsurf"),
			filepath.Join(os.Getenv("APPDATA"), "Windsurf"),
		}
	}
	installed := false
	for _, p := range candidates {
		if p != "" {
			if _, err := os.Stat(p); err == nil {
				installed = true
			}
		}
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"provider": provider, "installed": installed, "loggedIn": false, "platform": runtime.GOOS,
	})
}

// ---------- POST actions ----------

var noPKCEExchangeProviders = map[string]bool{"cline": true, "clinepass": true, "kimchi": true}

var noPKCEPollProviders = map[string]bool{
	"github": true, "kimi": true, "kimi-coding": true, "kilocode": true,
	"codebuddy-cn": true, "codebuddy-intl": true, "glm": true, "nous": true,
}

func (deps Deps) oauthPostAction(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	action := r.PathValue("action")

	body, err := ReadBodyJSON(r)
	if err != nil {
		Err(w, http.StatusBadRequest, "Invalid or empty request body")
		return
	}

	switch action {
	case "register-session":
		if provider != "trae" && provider != "windsurf" && provider != "zed" {
			Err(w, http.StatusBadRequest, "register-session is only available for trae, windsurf and zed")
			return
		}
		state := r.URL.Query().Get("state")
		if state == "" {
			state = Str(body, "state")
		}
		if state == "" {
			Err(w, http.StatusBadRequest, "Missing state")
			return
		}
		sess := &oauthsvc.ProxySession{State: state, Provider: provider}
		if provider == "zed" {
			sess.CodeVerifier = Str(body, "codeVerifier")
			sess.Result = map[string]any{"systemId": Str(body, "systemId")}
		}
		oauthsvc.RegisterProxySession(sess)
		WriteJSON(w, http.StatusOK, map[string]any{"success": true})
		return

	case "exchange":
		deps.oauthExchange(w, r, provider, body)
		return

	case "poll":
		deps.oauthPoll(w, r, provider, body)
		return

	case "manual-code":
		deps.oauthManualCode(w, r, provider, body)
		return
	}
	Err(w, http.StatusBadRequest, "Unknown action")
}

func (deps Deps) oauthExchange(w http.ResponseWriter, r *http.Request, provider string, body map[string]any) {
	ctx := r.Context()
	code := Str(body, "code")

	// Xiaomi MiMo: the callback session already holds the decrypted result.
	if provider == "xiaomi-mimo" {
		state := Str(body, "state")
		sess := oauthsvc.GetProxySession(state)
		if sess == nil || sess.Status != "done" || sess.Result == nil {
			Err(w, http.StatusBadRequest, "Xiaomi login session not completed")
			return
		}
		res := sess.Result
		uid, _ := res["uid"].(string)
		sk, _ := res["sk"].(string)
		baseURL, _ := res["url"].(string)
		if sk == "" {
			Err(w, http.StatusBadRequest, "Xiaomi session carries no key")
			return
		}
		tokens := map[string]any{
			"accessToken": sk,
			"expiresIn":   float64(365 * 24 * 3600),
			"providerSpecificData": map[string]any{
				"uid": uid, "baseUrl": baseURL, "authMethod": "oauth",
			},
		}
		if uid != "" {
			tokens["name"] = uid
		}
		rec, err := deps.saveOAuthConnection("xiaomi-mimo", "oauth", tokens)
		if err != nil {
			Err(w, http.StatusInternalServerError, err.Error())
			return
		}
		oauthsvc.ClearProxySession(state)
		successConnection(w, rec)
		return
	}

	// Trae / Windsurf: the code is a callback URL or a pasted token.
	if provider == "trae" || provider == "windsurf" {
		if code == "" {
			Err(w, http.StatusBadRequest, "Missing code")
			return
		}
		var tokens map[string]any
		var err error
		authType := "oauth"
		if provider == "trae" {
			login, lerr := oauthsvc.ResolveTraeLoginResult(code)
			if lerr != nil {
				Err(w, http.StatusBadRequest, lerr.Error())
				return
			}
			tokens, err = oauthsvc.ExchangeTraeLoginResult(ctx, oauthsvc.ConfigFor("trae"), login)
		} else {
			tokens, err = oauthsvc.ExchangeWindsurfAuthCode(ctx, oauthsvc.ConfigFor("windsurf"), code)
			authType = "api_key"
		}
		if err != nil {
			Err(w, http.StatusInternalServerError, err.Error())
			return
		}
		rec, err := deps.saveOAuthConnection(provider, authType, tokens)
		if err != nil {
			Err(w, http.StatusInternalServerError, err.Error())
			return
		}
		successConnection(w, rec)
		return
	}

	if _, ok := oauthsvc.GetProvider(provider); !ok {
		Err(w, http.StatusNotFound, "Unknown provider: "+provider)
		return
	}
	if code == "" {
		Err(w, http.StatusBadRequest, "Missing code")
		return
	}

	// Raw ChatGPT access token pasted as the code (codex JWT shortcut).
	if strings.HasPrefix(code, "eyJ") && len(strings.Split(code, ".")) == 3 && oauthsvc.DecodeJWTPayload(code) != nil {
		info := oauthsvc.ExtractCodexAccountInfo(code)
		payload := oauthsvc.DecodeJWTPayload(code)
		tokens := map[string]any{"accessToken": code}
		if info.Email != "" {
			tokens["email"] = info.Email
		}
		psd := map[string]any{"authMethod": "access_token"}
		if info.ChatGPTAccountID != "" {
			psd["chatgptAccountId"] = info.ChatGPTAccountID
		}
		if info.ChatGPTPlanType != "" {
			psd["chatgptPlanType"] = info.ChatGPTPlanType
		}
		tokens["providerSpecificData"] = psd
		if exp, ok := payload["exp"].(float64); ok && exp > 0 {
			tokens["expiresAt"] = time.Unix(int64(exp), 0).UTC().Format(time.RFC3339)
		}
		rec, err := deps.saveOAuthConnection(provider, "access_token", tokens)
		if err != nil {
			Err(w, http.StatusInternalServerError, err.Error())
			return
		}
		successConnection(w, rec)
		return
	}

	redirectURI := Str(body, "redirectUri")
	codeVerifier := Str(body, "codeVerifier")
	if !noPKCEExchangeProviders[provider] {
		if redirectURI == "" || codeVerifier == "" {
			Err(w, http.StatusBadRequest, "Missing code, redirectUri or codeVerifier")
			return
		}
	}
	meta := map[string]any{}
	if m, ok := body["meta"].(map[string]any); ok {
		meta = m
	}
	if provider == "zed" && Str(body, "systemId") != "" {
		meta["systemId"] = Str(body, "systemId")
	}
	tokens, err := oauthsvc.ExchangeTokens(ctx, provider, code, redirectURI, codeVerifier, Str(body, "state"), meta)
	if err != nil {
		Err(w, http.StatusInternalServerError, err.Error())
		return
	}
	rec, err := deps.saveOAuthConnection(provider, "oauth", tokens)
	if err != nil {
		Err(w, http.StatusInternalServerError, err.Error())
		return
	}
	successConnection(w, rec)
}

func (deps Deps) oauthPoll(w http.ResponseWriter, r *http.Request, provider string, body map[string]any) {
	ctx := r.Context()
	deviceCode := Str(body, "deviceCode")
	if deviceCode == "" {
		Err(w, http.StatusBadRequest, "Missing deviceCode")
		return
	}
	engine := provider
	saveProvider := provider
	if provider == "kimi-coding" {
		engine = "kimi"
		saveProvider = "kimi"
	}
	if _, ok := oauthsvc.GetProvider(engine); !ok {
		Err(w, http.StatusNotFound, "Unknown provider: "+provider)
		return
	}
	extra := map[string]any{}
	if e, ok := body["extraData"].(map[string]any); ok {
		extra = e
	}
	if provider == "qoder" || provider == "qoder-cn" {
		if cv := Str(body, "codeVerifier"); cv != "" {
			extra["codeVerifier"] = cv
		}
	}
	result, err := oauthsvc.PollForToken(ctx, engine, deviceCode, Str(body, "codeVerifier"), extra)
	if err != nil {
		Err(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !result.Success {
		resp := map[string]any{
			"success": false, "error": result.Error,
			"errorDescription": result.ErrorDescription,
			"pending":          result.Pending(),
		}
		if result.Fatal {
			resp["fatal"] = true
		}
		WriteJSON(w, http.StatusOK, resp)
		return
	}
	rec, err := deps.saveOAuthConnection(saveProvider, "oauth", result.Tokens)
	if err != nil {
		Err(w, http.StatusInternalServerError, err.Error())
		return
	}
	successConnection(w, rec)
}

func (deps Deps) oauthManualCode(w http.ResponseWriter, r *http.Request, provider string, body map[string]any) {
	if provider != "xai" {
		Err(w, http.StatusBadRequest, "manual-code is only available for xai")
		return
	}
	state := Str(body, "state")
	code := Str(body, "code")
	sess := oauthsvc.GetProxySession(state)
	if sess == nil {
		Err(w, http.StatusBadRequest, "Session not found or expired")
		return
	}
	tokens, err := oauthsvc.ExchangeTokens(r.Context(), "xai", code, sess.RedirectURI, sess.CodeVerifier, state, nil)
	if err != nil {
		Err(w, http.StatusInternalServerError, err.Error())
		return
	}
	rec, err := deps.saveOAuthConnection("xai", "oauth", tokens)
	if err != nil {
		Err(w, http.StatusInternalServerError, err.Error())
		return
	}
	oauthsvc.ClearProxySession(state)
	oauthsvc.StopCallbackServer("xai")
	successConnection(w, rec)
}

// ---------- bulk import shared shape ----------

func readBodyAny(r *http.Request) (any, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty body")
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func bulkItems(v any) []map[string]any {
	var list []any
	switch t := v.(type) {
	case []any:
		list = t
	case map[string]any:
		if acc, ok := t["accounts"].([]any); ok {
			list = acc
		} else {
			list = []any{t}
		}
	}
	out := []map[string]any{}
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

var _ = strings.TrimSpace
var _ = json.Marshal

// ---------- codex / grok bulk import + import-token ----------

func (deps Deps) bulkImport(w http.ResponseWriter, r *http.Request, provider string, withTotal bool) {
	v, err := readBodyAny(r)
	if err != nil {
		Err(w, http.StatusBadRequest, "Invalid or empty request body")
		return
	}
	items := bulkItems(v)
	results := []map[string]any{}
	failed := 0
	for i, item := range items {
		res := map[string]any{"index": float64(i)}
		accessToken, _ := item["accessToken"].(string)
		if accessToken == "" {
			accessToken, _ = item["access_token"].(string)
		}
		if accessToken == "" {
			res["ok"] = false
			res["error"] = "Missing accessToken"
			failed++
			results = append(results, res)
			continue
		}
		rec := db.Record{}
		for k, val := range item {
			rec[k] = val
		}
		// Normalize snake_case token fields.
		rec["accessToken"] = accessToken
		delete(rec, "access_token")
		if rt, _ := item["refreshToken"].(string); rt == "" {
			if rt2, _ := item["refresh_token"].(string); rt2 != "" {
				rec["refreshToken"] = rt2
			}
		}
		delete(rec, "refresh_token")
		delete(rec, "id")
		delete(rec, "provider")
		delete(rec, "authType")
		delete(rec, "createdAt")
		delete(rec, "updatedAt")
		rec["provider"] = provider
		rec["authType"] = "oauth"
		// Backfill identity from the JWT when missing.
		info := oauthsvc.ExtractCodexAccountInfo(accessToken)
		if provider == "codex" {
			if Str(rec, "email") == "" && info.Email != "" {
				rec["email"] = info.Email
			}
			psd, _ := rec["providerSpecificData"].(map[string]any)
			if psd == nil {
				psd = map[string]any{}
			}
			if info.ChatGPTAccountID != "" {
				psd["chatgptAccountId"] = info.ChatGPTAccountID
			}
			if info.ChatGPTPlanType != "" {
				psd["chatgptPlanType"] = info.ChatGPTPlanType
			}
			if len(psd) > 0 {
				rec["providerSpecificData"] = psd
			}
		} else if Str(rec, "email") == "" {
			if email := oauthsvc.ExtractEmailFromAccessToken(accessToken); email != "" {
				rec["email"] = email
			}
		}
		if rec["expiresAt"] == nil {
			if ei, ok := item["expiresIn"].(float64); ok && ei > 0 {
				rec["expiresAt"] = time.Now().Add(time.Duration(ei) * time.Second).UTC().Format(time.RFC3339)
			}
		}
		if rec["testStatus"] == nil {
			rec["testStatus"] = "active"
		}
		if rec["isActive"] == nil {
			rec["isActive"] = true
		}
		rec["lastRefreshAt"] = float64(time.Now().UnixMilli())
		created, err := deps.Store.CreateProviderConnection(rec)
		if err != nil {
			res["ok"] = false
			res["error"] = err.Error()
			failed++
		} else {
			res["ok"] = true
			res["id"] = created["id"]
			if e := created["email"]; e != nil {
				res["email"] = e
			}
		}
		results = append(results, res)
	}
	resp := map[string]any{"success": failed == 0, "failed": float64(failed), "results": results}
	if withTotal {
		resp["total"] = float64(len(items))
	}
	WriteJSON(w, http.StatusOK, resp)
}

func (deps Deps) codexBulkImport(w http.ResponseWriter, r *http.Request) {
	deps.bulkImport(w, r, "codex", false)
}

func (deps Deps) grokBulkImport(w http.ResponseWriter, r *http.Request) {
	deps.bulkImport(w, r, "grok-cli", true)
}

func (deps Deps) codexImportToken(w http.ResponseWriter, r *http.Request) {
	body, err := ReadBodyJSON(r)
	if err != nil {
		Err(w, http.StatusBadRequest, "Invalid or empty request body")
		return
	}
	accessToken := Str(body, "accessToken")
	if accessToken == "" {
		accessToken = Str(body, "token")
	}
	if accessToken == "" {
		Err(w, http.StatusBadRequest, "Missing accessToken")
		return
	}
	payload := oauthsvc.DecodeJWTPayload(accessToken)
	if payload == nil {
		Err(w, http.StatusBadRequest, "Invalid access token: not a JWT")
		return
	}
	info := oauthsvc.ExtractCodexAccountInfo(accessToken)
	psd := map[string]any{"authMethod": "access_token"}
	if info.ChatGPTAccountID != "" {
		psd["chatgptAccountId"] = info.ChatGPTAccountID
	}
	if info.ChatGPTPlanType != "" {
		psd["chatgptPlanType"] = info.ChatGPTPlanType
	}
	if exp, ok := payload["exp"].(float64); ok {
		psd["jwtExp"] = exp
	}
	if profile, ok := payload["https://api.openai.com/profile"].(map[string]any); ok {
		for k, v := range profile {
			psd[k] = v
		}
	}
	name := Str(body, "name")
	if name == "" {
		name = Str(payload, "name")
	}
	if name == "" {
		name = info.Email
	}
	if name == "" {
		name = "ChatGPT Access Token"
	}
	rec := db.Record{
		"provider": "codex", "authType": "access_token",
		"accessToken": accessToken, "name": name,
		"providerSpecificData": psd,
		"testStatus":           "active", "isActive": true,
	}
	if info.Email != "" {
		rec["email"] = info.Email
		rec["displayName"] = name
	}
	if exp, ok := payload["exp"].(float64); ok && exp > 0 {
		rec["expiresAt"] = time.Unix(int64(exp), 0).UTC().Format(time.RFC3339)
	}
	created, err := deps.Store.CreateProviderConnection(rec)
	if err != nil {
		Err(w, http.StatusInternalServerError, err.Error())
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"success": true, "connection": connSummary(created),
		"workspace": info.ChatGPTAccountID, "plan": info.ChatGPTPlanType,
	})
}

// ---------- cursor import / auto-import ----------

func cursorImportInstructions(w http.ResponseWriter, r *http.Request) {
	paths := oauthsvc.CursorTokenStoragePaths()
	WriteJSON(w, http.StatusOK, map[string]any{
		"instructions": map[string]any{
			"title": "How to get your Cursor token",
			"steps": []string{
				"1. Open Cursor IDE and make sure you're logged in",
				"2. Find the state.vscdb file:",
				"   - Linux: " + paths["linux"],
				"   - macOS: " + paths["darwin"],
				"   - Windows: " + paths["windows"],
				"3. Open the database with SQLite browser or CLI:",
				`   sqlite3 state.vscdb "SELECT value FROM itemTable WHERE key='cursorAuth/accessToken'"`,
				"4. Also get the machine ID:",
				`   sqlite3 state.vscdb "SELECT value FROM itemTable WHERE key='storage.serviceMachineId'"`,
				"5. Paste both values in the form below",
			},
		},
		"requiredFields": []string{"accessToken", "machineId"},
	})
}

func (deps Deps) cursorImport(w http.ResponseWriter, r *http.Request) {
	body, err := ReadBodyJSON(r)
	if err != nil {
		Err(w, http.StatusBadRequest, "Invalid or empty request body")
		return
	}
	validated, err := oauthsvc.CursorValidateImportToken(Str(body, "accessToken"), Str(body, "machineId"))
	if err != nil {
		Err(w, http.StatusBadRequest, err.Error())
		return
	}
	machineID, _ := validated["machineId"].(string)
	tokens := map[string]any{
		"accessToken": validated["accessToken"],
		"expiresIn":   validated["expiresIn"],
		"providerSpecificData": map[string]any{
			"machineId": machineID, "authMethod": "imported",
			"checksum": oauthsvc.CursorChecksum(machineID),
		},
	}
	if email, _, ok := oauthsvc.CursorExtractUserInfo(Str(body, "accessToken")); ok && email != "" {
		tokens["email"] = email
	}
	rec, err := deps.saveOAuthConnection("cursor", "oauth", tokens)
	if err != nil {
		Err(w, http.StatusInternalServerError, err.Error())
		return
	}
	successConnection(w, rec)
}

func (deps Deps) cursorAutoImport(w http.ResponseWriter, r *http.Request) {
	candidates := oauthsvc.CursorCandidateDBPaths()
	for _, p := range candidates {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		accessToken, machineID, err := oauthsvc.CursorReadTokensFromDB(p)
		if err != nil || accessToken == "" || machineID == "" {
			continue
		}
		validated, err := oauthsvc.CursorValidateImportToken(accessToken, machineID)
		if err != nil {
			continue
		}
		tokens := map[string]any{
			"accessToken": validated["accessToken"],
			"expiresIn":   validated["expiresIn"],
			"providerSpecificData": map[string]any{
				"machineId": machineID, "authMethod": "imported",
				"checksum": oauthsvc.CursorChecksum(machineID),
			},
		}
		if email, _, ok := oauthsvc.CursorExtractUserInfo(accessToken); ok && email != "" {
			tokens["email"] = email
		}
		rec, err := deps.saveOAuthConnection("cursor", "oauth", tokens)
		if err != nil {
			Err(w, http.StatusInternalServerError, err.Error())
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{
			"found": true, "success": true, "connection": connSummary(rec), "dbPath": p,
		})
		return
	}
	resp := map[string]any{"found": false}
	if len(candidates) > 0 {
		resp["dbPath"] = candidates[0]
	}
	if runtime.GOOS == "windows" {
		resp["windowsManual"] = true
	}
	WriteJSON(w, http.StatusOK, resp)
}

// ---------- gitlab PAT ----------

func (deps Deps) gitlabPAT(w http.ResponseWriter, r *http.Request) {
	body, err := ReadBodyJSON(r)
	if err != nil {
		Err(w, http.StatusBadRequest, "Invalid or empty request body")
		return
	}
	token := Str(body, "token")
	if token == "" {
		token = Str(body, "accessToken")
	}
	if token == "" {
		Err(w, http.StatusBadRequest, "Missing token")
		return
	}
	cfg := oauthsvc.ConfigFor("gitlab")
	base := Str(body, "baseUrl")
	if base == "" {
		base = cfg.StrOr("defaultBaseUrl", "https://gitlab.com")
	}
	base = strings.TrimRight(base, "/")
	status, user, herr := oauthsvc.GetJSON(r.Context(), base+cfg.StrOr("userInfoUrlPath", "/api/v4/user"),
		map[string]string{"Private-Token": token})
	if herr != nil {
		Err(w, http.StatusInternalServerError, herr.Error())
		return
	}
	if status != http.StatusOK {
		Err(w, http.StatusUnauthorized, "GitLab token verification failed")
		return
	}
	email := ""
	if user != nil {
		email = oauthsvcPickStr(user, "email", "public_email")
	}
	tokens := map[string]any{
		"accessToken": token,
		"providerSpecificData": map[string]any{
			"authKind": "personal_access_token",
			"baseUrl":  base,
			"username": oauthsvcPickStr(user, "username"),
			"name":     oauthsvcPickStr(user, "name"),
			"email":    email,
		},
	}
	if email != "" {
		tokens["email"] = email
	}
	if name := oauthsvcPickStr(user, "name"); name != "" {
		tokens["displayName"] = name
	}
	rec, err := deps.saveOAuthConnection("gitlab", "oauth", tokens)
	if err != nil {
		Err(w, http.StatusInternalServerError, err.Error())
		return
	}
	successConnection(w, rec)
}

func oauthsvcPickStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// ---------- iflow cookie ----------

func (deps Deps) iflowCookie(w http.ResponseWriter, r *http.Request) {
	body, err := ReadBodyJSON(r)
	if err != nil {
		Err(w, http.StatusBadRequest, "Invalid or empty request body")
		return
	}
	cookie := Str(body, "cookie")
	idx := strings.Index(cookie, "BXAuth=")
	if idx == -1 {
		Err(w, http.StatusBadRequest, "Cookie must contain BXAuth=")
		return
	}
	value := cookie[idx+len("BXAuth="):]
	if end := strings.Index(value, ";"); end != -1 {
		value = value[:end]
	}
	value = strings.TrimSpace(value)
	if value == "" {
		Err(w, http.StatusBadRequest, "Empty BXAuth cookie value")
		return
	}
	cookieHeader := "BXAuth=" + value + ";"
	endpoint := "https://platform.iflow.cn/api/openapi/apikey"
	status, data, herr := oauthsvc.PostJSON(r.Context(), endpoint, map[string]any{},
		map[string]string{"Cookie": cookieHeader})
	if herr != nil || status != http.StatusOK {
		status, data, herr = oauthsvc.GetJSON(r.Context(), endpoint, map[string]string{"Cookie": cookieHeader})
		if herr != nil {
			Err(w, http.StatusInternalServerError, herr.Error())
			return
		}
		if status != http.StatusOK {
			Err(w, http.StatusBadGateway, "iFlow API key request failed")
			return
		}
	}
	payload := data
	if d, ok := data["data"].(map[string]any); ok {
		payload = d
	}
	apiKey := oauthsvcPickStr(payload, "apiKey", "api_key", "key")
	if apiKey == "" {
		Err(w, http.StatusBadGateway, "iFlow returned no API key")
		return
	}
	psd := map[string]any{"cookie": cookieHeader}
	if v := payload["expireTime"]; v != nil {
		psd["expireTime"] = v
	}
	tokens := map[string]any{
		"accessToken": apiKey, "apiKey": apiKey, "providerSpecificData": psd,
	}
	rec, err := deps.saveOAuthConnection("iflow", "cookie", tokens)
	if err != nil {
		Err(w, http.StatusInternalServerError, err.Error())
		return
	}
	successConnection(w, rec)
}

// ---------- kiro routes ----------

func (deps Deps) kiroAPIKey(w http.ResponseWriter, r *http.Request) {
	body, err := ReadBodyJSON(r)
	if err != nil {
		Err(w, http.StatusBadRequest, "Invalid or empty request body")
		return
	}
	apiKey := Str(body, "apiKey")
	if apiKey == "" {
		apiKey = Str(body, "accessToken")
	}
	if apiKey == "" {
		Err(w, http.StatusBadRequest, "Missing apiKey")
		return
	}
	region := Str(body, "region")
	if _, err := oauthsvc.KiroValidateAPIKey(r.Context(), apiKey, region); err != nil {
		// JS deliberately returns a generic message (no upstream body leak).
		Err(w, http.StatusInternalServerError, "API key validation failed")
		return
	}
	if region == "" {
		region = "us-east-1"
	}
	tokens := map[string]any{
		"accessToken": apiKey,
		"expiresIn":   float64(365 * 24 * 3600),
		"providerSpecificData": map[string]any{
			"region": region, "authMethod": "api_key",
		},
	}
	rec, err := deps.saveOAuthConnection("kiro", "api_key", tokens)
	if err != nil {
		Err(w, http.StatusInternalServerError, err.Error())
		return
	}
	successConnection(w, rec)
}

func (deps Deps) kiroImport(w http.ResponseWriter, r *http.Request) {
	body, err := ReadBodyJSON(r)
	if err != nil {
		Err(w, http.StatusBadRequest, "Invalid or empty request body")
		return
	}
	refreshToken := Str(body, "refreshToken")
	if refreshToken == "" {
		Err(w, http.StatusBadRequest, "Missing refreshToken")
		return
	}
	region := Str(body, "region")
	if region == "" {
		region = "us-east-1"
	}
	psd := map[string]any{"region": region}
	if v := Str(body, "clientId"); v != "" {
		psd["clientId"] = v
	}
	if v := Str(body, "clientSecret"); v != "" {
		psd["clientSecret"] = v
	}
	if v := Str(body, "profileArn"); v != "" {
		psd["profileArn"] = v
	}
	if v := Str(body, "startUrl"); v != "" {
		psd["startUrl"] = v
	}
	authMethod := "social"
	if psd["clientId"] != nil && psd["clientSecret"] != nil {
		authMethod = "idc"
	}
	if v := Str(body, "authMethod"); v != "" {
		authMethod = v
	}
	psd["authMethod"] = authMethod

	tokens, err := oauthsvc.KiroValidateImportToken(r.Context(), refreshToken, psd)
	if err != nil {
		Err(w, http.StatusBadGateway, "Kiro token validation failed: "+err.Error())
		return
	}
	out := map[string]any{"providerSpecificData": psd}
	accessToken := oauthsvcPickStr(tokens, "accessToken", "access_token")
	out["accessToken"] = accessToken
	if rt := oauthsvcPickStr(tokens, "refreshToken", "refresh_token"); rt != "" {
		out["refreshToken"] = rt
	} else {
		out["refreshToken"] = refreshToken
	}
	if ei, ok := tokens["expiresIn"].(float64); ok {
		out["expiresIn"] = ei
	}
	if psd["profileArn"] == nil && accessToken != "" {
		if arn := oauthsvc.FetchKiroProfileArn(r.Context(), accessToken); arn != "" {
			psd["profileArn"] = arn
		}
	}
	if idToken := oauthsvcPickStr(tokens, "idToken", "id_token"); idToken != "" {
		if email := oauthsvc.KiroExtractEmail(idToken); email != "" {
			out["email"] = email
		}
	}
	rec, err := deps.saveOAuthConnection("kiro", "oauth", out)
	if err != nil {
		Err(w, http.StatusInternalServerError, err.Error())
		return
	}
	successConnection(w, rec)
}

func kiroSocialAuthorize(w http.ResponseWriter, r *http.Request) {
	provider := r.URL.Query().Get("provider")
	if provider == "" {
		provider = "google"
	}
	pkce := oauthsvc.GeneratePKCE(32)
	loginURL, err := oauthsvc.KiroSocialLoginURL(provider, pkce.CodeChallenge, pkce.State)
	if err != nil {
		Err(w, http.StatusBadRequest, err.Error())
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"success": true, "authUrl": loginURL,
		"codeVerifier": pkce.CodeVerifier, "state": pkce.State,
	})
}

func (deps Deps) kiroSocialExchange(w http.ResponseWriter, r *http.Request) {
	body, err := ReadBodyJSON(r)
	if err != nil {
		Err(w, http.StatusBadRequest, "Invalid or empty request body")
		return
	}
	code := Str(body, "code")
	codeVerifier := Str(body, "codeVerifier")
	if code == "" || codeVerifier == "" {
		Err(w, http.StatusBadRequest, "Missing code or codeVerifier")
		return
	}
	tokens, err := oauthsvc.KiroSocialExchange(r.Context(), code, codeVerifier)
	if err != nil {
		Err(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := map[string]any{}
	accessToken := oauthsvcPickStr(tokens, "accessToken", "access_token")
	out["accessToken"] = accessToken
	if rt := oauthsvcPickStr(tokens, "refreshToken", "refresh_token"); rt != "" {
		out["refreshToken"] = rt
	}
	if ei, ok := tokens["expiresIn"].(float64); ok {
		out["expiresIn"] = ei
	} else if ei, ok := tokens["expires_in"].(float64); ok {
		out["expiresIn"] = ei
	}
	psd := map[string]any{"authMethod": "social", "region": "us-east-1"}
	if accessToken != "" {
		if arn := oauthsvc.FetchKiroProfileArn(r.Context(), accessToken); arn != "" {
			psd["profileArn"] = arn
		}
	}
	out["providerSpecificData"] = psd
	if idToken := oauthsvcPickStr(tokens, "idToken", "id_token"); idToken != "" {
		if email := oauthsvc.KiroExtractEmail(idToken); email != "" {
			out["email"] = email
		}
	}
	rec, err := deps.saveOAuthConnection("kiro", "oauth", out)
	if err != nil {
		Err(w, http.StatusInternalServerError, err.Error())
		return
	}
	successConnection(w, rec)
}

func (deps Deps) kiroImportCLIProxy(w http.ResponseWriter, r *http.Request) {
	body, err := ReadBodyJSON(r)
	if err != nil {
		Err(w, http.StatusBadRequest, "Invalid or empty request body")
		return
	}
	normalized, err := oauthsvc.NormalizeKiroExternalIdpAuth(body)
	if err != nil {
		Err(w, http.StatusBadRequest, err.Error())
		return
	}
	refreshToken, _ := normalized["refreshToken"].(string)
	psd := map[string]any{"authMethod": "external_idp"}
	for _, k := range []string{"clientId", "region", "issuerUrl", "tokenEndpoint", "scopes", "profileArn", "provider"} {
		if v, ok := normalized[k]; ok {
			psd[k] = v
		}
	}
	out := map[string]any{"refreshToken": refreshToken, "providerSpecificData": psd}
	// Best-effort refresh against the IdP token endpoint to mint an access
	// token now (the JS route does the same round-trip).
	if endpoint, _ := normalized["tokenEndpoint"].(string); endpoint != "" {
		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
		}
		if cid, _ := normalized["clientId"].(string); cid != "" {
			form.Set("client_id", cid)
		}
		if scopes, _ := normalized["scopes"].(string); scopes != "" {
			form.Set("scope", scopes)
		}
		status, data, herr := oauthsvc.PostForm(r.Context(), endpoint, form, nil)
		if herr != nil || status != http.StatusOK {
			Err(w, http.StatusBadGateway, "Kiro external IdP token refresh failed")
			return
		}
		out["accessToken"] = oauthsvcPickStr(data, "access_token")
		if ei, ok := data["expires_in"].(float64); ok {
			out["expiresIn"] = ei
		}
		if idToken := oauthsvcPickStr(data, "id_token"); idToken != "" {
			if email := oauthsvc.KiroExtractEmail(idToken); email != "" {
				out["email"] = email
			}
		}
	}
	rec, err := deps.saveOAuthConnection("kiro", "oauth", out)
	if err != nil {
		Err(w, http.StatusInternalServerError, err.Error())
		return
	}
	successConnection(w, rec)
}

func (deps Deps) kiroAutoImport(w http.ResponseWriter, r *http.Request) {
	cand, err := oauthsvc.ScanKiroSSOCache()
	if err != nil {
		WriteJSON(w, http.StatusOK, map[string]any{"found": false, "error": err.Error()})
		return
	}
	psd := map[string]any{"authMethod": "idc", "region": cand.Region}
	if cand.ClientID != "" {
		psd["clientId"] = cand.ClientID
	}
	if cand.ClientSecret != "" {
		psd["clientSecret"] = cand.ClientSecret
	}
	if cand.ProfileARN != "" {
		psd["profileArn"] = cand.ProfileARN
	}
	out := map[string]any{"refreshToken": cand.RefreshToken, "providerSpecificData": psd}
	// Best-effort refresh to capture a live access token.
	if tokens, err := oauthsvc.KiroRefreshToken(r.Context(), cand.RefreshToken, psd); err == nil {
		if at := oauthsvcPickStr(tokens, "accessToken", "access_token"); at != "" {
			out["accessToken"] = at
			if psd["profileArn"] == nil {
				if arn := oauthsvc.FetchKiroProfileArn(r.Context(), at); arn != "" {
					psd["profileArn"] = arn
				}
			}
		}
		if ei, ok := tokens["expiresIn"].(float64); ok {
			out["expiresIn"] = ei
		}
	}
	rec, err := deps.saveOAuthConnection("kiro", "oauth", out)
	if err != nil {
		Err(w, http.StatusInternalServerError, err.Error())
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"found": true, "success": true, "connection": connSummary(rec), "source": cand.FilePath,
	})
}

// ---------- zed import / auto-import ----------

func (deps Deps) zedImport(w http.ResponseWriter, r *http.Request) {
	body, err := ReadBodyJSON(r)
	if err != nil {
		Err(w, http.StatusBadRequest, "Invalid or empty request body")
		return
	}
	userID := Str(body, "userId")
	accessToken := Str(body, "accessToken")
	if userID == "" || accessToken == "" {
		Err(w, http.StatusBadRequest, "Missing userId or accessToken")
		return
	}
	systemID := Str(body, "systemId")
	if systemID == "" {
		systemID = oauthsvc.GenerateState()
	}
	user, err := oauthsvc.FetchZedAuthenticatedUser(r.Context(), userID, accessToken, systemID)
	if err != nil {
		Err(w, http.StatusUnauthorized, "Zed token validation failed")
		return
	}
	tokens := map[string]any{"accessToken": accessToken}
	psd := map[string]any{"authMethod": "imported", "userId": userID, "systemId": systemID}
	if orgID := oauthsvc.ResolveZedOrganizationID(user); orgID != "" {
		psd["organizationId"] = orgID
	}
	tokens["providerSpecificData"] = psd
	if email := oauthsvcPickStr(user, "email"); email != "" {
		tokens["email"] = email
	}
	if name := oauthsvcPickStr(user, "name", "github_login"); name != "" {
		tokens["displayName"] = name
	}
	rec, err := deps.saveOAuthConnection("zed", "oauth", tokens)
	if err != nil {
		Err(w, http.StatusInternalServerError, err.Error())
		return
	}
	successConnection(w, rec)
}

func (deps Deps) zedAutoImport(w http.ResponseWriter, r *http.Request) {
	creds := oauthsvc.ReadZedIDECredentials()
	if !creds.Found {
		WriteJSON(w, http.StatusOK, map[string]any{"found": false, "error": creds.Error})
		return
	}
	tokens := map[string]any{"accessToken": creds.AccessToken}
	psd := map[string]any{"authMethod": "imported", "userId": creds.UserID, "systemId": creds.SystemID}
	if user, err := oauthsvc.FetchZedAuthenticatedUser(r.Context(), creds.UserID, creds.AccessToken, creds.SystemID); err == nil {
		if email := oauthsvcPickStr(user, "email"); email != "" {
			tokens["email"] = email
		}
		if name := oauthsvcPickStr(user, "name", "github_login"); name != "" {
			tokens["displayName"] = name
		}
		if orgID := oauthsvc.ResolveZedOrganizationID(user); orgID != "" {
			psd["organizationId"] = orgID
		}
	}
	tokens["providerSpecificData"] = psd
	rec, err := deps.saveOAuthConnection("zed", "oauth", tokens)
	if err != nil {
		Err(w, http.StatusInternalServerError, err.Error())
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"found": true, "success": true, "connection": connSummary(rec),
	})
}

// ---------- xiaomi-mimo routes ----------

// saveXiaomiAPIKey validates (soft-fail) and upserts a MiMo key connection,
// mirroring the dedup rules of the JS api-key route.
func (deps Deps) saveXiaomiAPIKey(w http.ResponseWriter, r *http.Request, apiKey string, body map[string]any) {
	ctx := r.Context()
	baseURL := Str(body, "baseUrl")
	if baseURL == "" {
		baseURL = oauthsvc.XiaomiDefaultAPIURL
	}
	uid := Str(body, "uid")
	passToken := Str(body, "passToken")
	userID := Str(body, "userId")
	cUserID := Str(body, "cUserId")
	region := Str(body, "region")
	sessionOnly := apiKey == "" && passToken != ""
	if apiKey != "" && !strings.HasPrefix(apiKey, "sk-") && !sessionOnly {
		Err(w, http.StatusBadRequest, "API key must start with sk-")
		return
	}
	validated := false
	modelCount := 0
	if apiKey != "" {
		endpoint := strings.TrimRight(baseURL, "/") + "/models"
		status, data, err := oauthsvc.GetJSON(ctx, endpoint, map[string]string{
			"Authorization": "Bearer " + apiKey,
			"X-Mimo-Source": "mimocode-cli",
		})
		if err == nil && status == http.StatusOK {
			validated = true
			if list, ok := data["data"].([]any); ok {
				modelCount = len(list)
			}
		}
	}
	psd := map[string]any{"baseUrl": baseURL, "authMethod": "api_key"}
	if uid != "" {
		psd["uid"] = uid
	}
	if passToken != "" {
		psd["mimoPassToken"] = passToken
	}
	if userID != "" {
		psd["mimoUserId"] = userID
	}
	if cUserID != "" {
		psd["mimoCUserId"] = cUserID
	}
	if region != "" {
		psd["region"] = region
	}
	email := ""
	if uid != "" {
		email = uid + "@xiaomimimo.com"
	}

	// Dedup: same uid+email, same key, or same session identity+region.
	existing, _ := deps.Store.GetProviderConnections(db.ConnectionFilter{Provider: "xiaomi-mimo"})
	var match db.Record
	for _, c := range existing {
		cpsd, _ := c["providerSpecificData"].(map[string]any)
		sameKey := apiKey != "" && c["accessToken"] == apiKey
		sameUID := uid != "" && cpsd != nil && cpsd["uid"] == uid && c["email"] == email
		sameSession := sessionOnly && cpsd != nil &&
			cpsd["mimoUserId"] == userID && cpsd["region"] == region
		if sameKey || sameUID || sameSession {
			match = c
			break
		}
	}
	if match != nil {
		id, _ := match["id"].(string)
		updates := db.Record{"providerSpecificData": psd, "testStatus": "active"}
		if apiKey != "" {
			updates["accessToken"] = apiKey
		}
		if email != "" {
			updates["email"] = email
		}
		updated, err := deps.Store.UpdateProviderConnection(id, updates)
		if err != nil {
			Err(w, http.StatusInternalServerError, err.Error())
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{
			"success": true, "validated": validated, "modelCount": float64(modelCount),
			"updated": true, "connection": connSummary(updated),
		})
		return
	}
	tokens := map[string]any{
		"accessToken": apiKey, "providerSpecificData": psd,
		"expiresIn": float64(365 * 24 * 3600),
	}
	if email != "" {
		tokens["email"] = email
		tokens["name"] = uid
	}
	rec, err := deps.saveOAuthConnection("xiaomi-mimo", "api_key", tokens)
	if err != nil {
		Err(w, http.StatusInternalServerError, err.Error())
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"success": true, "validated": validated, "modelCount": float64(modelCount),
		"connection": connSummary(rec),
	})
}

func (deps Deps) xiaomiAPIKey(w http.ResponseWriter, r *http.Request) {
	body, err := ReadBodyJSON(r)
	if err != nil {
		Err(w, http.StatusBadRequest, "Invalid or empty request body")
		return
	}
	apiKey := Str(body, "apiKey")
	if apiKey == "" {
		apiKey = Str(body, "key")
	}
	if apiKey == "" && Str(body, "passToken") == "" {
		Err(w, http.StatusBadRequest, "Missing apiKey")
		return
	}
	deps.saveXiaomiAPIKey(w, r, apiKey, body)
}

func (deps Deps) xiaomiAutoImport(w http.ResponseWriter, r *http.Request) {
	found, err := oauthsvc.ScanXiaomiAuthJSON()
	if err != nil {
		WriteJSON(w, http.StatusOK, map[string]any{"found": false})
		return
	}
	body := map[string]any{"baseUrl": found.BaseURL, "uid": found.UID}
	deps.saveXiaomiAPIKey(w, r, found.APIKey, body)
}

// xiaomiLoginStart begins the MiMo web-login session: it walks the MiMo
// server's /api/user/xiaomi/me entry (which redirects to Xiaomi SSO),
// captures the cookie jar into the 9r_mimo_login session cookie, and
// returns the SSO page URL. NOTE: in the JS the subsequent page traffic is
// proxied by src/proxy.js (middleware) — that proxy is outside this
// registrar's files; the session cookie codec is fully compatible with it.
func xiaomiLoginStart(w http.ResponseWriter, r *http.Request) {
	body, _ := ReadBodyJSON(r)
	region := Str(body, "region")
	if region == "" {
		region = "cn"
	}
	state := oauthsvc.GenerateState()
	base := oauthsvc.MimoRegionBase(region)
	entry := base + "/api/user/xiaomi/me"

	jar := []oauthsvc.MimoCookie{}
	pageURL := entry
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			pageURL = req.URL.String()
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, entry, nil)
	if err != nil {
		Err(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		Err(w, http.StatusBadGateway, "MiMo login entry unreachable: "+err.Error())
		return
	}
	cookies := resp.Cookies()
	_ = resp.Body.Close()
	for _, c := range cookies {
		jar = append(jar, oauthsvc.MimoCookie{Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path})
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		pageURL = loc
	}
	sess := &oauthsvc.MimoLoginSession{
		State: state, Region: region, CreatedAt: time.Now().UnixMilli(), Jar: jar,
	}
	value, err := oauthsvc.EncodeMimoLoginSession(sess)
	if err != nil {
		Err(w, http.StatusInternalServerError, err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "9r_mimo_login", Value: value, Path: "/",
		MaxAge: 15 * 60, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	WriteJSON(w, http.StatusOK, map[string]any{
		"success": true, "state": state, "pageUrl": pageURL, "region": region,
	})
}

func xiaomiLoginStatus(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("9r_mimo_login")
	if err != nil || cookie.Value == "" {
		WriteJSON(w, http.StatusOK, map[string]any{"status": "pending"})
		return
	}
	sess, err := oauthsvc.DecodeMimoLoginSession(cookie.Value)
	if err != nil {
		WriteJSON(w, http.StatusOK, map[string]any{"status": "pending"})
		return
	}
	passToken, userID, cUserID := sess.MimoIdentity()
	if passToken == "" || userID == "" {
		WriteJSON(w, http.StatusOK, map[string]any{"status": "pending", "region": sess.Region})
		return
	}
	// Done — clear the session cookie like the JS does.
	http.SetCookie(w, &http.Cookie{Name: "9r_mimo_login", Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	WriteJSON(w, http.StatusOK, map[string]any{
		"status": "done", "region": sess.Region,
		"passToken": passToken, "userId": userID, "cUserId": cUserID,
	})
}

// ---------- OIDC SSO ----------

func (deps Deps) oidcConfig(r *http.Request) (oauthsvc.OIDCRuntimeConfig, map[string]any) {
	settings, _ := deps.Store.GetSettings()
	authMode := Str(settings, "authMode")
	return oauthsvc.OIDCRuntime(settings, authMode), settings
}

func (deps Deps) oidcStart(w http.ResponseWriter, r *http.Request) {
	cfg, _ := deps.oidcConfig(r)
	if !cfg.Enabled {
		http.Redirect(w, r, "/login?error=oidc_not_configured", http.StatusFound)
		return
	}
	discovery, err := oauthsvc.OIDCDiscovery(r.Context(), cfg.IssuerURL)
	if err != nil {
		http.Redirect(w, r, "/login?error="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	pkce := oauthsvc.GeneratePKCE(32)
	nonce := oauthsvc.GenerateState()
	origin := oauthsvc.PublicOrigin(r)
	redirectURI := origin + "/api/auth/oidc/callback"
	setOIDCCookie(w, "oidc_state", pkce.State)
	setOIDCCookie(w, "oidc_nonce", nonce)
	setOIDCCookie(w, "oidc_code_verifier", pkce.CodeVerifier)
	authURL := oauthsvc.OIDCBuildAuthorizationURL(
		oauthsvcPickStr(discovery, "authorization_endpoint"),
		cfg.ClientID, redirectURI, cfg.Scopes, pkce.State, nonce, pkce.CodeChallenge)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func setOIDCCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/api/auth/oidc",
		MaxAge: 10 * 60, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func clearOIDCCookies(w http.ResponseWriter) {
	for _, name := range []string{"oidc_state", "oidc_nonce", "oidc_code_verifier"} {
		http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/api/auth/oidc", MaxAge: -1, HttpOnly: true})
	}
}

func (deps Deps) oidcCallback(w http.ResponseWriter, r *http.Request) {
	cfg, _ := deps.oidcConfig(r)
	fail := func(code string) {
		clearOIDCCookies(w)
		http.Redirect(w, r, "/login?error="+url.QueryEscape(code), http.StatusFound)
	}
	if !cfg.Enabled {
		fail("oidc_not_configured")
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		fail(e)
		return
	}
	code := q.Get("code")
	if code == "" {
		fail("oidc_missing_code")
		return
	}
	stateCookie, _ := r.Cookie("oidc_state")
	if stateCookie == nil || stateCookie.Value == "" || stateCookie.Value != q.Get("state") {
		fail("oidc_invalid_state")
		return
	}
	nonceCookie, _ := r.Cookie("oidc_nonce")
	verifierCookie, _ := r.Cookie("oidc_code_verifier")
	nonce := ""
	verifier := ""
	if nonceCookie != nil {
		nonce = nonceCookie.Value
	}
	if verifierCookie != nil {
		verifier = verifierCookie.Value
	}
	discovery, err := oauthsvc.OIDCDiscovery(r.Context(), cfg.IssuerURL)
	if err != nil {
		fail(err.Error())
		return
	}
	origin := oauthsvc.PublicOrigin(r)
	redirectURI := origin + "/api/auth/oidc/callback"
	tokens, err := oauthsvc.OIDCExchangeCode(r.Context(),
		oauthsvcPickStr(discovery, "token_endpoint"), cfg, code, redirectURI, verifier)
	if err != nil {
		fail(err.Error())
		return
	}
	idToken := oauthsvcPickStr(tokens, "id_token")
	if idToken == "" {
		fail("oidc_missing_id_token")
		return
	}
	payload, err := oauthsvc.OIDCVerifyIDToken(r.Context(), idToken, discovery, cfg, nonce)
	if err != nil {
		fail(err.Error())
		return
	}
	// Stamp the SSO identity claims like the JS callback
	// (setDashboardAuthCookie with {oidc, oidcSub, oidcEmail, oidcName});
	// authStatus surfaces them as oidcLogin/oidcEmail/oidcName.
	var sub, email any
	if s := oauthsvcPickStr(payload, "sub"); s != "" {
		sub = s
	}
	if e := oauthsvc.OIDCPickEmail(payload); e != "" {
		email = e
	}
	clearOIDCCookies(w)
	SetSessionCookieWithClaims(w, r, deps.Store, map[string]any{
		"oidc":      true,
		"oidcSub":   sub,
		"oidcEmail": email,
		"oidcName":  oauthsvc.OIDCPickDisplayName(payload),
	})
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func (deps Deps) oidcTest(w http.ResponseWriter, r *http.Request) {
	settings, _ := deps.Store.GetSettings()
	requireLogin := true
	if v, ok := settings["requireLogin"].(bool); ok {
		requireLogin = v
	}
	if requireLogin && !VerifySessionToken(deps.Store, SessionToken(r)) {
		Err(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	cfg, _ := deps.oidcConfig(r)
	if cfg.IssuerURL == "" || cfg.ClientID == "" {
		WriteJSON(w, http.StatusOK, map[string]any{
			"ok": false, "error": "OIDC is not configured (issuer URL and client ID are required)",
		})
		return
	}
	discovery, err := oauthsvc.OIDCDiscovery(r.Context(), cfg.IssuerURL)
	if err != nil {
		WriteJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "Discovery failed: " + err.Error()})
		return
	}
	origin := oauthsvc.PublicOrigin(r)
	redirectURI := origin + "/api/auth/oidc/callback"
	classification, _, err := oauthsvc.OIDCProbeClientSecret(r.Context(),
		oauthsvcPickStr(discovery, "token_endpoint"), cfg, redirectURI)
	if err != nil {
		WriteJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "Client probe failed: " + err.Error()})
		return
	}
	secretValid := classification == "invalid_grant"
	resp := map[string]any{
		"ok": true, "discoveryOk": true,
		"issuer":                oauthsvcPickStr(discovery, "issuer"),
		"authorizationEndpoint": oauthsvcPickStr(discovery, "authorization_endpoint"),
		"tokenEndpoint":         oauthsvcPickStr(discovery, "token_endpoint"),
		"clientSecretValid":     secretValid,
		"clientSecretCheck":     classification,
		"clientConfigured":      cfg.ClientSecret != "",
	}
	if cfg.ClientSecret != "" && !secretValid {
		resp["message"] = "Discovery OK, but the client secret was rejected (invalid_client)"
	} else {
		resp["message"] = "OIDC configuration looks good"
	}
	WriteJSON(w, http.StatusOK, resp)
}

// ---------- SAML SSO ----------

func (deps Deps) samlConfig(r *http.Request) oauthsvc.SAMLRuntimeConfig {
	settings, _ := deps.Store.GetSettings()
	return oauthsvc.SAMLRuntime(settings, oauthsvc.PublicOrigin(r))
}

func (deps Deps) samlStart(w http.ResponseWriter, r *http.Request) {
	cfg := deps.samlConfig(r)
	if !oauthsvc.SAMLConfigured(cfg) {
		http.Redirect(w, r, "/login?error=saml_not_configured", http.StatusFound)
		return
	}
	requestID := "_" + oauthsvc.GenerateState()[:32]
	http.SetCookie(w, &http.Cookie{
		Name: "saml_state", Value: requestID, Path: "/api/auth/saml",
		MaxAge: 10 * 60, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	authURL, err := oauthsvc.BuildSAMLAuthnRequestURL(cfg, requestID, time.Now())
	if err != nil {
		http.Redirect(w, r, "/login?error="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (deps Deps) samlACS(w http.ResponseWriter, r *http.Request) {
	cfg := deps.samlConfig(r)
	fail := func(code string) {
		http.Redirect(w, r, "/login?error="+url.QueryEscape(code), http.StatusFound)
	}
	if !oauthsvc.SAMLConfigured(cfg) {
		fail("saml_not_configured")
		return
	}
	if err := r.ParseForm(); err != nil {
		fail("saml_invalid_request")
		return
	}
	samlResponse := r.FormValue("SAMLResponse")
	if samlResponse == "" {
		fail("saml_missing_response")
		return
	}
	expected := ""
	if c, err := r.Cookie("saml_state"); err == nil {
		expected = c.Value
	}
	profile, verified, err := oauthsvc.ValidateSAMLResponse(samlResponse, cfg, expected)
	if err != nil {
		fail(err.Error())
		return
	}
	if !verified {
		// Defense in depth: ValidateSAMLResponse verifies the XMLDSig
		// signature against the IdP cert (oauthsvc/saml_verify.go,
		// goxmldsig) and returns an error — redirected above with a
		// "saml_signature_missing:"/"saml_signature_invalid:" message —
		// for any signature problem, so this branch is unreachable in
		// practice. A session is still never issued from an unverified
		// assertion.
		fail("saml_signature_unverified")
		return
	}
	// Stamp the SSO identity claims like the JS ACS
	// (setDashboardAuthCookie with {saml, samlEmail, samlName});
	// authStatus surfaces them as samlLogin/samlEmail/samlName.
	var samlEmail any
	if e := oauthsvc.PickSAMLEmail(profile, cfg); e != "" {
		samlEmail = e
	}
	samlName := oauthsvc.PickSAMLDisplayName(profile, cfg)
	if samlName == "" {
		samlName = "SAML user"
	}
	SetSessionCookieWithClaims(w, r, deps.Store, map[string]any{
		"saml":      true,
		"samlEmail": samlEmail,
		"samlName":  samlName,
	})
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func (deps Deps) samlMetadata(w http.ResponseWriter, r *http.Request) {
	cfg := deps.samlConfig(r)
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	_, _ = w.Write([]byte(oauthsvc.GenerateSAMLMetadata(cfg)))
}

func (deps Deps) samlTest(w http.ResponseWriter, r *http.Request) {
	settings, _ := deps.Store.GetSettings()
	requireLogin := true
	if v, ok := settings["requireLogin"].(bool); ok {
		requireLogin = v
	}
	if requireLogin && !VerifySessionToken(deps.Store, SessionToken(r)) {
		Err(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	cfg := deps.samlConfig(r)
	if cfg.EntryPoint == "" {
		WriteJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "SAML entry point (IdP SSO URL) is not configured"})
		return
	}
	if u, err := url.Parse(cfg.EntryPoint); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		WriteJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "SAML entry point is not a valid URL"})
		return
	}
	if cfg.Cert == "" {
		WriteJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "SAML IdP certificate is not configured"})
		return
	}
	if !oauthsvc.CertLooksValid(cfg.Cert) {
		WriteJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "SAML IdP certificate does not look like a valid X.509 PEM"})
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "certValid": true,
		"acsUrl": oauthsvc.SAMLACSURL(cfg), "metadataUrl": oauthsvc.SAMLMetadataURL(cfg),
		"message": "SAML configuration looks good",
	})
}
