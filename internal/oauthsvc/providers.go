package oauthsvc

import (
	"fmt"
	"os"
	"strings"
)

// errf is the package-local error constructor.
func errf(format string, args ...any) error { return fmt.Errorf(format, args...) }

// Flow types (PROVIDERS[name].flowType in src/lib/oauth/providers/index.js).
const (
	FlowAuthorizationCode = "authorization_code"
	FlowDeviceCode        = "device_code"
	FlowImportToken       = "import_token"
	FlowBrowserToken      = "browser_token"
)

// ProviderDef mirrors one entry of the JS PROVIDERS registry.
type ProviderDef struct {
	ID string
	// FlowType: authorization_code (default in JS when absent), device_code,
	// import_token, browser_token.
	FlowType string
	// FixedPort / CallbackPath come from the provider config (codex 1455 +
	// /auth/callback; xai 56121).
	FixedPort    int
	CallbackPath string
	// PKCEVerifierBytes overrides the default 32 (xai uses 96).
	PKCEVerifierBytes int
}

// Providers is the port of the PROVIDERS map in
// src/lib/oauth/providers/index.js (28 providers).
var Providers = map[string]*ProviderDef{
	"claude":              {ID: "claude"},
	"codex":               {ID: "codex", FixedPort: 1455, CallbackPath: "/auth/callback"},
	"xai":                 {ID: "xai", FixedPort: 56121, PKCEVerifierBytes: 96},
	"grok-cli":            {ID: "grok-cli", FlowType: FlowDeviceCode},
	"muse":                {ID: "muse", FlowType: FlowDeviceCode},
	"gemini-cli":          {ID: "gemini-cli"},
	"antigravity":         {ID: "antigravity"},
	"iflow":               {ID: "iflow"},
	"qoder":               {ID: "qoder", FlowType: FlowDeviceCode},
	"qoder-cn":            {ID: "qoder-cn", FlowType: FlowDeviceCode},
	"github":              {ID: "github", FlowType: FlowDeviceCode},
	"kiro":                {ID: "kiro", FlowType: FlowDeviceCode},
	"cursor":              {ID: "cursor", FlowType: FlowImportToken},
	"kimi":                {ID: "kimi", FlowType: FlowDeviceCode},
	"kilocode":            {ID: "kilocode", FlowType: FlowDeviceCode},
	"cline":               {ID: "cline"},
	"clinepass":           {ID: "clinepass"},
	"gitlab":              {ID: "gitlab"},
	"codebuddy-cn":        {ID: "codebuddy-cn", FlowType: FlowDeviceCode},
	"codebuddy-intl":      {ID: "codebuddy-intl", FlowType: FlowDeviceCode},
	"kimchi":              {ID: "kimchi", FlowType: FlowBrowserToken},
	"trae":                {ID: "trae"},
	"windsurf":            {ID: "windsurf"},
	"zed":                 {ID: "zed"},
	"glm":                 {ID: "glm", FlowType: FlowDeviceCode},
	"minimax-code":        {ID: "minimax-code", FlowType: FlowDeviceCode},
	"minimax-code-global": {ID: "minimax-code-global", FlowType: FlowDeviceCode},
	"nous":                {ID: "nous", FlowType: FlowDeviceCode},
}

// ProviderNames returns the registered provider ids, sorted.
func ProviderNames() []string {
	names := make([]string, 0, len(Providers))
	for id := range Providers {
		names = append(names, id)
	}
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	return names
}

// GetProvider returns a provider definition by id.
func GetProvider(id string) (*ProviderDef, bool) {
	def, ok := Providers[id]
	return def, ok
}

// ---- Configs the JS keeps OUTSIDE the registry (constants/oauth.js,
// constants/xai.js, open-sse/providers/shared.js). Client ids/secrets below
// are the upstream project's published desktop OAuth clients — the same
// values the JS ships to every install; they are config, not user secrets.

// GoogleOAuthClient mirrors GOOGLE_OAUTH_CLIENT (gemini-cli).
var GoogleOAuthClient = struct{ ClientID, ClientSecret string }{
	ClientID:     "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com",
	ClientSecret: "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",
}

// AntigravityOAuthClient mirrors ANTIGRAVITY_OAUTH_CLIENT.
var AntigravityOAuthClient = struct{ ClientID, ClientSecret string }{
	ClientID:     "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com",
	ClientSecret: "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",
}

const (
	// XAI discovery + endpoints (src/lib/oauth/constants/xai.js).
	XAIDiscoveryURL = "https://auth.x.ai/.well-known/openid-configuration"
	XAIScope        = "openid profile email offline_access grok-cli:access api:access"
	XAIRedirectPort = 56121

	// Xiaomi MiMo (XIAOMI_MIMO_CONFIG).
	XiaomiPlatformURL   = "https://platform.xiaomimimo.com"
	XiaomiDefaultAPIURL = "https://api.xiaomimimo.com/v1"
	XiaomiKeyName       = "9router"
	XiaomiProxyPort     = 58080

	// Trae (TRAE_CONFIG).
	TraeLoginGuidanceURL = "https://api.marscode.com/cloudide/api/v3/trae/GetLoginGuidance"
	TraeExchangeTokenURL = "https://api.marscode.com/cloudide/api/v3/trae/oauth/ExchangeToken"
	TraeUserInfoURL      = "https://api.marscode.com/cloudide/api/v3/common/GetUserInfo"
	TraeClientID         = "ono9krqynydwx5"
	TraePlatform         = "trae"
	TraePollIntervalMs   = 1500

	// Windsurf (WINDSURF_CONFIG).
	WindsurfSignInURL     = "https://windsurf.com/editor/signin?response_type=token"
	WindsurfRegisterURL   = "https://register.windsurf.com/exa.seat_management_pb.SeatManagementService/RegisterUser"
	WindsurfFirebaseURL   = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword"
	WindsurfErrorPageHost = "error-page.windsurf.com"

	// Nous (NOUS_CONFIG).
	NousClientID    = "hermes-cli"
	NousPortalBase  = "https://portal.nousresearch.com"
	NousScope       = "inference:mint_agent_key inference:invoke"
	NousRedirectURI = NousPortalBase + "/oauth/callback"

	// Zed hosted sign-in URL (ZED_HOSTED_CONFIG.loginUrl).
	ZedHostedLoginURL = "https://zed.dev/login?provider_name=Zed"
)

// TestOverrides lets tests substitute a provider's base config (e.g.
// httptest endpoints). Nil in production.
var TestOverrides map[string]Config

// ConfigFor resolves a provider's effective OAuth config: the registry
// `oauth` block merged with the JS-side constants for the providers that
// keep config outside the registry.
func ConfigFor(id string) Config {
	cfg := Config{}
	if TestOverrides != nil {
		if override, ok := TestOverrides[id]; ok {
			for k, v := range override {
				cfg[k] = v
			}
			return cfg
		}
	}
	for k, v := range RegistryOAuth(id) {
		cfg[k] = v
	}
	switch id {
	case "xai":
		// XAI_CONFIG: clientId lives on the registry transport block.
		if raw := RegistryRaw("xai"); raw != nil {
			if t, ok := raw["transport"].(map[string]any); ok {
				cfg["clientId"] = strOf(t, "clientId")
				if cfg.Str("tokenUrl") == "" {
					cfg["tokenUrl"] = strOf(t, "tokenUrl")
				}
			}
		}
		cfg["discoveryUrl"] = XAIDiscoveryURL
		cfg["scope"] = XAIScope
	case "gemini-cli":
		cfg["clientId"] = GoogleOAuthClient.ClientID
		cfg["clientSecret"] = GoogleOAuthClient.ClientSecret
	case "antigravity":
		cfg["clientId"] = AntigravityOAuthClient.ClientID
		cfg["clientSecret"] = AntigravityOAuthClient.ClientSecret
	case "trae":
		cfg["loginGuidanceUrl"] = TraeLoginGuidanceURL
		cfg["tokenUrl"] = TraeExchangeTokenURL
		cfg["exchangeTokenUrl"] = TraeExchangeTokenURL
		cfg["userInfoUrl"] = TraeUserInfoURL
		if cfg.Str("clientId") == "" {
			cfg["clientId"] = TraeClientID
		}
		cfg["platform"] = TraePlatform
	case "windsurf":
		cfg["signinUrl"] = WindsurfSignInURL
		cfg["registerUrl"] = WindsurfRegisterURL
		cfg["firebaseSignInUrl"] = WindsurfFirebaseURL
	case "nous":
		if cfg.Str("clientId") == "" {
			cfg["clientId"] = NousClientID
		}
		if cfg.Str("scope") == "" && len(cfg.StrList("scopes")) == 0 {
			cfg["scope"] = NousScope
		}
	case "kimi":
		// JS: PROVIDER_OAUTH["kimi"].clientId, env KIMI_OAUTH_CLIENT_ID wins.
		if env := strings.TrimSpace(os.Getenv("KIMI_OAUTH_CLIENT_ID")); env != "" {
			cfg["clientId"] = env
		}
	}
	return cfg
}
