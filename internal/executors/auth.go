package executors

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Shared constants from open-sse/providers/shared.js.
const (
	anthropicAPIVersion = "2023-06-01" // ANTHROPIC_API_VERSION
	openAICompatBase    = "https://api.openai.com/v1"
	anthropicCompatBase = "https://api.anthropic.com/v1"
)

// Auth descriptors used as fallbacks (executors/default.js BEARER / XAPIKEY).
var (
	bearerAuth  = &AuthSpec{Combined: true, Header: "Authorization", Scheme: "bearer"}
	xAPIKeyAuth = &AuthSpec{Combined: true, Header: "x-api-key", Scheme: "raw", AnthropicVersion: true}
)

// setAuth applies a token to a header per scheme (default.js setAuth).
func setAuth(headers map[string]string, header, scheme, token string) {
	if scheme == "bearer" {
		headers[header] = "Bearer " + token
	} else {
		headers[header] = token
	}
}

// applyAuth resolves auth onto headers from a descriptor (default.js
// applyAuth). Legacy quirks preserved deliberately:
//   - combined descriptors ALWAYS set the header, even with no token — the
//     JS renders `Bearer ${undefined}` → the literal "Bearer undefined";
//     reproduced here so upstream behaviour matches the JS build byte-for-byte.
//   - split descriptors set only the branch matching the credential kind,
//     and skip entirely when both are absent.
func applyAuth(headers map[string]string, desc *AuthSpec, cred Credential) {
	if desc == nil {
		return
	}
	// Header hooks run BEFORE auth so dynamic overlays can't clobber the
	// token (default.js buildHeaders).
	for _, hook := range desc.Hooks {
		applyHeaderHook(hook, headers, cred)
	}
	if desc.Combined {
		token := cred.APIKey
		if token == "" {
			token = cred.AccessToken
		}
		if token == "" {
			token = "undefined" // legacy JS template rendering, see above
		}
		setAuth(headers, desc.Header, desc.Scheme, token)
		if desc.AnthropicVersion && headers["anthropic-version"] == "" {
			headers["anthropic-version"] = anthropicAPIVersion
		}
		return
	}
	if cred.APIKey != "" && desc.APIKey != nil {
		setAuth(headers, desc.APIKey.Header, desc.APIKey.Scheme, cred.APIKey)
	} else if cred.AccessToken != "" && desc.OAuth != nil {
		setAuth(headers, desc.OAuth.Header, desc.OAuth.Scheme, cred.AccessToken)
	}
	if desc.AnthropicVersion && headers["anthropic-version"] == "" {
		headers["anthropic-version"] = anthropicAPIVersion
	}
}

// resolveAuthDescriptor mirrors DefaultExecutor.resolveAuthDescriptor.
func resolveAuthDescriptor(providerID string, p *ProviderInfo) *AuthSpec {
	if strings.HasPrefix(providerID, "anthropic-compatible-") {
		return &AuthSpec{
			APIKey:           &AuthBranch{Header: "x-api-key", Scheme: "raw"},
			OAuth:            &AuthBranch{Header: "Authorization", Scheme: "bearer"},
			AnthropicVersion: true,
		}
	}
	if p != nil && p.Format == "claude" {
		return xAPIKeyAuth
	}
	return bearerAuth
}

// baseBuildHeaders is BaseExecutor.buildHeaders (base.js): Content-Type +
// config headers; anthropic-compatible-* uses x-api-key / Bearer + version,
// everything else prefers accessToken over apiKey; stream sets Accept.
func baseBuildHeaders(providerID string, req *Request) map[string]string {
	headers := map[string]string{"Content-Type": "application/json"}
	for k, v := range req.Provider.Headers {
		headers[k] = v
	}
	cred := req.Cred
	if strings.HasPrefix(providerID, "anthropic-compatible-") {
		if cred.APIKey != "" {
			headers["x-api-key"] = cred.APIKey
		} else if cred.AccessToken != "" {
			headers["Authorization"] = "Bearer " + cred.AccessToken
		}
		if headers["anthropic-version"] == "" {
			headers["anthropic-version"] = anthropicAPIVersion
		}
	} else {
		if cred.AccessToken != "" {
			headers["Authorization"] = "Bearer " + cred.AccessToken
		} else if cred.APIKey != "" {
			headers["Authorization"] = "Bearer " + cred.APIKey
		}
	}
	if req.Stream {
		headers["Accept"] = "text/event-stream"
	}
	return headers
}

// --- Header hooks (default.js HEADER_HOOKS) ---

func applyHeaderHook(name string, headers map[string]string, cred Credential) {
	switch name {
	case "kimiHeaders":
		for k, v := range buildKimiHeaders(cred.SpecificString("deviceId")) {
			headers[k] = v
		}
	case "minimaxHeaders":
		// MiniMax Code (default.js minimaxHeaders): placeholder x-api-key
		// rides next to the Bearer token + per-request session/timezone.
		headers["x-api-key"] = "sk-xxx"
		_, offset := time.Now().Zone()
		headers["X-Mavis-Timezone-Offset"] = strconv.Itoa(offset)
		if headers["X-Mavis-Session-Id"] == "" {
			headers["X-Mavis-Session-Id"] = newUUID()
		}
	case "museHeaders":
		// x-api-version only on subscription (minted key) requests.
		if cred.AccessToken != "" && cred.APIKey == "" {
			headers["x-api-version"] = "1.0.0"
		}
	case "clineHeaders":
		token := cred.APIKey
		if token == "" {
			token = cred.AccessToken
		}
		for k, v := range buildClineHeaders(token) {
			headers[k] = v
		}
	case "kilocodeOrg":
		if org := cred.SpecificString("orgId"); org != "" {
			headers["X-Kilocode-OrganizationID"] = org
		}
	}
}

// buildKimiHeaders ports config/appConstants.js buildKimiHeaders
// (X-Msh-* device identity headers; stable device_id from the connection).
func buildKimiHeaders(deviceID string) map[string]string {
	osName := runtime.GOOS
	arch := runtime.GOARCH
	deviceModel := osName + " " + arch
	switch osName {
	case "darwin":
		deviceModel = "macOS " + arch
	case "windows":
		deviceModel = "Windows " + arch
	case "linux":
		deviceModel = "Linux " + arch
	}
	deviceName, err := os.Hostname()
	if err != nil || deviceName == "" {
		deviceName = "unknown"
	}
	resolved := strings.TrimSpace(deviceID)
	if resolved == "" {
		resolved = "kimi-" + strconv.FormatInt(time.Now().UnixMilli(), 10)
	}
	return map[string]string{
		"X-Msh-Platform":     "9router",
		"X-Msh-Device-Name":  deviceName,
		"X-Msh-Device-Model": deviceModel,
		"X-Msh-Os-Version":   osName,
		"X-Msh-Device-Id":    resolved,
	}
}

// buildClineHeaders ports shared/clineAuth.js buildClineHeaders.
func buildClineHeaders(token string) map[string]string {
	// APP_VERSION in the JS is the dashboard version; kept as a constant
	// here — the parent may override via ProviderInfo headers.
	const appVersion = "0.5.104"
	headers := map[string]string{
		"HTTP-Referer":       "https://cline.bot",
		"X-Title":            "Cline",
		"User-Agent":         "9Router/" + appVersion,
		"X-PLATFORM":         runtime.GOOS,
		"X-PLATFORM-VERSION": "go",
		"X-CLIENT-TYPE":      "9router",
		"X-CLIENT-VERSION":   appVersion,
		"X-CORE-VERSION":     appVersion,
		"X-IS-MULTIROOT":     "false",
	}
	if token != "" {
		// getClineAuthorizationHeader: workos:-prefixed tokens pass through,
		// anything else is used as-is (Bearer added by cline's API).
		headers["Authorization"] = token
	}
	return headers
}

// mergeAnthropicBeta unions two comma-separated anthropic-beta lists
// (providers/shared.js mergeAnthropicBeta), preserving first-seen order.
func mergeAnthropicBeta(a, b string) string {
	seen := map[string]bool{}
	var out []string
	for _, src := range []string{a, b} {
		for _, f := range strings.Split(src, ",") {
			f = strings.TrimSpace(f)
			if f != "" && !seen[f] {
				seen[f] = true
				out = append(out, f)
			}
		}
	}
	return strings.Join(out, ",")
}
