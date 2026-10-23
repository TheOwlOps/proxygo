package oauthsvc

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Auto-import source readers: the local credential stores the
// {cursor,kiro,zed,xiaomi-mimo}/auto-import routes scan. Ported from the
// respective route files + src/lib/oauth/utils/zedCredentials.js.

// ---- Kiro SSO cache (~/.aws/sso/cache) ----

// KiroSSOCacheCandidate is one usable token file from the SSO cache.
type KiroSSOCacheCandidate struct {
	FilePath     string
	RefreshToken string
	ClientID     string // from the clientIdHash-named registration file match
	ClientSecret string
	Region       string
	ProfileARN   string
}

// ScanKiroSSOCache ports the kiro/auto-import scan: token JSON files whose
// refreshToken starts with the Kiro prefix, kiro-auth-token.json preferred,
// plus the client registration (matched by clientIdHash filename) and the
// profile.json ARN/region.
func ScanKiroSSOCache() (*KiroSSOCacheCandidate, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	cacheDir := filepath.Join(home, ".aws", "sso", "cache")
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return nil, errf("Kiro SSO cache not found")
	}
	readJSON := func(path string) map[string]any {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var m map[string]any
		if json.Unmarshal(raw, &m) != nil {
			return nil
		}
		return m
	}
	var tokenFile string
	var tokenData map[string]any
	// kiro-auth-token.json first, then any other cache file.
	names := []string{}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	ordered := []string{}
	for _, n := range names {
		if n == "kiro-auth-token.json" {
			ordered = append([]string{n}, ordered...)
		} else {
			ordered = append(ordered, n)
		}
	}
	for _, name := range ordered {
		data := readJSON(filepath.Join(cacheDir, name))
		if data == nil {
			continue
		}
		if rt := strOf(data, "refreshToken"); strings.HasPrefix(rt, kiroAPIKeyPrefix) {
			tokenFile = filepath.Join(cacheDir, name)
			tokenData = data
			break
		}
	}
	if tokenData == nil {
		return nil, errf("No Kiro token found in SSO cache")
	}
	cand := &KiroSSOCacheCandidate{
		FilePath:     tokenFile,
		RefreshToken: strOf(tokenData, "refreshToken"),
		Region:       "us-east-1",
	}
	// Client registration: file named by clientIdHash, or any registration
	// JSON carrying clientId/clientSecret.
	for _, name := range names {
		data := readJSON(filepath.Join(cacheDir, name))
		if data == nil {
			continue
		}
		if cid, secret := strOf(data, "clientId"), strOf(data, "clientSecret"); cid != "" && secret != "" {
			// Prefer the file whose name matches the sha256(clientId) hash.
			base := strings.TrimSuffix(name, filepath.Ext(name))
			if base == KiroClientIDHash(cid) || strings.Contains(name, "registration") || strings.Contains(name, "client") {
				cand.ClientID, cand.ClientSecret = cid, secret
				if r := strOf(data, "region"); r != "" {
					cand.Region = r
				}
				break
			}
			if cand.ClientID == "" {
				cand.ClientID, cand.ClientSecret = cid, secret
			}
		}
	}
	// profile.json (in the cache dir or ~/.kiro) carries the profile ARN.
	for _, p := range []string{
		filepath.Join(cacheDir, "profile.json"),
		filepath.Join(home, ".kiro", "profile.json"),
	} {
		if data := readJSON(p); data != nil {
			if arn := firstStr(strOf(data, "arn"), strOf(data, "profileArn")); arn != "" {
				cand.ProfileARN = arn
			}
		}
	}
	return cand, nil
}

// ---- Xiaomi MiMo auth.json ----

// XiaomiAuthFile is the parsed mimocode auth.json credential.
type XiaomiAuthFile struct {
	Path     string
	APIKey   string
	UID      string
	BaseURL  string
	Provider string // "xiaomi" entry key in the file
}

// XiaomiAuthJSONCandidates lists the auth.json locations per platform.
func XiaomiAuthJSONCandidates() []string {
	home, _ := os.UserHomeDir()
	paths := []string{filepath.Join(home, ".local", "share", "mimocode", "auth.json")}
	if appData := os.Getenv("APPDATA"); appData != "" {
		paths = append(paths, filepath.Join(appData, "Xiaomi MiMo", "auth.json"))
	}
	paths = append(paths,
		filepath.Join(home, "Library", "Application Support", "mimocode", "auth.json"),
		filepath.Join(home, "AppData", "Roaming", "Xiaomi MiMo", "auth.json"),
	)
	return paths
}

// ScanXiaomiAuthJSON ports the xiaomi-mimo/auto-import file scan.
func ScanXiaomiAuthJSON() (*XiaomiAuthFile, error) {
	for _, p := range XiaomiAuthJSONCandidates() {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var root map[string]any
		if json.Unmarshal(raw, &root) != nil {
			continue
		}
		entry, _ := root["xiaomi"].(map[string]any)
		if entry == nil {
			continue
		}
		key := strOf(entry, "key")
		if key == "" {
			continue
		}
		out := &XiaomiAuthFile{Path: p, APIKey: key, Provider: "xiaomi"}
		if meta, ok := entry["metadata"].(map[string]any); ok {
			out.UID = strOf(meta, "uid")
			out.BaseURL = strOf(meta, "base_url")
		}
		return out, nil
	}
	return nil, errf("Xiaomi MiMo auth.json not found")
}

// ---- Zed IDE credentials (OS keyring + kv_store system_id) ----

// ZedGlobalDBPaths ports getZedGlobalDbPaths.
func ZedGlobalDBPaths() []string {
	home, _ := os.UserHomeDir()
	channels := []string{"0-global", "0-stable", "0-preview"}
	var base string
	switch runtime.GOOS {
	case "darwin":
		base = filepath.Join(home, "Library", "Application Support", "Zed", "db")
	case "windows":
		local := os.Getenv("LOCALAPPDATA")
		if local == "" {
			local = filepath.Join(home, "AppData", "Local")
		}
		base = filepath.Join(local, "Zed", "db")
	default:
		xdg := os.Getenv("XDG_DATA_HOME")
		if xdg == "" {
			xdg = filepath.Join(home, ".local", "share")
		}
		base = filepath.Join(xdg, "zed", "db")
	}
	out := []string{}
	for _, c := range channels {
		out = append(out, filepath.Join(base, c, "db.sqlite"))
	}
	return out
}

// ReadZedSystemID ports readZedSystemId.
func ReadZedSystemID() string {
	for _, p := range ZedGlobalDBPaths() {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if v, err := ReadSQLiteKVStore(p, "system_id"); err == nil && v != "" {
			return v
		}
	}
	return ""
}

// ZedCredentials is readZedIdeCredentials' return shape.
type ZedCredentials struct {
	Found       bool
	UserID      string
	AccessToken string
	SystemID    string
	Error       string
}

// ReadZedIDECredentials ports readZedIdeCredentials. Linux reads the
// libsecret keyring via secret-tool; macOS the login Keychain via
// `security`. Windows Credential Manager has no stdlib Go equivalent —
// the JS shells to a PowerShell vault snippet; this port reports the gap
// instead of pretending (see the team report).
func ReadZedIDECredentials() ZedCredentials {
	var userID, accessToken, readErr string
	switch runtime.GOOS {
	case "linux":
		userID, accessToken, readErr = zedKeyringLinux()
	case "darwin":
		userID, accessToken, readErr = zedKeyringDarwin()
	case "windows":
		readErr = "Zed auto-import on Windows needs Credential Manager access (not ported — see report)"
	default:
		readErr = "Zed auto-import is not supported on platform " + runtime.GOOS
	}
	if userID == "" || accessToken == "" {
		if readErr == "" {
			readErr = "Zed IDE session not found in the system keyring. Sign in to Zed, then retry."
		}
		return ZedCredentials{Found: false, Error: readErr}
	}
	systemID := ReadZedSystemID()
	if systemID == "" {
		systemID = newUUID()
	}
	return ZedCredentials{Found: true, UserID: userID, AccessToken: accessToken, SystemID: systemID}
}

// The Zed keyring secret is a JSON blob {"user_id":…,"access_token":…}
// (newer builds) or "userId:accessToken". Both shapes are accepted.
func parseZedKeyringSecret(secret string) (string, string) {
	trimmed := strings.TrimSpace(secret)
	if strings.HasPrefix(trimmed, "{") {
		var m map[string]any
		if json.Unmarshal([]byte(trimmed), &m) == nil {
			uid := firstStr(strOf(m, "user_id"), strOf(m, "userId"))
			tok := firstStr(strOf(m, "access_token"), strOf(m, "accessToken"))
			if uid != "" && tok != "" {
				return uid, tok
			}
		}
	}
	if i := strings.Index(trimmed, ":"); i > 0 {
		return strings.TrimSpace(trimmed[:i]), strings.TrimSpace(trimmed[i+1:])
	}
	return "", ""
}

func zedKeyringLinux() (string, string, string) {
	if _, err := exec.LookPath("secret-tool"); err != nil {
		return "", "", "secret-tool not found (install libsecret / secret-tools)"
	}
	for _, args := range [][]string{
		{"lookup", "service", "https://zed.dev"},
		{"lookup", "label", "zed-github-account"},
		{"lookup", "service", "zed"},
	} {
		out, err := exec.Command("secret-tool", args...).Output()
		if err == nil && len(out) > 0 {
			if uid, tok := parseZedKeyringSecret(string(out)); uid != "" {
				return uid, tok, ""
			}
		}
	}
	return "", "", ""
}

func zedKeyringDarwin() (string, string, string) {
	out, err := exec.Command("security", "find-generic-password", "-s", "https://zed.dev", "-w").Output()
	if err != nil {
		return "", "", ""
	}
	uid, tok := parseZedKeyringSecret(string(out))
	return uid, tok, ""
}
