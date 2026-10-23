// Package mitm is the Go port of src/mitm: a local HTTPS man-in-the-middle
// proxy that intercepts AI-tool traffic (Antigravity, Copilot, Kiro,
// Cursor) via /etc/hosts DNS entries pointing at 127.0.0.1 and a locally
// trusted root CA, rewriting model names through the dashboard's MITM
// alias map and forwarding chat requests to the 9Router gateway.
//
// Public API (used by the cli-tools antigravity-mitm routes, Team I):
//
//	mitm.InitDBHooks(getSettings, updateSettings)  // settings access
//	mitm.GetMitmStatus() map[string]any
//	mitm.StartServer(apiKey, sudoPassword string, forceKillPort443 bool) error
//	mitm.StopServer(sudoPassword string) error
//	mitm.EnableToolDNS(tool, sudoPassword string) error
//	mitm.DisableToolDNS(tool, sudoPassword string) error
//	mitm.TrustCert(sudoPassword string) error
//	mitm.GetCachedPassword() string / SetCachedPassword(string)
//	mitm.LoadEncryptedPassword() (string, error)
//	mitm.IsSudoPasswordRequired() bool
//	mitm.RestoreToolDNS() / RemoveAllDNSEntriesSync()
package mitm

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"9router-go/internal/db"
)

// Dir is $DATA_DIR/mitm (paths.js MITM_DIR).
func Dir() string { return filepath.Join(db.DataDir(), "mitm") }

func ensureDir() { _ = os.MkdirAll(Dir(), 0o755) }

func isWindows() bool { return runtime.GOOS == "windows" }
func isMac() bool     { return runtime.GOOS == "darwin" }

// TargetHosts (config.js TARGET_HOSTS).
var TargetHosts = []string{
	"daily-cloudcode-pa.googleapis.com",
	"cloudcode-pa.googleapis.com",
	"api.individual.githubcopilot.com",
	"q.us-east-1.amazonaws.com",
	"codewhisperer.us-east-1.amazonaws.com",
	"runtime.us-east-1.kiro.dev",
	"api2.cursor.sh",
}

// ToolHosts (shared/constants/mitmToolHosts.js TOOL_HOSTS).
var ToolHosts = map[string][]string{
	"antigravity": {"daily-cloudcode-pa.googleapis.com", "cloudcode-pa.googleapis.com"},
	"copilot":     {"api.individual.githubcopilot.com"},
	"kiro":        {"runtime.us-east-1.kiro.dev", "q.us-east-1.amazonaws.com", "codewhisperer.us-east-1.amazonaws.com"},
	"cursor":      {"api2.cursor.sh"},
}

// URLPatterns (config.js URL_PATTERNS).
var URLPatterns = map[string][]string{
	"antigravity": {":generateContent", ":streamGenerateContent"},
	"copilot":     {"/chat/completions", "/v1/messages", "/responses"},
	"kiro":        {"/generateAssistantResponse"},
	"cursor":      {"/BidiAppend", "/RunSSE", "/RunPoll", "/Run"},
}

// HostRewrite (server.js HOST_REWRITE).
var HostRewrite = map[string]string{
	"cloudcode-pa.googleapis.com": "daily-cloudcode-pa.googleapis.com",
}

// ToolForHost maps a host to its tool (config.js getToolForHost).
func ToolForHost(host string) string {
	for tool, hosts := range ToolHosts {
		for _, h := range hosts {
			if h == host {
				return tool
			}
		}
	}
	return ""
}

// IsChatRequest ports config.js isChatRequest (incl. the Kiro
// x-amz-target header match for IDE ≥ 1.0.228).
func IsChatRequest(tool, url string, header map[string]string) bool {
	for _, p := range URLPatterns[tool] {
		if contains(url, p) {
			return true
		}
	}
	if tool == "kiro" {
		return contains(header["x-amz-target"], "GenerateAssistantResponse")
	}
	return false
}

func contains(s, sub string) bool {
	return sub != "" && strings.Contains(s, sub)
}
