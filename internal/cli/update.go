package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"proxygo/internal/selfupdate"
)

// Update check. The JS checks the npm registry
// (registry.npmjs.org/<pkg>/latest) because the JS CLI ships via npm.
// The Go build is not published to npm, so the port checks the
// project's GitHub releases instead — the release channel a Go binary
// is actually distributed through. Same contract as the JS: any
// failure (offline, timeout, bad payload) silently means "no update";
// --skip-update skips the check entirely.

var updateReleaseURL = "https://api.github.com/repos/TheOwlOps/proxygo/releases/latest"

var updateHTTPClient = &http.Client{Timeout: 3 * time.Second}

// latestReleaseVersion returns the newest released version (tag_name
// without a leading "v"), or "" on any failure.
func latestReleaseVersion() string {
	req, err := http.NewRequest("GET", updateReleaseURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "proxygo-cli/"+Version)
	resp, err := updateHTTPClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return ""
	}
	var data struct {
		TagName string `json:"tag_name"`
	}
	if json.Unmarshal(raw, &data) != nil {
		return ""
	}
	return strings.TrimPrefix(strings.TrimSpace(data.TagName), "v")
}

// cmdUpdate implements `proxygo-cli update` (Feature F5): check the
// GitHub Releases feed via internal/selfupdate and, when a newer
// release ships an asset for this platform, download it (sha256-
// verified against the release's checksums.txt when present) and
// swap it over the SERVER binary resolved through the launcher's
// usual chain (findServerBinary). The running server, if any, keeps
// its old binary until restarted — `stop` + `start` (or the tray)
// picks the new one up.
func cmdUpdate(args []string, stdout, stderr io.Writer) int {
	serverFlag := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--server":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "Missing value for --server")
				return 1
			}
			i++
			serverFlag = args[i]
		case "-h", "--help":
			fmt.Fprint(stdout, updateHelp)
			return 0
		default:
			fmt.Fprintf(stderr, "Unknown option: %s\n", args[i])
			return 1
		}
	}
	target, err := findServerBinary(serverFlag)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	selfupdate.CurrentVersion = Version
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	info, err := selfupdate.Check(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "Update check failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Server binary: %s\nCurrent version: %s\nLatest release: %s\n", target, info.Current, info.Version)
	if !info.UpdateAvailable {
		fmt.Fprintln(stdout, "Already up to date.")
		return 0
	}
	if !info.Compatible {
		fmt.Fprintf(stderr, "Version %s is available, but the release ships no %s asset — self-update is not possible from this release.\n", info.Version, selfupdate.AssetName())
		return 1
	}
	fmt.Fprintf(stdout, "Downloading %s…\n", info.AssetName)
	if err := selfupdate.Apply(ctx, info, target); err != nil {
		fmt.Fprintf(stderr, "Update failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Updated to %s. Restart the server (stop + start) to run the new version.\n", info.Version)
	return 0
}

const updateHelp = `Usage: proxygo-cli update [--server <path>]

Check GitHub Releases for a newer ProxyGo and replace the server
binary in place (sha256-verified when the release has checksums.txt).
The server binary is located with the usual chain: --server, then
$PROXYGO_SERVER_BIN, a sibling binary, PATH, <dataDir>/bin.
`

// newerVersionAvailable reports the newer version, if any.
func newerVersionAvailable() (string, bool) {
	latest := latestReleaseVersion()
	if latest == "" {
		return "", false
	}
	if CompareVersions(latest, Version) > 0 {
		return latest, true
	}
	return "", false
}
