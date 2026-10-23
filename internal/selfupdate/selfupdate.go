// Package selfupdate implements real self-update for the standalone
// 9router Go binary against GitHub Releases (Feature F5).
//
// The JS original updates by spawning an npm updater (`npm install -g
// 9router`); a standalone Go binary has no npm package, so the update
// channel is the project's GitHub Releases feed instead — the same
// feed the CLI's update *check* already reads. A release is usable
// only when it ships an asset named
//
//	9router-go-<GOOS>-<GOARCH>[.exe]
//
// plus, optionally, a checksums.txt whose sha256 for that asset is
// verified before anything is swapped. Upstream releases at the time
// of writing ship NO Go assets, so Check reports Compatible:false and
// callers keep their previous behaviour; the mechanism activates the
// moment a release carries the assets.
//
// Configuration (env, read at call time):
//
//	NINEROUTER_UPDATE_API   API base, default https://api.github.com
//	NINEROUTER_UPDATE_REPO  owner/repo, default decolua/9router
package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// CurrentVersion is the running build's version. It defaults to the
// mirrored source version; the CLI overrides it with its own Version
// before calling Check when updating the server binary.
var CurrentVersion = "0.5.104"

// HTTPClient performs the feed + download requests (tests substitute
// a client pointed at an httptest server via the env override).
var HTTPClient = &http.Client{Timeout: 5 * time.Minute}

const (
	defaultAPIBase = "https://api.github.com"
	defaultRepo    = "decolua/9router"
	maxAssetBytes  = 512 << 20 // sanity cap for a server binary download
)

// Info describes the latest release relative to the current build.
type Info struct {
	// Version is the latest release version (tag without leading "v").
	Version string
	// Current is the version Check compared against.
	Current string
	// UpdateAvailable is Version > Current.
	UpdateAvailable bool
	// Compatible reports the release carries an asset for this
	// GOOS/GOARCH. False for today's upstream releases (no Go assets).
	Compatible bool
	// AssetName / AssetURL identify the platform asset, when found.
	AssetName string
	AssetURL  string
	// Checksum is the expected sha256 (hex) of the asset, taken from
	// the release's checksums.txt when the release provides one.
	// Empty means "release has no checksums.txt — download unverified".
	Checksum string
	// ChecksumsURL is where the checksums.txt asset lives, if any.
	ChecksumsURL string
}

// AssetName is the platform asset file name for the running build.
func AssetName() string {
	name := fmt.Sprintf("9router-go-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

func apiBase() string {
	if v := os.Getenv("NINEROUTER_UPDATE_API"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return defaultAPIBase
}

func repoSlug() string {
	if v := os.Getenv("NINEROUTER_UPDATE_REPO"); v != "" {
		return v
	}
	return defaultRepo
}

type releaseJSON struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// Check fetches the latest release and evaluates it against
// CurrentVersion. Network/shape failures return an error; a release
// that simply has no suitable asset is NOT an error (Compatible is
// false and the caller decides).
func Check(ctx context.Context) (Info, error) {
	url := fmt.Sprintf("%s/repos/%s/releases/latest", apiBase(), repoSlug())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Info{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "9router-selfupdate/"+CurrentVersion)
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return Info{}, fmt.Errorf("selfupdate: fetch latest release: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Info{}, fmt.Errorf("selfupdate: latest release: HTTP %d", resp.StatusCode)
	}
	var rel releaseJSON
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&rel); err != nil {
		return Info{}, fmt.Errorf("selfupdate: decode release: %w", err)
	}
	version := strings.TrimPrefix(strings.TrimSpace(rel.TagName), "v")
	info := Info{
		Version: version,
		Current: CurrentVersion,
	}
	info.UpdateAvailable = version != "" && CompareVersions(version, CurrentVersion) > 0

	want := AssetName()
	for _, a := range rel.Assets {
		switch a.Name {
		case want:
			info.Compatible = true
			info.AssetName = a.Name
			info.AssetURL = a.URL
		case "checksums.txt":
			info.ChecksumsURL = a.URL
		}
	}
	if info.Compatible && info.ChecksumsURL != "" {
		sum, err := fetchChecksum(ctx, info.ChecksumsURL, info.AssetName)
		if err != nil {
			return Info{}, err
		}
		info.Checksum = sum // "" when the file doesn't list our asset
	}
	return info, nil
}

// fetchChecksum downloads a sha256sum-format file and returns the hex
// digest recorded for assetName ("" when absent).
func fetchChecksum(ctx context.Context, url, assetName string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "9router-selfupdate/"+CurrentVersion)
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("selfupdate: fetch checksums: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("selfupdate: checksums: HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == assetName {
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", nil
}

// Apply downloads info's asset and swaps it into place at targetPath
// (default: the running executable). The download lands in a temp
// file beside the target; the original is only touched by the final
// swap, so a failed download or checksum leaves it untouched.
func Apply(ctx context.Context, info Info, targetPath string) error {
	if !info.Compatible || info.AssetURL == "" {
		return fmt.Errorf("selfupdate: release %s has no asset for this platform", info.Version)
	}
	target := targetPath
	if target == "" {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("selfupdate: locate executable: %w", err)
		}
		target = exe
	}
	abs, err := filepath.Abs(target)
	if err == nil {
		target = abs
	}
	dir := filepath.Dir(target)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, info.AssetURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "9router-selfupdate/"+CurrentVersion)
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("selfupdate: download asset: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("selfupdate: download asset: HTTP %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp(dir, ".9router-update-*")
	if err != nil {
		return fmt.Errorf("selfupdate: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful swap (renamed away)

	h := sha256.New()
	written, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, maxAssetBytes+1))
	if err != nil {
		tmp.Close()
		return fmt.Errorf("selfupdate: download asset: %w", err)
	}
	if written > maxAssetBytes {
		tmp.Close()
		return fmt.Errorf("selfupdate: asset exceeds %d bytes", maxAssetBytes)
	}
	if info.Checksum != "" {
		got := hex.EncodeToString(h.Sum(nil))
		if !strings.EqualFold(got, info.Checksum) {
			tmp.Close()
			return fmt.Errorf("selfupdate: checksum mismatch for %s (got %s, want %s)", info.AssetName, got, info.Checksum)
		}
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("selfupdate: sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("selfupdate: close temp file: %w", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(tmpName, 0o755); err != nil {
			return fmt.Errorf("selfupdate: chmod temp file: %w", err)
		}
	}
	if err := swapFile(tmpName, target); err != nil {
		return fmt.Errorf("selfupdate: swap into %s: %w", target, err)
	}
	return nil
}

// CompareVersions compares two semver-ish versions: 1 if a > b,
// -1 if a < b, 0 if equal. Numeric core components decide first; a
// version without a prerelease outranks the same core with one, and
// prerelease dot-parts compare numerically when both are numeric.
func CompareVersions(a, b string) int {
	ca, pa := splitVersion(a)
	cb, pb := splitVersion(b)
	for i := 0; i < 3; i++ {
		if ca[i] != cb[i] {
			if ca[i] > cb[i] {
				return 1
			}
			return -1
		}
	}
	if pa == pb {
		return 0
	}
	if pa == "" {
		return 1
	}
	if pb == "" {
		return -1
	}
	as := strings.Split(pa, ".")
	bs := strings.Split(pb, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		ai, aerr := strconv.Atoi(as[i])
		bi, berr := strconv.Atoi(bs[i])
		if aerr == nil && berr == nil {
			if ai != bi {
				if ai > bi {
					return 1
				}
				return -1
			}
			continue
		}
		if as[i] != bs[i] {
			if as[i] > bs[i] {
				return 1
			}
			return -1
		}
	}
	switch {
	case len(as) > len(bs):
		return 1
	case len(as) < len(bs):
		return -1
	}
	return 0
}

func splitVersion(v string) ([3]int, string) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	core, pre, _ := strings.Cut(v, "-")
	var out [3]int
	for i, s := range strings.Split(core, ".") {
		if i >= 3 {
			break
		}
		n, _ := strconv.Atoi(s)
		out[i] = n
	}
	return out, pre
}
