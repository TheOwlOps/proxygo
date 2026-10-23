package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

var testAssetBytes = []byte("fake-new-proxygo-binary-bytes")

func testAssetSum() string {
	h := sha256.Sum256(testAssetBytes)
	return hex.EncodeToString(h[:])
}

// fakeGitHub serves a /releases/latest payload built from the given
// tag and asset list, plus the asset + checksums downloads.
func fakeGitHub(t *testing.T, tag string, withAsset, withChecksums bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/repos/test/repo/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		assets := ""
		sep := ""
		if withAsset {
			assets += fmt.Sprintf(`{"name":%q,"browser_download_url":%q}`, AssetName(), srv.URL+"/dl/asset")
			sep = ","
		}
		if withChecksums {
			assets += sep + fmt.Sprintf(`{"name":"checksums.txt","browser_download_url":%q}`, srv.URL+"/dl/checksums.txt")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"tag_name":%q,"assets":[%s]}`, tag, assets)
	})
	mux.HandleFunc("/dl/asset", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(testAssetBytes)
	})
	mux.HandleFunc("/dl/checksums.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  %s\n%s  other-file\n", testAssetSum(), AssetName(), testAssetSum())
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	t.Setenv("PROXYGO_UPDATE_API", srv.URL)
	t.Setenv("PROXYGO_UPDATE_REPO", "test/repo")
	return srv
}

func withCurrent(t *testing.T, v string) {
	t.Helper()
	old := CurrentVersion
	CurrentVersion = v
	t.Cleanup(func() { CurrentVersion = old })
}

func TestCheckCompatibleNewer(t *testing.T) {
	fakeGitHub(t, "v0.6.0", true, true)
	withCurrent(t, "0.5.104")
	info, err := Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != "0.6.0" || !info.UpdateAvailable {
		t.Fatalf("info = %+v", info)
	}
	if !info.Compatible || info.AssetName != AssetName() || info.AssetURL == "" {
		t.Fatalf("compatible/asset wrong: %+v", info)
	}
	if info.Checksum != testAssetSum() {
		t.Fatalf("checksum = %q, want %q", info.Checksum, testAssetSum())
	}
}

func TestCheckIncompatibleNoAsset(t *testing.T) {
	// Today's real upstream shape: a newer release with no Go assets.
	fakeGitHub(t, "v0.6.0", false, false)
	withCurrent(t, "0.5.104")
	info, err := Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !info.UpdateAvailable || info.Compatible {
		t.Fatalf("info = %+v, want update available but incompatible", info)
	}
}

func TestCheckNotNewer(t *testing.T) {
	fakeGitHub(t, "v0.5.104", true, false)
	withCurrent(t, "0.5.104")
	info, err := Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.UpdateAvailable {
		t.Fatalf("same version must not be an update: %+v", info)
	}
	if !info.Compatible {
		t.Fatalf("asset presence is reported independent of freshness: %+v", info)
	}
}

func TestApplySwapsTempFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("byte-swap assertion exercised on unix; windows path is compile-guarded")
	}
	srv := fakeGitHub(t, "v0.6.0", true, true)
	withCurrent(t, "0.5.104")
	dir := t.TempDir()
	target := filepath.Join(dir, "proxygo")
	if err := os.WriteFile(target, []byte("old-binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	info := Info{
		Version:    "0.6.0",
		Compatible: true,
		AssetName:  AssetName(),
		AssetURL:   srv.URL + "/dl/asset",
		Checksum:   testAssetSum(),
	}
	if err := Apply(context.Background(), info, target); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(testAssetBytes) {
		t.Fatalf("target = %q, want the downloaded bytes", got)
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o111 == 0 {
		t.Fatalf("swapped binary not executable: mode %v", fi.Mode())
	}
}

func TestApplyTamperedChecksumLeavesOriginal(t *testing.T) {
	srv := fakeGitHub(t, "v0.6.0", true, false)
	dir := t.TempDir()
	target := filepath.Join(dir, "proxygo")
	if err := os.WriteFile(target, []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	info := Info{
		Version:    "0.6.0",
		Compatible: true,
		AssetName:  AssetName(),
		AssetURL:   srv.URL + "/dl/asset",
		Checksum:   "0000000000000000000000000000000000000000000000000000000000000000",
	}
	if err := Apply(context.Background(), info, target); err == nil {
		t.Fatal("tampered checksum must fail")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old-binary" {
		t.Fatalf("original modified on checksum failure: %q", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("temp file leaked: %v", entries)
	}
}

func TestApplyIncompatible(t *testing.T) {
	info := Info{Version: "0.6.0", Compatible: false}
	if err := Apply(context.Background(), info, filepath.Join(t.TempDir(), "x")); err == nil {
		t.Fatal("incompatible release must not apply")
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.6.0", "0.5.104", 1},
		{"v0.5.104", "0.5.104", 0},
		{"0.5.9", "0.5.104", -1},
		{"1.0.0", "0.9.9", 1},
		{"0.6.0-beta.1", "0.6.0", -1},
		{"0.6.0-beta.2", "0.6.0-beta.1", 1},
		{"0.6.0", "0.6.0-rc.1", 1},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
