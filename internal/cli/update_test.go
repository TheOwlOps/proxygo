package cli

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeReleaseFeed serves a minimal GitHub latest-release payload for
// cmdUpdate tests. internal/selfupdate reads the API base + repo from
// the env overrides set here.
func fakeReleaseFeed(t *testing.T, tag string, assetsJSON string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"tag_name":%q,"assets":%s}`, tag, assetsJSON)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("PROXYGO_UPDATE_API", srv.URL)
	t.Setenv("PROXYGO_UPDATE_REPO", "test/repo")
}

func writeFakeServerBin(t *testing.T) string {
	t.Helper()
	target := filepath.Join(t.TempDir(), "proxygo")
	if err := os.WriteFile(target, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	return target
}

func TestCmdUpdateAlreadyUpToDate(t *testing.T) {
	fakeReleaseFeed(t, "v"+Version, "[]")
	target := writeFakeServerBin(t)
	var out, errBuf bytes.Buffer
	code := run([]string{"update", "--server", target}, &out, &errBuf, strings.NewReader(""))
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "Already up to date.") {
		t.Fatalf("stdout = %q", out.String())
	}
}

func TestCmdUpdateNewerButNoPlatformAsset(t *testing.T) {
	// A newer release whose only asset targets another platform.
	fakeReleaseFeed(t, "v9.9.9", `[{"name":"unrelated","browser_download_url":"http://127.0.0.1/x"}]`)
	target := writeFakeServerBin(t)
	var out, errBuf bytes.Buffer
	code := run([]string{"update", "--server", target}, &out, &errBuf, strings.NewReader(""))
	if code != 1 {
		t.Fatalf("code = %d, stdout = %s, stderr = %s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "no proxygo-") {
		t.Fatalf("stderr = %q", errBuf.String())
	}
}
