package tunnel

import (
	"strings"
	"testing"

	"9router-go/internal/db"
)

func TestStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DATA_DIR", dir)
	if got := LoadState(); got != nil {
		t.Fatalf("expected nil state, got %v", got)
	}
	SaveState(db.Record{"shortId": "abc123", "tunnelUrl": "https://x.trycloudflare.com"})
	got := LoadState()
	if got == nil || got["shortId"] != "abc123" || got["tunnelUrl"] != "https://x.trycloudflare.com" {
		t.Fatalf("state mismatch: %v", got)
	}
	ClearState()
	if got := LoadState(); got != nil {
		t.Fatalf("expected cleared state, got %v", got)
	}
}

func TestGenerateShortId(t *testing.T) {
	const charset = "abcdefghijklmnpqrstuvwxyz23456789"
	for i := 0; i < 50; i++ {
		id := GenerateShortId()
		if len(id) != 6 {
			t.Fatalf("shortId length = %d", len(id))
		}
		for _, c := range id {
			if !strings.ContainsRune(charset, c) {
				t.Fatalf("shortId char %q outside charset", c)
			}
		}
	}
}

func TestQuickTunnelURLFromLog(t *testing.T) {
	log := "INF https://api.trycloudflare.com is the api\n" +
		"INF |  https://first-one.trycloudflare.com  |\n" +
		"INF |  https://second-two.trycloudflare.com  |\n"
	if got := quickTunnelURLFromLog(log); got != "https://second-two.trycloudflare.com" {
		t.Fatalf("got %q", got)
	}
	if got := quickTunnelURLFromLog("nothing here"); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestStatusShapesEmpty(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DATA_DIR", dir)
	store, err := db.OpenInDir(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	st, err := GetTunnelStatus(store)
	if err != nil {
		t.Fatalf("tunnel status: %v", err)
	}
	if st["enabled"] != false || st["running"] != false || st["settingsEnabled"] != false {
		t.Fatalf("tunnel status = %v", st)
	}
	if _, ok := st["shortId"]; !ok {
		t.Fatalf("tunnel status missing shortId: %v", st)
	}
	dl := GetDownloadStatus()
	if dl["downloading"] != false {
		t.Fatalf("download status = %v", dl)
	}

	ts, err := GetTailscaleStatus(store)
	if err != nil {
		t.Fatalf("tailscale status: %v", err)
	}
	if ts["enabled"] != false || ts["settingsEnabled"] != false {
		t.Fatalf("tailscale status = %v", ts)
	}
}

func TestPublicURLFromState(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DATA_DIR", dir)
	store, err := db.OpenInDir(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if _, err := store.UpdateSettings(db.Record{"tunnelEnabled": true}); err != nil {
		t.Fatalf("settings: %v", err)
	}
	SaveState(db.Record{"shortId": "zz42ab", "tunnelUrl": "https://x.trycloudflare.com"})
	st, err := GetTunnelStatus(store)
	if err != nil {
		t.Fatalf("tunnel status: %v", err)
	}
	if st["publicUrl"] != "https://rzz42ab.abc-tunnel.us" {
		t.Fatalf("publicUrl = %v", st["publicUrl"])
	}
	if st["shortId"] != "zz42ab" {
		t.Fatalf("shortId = %v", st["shortId"])
	}
}
