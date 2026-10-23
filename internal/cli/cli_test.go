package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"9router-go/internal/db"
)

func runCapture(args ...string) (int, string, string) {
	var out, errBuf bytes.Buffer
	code := run(args, &out, &errBuf, strings.NewReader(""))
	return code, out.String(), errBuf.String()
}

func TestVersionForms(t *testing.T) {
	for _, args := range [][]string{{"--version"}, {"-v"}, {"version"}} {
		code, out, _ := runCapture(args...)
		if code != 0 || strings.TrimSpace(out) != Version {
			t.Fatalf("%v: code=%d out=%q, want version %q", args, code, out, Version)
		}
	}
	// JS cli/package.json version this port mirrors.
	if Version != "0.5.104" {
		t.Fatalf("Version=%q, want 0.5.104 (cli/package.json)", Version)
	}
}

func TestHelpListsCommandsAndJSFlags(t *testing.T) {
	code, out, _ := runCapture("--help")
	if code != 0 {
		t.Fatalf("help code=%d", code)
	}
	for _, want := range []string{"start", "stop", "status", "open", "tray", "reset-password", "--port", "--host", "--no-browser", "--log", "--skip-update", "http://localhost:20128/dashboard"} {
		if !strings.Contains(out, want) {
			t.Errorf("help missing %q", want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.5.104", "0.5.104", 0},
		{"0.5.105", "0.5.104", 1},
		{"0.5.103", "0.5.104", -1},
		{"1.0.0", "0.9.9", 1},
		{"0.6.0", "0.5.104", 1},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q,%q)=%d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestParseFlagsJSParity(t *testing.T) {
	opts, code, ok := parseFlags([]string{"-p", "8080", "-H", "127.0.0.1", "-n", "-l", "--skip-update"}, io.Discard, io.Discard)
	if !ok || code != 0 {
		t.Fatalf("parse failed ok=%v code=%d", ok, code)
	}
	if opts.Port != 8080 || opts.Host != "127.0.0.1" || !opts.NoBrowser || !opts.Log || !opts.SkipUpdate {
		t.Fatalf("unexpected opts: %+v", opts)
	}
	// JS: invalid port falls back to the default.
	opts, _, ok = parseFlags([]string{"--port", "abc"}, io.Discard, io.Discard)
	if !ok || opts.Port != DefaultPort {
		t.Fatalf("invalid port: ok=%v port=%d, want %d", ok, opts.Port, DefaultPort)
	}
	// Defaults match cli.js.
	d := defaultOptions()
	if d.Port != 20128 || d.Host != "0.0.0.0" {
		t.Fatalf("defaults %+v", d)
	}
}

func TestDisplayHost(t *testing.T) {
	if got := displayHost("0.0.0.0"); got != "localhost" {
		t.Errorf("displayHost(0.0.0.0)=%q, want localhost", got)
	}
	if got := displayHost("127.0.0.1"); got != "127.0.0.1" {
		t.Errorf("displayHost(127.0.0.1)=%q", got)
	}
	if got := dashboardURL(defaultOptions()); got != "http://localhost:20128/dashboard" {
		t.Errorf("dashboardURL=%q", got)
	}
}

func TestPidStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DATA_DIR", dir)
	want := pidState{PID: 4242, Port: 20128, Host: "0.0.0.0", Binary: "/bin/9router", StartedAt: "2026-10-23T00:00:00Z"}
	if err := writePidState(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "9router.pid")); err != nil {
		t.Fatalf("pid file missing: %v", err)
	}
	got, ok := readPidState()
	if !ok || got != want {
		t.Fatalf("read: ok=%v got=%+v want=%+v", ok, got, want)
	}
	removePidState()
	if _, ok := readPidState(); ok {
		t.Fatal("pid state still readable after remove")
	}
}

func TestFindServerBinary(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, serverBinaryName())
	if err := os.WriteFile(binPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Explicit path wins; missing explicit path errors.
	got, err := findServerBinary(binPath)
	if err != nil || got != binPath {
		t.Fatalf("explicit: got=%q err=%v", got, err)
	}
	if _, err := findServerBinary(filepath.Join(dir, "nope")); err == nil {
		t.Fatal("missing explicit path should error")
	}
	// Env var.
	t.Setenv("NINEROUTER_SERVER_BIN", binPath)
	got, err = findServerBinary("")
	if err != nil || got != binPath {
		t.Fatalf("env: got=%q err=%v", got, err)
	}
}

func TestStopAndStatusWhenNotRunning(t *testing.T) {
	t.Setenv("DATA_DIR", t.TempDir())
	code, out, _ := runCapture("stop")
	if code != 0 || !strings.Contains(out, "not running") {
		t.Fatalf("stop: code=%d out=%q", code, out)
	}
	code, out, _ = runCapture("status")
	if code != 1 || !strings.Contains(out, "not running") {
		t.Fatalf("status: code=%d out=%q", code, out)
	}
}

func TestTrayPrintsLimitation(t *testing.T) {
	t.Setenv("DATA_DIR", t.TempDir())
	t.Setenv("NINEROUTER_SERVER_BIN", filepath.Join(t.TempDir(), "missing-server"))
	// Tray must state the limitation before anything else; the start
	// then fails (no server binary in this env) which is fine here.
	var out, errBuf bytes.Buffer
	code := run([]string{"tray"}, &out, &errBuf, strings.NewReader(""))
	if !strings.Contains(out.String(), "system-tray ICON is not ported") {
		t.Fatalf("tray note missing, out=%q", out.String())
	}
	if code == 0 {
		t.Fatal("tray with missing server binary should fail")
	}
}

func TestResetPasswordClearsStoredHash(t *testing.T) {
	dir := t.TempDir()
	store, err := db.OpenInDir(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := store.UpdateSettings(db.Record{"password": "$2a$10$fakehashfakehashfakehashfakehashfakehashfa"}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	var out, errBuf bytes.Buffer
	if code := resetPasswordInDir(dir, &out, &errBuf); code != 0 {
		t.Fatalf("reset code=%d err=%q out=%q", code, errBuf.String(), out.String())
	}
	if !strings.Contains(out.String(), "reset to default") {
		t.Fatalf("unexpected reset output %q", out.String())
	}
	// The default literal must never be printed (JS route contract).
	if strings.Contains(out.String(), "123456") {
		t.Fatal("reset output leaked the default password literal")
	}

	store2, err := db.OpenInDir(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer store2.Close()
	settings, err := store2.GetSettings()
	if err != nil {
		t.Fatalf("get settings: %v", err)
	}
	if hash, _ := settings["password"].(string); hash != "" {
		t.Fatalf("password still set after reset: %q", hash)
	}

	// Second reset is a no-op success ("default already in effect").
	out.Reset()
	errBuf.Reset()
	if code := resetPasswordInDir(dir, &out, &errBuf); code != 0 {
		t.Fatalf("second reset code=%d", code)
	}
	if !strings.Contains(out.String(), "already in effect") {
		t.Fatalf("second reset output %q", out.String())
	}
}

func TestBareXaiPrintsVideoHelp(t *testing.T) {
	// `xai` without the `video` subcommand prints the video help and
	// exits 1 (connect/show/xai video themselves are real commands —
	// see commands_test.go).
	code, out, errOut := runCapture("xai")
	if code != 1 || !strings.Contains(out, "xai video") || !strings.Contains(errOut, "Usage:") {
		t.Fatalf("bare xai: code=%d out=%q err=%q", code, out, errOut)
	}
}
