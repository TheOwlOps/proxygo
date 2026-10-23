package pxpipe

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakePackage installs a minimal stand-in for pxpipe-proxy into dir:
// bin/cli.js imports dist/node.js (a tiny HTTP server on $PORT, like
// the real bundled entry) and dist/core/library.js exports a
// transformAnthropicMessages with the real result shape.
func fakePackage(t *testing.T, dir string) {
	t.Helper()
	root := PackageRoot(dir)
	files := map[string]string{
		"package.json": `{"name":"pxpipe-proxy","version":"0.15.0"}`,
		"bin/cli.js":   `import("../dist/node.js");`,
		"dist/node.js": `
import { createServer } from "node:http";
const port = Number(process.env.PORT ?? 47821);
createServer((req, res) => {
  res.writeHead(200, { "content-type": "text/html" });
  res.end("<html>pxpipe dashboard</html>");
}).listen(port, "127.0.0.1");
`,
		"dist/core/library.js": `
export async function transformAnthropicMessages({ body, model }) {
  return { applied: false, reason: "below_threshold", body };
}
`,
	}
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	// Bind :0 via a throwaway node? Simpler: use a high fixed port
	// derived from the test pid to avoid collisions across runs.
	return 49000 + (os.Getpid() % 1000)
}

func TestRunnerLifecycle(t *testing.T) {
	if FindNode() == "" {
		t.Skip("node not available")
	}
	dir := t.TempDir()
	fakePackage(t, dir)
	port := freePort(t)

	st, already, err := Start(dir, port)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if already {
		t.Fatal("first start reported alreadyRunning")
	}
	if st.PID <= 0 || st.Port != port || st.StartedAt <= 0 {
		t.Fatalf("state = %+v", st)
	}
	if !Probe(port) {
		t.Fatal("port not answering after start")
	}
	if _, ok := Running(dir); !ok {
		t.Fatal("Running() = false while child is up")
	}

	// Second start is a no-op reporting the same pid.
	st2, already, err := Start(dir, port)
	if err != nil || !already || st2.PID != st.PID {
		t.Fatalf("second start: %+v already=%v err=%v", st2, already, err)
	}

	stopped, err := Stop(dir)
	if err != nil || !stopped {
		t.Fatalf("stop: stopped=%v err=%v", stopped, err)
	}
	if Probe(port) {
		t.Fatal("port still answering after stop")
	}
	if _, ok := LoadState(dir); ok {
		t.Fatal("state still present after stop")
	}
	stopped, err = Stop(dir)
	if err != nil || stopped {
		t.Fatalf("second stop: stopped=%v err=%v", stopped, err)
	}

	// Restart from stopped, then restart while running.
	st3, err := Restart(dir, port)
	if err != nil {
		t.Fatalf("restart(stopped): %v", err)
	}
	st4, err := Restart(dir, port)
	if err != nil {
		t.Fatalf("restart(running): %v", err)
	}
	if st4.PID == st3.PID {
		t.Fatal("restart while running kept the same pid")
	}
	if _, err := Stop(dir); err != nil {
		t.Fatalf("final stop: %v", err)
	}
}

func TestStartNotInstalledAndEarlyExit(t *testing.T) {
	if FindNode() == "" {
		t.Skip("node not available")
	}
	dir := t.TempDir()
	_, _, err := Start(dir, freePort(t))
	if ce, ok := err.(*CodedError); !ok || ce.Code != "NOT_INSTALLED" {
		t.Fatalf("start without package: err=%v, want NOT_INSTALLED", err)
	}

	// Package whose server exits immediately → EARLY_EXIT.
	fakePackage(t, dir)
	nodeJS := filepath.Join(PackageRoot(dir), "dist", "node.js")
	if err := os.WriteFile(nodeJS, []byte("process.exit(3);\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err = Start(dir, freePort(t))
	if ce, ok := err.(*CodedError); !ok || ce.Code != "EARLY_EXIT" {
		t.Fatalf("start with crashing server: err=%v, want EARLY_EXIT", err)
	}
	if _, ok := LoadState(dir); ok {
		t.Fatal("state kept after early exit")
	}
}

func TestSelfTestAgainstFakeLibrary(t *testing.T) {
	if FindNode() == "" {
		t.Skip("node not available")
	}
	dir := t.TempDir()
	fakePackage(t, dir)
	res, err := SelfTest(dir, 15*time.Second)
	if err != nil {
		t.Fatalf("selftest: %v", err)
	}
	if !res.OK || res.Reason != "below_threshold" {
		t.Fatalf("selftest = %+v", res)
	}

	// A library that throws must surface as an error, not a pass.
	lib := LibraryEntry(dir)
	if err := os.WriteFile(lib, []byte("export async function transformAnthropicMessages() { throw new Error('boom'); }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := SelfTest(dir, 15*time.Second); err == nil || err.Error() != "boom" {
		t.Fatalf("selftest with throwing library: err=%v", err)
	}

	// Missing export is an error too.
	if err := os.WriteFile(lib, []byte("export const x = 1;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := SelfTest(dir, 15*time.Second); err == nil {
		t.Fatal("selftest with missing export should error")
	}
}

func TestSelfTestNotInstalled(t *testing.T) {
	if FindNode() == "" {
		t.Skip("node not available")
	}
	_, err := SelfTest(t.TempDir(), 5*time.Second)
	if ce, ok := err.(*CodedError); !ok || ce.Code != "NOT_INSTALLED" {
		t.Fatalf("err=%v, want NOT_INSTALLED", err)
	}
}
