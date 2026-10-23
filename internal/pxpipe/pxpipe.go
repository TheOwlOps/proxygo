// Package pxpipe supervises the pxpipe-proxy npm package installed under
// <dataDir>/pxpipe for the Go server.
//
// Investigation result (2026-10-23, against pxpipe-proxy@0.15.0 — the
// version `npm install pxpipe-proxy@latest` delivers):
//
//   - The 9Router JS server loads the package as an in-process library
//     (src/lib/pxpipe/loader.js imports dist/core/library.js and calls
//     transformAnthropicMessages). A Go binary cannot do that.
//   - BUT the package also ships a standalone server entry:
//     package.json "bin": { "pxpipe": "bin/cli.js" }, and bin/cli.js is a
//     shim that imports dist/node.js — a bundled Node HTTP proxy server
//     (listens on $PORT, default 47821, host $HOST default 127.0.0.1,
//     serves a dashboard on GET /, proxies Anthropic/OpenAI upstreams
//     with the same transform, and appends tracking events to the file
//     named by $PXPIPE_LOG).
//
// So the Go port runs that entry as a managed child process — the same
// pattern internal/api uses for the headroom python proxy (pid/state
// file, detached spawn, early-exit detection, SIGTERM→SIGKILL stop).
// Start points PXPIPE_LOG at <dir>/events.jsonl so the existing
// /api/pxpipe/stats and /logs handlers read the child's events with no
// change. "running" = child alive AND its dashboard port answering.
//
// Divergence from the JS (documented, deliberate): in JS, start/stop
// load/unload the transform module inside the gateway process and the
// chat pipeline calls it directly. In Go the transform lives in the
// child proxy process; the Go chat pipeline does not route through it
// (that wiring belongs to the token-saver integration, not this
// package). Node.js must be present — the pxpipe install step already
// requires npm, so this adds no new machine requirement.
package pxpipe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultPort is the pxpipe standalone server's own default port
// (dist/node.js: Number(process.env.PORT ?? 47821)).
const DefaultPort = 47821

// CodedError mirrors the { error, code } shape the pxpipe API routes
// return (src/lib/pxpipe + src/app/api/pxpipe/*).
type CodedError struct {
	Code string
	Msg  string
}

func (e *CodedError) Error() string { return e.Msg }

// State is the runner bookkeeping persisted in <dir>/runner.json.
type State struct {
	PID       int   `json:"pid"`
	Port      int   `json:"port"`
	StartedAt int64 `json:"startedAt"` // unix milliseconds
}

func statePath(dir string) string { return filepath.Join(dir, "runner.json") }

// LogPath is the child process stdout/stderr log.
func LogPath(dir string) string { return filepath.Join(dir, "proxy.log") }

// EventsPath is the events file the child appends to (PXPIPE_LOG) — the
// same file the stats/logs handlers aggregate.
func EventsPath(dir string) string { return filepath.Join(dir, "events.jsonl") }

// PackageRoot is where npm installed pxpipe-proxy.
func PackageRoot(dir string) string {
	return filepath.Join(dir, "node_modules", "pxpipe-proxy")
}

// ServerEntry is the standalone server entry (bin/cli.js → dist/node.js).
func ServerEntry(dir string) string { return filepath.Join(PackageRoot(dir), "bin", "cli.js") }

// LibraryEntry is the in-process transform module the JS loader imports.
func LibraryEntry(dir string) string {
	return filepath.Join(PackageRoot(dir), "dist", "core", "library.js")
}

// NodeServerBundle is dist/node.js, spawned via bin/cli.js.
func NodeServerBundle(dir string) string { return filepath.Join(PackageRoot(dir), "dist", "node.js") }

// FindNode locates a Node.js runtime. Mirrors the extended-PATH lookup
// the api package uses for npm (GUI-launched servers inherit a thin
// PATH on macOS).
func FindNode() string {
	env := os.Environ()
	for i, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			env[i] = "PATH=" + extendedPATH()
		}
	}
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("where", "node")
	} else {
		cmd = exec.Command("which", "node")
	}
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 {
		return ""
	}
	return strings.TrimSpace(lines[0])
}

func extendedPATH() string {
	if runtime.GOOS == "windows" {
		return os.Getenv("PATH")
	}
	return "/usr/local/bin:/opt/homebrew/bin:/usr/sbin:/usr/bin:/bin:/snap/bin:" + os.Getenv("PATH")
}

// LoadState reads runner.json and reports whether the recorded process
// is still alive. A stale state file is removed.
func LoadState(dir string) (State, bool) {
	var st State
	raw, err := os.ReadFile(statePath(dir))
	if err != nil || json.Unmarshal(raw, &st) != nil || st.PID <= 0 {
		return st, false
	}
	if !pidAlive(st.PID) {
		_ = os.Remove(statePath(dir))
		return st, false
	}
	return st, true
}

func writeState(dir string, st State) {
	_ = os.MkdirAll(dir, 0o755)
	raw, _ := json.Marshal(st)
	_ = os.WriteFile(statePath(dir), raw, 0o644)
}

func clearState(dir string) { _ = os.Remove(statePath(dir)) }

// Probe reports whether something answers HTTP on the pxpipe port
// (the standalone server serves its dashboard on GET /). The transport
// bypasses any proxy env: this is a loopback check.
func Probe(port int) bool {
	client := &http.Client{
		Timeout:   800 * time.Millisecond,
		Transport: &http.Transport{Proxy: nil},
	}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode < 400
}

// Running returns the live state when the child is alive and serving.
func Running(dir string) (State, bool) {
	st, ok := LoadState(dir)
	if !ok {
		return st, false
	}
	return st, Probe(st.Port)
}

var (
	procsMu sync.Mutex
	procs   = map[int]*exec.Cmd{}
)

// Start spawns the pxpipe standalone server as a detached child.
// Mirrors startHeadroomProxy: already-running is reported, an early
// exit is a coded EARLY_EXIT error.
func Start(dir string, port int) (State, bool, error) {
	if port <= 0 || port >= 65536 {
		port = DefaultPort
	}
	if st, ok := LoadState(dir); ok {
		return st, true, nil
	}
	node := FindNode()
	if node == "" {
		return State{}, false, &CodedError{Code: "NODE_NOT_FOUND", Msg: "Node.js runtime not found in PATH. Install Node.js to run PXPIPE."}
	}
	entry := ServerEntry(dir)
	if _, err := os.Stat(entry); err != nil {
		return State{}, false, &CodedError{Code: "NOT_INSTALLED", Msg: "PXPIPE is not installed"}
	}
	if _, err := os.Stat(NodeServerBundle(dir)); err != nil {
		return State{}, false, &CodedError{Code: "NOT_INSTALLED", Msg: "PXPIPE package is incomplete (dist/node.js missing) — reinstall it"}
	}
	_ = os.MkdirAll(dir, 0o755)
	logFile, err := os.OpenFile(LogPath(dir), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return State{}, false, err
	}
	defer logFile.Close()

	cmd := exec.Command(node, entry)
	cmd.Dir = PackageRoot(dir)
	cmd.Env = childEnv(dir, port)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = detachAttr()
	if err := cmd.Start(); err != nil {
		return State{}, false, &CodedError{Code: "SPAWN_FAILED", Msg: "Failed to spawn pxpipe proxy: " + err.Error()}
	}
	pid := cmd.Process.Pid
	procsMu.Lock()
	procs[pid] = cmd
	procsMu.Unlock()
	st := State{PID: pid, Port: port, StartedAt: time.Now().UnixMilli()}
	writeState(dir, st)

	exitCh := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		procsMu.Lock()
		delete(procs, pid)
		procsMu.Unlock()
		exitCh <- err
	}()

	// Ready when the dashboard port answers; early exit is an error.
	deadline := time.Now().Add(10 * time.Second)
	for {
		select {
		case err := <-exitCh:
			clearState(dir)
			code := 0
			if exitErr, ok := err.(*exec.ExitError); ok {
				code = exitErr.ExitCode()
			}
			return State{}, false, &CodedError{Code: "EARLY_EXIT", Msg: fmt.Sprintf("pxpipe proxy exited early (code=%d) — see proxy.log", code)}
		default:
		}
		if Probe(port) {
			return st, false, nil
		}
		if time.Now().After(deadline) {
			if !pidAlive(pid) {
				clearState(dir)
				return State{}, false, &CodedError{Code: "EARLY_EXIT", Msg: "pxpipe proxy exited during startup — see proxy.log"}
			}
			// Alive but slow to open the port: report started; status
			// probes will tell the truth (headroom does the same).
			return st, false, nil
		}
		time.Sleep(150 * time.Millisecond)
	}
}

// Stop terminates the managed child (SIGTERM, then SIGKILL after a
// grace period — the server handles SIGTERM gracefully). Reports
// whether anything was running.
func Stop(dir string) (bool, error) {
	st, ok := LoadState(dir)
	if !ok {
		clearState(dir)
		return false, nil
	}
	terminateProcess(st.PID, false)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && pidAlive(st.PID) {
		time.Sleep(100 * time.Millisecond)
	}
	if pidAlive(st.PID) {
		terminateProcess(st.PID, true)
		deadline = time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) && pidAlive(st.PID) {
			time.Sleep(100 * time.Millisecond)
		}
	}
	clearState(dir)
	return true, nil
}

// Restart stops the child if running and starts it again (picks up an
// upgraded install, like the JS unload+load).
func Restart(dir string, port int) (State, error) {
	if st, ok := LoadState(dir); ok {
		if port <= 0 {
			port = st.Port
		}
		if _, err := Stop(dir); err != nil {
			return State{}, err
		}
	}
	st, _, err := Start(dir, port)
	return st, err
}

// childEnv builds the child environment: inherit, but pin the three
// variables the standalone server reads for its bind + event log.
func childEnv(dir string, port int) []string {
	out := make([]string, 0, len(os.Environ())+3)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "PORT=") || strings.HasPrefix(kv, "HOST=") || strings.HasPrefix(kv, "PXPIPE_LOG=") {
			continue
		}
		out = append(out, kv)
	}
	return append(out,
		"PORT="+strconv.Itoa(port),
		"HOST=127.0.0.1",
		"PXPIPE_LOG="+EventsPath(dir),
	)
}

// ---------- self-test (JS loader.js selfTest equivalent) ----------

// SelfTestResult is the outcome of one synthetic transform run.
type SelfTestResult struct {
	OK         bool
	Reason     string
	DurationMs int64
}

// selfTestShim is written to <dir>/selftest.mjs and run with node: it
// performs exactly the JS selfTest — import the installed library and
// transform a tiny synthetic Claude request, printing one JSON line.
const selfTestShim = `import { pathToFileURL } from "node:url";
const lib = process.argv[2];
try {
  const mod = await import(pathToFileURL(lib).href);
  if (typeof mod.transformAnthropicMessages !== "function") {
    console.log(JSON.stringify({ ok: false, error: "installed pxpipe package does not export transformAnthropicMessages" }));
    process.exit(0);
  }
  const body = new TextEncoder().encode(JSON.stringify({
    model: "claude-fable-5",
    max_tokens: 16,
    messages: [{ role: "user", content: "ping" }],
  }));
  const startedAt = Date.now();
  const result = await mod.transformAnthropicMessages({ body, model: "claude-fable-5" });
  if (!result || typeof result.applied !== "boolean" || !(result.body instanceof Uint8Array)) {
    console.log(JSON.stringify({ ok: false, error: "transform returned an unexpected shape" }));
    process.exit(0);
  }
  console.log(JSON.stringify({ ok: true, reason: result.reason ?? null, durationMs: Date.now() - startedAt }));
} catch (e) {
  console.log(JSON.stringify({ ok: false, error: String((e && e.message) || e) }));
}
`

// SelfTest runs the JS health self-test against the installed package
// in a short-lived node process (the Go runtime cannot import the ESM
// library in-process). Fails with a plain error describing the cause.
func SelfTest(dir string, timeout time.Duration) (SelfTestResult, error) {
	node := FindNode()
	if node == "" {
		return SelfTestResult{}, &CodedError{Code: "NODE_NOT_FOUND", Msg: "Node.js runtime not found in PATH. Install Node.js to run PXPIPE."}
	}
	lib := LibraryEntry(dir)
	if _, err := os.Stat(lib); err != nil {
		return SelfTestResult{}, &CodedError{Code: "NOT_INSTALLED", Msg: "PXPIPE is not installed"}
	}
	shim := filepath.Join(dir, "selftest.mjs")
	if err := os.WriteFile(shim, []byte(selfTestShim), 0o644); err != nil {
		return SelfTestResult{}, err
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, shim, lib)
	cmd.Dir = PackageRoot(dir)
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return SelfTestResult{}, fmt.Errorf("pxpipe self-test timed out after %s", timeout)
		}
		return SelfTestResult{}, fmt.Errorf("pxpipe self-test failed to run: %w", err)
	}
	var line string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.TrimSpace(l) != "" {
			line = strings.TrimSpace(l)
		}
	}
	var parsed struct {
		OK         bool    `json:"ok"`
		Reason     *string `json:"reason"`
		DurationMs int64   `json:"durationMs"`
		Error      string  `json:"error"`
	}
	if err := json.Unmarshal([]byte(line), &parsed); err != nil {
		return SelfTestResult{}, fmt.Errorf("pxpipe self-test returned unparseable output: %q", line)
	}
	if !parsed.OK {
		msg := parsed.Error
		if msg == "" {
			msg = "unknown error"
		}
		return SelfTestResult{}, fmt.Errorf("%s", msg)
	}
	reason := ""
	if parsed.Reason != nil {
		reason = *parsed.Reason
	}
	return SelfTestResult{OK: true, Reason: reason, DurationMs: parsed.DurationMs}, nil
}
