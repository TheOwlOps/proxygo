package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"proxygo/internal/db"
)

// pidState is the Go CLI's own bookkeeping for the server it started:
// <dataDir>/proxygo.pid (JSON). The JS launcher tracks no pid file for
// the main server (it kills processes by name scan instead); the pid
// file is what lets the Go port implement stop/status safely.
type pidState struct {
	PID       int    `json:"pid"`
	Port      int    `json:"port"`
	Host      string `json:"host"`
	Binary    string `json:"binary"`
	StartedAt string `json:"startedAt"`
}

func pidFilePath() string { return filepath.Join(db.DataDir(), "proxygo.pid") }

func writePidState(st pidState) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(pidFilePath()), 0o755); err != nil {
		return err
	}
	return os.WriteFile(pidFilePath(), b, 0o644)
}

func readPidState() (pidState, bool) {
	var st pidState
	b, err := os.ReadFile(pidFilePath())
	if err != nil || json.Unmarshal(b, &st) != nil || st.PID <= 0 {
		return st, false
	}
	return st, true
}

func removePidState() { _ = os.Remove(pidFilePath()) }

// executablePath is overridable in tests.
var executablePath = os.Executable

// serverBinaryName is the Go server artifact (cmd/proxygo).
func serverBinaryName() string {
	if runtime.GOOS == "windows" {
		return "proxygo.exe"
	}
	return "proxygo"
}

// findServerBinary locates the Go server binary. This is the documented
// adaptation of the JS "bundled app/server.js next to cli.js" model:
//  1. explicit --server path
//  2. $PROXYGO_SERVER_BIN
//  3. a `proxygo` binary next to the CLI executable
//  4. `proxygo` on PATH (never the CLI executable itself)
//  5. <dataDir>/bin/proxygo
func findServerBinary(explicit string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", fmt.Errorf("server binary not found at %s", explicit)
		}
		return explicit, nil
	}
	if env := os.Getenv("PROXYGO_SERVER_BIN"); env != "" {
		if _, err := os.Stat(env); err == nil {
			return env, nil
		}
		return "", fmt.Errorf("server binary not found at PROXYGO_SERVER_BIN=%s", env)
	}
	name := serverBinaryName()
	if exe, err := executablePath(); err == nil {
		sibling := filepath.Join(filepath.Dir(exe), name)
		if sibling != exe {
			if _, err := os.Stat(sibling); err == nil {
				return sibling, nil
			}
		}
		if p, err := exec.LookPath(name); err == nil && p != exe {
			abs, _ := filepath.Abs(p)
			exeAbs, _ := filepath.Abs(exe)
			if abs != exeAbs {
				return p, nil
			}
		}
	}
	candidate := filepath.Join(db.DataDir(), "bin", name)
	if _, err := os.Stat(candidate); err == nil {
		return candidate, nil
	}
	return "", fmt.Errorf("proxygo server binary not found.\n" +
		"Build it with `go build -o proxygo ./cmd/proxygo` and place it next to " +
		"this CLI or on PATH, set PROXYGO_SERVER_BIN, or pass --server <path>")
}

// displayHost ports getDisplayHost in cli.js: local URL stays "localhost"
// when bound to all interfaces.
func displayHost(host string) string {
	if host == DefaultHost {
		return "localhost"
	}
	return host
}

// lanIP ports getLanIp in cli.js: first non-internal IPv4.
func lanIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.To4() != nil && !ip.IsLoopback() {
				return ip.String()
			}
		}
	}
	return ""
}

// waitServerReady ports waitServerReady in cli.js: poll TCP connect
// until the server accepts connections or the timeout hits.
func waitServerReady(port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(150 * time.Millisecond)
	}
}

func portAccepting(port int) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// openBrowser ports openBrowser in cli.js (open / start / xdg-open).
func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	_ = cmd.Process.Release()
	return nil
}

func dashboardURL(opts options) string {
	return fmt.Sprintf("http://%s:%d/dashboard", displayHost(opts.Host), opts.Port)
}

func cmdStart(opts options, stdout, stderr io.Writer) int {
	dir := db.DataDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintf(stderr, "Error: cannot create data dir %s: %v\n", dir, err)
		return 1
	}

	// Update check: the JS prints an "update available" notice on
	// start (sourced from npm; the Go port checks GitHub releases —
	// see update.go). Runs concurrently; the result is collected at a
	// success exit with a short grace period. Failures are silent and
	// --skip-update disables the check entirely.
	var updateCh chan string
	if !opts.SkipUpdate {
		updateCh = make(chan string, 1)
		go func() {
			if v, ok := newerVersionAvailable(); ok {
				updateCh <- v
			} else {
				updateCh <- ""
			}
		}()
	}
	printUpdate := func() {
		if updateCh == nil {
			return
		}
		select {
		case v := <-updateCh:
			if v != "" {
				fmt.Fprintf(stdout, "⬆ A new version of proxygo is available: %s (you have %s)\n", v, Version)
			}
		case <-time.After(1500 * time.Millisecond):
		}
	}

	// Already running (started by this CLI): JS kills and restarts; the
	// Go port reports instead — `stop` first if a restart is wanted.
	if st, ok := readPidState(); ok && processAlive(st.PID) {
		fmt.Fprintf(stdout, "ProxyGo server is already running (PID %d) on port %d.\n", st.PID, st.Port)
		fmt.Fprintf(stdout, "Dashboard: http://%s:%d/dashboard\n", displayHost(st.Host), st.Port)
		fmt.Fprintln(stdout, "Use `proxygo-cli stop` first if you want to restart it.")
		printUpdate()
		return 0
	}
	removePidState() // stale, if any

	if portAccepting(opts.Port) {
		fmt.Fprintf(stderr, "Error: port %d is already in use by another process.\n", opts.Port)
		fmt.Fprintln(stderr, "The Go CLI does not kill foreign processes (the JS launcher did). Free the port or pass --port.")
		return 1
	}

	bin, err := findServerBinary(opts.ServerBin)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "\n🚀 %s v%s\n", AppName, Version)
	if opts.Host == DefaultHost {
		if ip := lanIP(); ip != "" {
			fmt.Fprintf(stdout, "⚠ Network-exposed: reachable at http://%s:%d (bound 0.0.0.0). Use --host 127.0.0.1 for local-only.\n", ip, opts.Port)
		}
	}

	env := serverEnv(opts)
	cmd := exec.Command(bin)
	cmd.Env = env
	cmd.Dir = dir

	var logFile *os.File
	if opts.Log {
		// JS --log: show server logs (the supervisor stays in front).
		cmd.Stdout = stdout
		cmd.Stderr = stderr
		cmd.Stdin = nil
		if err := cmd.Start(); err != nil {
			fmt.Fprintf(stderr, "Failed to start server: %v\n", err)
			return 1
		}
		_ = writePidState(pidState{PID: cmd.Process.Pid, Port: opts.Port, Host: opts.Host, Binary: bin, StartedAt: time.Now().Format(time.RFC3339)})
		defer removePidState()
		fmt.Fprintf(stdout, "Server: http://%s:%d (foreground, Ctrl+C to stop)\n", displayHost(opts.Host), opts.Port)
		if err := cmd.Wait(); err != nil {
			fmt.Fprintf(stderr, "Server exited: %v\n", err)
			return 1
		}
		return 0
	}

	logPath := filepath.Join(dir, "logs", "server.log")
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err == nil {
		if f, ferr := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); ferr == nil {
			logFile = f
			cmd.Stdout = f
			cmd.Stderr = f
		}
	}
	cmd.SysProcAttr = detachAttr()
	if err := cmd.Start(); err != nil {
		if logFile != nil {
			_ = logFile.Close()
		}
		fmt.Fprintf(stderr, "Failed to start server: %v\n", err)
		return 1
	}
	pid := cmd.Process.Pid
	_ = cmd.Process.Release()
	if logFile != nil {
		_ = logFile.Close()
	}
	_ = writePidState(pidState{PID: pid, Port: opts.Port, Host: opts.Host, Binary: bin, StartedAt: time.Now().Format(time.RFC3339)})

	if !waitServerReady(opts.Port, 15*time.Second) {
		fmt.Fprintf(stderr, "❌ Server did not become ready on port %d within 15s. See log: %s\n", opts.Port, logPath)
		return 1
	}
	fmt.Fprintf(stdout, "✅ Server ready: http://%s:%d\n", displayHost(opts.Host), opts.Port)
	fmt.Fprintf(stdout, "Dashboard: %s\n", dashboardURL(opts))
	fmt.Fprintf(stdout, "Logs: %s · Stop: proxygo-cli stop · Status: proxygo-cli status\n", logPath)
	printUpdate()

	if !opts.NoBrowser {
		if err := openBrowser(dashboardURL(opts)); err != nil {
			fmt.Fprintf(stdout, "Open browser manually: %s\n", dashboardURL(opts))
		}
	}
	return 0
}

// serverEnv builds the child env: the Go server reads PORT (and DATA_DIR,
// WEB_DIR, …) from its environment, matching the JS PORT/HOSTNAME spawn
// env as far as the Go server honours it (it binds all interfaces, so
// HOSTNAME is informational only — documented adaptation).
func serverEnv(opts options) []string {
	env := os.Environ()
	out := env[:0]
	for _, kv := range env {
		if strings.HasPrefix(kv, "PORT=") {
			continue
		}
		out = append(out, kv)
	}
	out = append(out, "PORT="+strconv.Itoa(opts.Port))
	if opts.Tray {
		out = append(out, "TRAY_MODE=1") // JS sets this for --tray
	}
	return out
}

func cmdStop(stdout, stderr io.Writer) int {
	st, ok := readPidState()
	if !ok {
		fmt.Fprintln(stdout, "ProxyGo server is not running (no pid file).")
		return 0
	}
	if !processAlive(st.PID) {
		removePidState()
		fmt.Fprintf(stdout, "Server (PID %d) already exited; removed stale pid file.\n", st.PID)
		return 0
	}
	terminateProcess(st.PID, false)
	if !waitForExit(st.PID, 5*time.Second) {
		terminateProcess(st.PID, true)
		_ = waitForExit(st.PID, 3*time.Second)
	}
	removePidState()

	// JS parity: also stop the app-owned side processes via their pid
	// files (MITM proxy + tunnels) — best-effort.
	killByPidFile(filepath.Join(db.DataDir(), "mitm", ".mitm.pid"))
	killByPidFile(filepath.Join(db.DataDir(), "tunnel", "cloudflared.pid"))
	killByPidFile(filepath.Join(db.DataDir(), "tunnel", "tailscale.pid"))

	fmt.Fprintf(stdout, "✅ Stopped ProxyGo server (PID %d).\n", st.PID)
	return 0
}

// killByPidFile ports killByPidFile in cli.js (best-effort).
func killByPidFile(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return
	}
	if processAlive(pid) {
		terminateProcess(pid, false)
		if !waitForExit(pid, 1500*time.Millisecond) {
			terminateProcess(pid, true)
		}
	}
	_ = os.Remove(path)
}

func waitForExit(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return !processAlive(pid)
}

func cmdStatus(opts options, stdout, stderr io.Writer) int {
	st, hasPid := readPidState()
	port := opts.Port
	host := opts.Host
	if hasPid {
		port = st.Port
		host = st.Host
	}
	if hasPid && processAlive(st.PID) {
		fmt.Fprintf(stdout, "● running — PID %d, started %s\n", st.PID, st.StartedAt)
		fmt.Fprintf(stdout, "  Server:    http://%s:%d\n", displayHost(host), port)
		fmt.Fprintf(stdout, "  Dashboard: http://%s:%d/dashboard\n", displayHost(host), port)
		fmt.Fprintf(stdout, "  Binary:    %s\n", st.Binary)
		if healthOK(port) {
			fmt.Fprintln(stdout, "  Health:    OK (/health responded)")
		} else {
			fmt.Fprintln(stdout, "  Health:    not responding yet")
		}
		return 0
	}
	if hasPid {
		removePidState()
		fmt.Fprintln(stdout, "○ not running (removed stale pid file)")
		return 1
	}
	if healthOK(port) {
		fmt.Fprintf(stdout, "● a ProxyGo server responds on port %d, but it was not started by this CLI (no pid file)\n", port)
		fmt.Fprintf(stdout, "  Dashboard: http://%s:%d/dashboard\n", displayHost(host), port)
		return 0
	}
	fmt.Fprintln(stdout, "○ not running")
	return 1
}

func healthOK(port int) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/health", port))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK
}

func cmdOpen(opts options, stdout, stderr io.Writer) int {
	if st, ok := readPidState(); ok {
		opts.Port = st.Port
		opts.Host = st.Host
	}
	url := dashboardURL(opts)
	if err := openBrowser(url); err != nil {
		fmt.Fprintf(stdout, "Open browser manually: %s\n", url)
		return 0
	}
	fmt.Fprintf(stdout, "Opening %s\n", url)
	return 0
}

// cmdTray documents and emulates the JS --tray flow as far as a
// dependency-free Go binary can: the server is started detached (so it
// keeps running after the terminal closes), but there is NO tray icon —
// the JS tray needs a GUI helper (systray2 / PowerShell NotifyIcon)
// and this port deliberately adds no GUI dependencies. Manage the
// background server with `stop` / `status` / `open`.
func cmdTray(opts options, stdout, stderr io.Writer) int {
	fmt.Fprintln(stdout, "🔔 Tray mode (Go port): starting the server in the background.")
	fmt.Fprintln(stdout, "⚠ The system-tray ICON is not ported: the JS tray is a GUI helper (systray2 on macOS/Linux, PowerShell NotifyIcon on Windows) and the Go CLI adds no GUI dependencies.")
	fmt.Fprintln(stdout, "   Use `proxygo-cli status`, `proxygo-cli open` and `proxygo-cli stop` instead of the tray menu.")
	opts.NoBrowser = true // JS tray mode does not pop a browser either
	return cmdStart(opts, stdout, stderr)
}
