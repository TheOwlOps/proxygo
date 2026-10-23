// Package tunnel is the Go port of src/lib/tunnel: Cloudflare quick
// tunnels and Tailscale Funnel management. Both services shell out to
// external binaries (cloudflared / tailscale[d]); when a binary is
// absent the behaviour mirrors the JS (status reports not-installed /
// not-running, enable returns the underlying error).
package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"proxygo/internal/db"
)

// Settings is the slice of the dashboard store the tunnel services use
// (getSettings / updateSettings in the JS). *db.Store satisfies it.
type Settings interface {
	GetSettings() (db.Record, error)
	UpdateSettings(db.Record) (db.Record, error)
}

// Watchdog timings (shared/watchdogConfig.js).
const (
	RestartCooldownMs      = 120000
	NetworkSettleMs        = 2500
	WatchdogIntervalMs     = 60000
	NetworkCheckIntervalMs = 5000
)

// Dir is $DATA_DIR/tunnel.
func Dir() string { return filepath.Join(db.DataDir(), "tunnel") }

func stateFile() string { return filepath.Join(Dir(), "state.json") }

func ensureDir() { _ = os.MkdirAll(Dir(), 0o755) }

// LoadState reads tunnel/state.json (shared/state.js loadState).
func LoadState() db.Record {
	raw, err := os.ReadFile(stateFile())
	if err != nil {
		return nil
	}
	var out db.Record
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}

// SaveState writes tunnel/state.json.
func SaveState(state db.Record) {
	ensureDir()
	raw, _ := json.MarshalIndent(state, "", "  ")
	_ = os.WriteFile(stateFile(), raw, 0o644)
}

// ClearState removes tunnel/state.json.
func ClearState() { _ = os.Remove(stateFile()) }

const shortIDChars = "abcdefghijklmnpqrstuvwxyz23456789"

// GenerateShortId returns a 6-char id (shared/state.js generateShortId).
func GenerateShortId() string {
	buf := make([]byte, 6)
	_, _ = rand.Read(buf)
	out := make([]byte, 6)
	for i, b := range buf {
		out[i] = shortIDChars[int(b)%len(shortIDChars)]
	}
	return string(out)
}

// CheckInternet mirrors shared/internetCheck.js: TCP connect 1.1.1.1:443.
func CheckInternet() bool {
	conn, err := net.DialTimeout("tcp", "1.1.1.1:443", 3*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

var publicResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{Timeout: 3 * time.Second}
		for _, srv := range []string{"1.1.1.1:53", "1.0.0.1:53", "8.8.8.8:53"} {
			if conn, err := d.DialContext(ctx, "udp", srv); err == nil {
				return conn, nil
			}
		}
		return nil, fmt.Errorf("no public DNS reachable")
	},
}

// ResolveDNS mirrors shared/dnsResolver.js resolveDns: public resolver
// first, OS resolver as fallback; true when the hostname resolves.
func ResolveDNS(hostname string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if _, err := publicResolver.LookupHost(ctx, hostname); err == nil {
		return true
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), timeout)
	defer cancel2()
	_, err := net.DefaultResolver.LookupHost(ctx2, hostname)
	return err == nil
}

// ProbeURLAlive mirrors the healthCheck.js probe: DNS resolves and
// GET {url}/api/health returns 2xx.
func ProbeURLAlive(rawURL string, dnsTimeout, fetchTimeout time.Duration) bool {
	if rawURL == "" {
		return false
	}
	u, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return false
	}
	if !ResolveDNS(u.URL.Hostname(), dnsTimeout) {
		return false
	}
	client := &http.Client{Timeout: fetchTimeout}
	resp, err := client.Get(rawURL + "/api/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// WaitForHealth polls ProbeURLAlive every 2s until timeout (healthCheck.js).
func WaitForHealth(rawURL string, dnsTimeout, fetchTimeout, timeout time.Duration, cancelled func() bool) error {
	start := time.Now()
	for time.Since(start) < timeout {
		if cancelled != nil && cancelled() {
			return fmt.Errorf("cancelled")
		}
		if ProbeURLAlive(rawURL, dnsTimeout, fetchTimeout) {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("Health check timeout after %dms", timeout.Milliseconds())
}

// pidAlive probes a pid (unix: kill -0; Windows: tasklist).
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	if runtime.GOOS == "windows" {
		out, err := runCmd(2*time.Second, "tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/NH")
		return err == nil && strings.Contains(string(out), fmt.Sprintf(" %d ", pid))
	}
	_, err := runCmd(2*time.Second, "kill", "-0", fmt.Sprintf("%d", pid))
	return err == nil
}

// runCmd runs a command with a timeout and returns combined output.
func runCmd(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func isWindows() bool { return runtime.GOOS == "windows" }

func strOf(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func boolOf(v any) bool {
	b, _ := v.(bool)
	return b
}
