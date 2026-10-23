package tunnel

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"9router-go/internal/db"
)

// WorkerURL (cloudflare/config.js WORKER_URL).
func WorkerURL() string {
	if v := os.Getenv("TUNNEL_WORKER_URL"); v != "" {
		return v
	}
	return "https://abc-tunnel.us"
}

// Cloudflare health-check timings (cloudflare/config.js HEALTH_CHECK).
const (
	cfHealthTimeoutMs  = 60000
	cfFetchTimeoutMs   = 5000
	cfDNSTimeoutMs     = 2000
	cfProbeURLDeadline = 5 * time.Second
)

func binDir() string { return filepath.Join(db.DataDir(), "bin") }

func cloudflaredPath() string {
	name := "cloudflared"
	if isWindows() {
		name += ".exe"
	}
	return filepath.Join(binDir(), name)
}

func pidFile() string { return filepath.Join(Dir(), "cloudflared.pid") }

// SavePid / LoadPid / ClearPid (cloudflare/pid.js).
func SavePid(pid int) {
	ensureDir()
	_ = os.WriteFile(pidFile(), []byte(strconv.Itoa(pid)), 0o644)
}

func LoadPid() int {
	raw, err := os.ReadFile(pidFile())
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	return pid
}

func ClearPid(expected ...int) bool {
	if _, err := os.Stat(pidFile()); err != nil {
		return false
	}
	if len(expected) > 0 && LoadPid() != expected[0] {
		return false
	}
	return os.Remove(pidFile()) == nil
}

// ---------- binary download (cloudflared.js) ----------

var platformMappings = map[string]map[string]string{
	"darwin":  {"amd64": "cloudflared-darwin-amd64.tgz", "arm64": "cloudflared-darwin-arm64.tgz"},
	"windows": {"amd64": "cloudflared-windows-amd64.exe", "386": "cloudflared-windows-386.exe", "arm64": "cloudflared-windows-386.exe"},
	"linux":   {"amd64": "cloudflared-linux-amd64", "arm64": "cloudflared-linux-arm64"},
}

var platformFallback = map[string]string{
	"darwin": "cloudflared-darwin-amd64.tgz", "windows": "cloudflared-windows-386.exe", "linux": "cloudflared-linux-amd64",
}

const githubBaseURL = "https://github.com/cloudflare/cloudflared/releases/latest/download"

func downloadURL() (string, error) {
	mapping, ok := platformMappings[runtime.GOOS]
	if !ok {
		return "", fmt.Errorf("Unsupported platform: %s", runtime.GOOS)
	}
	name, ok := mapping[runtime.GOARCH]
	if !ok {
		name = platformFallback[runtime.GOOS]
	}
	return githubBaseURL + "/" + name, nil
}

var dlState = struct {
	sync.Mutex
	downloading bool
	progress    int
}{}

// GetDownloadStatus (cloudflared.js getDownloadStatus).
func GetDownloadStatus() db.Record {
	dlState.Lock()
	defer dlState.Unlock()
	return db.Record{"downloading": dlState.downloading, "progress": dlState.progress}
}

func isValidBinary(path string) bool {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() < 1024*1024 {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	magic := make([]byte, 4)
	if _, err := f.Read(magic); err != nil {
		return false
	}
	hex := fmt.Sprintf("%x", magic)
	switch runtime.GOOS {
	case "windows":
		return strings.HasPrefix(hex, "4d5a")
	case "darwin":
		return strings.HasPrefix(hex, "cffaedfe") || strings.HasPrefix(hex, "cefaedfe")
	default:
		return strings.HasPrefix(hex, "7f454c46")
	}
}

var ensureMu sync.Mutex

// EnsureCloudflared downloads the binary when missing/invalid.
func EnsureCloudflared() (string, error) {
	ensureMu.Lock()
	defer ensureMu.Unlock()
	dir := binDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	binPath := cloudflaredPath()
	tmpPath := binPath + ".tmp"
	_ = os.Remove(tmpPath)
	if _, err := os.Stat(binPath); err == nil {
		if !isValidBinary(binPath) {
			_ = os.Remove(binPath)
		} else {
			if !isWindows() {
				_ = os.Chmod(binPath, 0o755)
			}
			return binPath, nil
		}
	}
	url, err := downloadURL()
	if err != nil {
		return "", err
	}
	isArchive := strings.HasSuffix(url, ".tgz")
	dest := tmpPath
	if isArchive {
		dest = filepath.Join(dir, "cloudflared.tgz.tmp")
	}
	if err := downloadFile(url, dest); err != nil {
		return "", err
	}
	if isArchive {
		if err := extractTgz(dest, dir); err != nil {
			return "", err
		}
		_ = os.Remove(dest)
	} else {
		if err := os.Rename(dest, binPath); err != nil {
			return "", err
		}
	}
	if !isWindows() {
		_ = os.Chmod(binPath, 0o755)
	}
	return binPath, nil
}

func downloadFile(url, dest string) error {
	dlState.Lock()
	dlState.downloading = true
	dlState.progress = 0
	dlState.Unlock()
	defer func() {
		dlState.Lock()
		dlState.downloading = false
		dlState.Unlock()
	}()
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("Download failed with status %d", resp.StatusCode)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	var received int64
	buf := make([]byte, 64*1024)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				_ = os.Remove(dest)
				return werr
			}
			received += int64(n)
			if resp.ContentLength > 0 {
				dlState.Lock()
				dlState.progress = int(received * 100 / resp.ContentLength)
				dlState.Unlock()
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			_ = os.Remove(dest)
			return rerr
		}
	}
	dlState.Lock()
	dlState.progress = 100
	dlState.Unlock()
	return nil
}

func extractTgz(archive, dir string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target := filepath.Join(dir, filepath.Base(hdr.Name))
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, tr)
		_ = out.Close()
		if err != nil {
			return err
		}
	}
}

// ---------- process management (cloudflared.js) ----------

var quickURLRe = regexp.MustCompile(`https://([a-z0-9-]+)\.trycloudflare\.com`)

func quickTunnelURLFromLog(msg string) string {
	var found string
	for _, m := range quickURLRe.FindAllStringSubmatch(msg, -1) {
		if m[1] == "api" {
			continue
		}
		found = "https://" + m[1] + ".trycloudflare.com"
	}
	return found
}

type cloudflareService struct {
	mu               sync.Mutex
	proc             *exec.Cmd
	cancelled        bool
	spawnInProgress  bool
	activeLocalPort  int
	onUnexpectedExit func()
}

var cfSvc = &cloudflareService{}

// SetTunnelUnexpectedExitCallback (manager.js).
func SetTunnelUnexpectedExitCallback(cb func()) {
	cfSvc.mu.Lock()
	cfSvc.onUnexpectedExit = cb
	cfSvc.mu.Unlock()
}

// IsTunnelManuallyDisabled / IsTunnelReconnecting (manager.js).
func IsTunnelManuallyDisabled() bool {
	cfSvc.mu.Lock()
	defer cfSvc.mu.Unlock()
	return cfSvc.cancelled
}

func IsTunnelReconnecting() bool {
	cfSvc.mu.Lock()
	defer cfSvc.mu.Unlock()
	return cfSvc.spawnInProgress
}

// IsCloudflaredRunning: pid file + alive probe (cloudflared.js).
func IsCloudflaredRunning() bool {
	pid := LoadPid()
	if pid == 0 {
		return false
	}
	return pidAlive(pid)
}

// KillCloudflared kills the tracked process, the pid-file process, and any
// cloudflared whose command line targets localPort (cloudflared.js).
func KillCloudflared(localPort int) {
	cfSvc.mu.Lock()
	proc := cfSvc.proc
	cfSvc.proc = nil
	cfSvc.mu.Unlock()
	if proc != nil && proc.Process != nil {
		_ = proc.Process.Kill()
	}
	if pid := LoadPid(); pid != 0 {
		if p, err := os.FindProcess(pid); err == nil {
			_ = p.Kill()
		}
		ClearPid()
	}
	if localPort > 0 {
		if isWindows() {
			ps := fmt.Sprintf(`Get-CimInstance Win32_Process -Filter "Name='cloudflared.exe'" | Where-Object { $_.CommandLine -match ':%d(\D|$)' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }`, localPort)
			_, _ = runCmd(10*time.Second, "powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps)
		} else {
			_, _ = runCmd(5*time.Second, "sh", "-c", fmt.Sprintf(`pkill -f "cloudflared.*:%d([^0-9]|$)" 2>/dev/null || true`, localPort))
		}
	}
}

// SpawnQuickTunnel starts `cloudflared tunnel --url http://127.0.0.1:PORT`
// and resolves with the first trycloudflare URL from its log output;
// later URL changes are reported through onURL (cloudflared.js).
func SpawnQuickTunnel(localPort int, onURL func(string)) (string, error) {
	binaryPath, err := EnsureCloudflared()
	if err != nil {
		return "", err
	}
	configDir, err := os.MkdirTemp("", "cloudflared-quick-")
	if err != nil {
		return "", err
	}
	configPath := filepath.Join(configDir, "config.yml")
	_ = os.WriteFile(configPath, []byte("# quick-tunnel config placeholder\n"), 0o644)

	protocol := strings.ToLower(strings.TrimSpace(os.Getenv("TUNNEL_TRANSPORT_PROTOCOL")))
	if protocol == "" {
		protocol = strings.ToLower(strings.TrimSpace(os.Getenv("CLOUDFLARED_PROTOCOL")))
	}
	if protocol != "http2" && protocol != "quic" && protocol != "auto" {
		protocol = "http2"
	}
	cmd := exec.Command(binaryPath, "tunnel", "--url", fmt.Sprintf("http://127.0.0.1:%d", localPort),
		"--config", configPath, "--no-autoupdate", "--retries", "99")
	cmd.Dir = os.TempDir()
	cmd.Env = append(os.Environ(), "TUNNEL_TRANSPORT_PROTOCOL="+protocol)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	SavePid(cmd.Process.Pid)
	cfSvc.mu.Lock()
	cfSvc.proc = cmd
	cancelledAtSpawn := cfSvc.cancelled
	cfSvc.mu.Unlock()
	_ = cancelledAtSpawn

	urlCh := make(chan string, 1)
	errCh := make(chan error, 1)
	var logMu sync.Mutex
	logTail := ""
	lastURL := ""
	scan := func(r io.Reader) {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			line := sc.Text()
			logMu.Lock()
			logTail = (logTail + line + "\n")
			if len(logTail) > 4000 {
				logTail = logTail[len(logTail)-4000:]
			}
			logMu.Unlock()
			u := quickTunnelURLFromLog(line)
			if u == "" {
				continue
			}
			select {
			case urlCh <- u:
				lastURL = u
			default:
				if u != lastURL {
					lastURL = u
					if onURL != nil {
						onURL(u)
					}
				}
			}
		}
	}
	go scan(stdout)
	go scan(stderr)
	go func() {
		err := cmd.Wait()
		ClearPid(cmd.Process.Pid)
		cfSvc.mu.Lock()
		if cfSvc.proc == cmd {
			cfSvc.proc = nil
		}
		cb := cfSvc.onUnexpectedExit
		intentional := cfSvc.cancelled
		cfSvc.mu.Unlock()
		if err != nil {
			select {
			case errCh <- err:
			default:
			}
		}
		if !intentional && cb != nil {
			// Only fires when the tunnel had connected; the manager
			// treats any post-spawn exit as unexpected like the JS
			// watchdog path does.
			cb()
		}
	}()

	select {
	case u := <-urlCh:
		_ = os.RemoveAll(configDir)
		return u, nil
	case err := <-errCh:
		_ = os.RemoveAll(configDir)
		logMu.Lock()
		tail := logTail
		logMu.Unlock()
		if len(tail) > 600 {
			tail = tail[len(tail)-600:]
		}
		return "", fmt.Errorf("cloudflared quick tunnel exited: %v. Last log: %s", err, strings.TrimSpace(tail))
	case <-time.After(90 * time.Second):
		_ = os.RemoveAll(configDir)
		logMu.Lock()
		tail := logTail
		logMu.Unlock()
		if len(tail) > 800 {
			tail = tail[len(tail)-800:]
		}
		return "", fmt.Errorf("Quick tunnel timed out. Last log: %s", strings.TrimSpace(tail))
	}
}

// ---------- manager (cloudflare/manager.js) ----------

func registerTunnelURL(shortId, tunnelURL string) error {
	body, _ := json.Marshal(map[string]any{"shortId": shortId, "tunnelUrl": tunnelURL})
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(WorkerURL()+"/api/tunnel/register", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// EnableTunnel ports manager.js enableTunnel (localPort default 20128).
func EnableTunnel(store Settings, localPort int) (db.Record, error) {
	if localPort <= 0 {
		localPort = 20128
	}
	cfSvc.mu.Lock()
	cfSvc.cancelled = false
	cfSvc.activeLocalPort = localPort
	cfSvc.spawnInProgress = true
	cfSvc.mu.Unlock()
	defer func() {
		cfSvc.mu.Lock()
		cfSvc.spawnInProgress = false
		cfSvc.mu.Unlock()
	}()
	cancelled := func() bool {
		cfSvc.mu.Lock()
		defer cfSvc.mu.Unlock()
		return cfSvc.cancelled
	}

	if IsCloudflaredRunning() {
		if existing := LoadState(); existing != nil && strOf(existing["tunnelUrl"]) != "" && strOf(existing["shortId"]) != "" {
			publicURL := "https://r" + strOf(existing["shortId"]) + ".abc-tunnel.us"
			directOK := ProbeURLAlive(strOf(existing["tunnelUrl"]), cfDNSTimeoutMs*time.Millisecond, cfFetchTimeoutMs*time.Millisecond)
			publicOK := ProbeURLAlive(publicURL, cfDNSTimeoutMs*time.Millisecond, cfFetchTimeoutMs*time.Millisecond)
			if directOK && publicOK {
				return db.Record{"success": true, "tunnelUrl": existing["tunnelUrl"], "shortId": existing["shortId"], "publicUrl": publicURL, "alreadyRunning": true}, nil
			}
		}
	}

	KillCloudflared(localPort)
	if cancelled() {
		return nil, fmt.Errorf("tunnel cancelled")
	}

	existing := LoadState()
	shortId := ""
	if existing != nil {
		shortId = strOf(existing["shortId"])
	}
	if shortId == "" {
		shortId = GenerateShortId()
	}

	onURLUpdate := func(url string) {
		if cancelled() {
			return
		}
		_ = registerTunnelURL(shortId, url)
		SaveState(db.Record{"shortId": shortId, "tunnelUrl": url})
		_, _ = store.UpdateSettings(db.Record{"tunnelEnabled": true, "tunnelUrl": url})
	}

	tunnelURL, err := SpawnQuickTunnel(localPort, onURLUpdate)
	if err != nil {
		return nil, err
	}
	if cancelled() {
		return nil, fmt.Errorf("tunnel cancelled")
	}
	publicURL := "https://r" + shortId + ".abc-tunnel.us"
	_ = registerTunnelURL(shortId, tunnelURL)
	SaveState(db.Record{"shortId": shortId, "tunnelUrl": tunnelURL})
	_, _ = store.UpdateSettings(db.Record{"tunnelEnabled": true, "tunnelUrl": tunnelURL})

	if err := WaitForHealth(publicURL, cfDNSTimeoutMs*time.Millisecond, cfFetchTimeoutMs*time.Millisecond, cfHealthTimeoutMs*time.Millisecond, cancelled); err != nil {
		return nil, err
	}
	_ = ProbeURLAlive(tunnelURL, cfDNSTimeoutMs*time.Millisecond, cfFetchTimeoutMs*time.Millisecond) // best-effort, like JS
	return db.Record{"success": true, "tunnelUrl": tunnelURL, "shortId": shortId, "publicUrl": publicURL}, nil
}

// DisableTunnel ports manager.js disableTunnel.
func DisableTunnel(store Settings) (db.Record, error) {
	cfSvc.mu.Lock()
	cfSvc.cancelled = true
	port := cfSvc.activeLocalPort
	cfSvc.onUnexpectedExit = nil
	cfSvc.mu.Unlock()

	KillCloudflared(port)
	ClearPid()
	if state := LoadState(); state != nil {
		SaveState(db.Record{"shortId": state["shortId"], "tunnelUrl": nil})
	}
	_, _ = store.UpdateSettings(db.Record{"tunnelEnabled": false, "tunnelUrl": ""})
	cfSvc.mu.Lock()
	cfSvc.spawnInProgress = false
	cfSvc.activeLocalPort = 0
	cfSvc.mu.Unlock()
	return db.Record{"success": true}, nil
}

// GetTunnelStatus ports manager.js getTunnelStatus.
func GetTunnelStatus(store Settings) (db.Record, error) {
	settings, err := store.GetSettings()
	if err != nil {
		return nil, err
	}
	settingsEnabled := boolOf(settings["tunnelEnabled"])
	state := LoadState()
	shortId, tunnelURL := "", ""
	if state != nil {
		shortId = strOf(state["shortId"])
		tunnelURL = strOf(state["tunnelUrl"])
	}
	publicURL := ""
	if shortId != "" {
		publicURL = "https://r" + shortId + ".abc-tunnel.us"
	}
	running := false
	if settingsEnabled {
		running = IsCloudflaredRunning()
	}
	return db.Record{
		"enabled": settingsEnabled && running, "settingsEnabled": settingsEnabled,
		"tunnelUrl": tunnelURL, "shortId": shortId, "publicUrl": publicURL, "running": running,
	}, nil
}
