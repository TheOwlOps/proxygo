package tunnel

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"proxygo/internal/db"
)

// Tailscale health timings (tailscale/config.js HEALTH_CHECK).
const (
	tsHealthTimeoutMs      = 180000
	tsEnableTimeoutMs      = 20000
	tsFetchTimeoutMs       = 8000
	tsDNSTimeoutMs         = 3000
	tsProbeTTL             = 10 * time.Second
	tsProbeTimeout         = 1500 * time.Millisecond
	tsExtendedPath         = "/usr/local/bin:/opt/homebrew/bin:/usr/sbin:/usr/bin:/bin:/snap/bin"
	tsWindowsBin           = `C:\Program Files\Tailscale\tailscale.exe`
	tsSystemSocket         = "/var/run/tailscale/tailscaled.sock"
	tsAuthURLPattern       = `https://login\.tailscale\.com/a/[a-zA-Z0-9]+`
	tsFunnelNotEnabledHint = "Funnel is not enabled"
)

// PasswordProvider supplies the cached sudo password (in the JS this is
// the MITM manager's password cache). The api layer wires it from
// internal/mitm; empty means no cached password.
var PasswordProvider func() string

func sudoPassword() string {
	if PasswordProvider != nil {
		return PasswordProvider()
	}
	return ""
}

// TailscaleDir / TailscaleSocket (tailscale.js TAILSCALE_DIR / _SOCKET).
func TailscaleDir() string { return filepath.Join(db.DataDir(), "tailscale") }
func TailscaleSocket() string {
	return filepath.Join(TailscaleDir(), "tailscaled.sock")
}

func extendedEnv() []string {
	path := tsExtendedPath + ":" + os.Getenv("PATH")
	if isWindows() {
		path = os.Getenv("PATH")
	}
	env := os.Environ()
	out := env[:0]
	for _, e := range env {
		if !strings.HasPrefix(e, "PATH=") {
			out = append(out, e)
		}
	}
	return append(out, "PATH="+path)
}

func socketFlag() []string {
	if isWindows() {
		return nil
	}
	return []string{"--socket", TailscaleSocket()}
}

func systemSocketFlag() []string {
	if isWindows() {
		return nil
	}
	return []string{"--socket", tsSystemSocket}
}

func tsArgs(args ...string) []string {
	return append(socketFlag(), args...)
}

// ---------- binary detection ----------

var binCache = struct {
	sync.Mutex
	value   string
	set     bool
	fetched time.Time
}{}

func tailscaleBinPath() string {
	name := "tailscale"
	if isWindows() {
		name += ".exe"
	}
	return filepath.Join(binDir(), name)
}

func fallbackBin() string {
	if _, err := os.Stat(tailscaleBinPath()); err == nil {
		return tailscaleBinPath()
	}
	if isWindows() {
		if _, err := os.Stat(tsWindowsBin); err == nil {
			return tsWindowsBin
		}
		return ""
	}
	for _, p := range []string{"/usr/local/bin/tailscale", "/opt/homebrew/bin/tailscale", "/usr/sbin/tailscale", "/usr/bin/tailscale", "/snap/bin/tailscale"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// GetTailscaleBin resolves the CLI path (PATH lookup, then well-known
// locations, then the DATA_DIR/bin copy).
func GetTailscaleBin() string {
	binCache.Lock()
	defer binCache.Unlock()
	if binCache.set && time.Since(binCache.fetched) < tsProbeTTL {
		return binCache.value
	}
	v := ""
	if p, err := exec.LookPath("tailscale"); err == nil {
		v = p
	} else {
		v = fallbackBin()
	}
	binCache.value, binCache.set, binCache.fetched = v, true, time.Now()
	return v
}

// IsTailscaleInstalled (tailscale.js).
func IsTailscaleInstalled() bool { return GetTailscaleBin() != "" }

func runTS(timeout time.Duration, args ...string) ([]byte, error) {
	bin := GetTailscaleBin()
	if bin == "" {
		return nil, fmt.Errorf("tailscale not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = extendedEnv()
	return cmd.CombinedOutput()
}

type tsStatus struct {
	BackendState string
	AuthURL      string
	Self         *struct {
		Online  bool
		DNSName string
	}
}

func statusJSON(socketArgs []string, timeout time.Duration) (*tsStatus, error) {
	args := append(append([]string{}, socketArgs...), "status", "--json")
	out, err := runTS(timeout, args...)
	if err != nil {
		return nil, err
	}
	var st tsStatus
	if err := json.Unmarshal(out, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func probeStatusAnySocket() *tsStatus {
	for _, sf := range [][]string{socketFlag(), systemSocketFlag()} {
		if st, err := statusJSON(sf, tsProbeTimeout); err == nil {
			return st
		}
	}
	return nil
}

// ---------- probes (cached like the JS) ----------

type boolCache struct {
	mu        sync.Mutex
	value     bool
	fetched   time.Time
	refreshFn func() bool
}

func (c *boolCache) get() bool {
	c.mu.Lock()
	stale := time.Since(c.fetched) > tsProbeTTL
	v := c.value
	c.mu.Unlock()
	if stale {
		go func() {
			nv := c.refreshFn()
			c.mu.Lock()
			c.value, c.fetched = nv, time.Now()
			c.mu.Unlock()
		}()
	}
	return v
}

var loggedInCache = &boolCache{refreshFn: func() bool {
	st := probeStatusAnySocket()
	return st != nil && st.BackendState == "Running" && st.Self != nil && st.Self.Online
}}

var runningCache = &boolCache{refreshFn: func() bool {
	out, err := runTS(tsProbeTimeout, tsArgs("funnel", "status", "--json")...)
	if err != nil {
		return false
	}
	var data map[string]any
	if json.Unmarshal(out, &data) != nil {
		return false
	}
	allow, _ := data["AllowFunnel"].(map[string]any)
	return len(allow) > 0
}}

// IsTailscaleLoggedIn (cached, background-refresh like the JS).
func IsTailscaleLoggedIn() bool {
	if GetTailscaleBin() == "" {
		return false
	}
	return loggedInCache.get()
}

// IsTailscaleRunning (cached funnel probe).
func IsTailscaleRunning() bool {
	if GetTailscaleBin() == "" {
		return false
	}
	return runningCache.get()
}

// IsTailscaleLoggedInStrict (authoritative awaitable probe).
func IsTailscaleLoggedInStrict() bool {
	bin := GetTailscaleBin()
	if bin == "" {
		return false
	}
	st, err := statusJSON(socketFlag(), 5*time.Second)
	if err != nil {
		return false
	}
	ok := st.BackendState == "Running" && st.Self != nil && st.Self.Online
	loggedInCache.mu.Lock()
	loggedInCache.value, loggedInCache.fetched = ok, time.Now()
	loggedInCache.mu.Unlock()
	return ok
}

// IsTailscaleRunningStrict (authoritative funnel probe).
func IsTailscaleRunningStrict() bool {
	out, err := runTS(tsProbeTimeout, tsArgs("funnel", "status", "--json")...)
	if err != nil {
		return false
	}
	var data map[string]any
	if json.Unmarshal(out, &data) != nil {
		return false
	}
	allow, _ := data["AllowFunnel"].(map[string]any)
	running := len(allow) > 0
	runningCache.mu.Lock()
	runningCache.value, runningCache.fetched = running, time.Now()
	runningCache.mu.Unlock()
	return running
}

// IsSystemDaemonRunning probes the system socket's BackendState.
func IsSystemDaemonRunning() bool {
	if isWindows() {
		return false
	}
	if _, err := os.Stat(tsSystemSocket); err != nil {
		return false
	}
	st, err := statusJSON(systemSocketFlag(), tsProbeTimeout)
	return err == nil && st.BackendState == "Running"
}

// IsDaemonAlive: a tailscaled process exists (pgrep).
func IsDaemonAlive() bool {
	if isWindows() {
		return false
	}
	_, err := runCmd(2*time.Second, "pgrep", "-x", "tailscaled")
	return err == nil
}

func funnelURLFromStatus() string {
	st, err := statusJSON(socketFlag(), 5*time.Second)
	if err != nil || st.Self == nil {
		return ""
	}
	dns := strings.TrimSuffix(st.Self.DNSName, ".")
	if dns == "" {
		return ""
	}
	return "https://" + dns
}

// ---------- daemon / login / funnel ----------

func isDaemonTunMode() *bool {
	// JS reads the daemon's --tun flag from its cmdline; approximate via
	// pgrep args on unix.
	if isWindows() {
		return nil
	}
	out, err := runCmd(2*time.Second, "sh", "-c", "ps -eo args | grep '[t]ailscaled' | head -1")
	if err != nil || len(out) == 0 {
		return nil
	}
	tun := !strings.Contains(string(out), "userspace-networking")
	return &tun
}

func execWithPassword(command, password string) error {
	if strings.Contains(password, "\n") {
		return fmt.Errorf("invalid sudo password")
	}
	cmd := exec.Command("sudo", "-S", "sh", "-c", command)
	cmd.Stdin = strings.NewReader(password + "\n")
	cmd.Env = extendedEnv()
	return cmd.Run()
}

// StartDaemonWithPassword ports tailscale.js startDaemonWithPassword.
func StartDaemonWithPassword(password string) error {
	if isWindows() {
		_, _ = runCmd(10*time.Second, "net", "start", "Tailscale")
		bin := GetTailscaleBin()
		if bin == "" {
			return nil
		}
		for i := 0; i < 20; i++ {
			if st, err := statusJSON(nil, 2*time.Second); err == nil && st.BackendState != "" && st.BackendState != "NoState" {
				return nil
			}
			time.Sleep(500 * time.Millisecond)
		}
		return nil
	}

	currentMode := isDaemonTunMode()
	wantTun := password != "" || (currentMode != nil && *currentMode)
	if currentMode != nil && *currentMode == wantTun {
		if _, err := runTS(3*time.Second, tsArgs("status", "--json")...); err == nil {
			return nil
		}
	}
	// Kill daemons bound to our socket, escalating like the JS.
	_, _ = runCmd(3*time.Second, "sh", "-c", fmt.Sprintf(`pkill -9 -f "tailscaled.*%s"`, TailscaleSocket()))
	if password != "" {
		_ = execWithPassword(fmt.Sprintf(`pkill -9 -f "tailscaled.*%s"`, TailscaleSocket()), password)
	} else {
		_, _ = runCmd(3*time.Second, "sh", "-c", fmt.Sprintf(`sudo -n pkill -9 -f "tailscaled.*%s"`, TailscaleSocket()))
	}
	time.Sleep(1500 * time.Millisecond)

	if err := os.MkdirAll(TailscaleDir(), 0o755); err != nil {
		return err
	}
	tailscaledBin := "tailscaled"
	if runtime.GOOS == "darwin" {
		tailscaledBin = "/usr/local/bin/tailscaled"
	}
	daemonArgs := []string{"--socket=" + TailscaleSocket(), "--statedir=" + TailscaleDir()}
	if !wantTun {
		daemonArgs = append(daemonArgs, "--tun=userspace-networking")
	}
	var cmd *exec.Cmd
	if wantTun {
		cmd = exec.Command("sudo", append([]string{"-S", tailscaledBin}, daemonArgs...)...)
		cmd.Stdin = strings.NewReader(password + "\n")
	} else {
		cmd = exec.Command(tailscaledBin, daemonArgs...)
	}
	cmd.Dir = os.TempDir()
	cmd.Env = extendedEnv()
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	time.Sleep(3 * time.Second)
	return nil
}

var authURLRe = regexp.MustCompile(tsAuthURLPattern)

func authURLFromStatus() string {
	st, err := statusJSON(socketFlag(), 2*time.Second)
	if err != nil {
		return ""
	}
	return st.AuthURL
}

// LoginResult mirrors startLogin's resolutions.
type LoginResult struct {
	AuthURL         string
	AlreadyLoggedIn bool
}

// StartLogin runs `tailscale up` and captures the auth URL.
func StartLogin(hostname string) (*LoginResult, error) {
	bin := GetTailscaleBin()
	if bin == "" {
		return nil, fmt.Errorf("Tailscale not installed")
	}
	go func() { _ = StartDaemonWithPassword("") }()
	if IsTailscaleLoggedIn() {
		return &LoginResult{AlreadyLoggedIn: true}, nil
	}
	args := tsArgs("up", "--accept-routes")
	if hostname != "" {
		args = append(args, "--hostname="+hostname)
	}
	cmd := exec.Command(bin, args...)
	cmd.Env = extendedEnv()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	output := &strings.Builder{}
	var mu sync.Mutex
	scan := func(r io.Reader) {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			mu.Lock()
			output.WriteString(sc.Text() + "\n")
			mu.Unlock()
		}
	}
	go scan(stdout)
	go scan(stderr)
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		text := output.String()
		mu.Unlock()
		if m := authURLRe.FindString(text); m != "" {
			return &LoginResult{AuthURL: m}, nil
		}
		if u := authURLFromStatus(); u != "" {
			return &LoginResult{AuthURL: u}, nil
		}
		select {
		case <-done:
			if IsTailscaleLoggedIn() {
				return &LoginResult{AlreadyLoggedIn: true}, nil
			}
		case <-time.After(500 * time.Millisecond):
		}
	}
	mu.Lock()
	text := output.String()
	mu.Unlock()
	if m := authURLRe.FindString(text); m != "" {
		return &LoginResult{AuthURL: m}, nil
	}
	if u := authURLFromStatus(); u != "" {
		return &LoginResult{AuthURL: u}, nil
	}
	return nil, fmt.Errorf("tailscale up timed out without auth URL")
}

// FunnelResult mirrors startFunnel's resolutions.
type FunnelResult struct {
	TunnelURL        string
	FunnelNotEnabled bool
	EnableURL        string
}

// StartFunnel ports tailscale.js startFunnel.
func StartFunnel(port int) (*FunnelResult, error) {
	bin := GetTailscaleBin()
	if bin == "" {
		return nil, fmt.Errorf("Tailscale not installed")
	}
	_, _ = runTS(5*time.Second, tsArgs("funnel", "--bg", "reset")...)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, tsArgs("funnel", "--bg", fmt.Sprintf("%d", port))...)
	cmd.Env = extendedEnv()
	out, err := cmd.CombinedOutput()
	output := string(out)
	if strings.Contains(output, tsFunnelNotEnabledHint) {
		enable := ""
		if m := regexp.MustCompile(`https://[^\s]+`).FindString(output); m != "" {
			enable = m
		}
		return &FunnelResult{FunnelNotEnabled: true, EnableURL: enable}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tailscale funnel failed: %s", strings.TrimSpace(output))
	}
	return &FunnelResult{TunnelURL: funnelURLFromStatus()}, nil
}

// StopFunnel resets the funnel (tailscale.js stopFunnel).
func StopFunnel() {
	_, _ = runTS(5*time.Second, tsArgs("funnel", "--bg", "reset")...)
}

// ProvisionCert runs `tailscale cert <hostname>` (best-effort).
func ProvisionCert(hostname string) {
	if hostname == "" || GetTailscaleBin() == "" {
		return
	}
	dir := filepath.Join(TailscaleDir(), "certs")
	_ = os.MkdirAll(dir, 0o755)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, GetTailscaleBin(), tsArgs("cert", "--cert-file", filepath.Join(dir, hostname+".crt"), "--key-file", filepath.Join(dir, hostname+".key"), hostname)...)
	cmd.Env = extendedEnv()
	_ = cmd.Run()
}

// StopDaemon kills tailscaled (sudo escalation like the JS).
func StopDaemon(password string) {
	_, _ = runCmd(3*time.Second, "pkill", "-x", "tailscaled")
	if _, err := runCmd(2*time.Second, "pgrep", "-x", "tailscaled"); err != nil {
		return
	}
	if password != "" {
		_ = execWithPassword("pkill -x tailscaled", password)
	}
}

// ---------- install (tailscale.js installTailscale) ----------

// InstallTailscale installs the OS package, starts the daemon, and
// begins login. Progress lines stream through log (may be nil).
func InstallTailscale(password, hostname string, log func(string)) (*LoginResult, error) {
	if log == nil {
		log = func(string) {}
	}
	switch runtime.GOOS {
	case "windows":
		if err := installTailscaleWindows(log); err != nil {
			return nil, err
		}
		return &LoginResult{}, nil
	case "darwin":
		if err := installTailscaleMac(password, log); err != nil {
			return nil, err
		}
	default:
		if err := installTailscaleLinux(password, log); err != nil {
			return nil, err
		}
	}
	log("Starting daemon...")
	if err := StartDaemonWithPassword(password); err != nil {
		return nil, err
	}
	log("Logging in...")
	return StartLogin(hostname)
}

func streamCmd(log func(string), name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Env = extendedEnv()
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		return err
	}
	scan := func(r io.Reader) {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); line != "" {
				log(line)
			}
		}
	}
	go scan(stdout)
	go scan(stderr)
	return cmd.Wait()
}

func installTailscaleMac(password string, log func(string)) error {
	if _, err := runCmd(tsProbeTimeout, "which", "brew"); err == nil {
		log("Installing via Homebrew...")
		if err := streamCmd(log, "brew", "install", "tailscale"); err != nil {
			return fmt.Errorf("brew install failed: %v", err)
		}
		return nil
	}
	pkgPath := filepath.Join(os.TempDir(), "tailscale.pkg")
	log("Downloading Tailscale package...")
	if err := streamCmd(log, "curl", "-fL", "--progress-bar", "https://pkgs.tailscale.com/stable/tailscale-latest.pkg", "-o", pkgPath); err != nil {
		return fmt.Errorf("Download failed")
	}
	defer os.Remove(pkgPath)
	log("Installing package...")
	cmd := exec.Command("sudo", "-S", "installer", "-pkg", pkgPath, "-target", "/")
	cmd.Stdin = strings.NewReader(password + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := string(out)
		if strings.Contains(msg, "incorrect password") || strings.Contains(msg, "Sorry") {
			return fmt.Errorf("Wrong sudo password")
		}
		return fmt.Errorf("%s", strings.TrimSpace(msg))
	}
	return nil
}

func installTailscaleLinux(password string, log func(string)) error {
	if strings.Contains(password, "\n") {
		return fmt.Errorf("Invalid sudo password")
	}
	log("Downloading install script...")
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Get("https://tailscale.com/install.sh")
	if err != nil {
		return fmt.Errorf("Failed to download install script: %v", err)
	}
	defer resp.Body.Close()
	script, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != 200 {
		return fmt.Errorf("Failed to download install script")
	}
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("tailscale-install-%d.sh", time.Now().UnixNano()))
	if err := os.WriteFile(tmp, script, 0o700); err != nil {
		return fmt.Errorf("Failed to write install script: %v", err)
	}
	defer os.Remove(tmp)
	log("Running install script...")
	cmd := exec.Command("sudo", "-S", "sh", tmp)
	cmd.Stdin = strings.NewReader(password + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := string(out)
		if strings.Contains(msg, "incorrect password") || strings.Contains(msg, "Sorry") {
			return fmt.Errorf("Wrong sudo password")
		}
		if strings.TrimSpace(msg) == "" {
			msg = err.Error()
		}
		return fmt.Errorf("%s", strings.TrimSpace(msg))
	}
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			log(line)
		}
	}
	return nil
}

func installTailscaleWindows(log func(string)) error {
	msiPath := filepath.Join(os.TempDir(), "tailscale-setup.msi")
	log("Downloading Tailscale installer...")
	if err := streamCmd(log, "curl.exe", "-L", "-#", "-o", msiPath, "https://pkgs.tailscale.com/stable/tailscale-setup-latest-amd64.msi"); err != nil {
		return fmt.Errorf("Download failed")
	}
	defer os.Remove(msiPath)
	log("Installing Tailscale (UAC prompt may appear)...")
	ps := fmt.Sprintf("Start-Process msiexec -ArgumentList '/i','%s','TS_NOLAUNCH=true','/quiet','/norestart' -Verb RunAs -Wait", msiPath)
	if _, err := runCmd(5*time.Minute, "powershell", "-NoProfile", "-NonInteractive", "-Command", ps); err != nil {
		return fmt.Errorf("msiexec failed: %v", err)
	}
	return nil
}

// ---------- manager (tailscale/manager.js) ----------

type tailscaleService struct {
	mu              sync.Mutex
	cancelled       bool
	spawnInProgress bool
	activeLocalPort int
}

var tsSvc = &tailscaleService{}

// IsTailscaleReconnecting (manager.js).
func IsTailscaleReconnecting() bool {
	tsSvc.mu.Lock()
	defer tsSvc.mu.Unlock()
	return tsSvc.spawnInProgress
}

// EnableTailscale ports manager.js enableTailscale.
func EnableTailscale(store Settings, localPort int) (db.Record, error) {
	if localPort <= 0 {
		localPort = 20128
	}
	tsSvc.mu.Lock()
	tsSvc.cancelled = false
	tsSvc.activeLocalPort = localPort
	tsSvc.spawnInProgress = true
	tsSvc.mu.Unlock()
	defer func() {
		tsSvc.mu.Lock()
		tsSvc.spawnInProgress = false
		tsSvc.mu.Unlock()
	}()
	cancelled := func() bool {
		tsSvc.mu.Lock()
		defer tsSvc.mu.Unlock()
		return tsSvc.cancelled
	}

	if err := StartDaemonWithPassword(sudoPassword()); err != nil {
		return nil, err
	}
	if cancelled() {
		return nil, fmt.Errorf("tailscale cancelled")
	}
	existing := LoadState()
	shortId := ""
	if existing != nil {
		shortId = strOf(existing["shortId"])
	}
	if shortId == "" {
		shortId = GenerateShortId()
	}

	if !IsTailscaleLoggedInStrict() {
		login, err := StartLogin(shortId)
		if err != nil {
			return nil, err
		}
		if login != nil && login.AuthURL != "" {
			return db.Record{"success": false, "needsLogin": true, "authUrl": login.AuthURL}, nil
		}
	}
	if cancelled() {
		return nil, fmt.Errorf("tailscale cancelled")
	}

	StopFunnel()
	result, err := StartFunnel(localPort)
	if err != nil {
		if matched, _ := regexp.MatchString(`NoState|unexpected state|not logged in|Logged ?out|NeedsLogin`, err.Error()); matched {
			login, lerr := StartLogin(shortId)
			if lerr == nil && login != nil && login.AuthURL != "" {
				return db.Record{"success": false, "needsLogin": true, "authUrl": login.AuthURL}, nil
			}
		}
		return nil, err
	}
	if cancelled() {
		return nil, fmt.Errorf("tailscale cancelled")
	}
	if result.FunnelNotEnabled {
		return db.Record{"success": false, "funnelNotEnabled": true, "enableUrl": result.EnableURL}, nil
	}
	if !IsTailscaleLoggedInStrict() || !IsTailscaleRunningStrict() {
		StopFunnel()
		return db.Record{"success": false, "error": "Tailscale not connected. Device may have been removed. Please re-login."}, nil
	}
	_, _ = store.UpdateSettings(db.Record{"tailscaleEnabled": true, "tailscaleUrl": result.TunnelURL})
	if u, err := http.NewRequest(http.MethodGet, result.TunnelURL, nil); err == nil {
		ProvisionCert(u.URL.Hostname())
	}
	_ = WaitForHealth(result.TunnelURL, tsDNSTimeoutMs*time.Millisecond, tsFetchTimeoutMs*time.Millisecond, tsEnableTimeoutMs*time.Millisecond, cancelled) // non-fatal like JS
	return db.Record{"success": true, "tunnelUrl": result.TunnelURL}, nil
}

// DisableTailscale ports manager.js disableTailscale.
func DisableTailscale(store Settings) (db.Record, error) {
	tsSvc.mu.Lock()
	tsSvc.cancelled = true
	tsSvc.mu.Unlock()
	StopFunnel()
	_, _ = store.UpdateSettings(db.Record{"tailscaleEnabled": false, "tailscaleUrl": ""})
	return db.Record{"success": true}, nil
}

// GetTailscaleStatus ports manager.js getTailscaleStatus.
func GetTailscaleStatus(store Settings) (db.Record, error) {
	settings, err := store.GetSettings()
	if err != nil {
		return nil, err
	}
	settingsEnabled := boolOf(settings["tailscaleEnabled"])
	tunnelURL := strOf(settings["tailscaleUrl"])
	loggedIn, running := false, false
	if settingsEnabled {
		loggedIn = IsTailscaleLoggedIn()
		if loggedIn {
			running = IsTailscaleRunning()
		}
	}
	return db.Record{
		"enabled": settingsEnabled && running, "settingsEnabled": settingsEnabled,
		"tunnelUrl": tunnelURL, "running": running, "loggedIn": loggedIn,
	}, nil
}
