package mitm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Manager port (manager.js): settings hooks, sudo-password cache +
// AES-256-GCM encrypted persistence (key = sha256(machineId +
// "9router-mitm-pwd") — byte-compatible with the JS on Linux, where
// node-machine-id reads /etc/machine-id), server lifecycle, DNS tool
// state, cert trust.

const encryptSalt = "9router-mitm-pwd"

type hooksT struct {
	getSettings    func() (map[string]any, error)
	updateSettings func(map[string]any) error
	aliasFor       func(tool string) (map[string]string, bool)
}

var hooks hooksT

// InitDBHooks wires settings access (manager.js initDbHooks). The
// aliasFor callback should return the settings mitmAlias entry for a
// tool ({model: mapped}).
func InitDBHooks(
	getSettings func() (map[string]any, error),
	updateSettings func(map[string]any) error,
	aliasFor func(tool string) (map[string]string, bool),
) {
	hooks.getSettings = getSettings
	hooks.updateSettings = updateSettings
	hooks.aliasFor = aliasFor
}

// ---- password cache (globalThis.__mitmSudoPassword) ----

var (
	pwdMu     sync.Mutex
	pwdCached string
)

func GetCachedPassword() string {
	pwdMu.Lock()
	defer pwdMu.Unlock()
	return pwdCached
}

func SetCachedPassword(p string) {
	pwdMu.Lock()
	defer pwdMu.Unlock()
	pwdCached = p
}

func machineID() string {
	switch {
	case isWindows():
		out, err := exec.Command("reg", "query", `HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid").CombinedOutput()
		if err == nil {
			for _, f := range strings.Fields(string(out)) {
				if len(f) == 36 && strings.Count(f, "-") == 4 {
					return f
				}
			}
		}
	case isMac():
		out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").CombinedOutput()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if strings.Contains(line, "IOPlatformUUID") {
					parts := strings.Split(line, "\"")
					if len(parts) >= 4 {
						return parts[3]
					}
				}
			}
		}
	default:
		if raw, err := os.ReadFile("/etc/machine-id"); err == nil {
			return strings.TrimSpace(string(raw))
		}
		if raw, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil {
			return strings.TrimSpace(string(raw))
		}
	}
	h, _ := os.Hostname()
	return h
}

func deriveKey() []byte {
	sum := sha256.Sum256([]byte(machineID() + encryptSalt))
	return sum[:]
}

// EncryptPassword: "ivHex:tagHex:dataHex" AES-256-GCM (manager.js).
func EncryptPassword(plaintext string) string {
	key := deriveKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ""
	}
	iv := make([]byte, 12)
	_, _ = rand.Read(iv)
	sealed := gcm.Seal(nil, iv, []byte(plaintext), nil)
	tag := sealed[len(sealed)-gcm.Overhead():]
	data := sealed[:len(sealed)-gcm.Overhead()]
	return hex.EncodeToString(iv) + ":" + hex.EncodeToString(tag) + ":" + hex.EncodeToString(data)
}

// DecryptPassword reverses EncryptPassword; "" on any failure.
func DecryptPassword(stored string) string {
	parts := strings.Split(stored, ":")
	if len(parts) != 3 {
		return ""
	}
	iv, err1 := hex.DecodeString(parts[0])
	tag, err2 := hex.DecodeString(parts[1])
	data, err3 := hex.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return ""
	}
	block, err := aes.NewCipher(deriveKey())
	if err != nil {
		return ""
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ""
	}
	sealed := append(append([]byte{}, data...), tag...)
	plain, err := gcm.Open(nil, iv, sealed, nil)
	if err != nil {
		return ""
	}
	return string(plain)
}

// LoadEncryptedPassword reads settings.mitmSudoEncrypted.
func LoadEncryptedPassword() (string, error) {
	if hooks.getSettings == nil {
		return "", nil
	}
	settings, err := hooks.getSettings()
	if err != nil {
		return "", err
	}
	enc, _ := settings["mitmSudoEncrypted"].(string)
	if enc == "" {
		return "", nil
	}
	return DecryptPassword(enc), nil
}

func clearEncryptedPassword() {
	if hooks.updateSettings == nil {
		return
	}
	_ = hooks.updateSettings(map[string]any{"mitmSudoEncrypted": nil})
}

// ClearEncryptedPassword export (manager.js).
func ClearEncryptedPassword() { clearEncryptedPassword() }

func saveMitmSettings(enabled bool, password string) {
	if hooks.updateSettings == nil {
		return
	}
	updates := map[string]any{"mitmEnabled": enabled}
	if password != "" {
		updates["mitmSudoEncrypted"] = EncryptPassword(password)
	}
	_ = hooks.updateSettings(updates)
}

func effectivePassword(given string) string {
	if given != "" {
		return given
	}
	if p := GetCachedPassword(); p != "" {
		return p
	}
	p, _ := LoadEncryptedPassword()
	return p
}

// ---- DNS tool state (manager.js loadDnsToolState/saveDnsToolState) ----

func dnsStatePath() string { return filepath.Join(Dir(), "dns-tools.json") }

func loadDNSToolState() map[string]bool {
	out := map[string]bool{}
	raw, err := os.ReadFile(dnsStatePath())
	if err != nil {
		return out
	}
	_ = json.Unmarshal(raw, &out)
	return out
}

func saveDNSToolState(tool string, enabled bool) {
	state := loadDNSToolState()
	state[tool] = enabled
	ensureDir()
	raw, _ := json.Marshal(state)
	_ = os.WriteFile(dnsStatePath(), raw, 0o644)
}

// RestoreToolDNS re-adds DNS entries for tools enabled in saved state.
func RestoreToolDNS(sudoPassword string) {
	pwd := effectivePassword(sudoPassword)
	for tool, enabled := range loadDNSToolState() {
		if !enabled {
			continue
		}
		if _, ok := ToolHosts[tool]; !ok {
			continue
		}
		_ = AddDNSEntry(tool, pwd)
	}
}

// HasDNSPrivilege (manager.js hasDnsPrivilege).
func HasDNSPrivilege() bool {
	if isWindows() {
		// Best effort: writing a probe is intrusive; assume elevated
		// when the process can open the hosts file for append.
		f, err := os.OpenFile(hostsFile(), os.O_APPEND|os.O_WRONLY, 0)
		if err == nil {
			_ = f.Close()
			return true
		}
		return false
	}
	if os.Geteuid() == 0 {
		return true
	}
	if !IsSudoPasswordRequired() {
		return true
	}
	return effectivePassword("") != ""
}

// ---- server lifecycle ----

func pidFilePath() string { return filepath.Join(Dir(), "server.pid") }

var (
	srvMu      sync.Mutex
	srvRunning *mitmServer
	srvStarted time.Time
)

// PortBusyError mirrors the JS PORT_443_BUSY error ({code, portOwner}).
type PortBusyError struct {
	PID  int
	Name string
}

func (e *PortBusyError) Error() string {
	return fmt.Sprintf("Port 443 is already in use by %q (PID %d).", e.Name, e.PID)
}

// IsRunning reports the in-process server state.
func IsRunning() bool {
	srvMu.Lock()
	defer srvMu.Unlock()
	return srvRunning != nil
}

// GetMitmStatus (manager.js): {running, pid, certExists, certTrusted,
// dnsStatus}.
func GetMitmStatus() map[string]any {
	running := IsRunning()
	var pid any
	if running {
		pid = os.Getpid()
	} else if raw, err := os.ReadFile(pidFilePath()); err == nil {
		if p, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil && p > 0 && pidAliveCheck(p) {
			running = true
			pid = p
		} else {
			_ = os.Remove(pidFilePath())
		}
	}
	certPath := rootCACertPath()
	_, statErr := os.Stat(certPath)
	certExists := statErr == nil
	certTrusted := false
	if certExists {
		certTrusted = CheckCertInstalled(certPath)
	}
	return map[string]any{
		"running":     running,
		"pid":         pid,
		"certExists":  certExists,
		"certTrusted": certTrusted,
		"dnsStatus":   CheckAllDNSStatus(),
	}
}

func pidAliveCheck(pid int) bool {
	if isWindows() {
		out, err := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/NH").CombinedOutput()
		return err == nil && strings.Contains(string(out), strconv.Itoa(pid))
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

func resolveRouterBase() string {
	if hooks.getSettings != nil {
		if settings, err := hooks.getSettings(); err == nil {
			if v, ok := settings["mitmRouterBaseUrl"].(string); ok && strings.TrimSpace(v) != "" {
				return strings.TrimRight(strings.TrimSpace(v), "/")
			}
		}
	}
	if v := os.Getenv("MITM_ROUTER_BASE"); strings.TrimSpace(v) != "" {
		return strings.TrimRight(strings.TrimSpace(v), "/")
	}
	return "http://localhost:20128"
}

// StartServer (manager.js startServer): generate/refresh the root CA,
// ensure trust, then bind the MITM listener in-process.
//
// forceKillPort443: when the port is held by another process, kill it
// (sudo pkill on the listener pid) instead of erroring.
func StartServer(apiKey, sudoPassword string, forceKillPort443 bool) (map[string]any, error) {
	srvMu.Lock()
	defer srvMu.Unlock()
	if srvRunning != nil {
		return nil, errors.New("MITM server is already running")
	}
	ensureDir()
	pwd := effectivePassword(sudoPassword)

	// Step 1: root CA.
	certPath, keyPath := rootCACertPath(), rootCAKeyPath()
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	certExists := certErr == nil && keyErr == nil
	if !certExists || IsCertExpired(certPath) {
		if certExists {
			_ = UninstallCert(pwd, certPath)
		}
		if _, _, err := GenerateRootCA(); err != nil {
			return nil, err
		}
		// Fresh CA bytes — reset the cached CA.
		resetCACache()
	}

	// Step 1.5: trust.
	linuxNoSystemTrust := !isWindows() && !isMac() && !IsSudoAvailable() && os.Geteuid() != 0
	if !CheckCertInstalled(certPath) && !linuxNoSystemTrust {
		if pwd == "" && IsSudoPasswordRequired() {
			return nil, errors.New("Sudo password required to install Root CA certificate")
		}
		if err := InstallCert(pwd, certPath); err != nil {
			return nil, fmt.Errorf("Failed to trust certificate: %v", err)
		}
	}

	// Step 2: bind (port-busy handling).
	s := &mitmServer{apiKey: apiKey, base: resolveRouterBase(), leafs: map[string]*tls.Certificate{}}
	if err := s.startListener(); err != nil {
		if isAddrInUse(err) {
			ownerPID, ownerName := port443Owner()
			if forceKillPort443 && ownerPID > 0 {
				killPID(ownerPID, pwd)
				time.Sleep(500 * time.Millisecond)
				if err2 := s.startListener(); err2 != nil {
					return nil, err2
				}
			} else {
				return nil, &PortBusyError{PID: ownerPID, Name: ownerName}
			}
		} else {
			return nil, err
		}
	}
	srvRunning = s
	srvStarted = time.Now()
	_ = os.WriteFile(pidFilePath(), []byte(strconv.Itoa(os.Getpid())), 0o644)
	saveMitmSettings(true, sudoPassword)
	if sudoPassword != "" {
		SetCachedPassword(sudoPassword)
	}
	if hooks.updateSettings != nil {
		_ = hooks.updateSettings(map[string]any{"mitmCertInstalled": true})
	}
	return map[string]any{"running": true, "pid": os.Getpid()}, nil
}

func isAddrInUse(err error) bool {
	return strings.Contains(err.Error(), "address already in use") || strings.Contains(err.Error(), "Only one usage")
}

func port443Owner() (int, string) {
	if isWindows() {
		out, err := exec.Command("powershell", "-NoProfile", "-Command",
			"(Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1).OwningProcess").CombinedOutput()
		if err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(out))); err == nil {
				return pid, "unknown"
			}
		}
		return 0, "unknown"
	}
	out, err := exec.Command("sh", "-c", "command -v lsof >/dev/null && lsof -ti tcp:443 -sTCP:LISTEN | head -1 || ss -ltnp 'sport = :443' 2>/dev/null | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2").CombinedOutput()
	if err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(out))); err == nil && pid > 0 {
			name := "unknown"
			if nout, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").CombinedOutput(); err == nil {
				name = strings.TrimSpace(string(nout))
			}
			return pid, name
		}
	}
	return 0, "unknown"
}

func killPID(pid int, sudoPassword string) {
	if isWindows() {
		_, _ = exec.Command("taskkill", "/F", "/PID", strconv.Itoa(pid)).CombinedOutput()
		return
	}
	proc, err := os.FindProcess(pid)
	if err == nil {
		_ = proc.Signal(os.Interrupt)
	}
	_ = ExecWithPassword(fmt.Sprintf("kill -9 %d 2>/dev/null || true", pid), sudoPassword)
}

// StopServer (manager.js stopServer): stop listener, strip all DNS
// entries, persist mitmEnabled=false.
func StopServer(sudoPassword string) error {
	srvMu.Lock()
	s := srvRunning
	srvRunning = nil
	srvMu.Unlock()
	if s != nil {
		s.stop()
	}
	_ = os.Remove(pidFilePath())
	pwd := effectivePassword(sudoPassword)
	RemoveAllDNSEntries(pwd)
	for tool := range ToolHosts {
		saveDNSToolState(tool, false)
	}
	saveMitmSettings(false, "")
	return nil
}

// EnableToolDNS requires the server running (manager.js).
func EnableToolDNS(tool, sudoPassword string) (map[string]any, error) {
	if !IsRunning() {
		return nil, errors.New("MITM server is not running. Start the server first.")
	}
	pwd := effectivePassword(sudoPassword)
	if err := AddDNSEntry(tool, pwd); err != nil {
		return nil, err
	}
	saveDNSToolState(tool, true)
	return map[string]any{"success": true}, nil
}

// DisableToolDNS removes a tool's DNS entries.
func DisableToolDNS(tool, sudoPassword string) (map[string]any, error) {
	pwd := effectivePassword(sudoPassword)
	if err := RemoveDNSEntry(tool, pwd); err != nil {
		return nil, err
	}
	saveDNSToolState(tool, false)
	return map[string]any{"success": true}, nil
}

// TrustCert installs the root CA standalone (manager.js trustCert).
func TrustCert(sudoPassword string) (map[string]any, error) {
	ensureDir()
	if _, _, err := GenerateRootCA(); err != nil {
		return nil, err
	}
	resetCACache()
	pwd := effectivePassword(sudoPassword)
	if pwd == "" && IsSudoPasswordRequired() {
		return nil, errors.New("Sudo password required")
	}
	if err := InstallCert(pwd, rootCACertPath()); err != nil {
		return nil, err
	}
	if hooks.updateSettings != nil {
		_ = hooks.updateSettings(map[string]any{"mitmCertInstalled": true})
	}
	return map[string]any{"success": true}, nil
}

func resetCACache() {
	caOnce = sync.Once{}
	caVal = nil
	caErr = nil
}

var _ = srvStarted
