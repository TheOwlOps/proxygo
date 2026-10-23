package mitm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Hosts-file DNS management (dns/dnsConfig.js). Entries are plain
// `127.0.0.1 <host>` lines for the tool hosts; writes go through sudo tee
// on unix (password via stdin) and an atomic temp-file swap on Windows.

func hostsFile() string {
	if isWindows() {
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		return filepath.Join(root, "System32", "drivers", "etc", "hosts")
	}
	return "/etc/hosts"
}

// ExecWithPassword runs a shell command via `sudo -S sh -c` with the
// password on stdin (dnsConfig.js execWithPassword). A nil/empty
// password runs through `sudo -n` (non-interactive).
func ExecWithPassword(command, password string) error {
	if strings.Contains(password, "\n") {
		return fmt.Errorf("invalid sudo password")
	}
	var cmd *exec.Cmd
	if password == "" {
		cmd = exec.Command("sudo", "-n", "sh", "-c", command)
	} else {
		cmd = exec.Command("sudo", "-S", "sh", "-c", command)
		cmd.Stdin = strings.NewReader(password + "\n")
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := string(out)
		if strings.Contains(msg, "incorrect password") || strings.Contains(msg, "Sorry") {
			return fmt.Errorf("Wrong sudo password")
		}
		if strings.TrimSpace(msg) != "" {
			return fmt.Errorf("%s", strings.TrimSpace(msg))
		}
		return err
	}
	return nil
}

// IsSudoAvailable: `sudo -n true` succeeds (passwordless sudo or root).
func IsSudoAvailable() bool {
	if isWindows() {
		return false
	}
	if os.Geteuid() == 0 {
		return true
	}
	return exec.Command("sudo", "-n", "true").Run() == nil
}

// IsSudoPasswordRequired: unix, not root, no passwordless sudo.
func IsSudoPasswordRequired() bool {
	if isWindows() {
		return false
	}
	return os.Geteuid() != 0 && !IsSudoAvailable()
}

func readHosts() string {
	raw, _ := os.ReadFile(hostsFile())
	return string(raw)
}

// CheckDNSEntry (dnsConfig.js): host present in the hosts file; with no
// host, the legacy antigravity check (all antigravity hosts present).
func CheckDNSEntry(host string) bool {
	content := readHosts()
	if host != "" {
		return strings.Contains(content, host)
	}
	for _, h := range ToolHosts["antigravity"] {
		if !strings.Contains(content, h) {
			return false
		}
	}
	return true
}

// CheckAllDNSStatus returns {tool: all-hosts-present}.
func CheckAllDNSStatus() map[string]bool {
	content := readHosts()
	out := map[string]bool{}
	for tool, hosts := range ToolHosts {
		ok := true
		for _, h := range hosts {
			if !strings.Contains(content, h) {
				ok = false
				break
			}
		}
		out[tool] = ok
	}
	return out
}

func flushDNS(password string) {
	if isWindows() {
		_, _ = exec.Command("ipconfig", "/flushdns").CombinedOutput()
		return
	}
	if isMac() {
		_ = ExecWithPassword("dscacheutil -flushcache && killall -HUP mDNSResponder", password)
	} else {
		_ = ExecWithPassword("resolvectl flush-caches 2>/dev/null || true", password)
	}
}

func writeHosts(next, password string) error {
	if isWindows() {
		// Atomic swap via temp + backup, mirroring atomicWriteHostsWin.
		target := hostsFile()
		tmpNew := target + ".proxygo.new"
		tmpBak := target + ".proxygo.bak"
		if err := os.WriteFile(tmpNew, []byte(next), 0o644); err != nil {
			return err
		}
		_ = os.Remove(tmpBak)
		if err := os.Rename(target, tmpBak); err != nil {
			return err
		}
		if err := os.Rename(tmpNew, target); err != nil {
			_ = os.Rename(tmpBak, target)
			return err
		}
		_ = os.Remove(tmpBak)
		return nil
	}
	escaped := strings.ReplaceAll(next, "'", `'\\''`)
	return ExecWithPassword(fmt.Sprintf("printf '%%s' '%s' | tee %s > /dev/null", escaped, hostsFile()), password)
}

// AddDNSEntry appends the tool's hosts as 127.0.0.1 lines (dnsConfig.js).
func AddDNSEntry(tool, sudoPassword string) error {
	hosts, ok := ToolHosts[tool]
	if !ok {
		return fmt.Errorf("Unknown tool: %s", tool)
	}
	var toAdd []string
	for _, h := range hosts {
		if !CheckDNSEntry(h) {
			toAdd = append(toAdd, h)
		}
	}
	if len(toAdd) == 0 {
		return nil
	}
	current := strings.TrimRight(readHosts(), " \t\r\n")
	sep := "\n"
	if isWindows() {
		sep = "\r\n"
	}
	var lines []string
	for _, h := range toAdd {
		lines = append(lines, "127.0.0.1 "+h)
	}
	next := current + sep + strings.Join(lines, sep) + sep
	if err := writeHosts(next, sudoPassword); err != nil {
		if strings.Contains(err.Error(), "incorrect password") {
			return fmt.Errorf("Wrong sudo password")
		}
		return fmt.Errorf("Failed to add DNS entry: %v", err)
	}
	flushDNS(sudoPassword)
	return nil
}

// RemoveDNSEntry drops lines containing the tool's hosts (dnsConfig.js).
func RemoveDNSEntry(tool, sudoPassword string) error {
	hosts, ok := ToolHosts[tool]
	if !ok {
		return fmt.Errorf("Unknown tool: %s", tool)
	}
	var toRemove []string
	for _, h := range hosts {
		if CheckDNSEntry(h) {
			toRemove = append(toRemove, h)
		}
	}
	if len(toRemove) == 0 {
		return nil
	}
	var kept []string
	for _, line := range strings.Split(readHosts(), "\n") {
		trimmed := strings.TrimRight(line, "\r")
		drop := false
		for _, h := range toRemove {
			if strings.Contains(trimmed, h) {
				drop = true
				break
			}
		}
		if !drop {
			kept = append(kept, trimmed)
		}
	}
	next := strings.TrimRight(strings.Join(kept, "\n"), " \t\r\n") + "\n"
	if err := writeHosts(next, sudoPassword); err != nil {
		if strings.Contains(err.Error(), "incorrect password") {
			return fmt.Errorf("Wrong sudo password")
		}
		return fmt.Errorf("Failed to remove DNS entry: %v", err)
	}
	flushDNS(sudoPassword)
	return nil
}

// RemoveAllDNSEntries removes every tool's entries (dnsConfig.js).
func RemoveAllDNSEntries(sudoPassword string) {
	for tool := range ToolHosts {
		_ = RemoveDNSEntry(tool, sudoPassword)
	}
}

// RemoveAllDNSEntriesSync strips all tool hosts without sudo (shutdown
// path; assumes the caller already has rights).
func RemoveAllDNSEntriesSync() {
	content := readHosts()
	if content == "" {
		return
	}
	all := map[string]bool{}
	for _, hosts := range ToolHosts {
		for _, h := range hosts {
			all[h] = true
		}
	}
	var kept []string
	for _, line := range strings.Split(content, "\n") {
		drop := false
		for h := range all {
			if strings.Contains(line, h) {
				drop = true
				break
			}
		}
		if !drop {
			kept = append(kept, line)
		}
	}
	_ = os.WriteFile(hostsFile(), []byte(strings.Join(kept, "\n")), 0o644)
}
