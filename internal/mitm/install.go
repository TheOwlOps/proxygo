package mitm

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Root-CA trust-store installation (cert/install.js): macOS system
// keychain, Windows certutil Root store, Linux distro CA dirs +
// NSS databases (Firefox/Chromium).

const rootCACN = "9Router MITM Root CA"

var linuxCADirs = []struct {
	dir string
	cmd string
}{
	{"/usr/local/share/ca-certificates", "update-ca-certificates"},
	{"/etc/pki/ca-trust/source/anchors", "update-ca-trust"},
	{"/etc/ca-certificates/trust-source/anchors", "update-ca-trust"},
	{"/etc/pki/trust/anchors", "update-ca-certificates"},
}

func certFingerprint(certPath string) (string, error) {
	raw, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return "", fmt.Errorf("unparsable cert")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return "", err
	}
	sum := sha1.Sum(block.Bytes)
	return strings.ToUpper(hex.EncodeToString(sum[:])), nil
}

// CheckCertInstalled reports trust-store presence per platform.
func CheckCertInstalled(certPath string) bool {
	fp, err := certFingerprint(certPath)
	if err != nil {
		return false
	}
	switch {
	case isMac():
		out, err := exec.Command("security", "find-certificate", "-a", "-c", rootCACN, "-Z", "/Library/Keychains/System.keychain").CombinedOutput()
		return err == nil && strings.Contains(string(out), fp)
	case isWindows():
		return exec.Command("certutil", "-store", "Root", fp).Run() == nil
	default:
		// Debian/Ubuntu: installed file under the CA dir + bundle grep.
		for _, d := range linuxCADirs {
			if _, err := os.Stat(filepath.Join(d.dir, "9router-mitm.crt")); err == nil {
				return true
			}
			if _, err := os.Stat(filepath.Join(d.dir, "9router-mitm.pem")); err == nil {
				return true
			}
		}
		return false
	}
}

// InstallCert installs the root CA into the OS trust store.
func InstallCert(sudoPassword, certPath string) error {
	switch {
	case isMac():
		del := fmt.Sprintf(`security delete-certificate -c "%s" /Library/Keychains/System.keychain 2>/dev/null; true`, rootCACN)
		install := fmt.Sprintf(`security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "%s"`, certPath)
		return ExecWithPassword(del+" && "+install, sudoPassword)
	case isWindows():
		script := fmt.Sprintf(`certutil -delstore Root "%s" 2>$null | Out-Null; $exit = & certutil -addstore Root "%s" 2>&1; if ($LASTEXITCODE -ne 0) { throw "certutil exit $LASTEXITCODE" }`, rootCACN, certPath)
		out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
		if err != nil {
			return fmt.Errorf("certutil: %s", strings.TrimSpace(string(out)))
		}
		return nil
	default:
		var target *struct {
			dir string
			cmd string
		}
		for i := range linuxCADirs {
			if st, err := os.Stat(linuxCADirs[i].dir); err == nil && st.IsDir() {
				target = &linuxCADirs[i]
				break
			}
		}
		if target == nil {
			return fmt.Errorf("no supported CA directory found")
		}
		dst := filepath.Join(target.dir, "9router-mitm.crt")
		cmd := fmt.Sprintf("cp %s %s && %s", shellQuote(certPath), shellQuote(dst), target.cmd)
		if err := ExecWithPassword(cmd, sudoPassword); err != nil {
			return err
		}
		installNSS(sudoPassword, certPath)
		return nil
	}
}

// UninstallCert removes the root CA from the trust store (best effort).
func UninstallCert(sudoPassword, certPath string) error {
	switch {
	case isMac():
		fp, err := certFingerprint(certPath)
		if err != nil {
			return err
		}
		return ExecWithPassword(fmt.Sprintf(`security delete-certificate -Z "%s" /Library/Keychains/System.keychain`, fp), sudoPassword)
	case isWindows():
		out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", fmt.Sprintf(`certutil -delstore Root "%s"`, rootCACN)).CombinedOutput()
		if err != nil {
			return fmt.Errorf("certutil: %s", strings.TrimSpace(string(out)))
		}
		return nil
	default:
		for _, d := range linuxCADirs {
			dst := filepath.Join(d.dir, "9router-mitm.crt")
			if _, err := os.Stat(dst); err == nil {
				_ = ExecWithPassword(fmt.Sprintf("rm -f %s && %s", shellQuote(dst), d.cmd), sudoPassword)
			}
		}
		return nil
	}
}

// installNSS adds the cert to NSS DBs (Firefox/Chromium) like install.js.
func installNSS(sudoPassword, certPath string) {
	if _, err := exec.LookPath("certutil"); err != nil {
		return
	}
	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(home, ".pki", "nssdb"),
		filepath.Join(home, ".mozilla", "firefox"),
	}
	_ = sudoPassword
	for _, base := range candidates {
		matches, _ := filepath.Glob(filepath.Join(base, "*", "cert9.db"))
		dbs := matches
		if _, err := os.Stat(filepath.Join(base, "cert9.db")); err == nil {
			dbs = append(dbs, filepath.Join(base, "cert9.db"))
		}
		for _, dbFile := range dbs {
			dbDir := filepath.Dir(dbFile)
			_ = exec.Command("certutil", "-d", "sql:"+dbDir, "-D", "-n", rootCACN).Run()
			_ = exec.Command("certutil", "-d", "sql:"+dbDir, "-A", "-t", "C,,", "-n", rootCACN, "-i", certPath).Run()
		}
	}
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\\''`) + "'"
}
