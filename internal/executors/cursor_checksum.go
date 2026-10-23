package executors

// Port of open-sse/utils/cursorChecksum.js — the x-cursor-checksum
// header (Jyh cipher) and the derived Cursor client identity headers.

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"runtime"
	"strings"
	"time"
)

// cursorNow is indirected so checksum fixtures can pin the clock
// (the JS reads Date.now()).
var cursorNow = time.Now

// GenerateHashed64Hex ports generateHashed64Hex(): SHA-256 hex of
// input+salt.
// GenerateHashed64Hex ports generateHashed64Hex(input, salt = "").
func GenerateHashed64Hex(input string, salt ...string) string {
	s := ""
	if len(salt) > 0 {
		s = salt[0]
	}
	sum := sha256.Sum256([]byte(input + s))
	return hex.EncodeToString(sum[:])
}

var uuidNamespaceDNS = [16]byte{
	0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1,
	0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8,
}

// uuidV5 is RFC 4122 UUID v5 (SHA-1, name-based) — the JS uses the
// `uuid` package's v5 with the DNS namespace for session ids.
func uuidV5(name string, namespace [16]byte) string {
	h := sha1.New()
	h.Write(namespace[:])
	h.Write([]byte(name))
	sum := h.Sum(nil)
	var b [16]byte
	copy(b[:], sum[:16])
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	return formatUUID(b)
}

func formatUUID(b [16]byte) string {
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// GenerateSessionID ports generateSessionId(): UUID v5 of the auth
// token in the DNS namespace.
func GenerateSessionID(authToken string) string {
	return uuidV5(authToken, uuidNamespaceDNS)
}

// GenerateCursorChecksum ports generateCursorChecksum(): Jyh cipher
// over 6 bytes extracted from the unix-millis/1e6 timestamp with JS
// 32-bit shift semantics (see generateCursorChecksumAt).
//
// Note: the JS comment says "XOR then update key", but the shipped code
// is `b = ((b ^ t) + (i % 256)) & 0xFF; t = b` — this port follows the
// code, not the comment.
func GenerateCursorChecksum(machineID string) string {
	return generateCursorChecksumAt(machineID, cursorNow().UnixMilli())
}

func generateCursorChecksumAt(machineID string, nowMillis int64) string {
	timestamp := nowMillis / 1000000
	// The JS extracts the 6 bytes with >> 40 / >> 32 / … on a JS
	// number, i.e. ToInt32 with the shift count masked to 5 bits —
	// so >> 40 is really >> 8 and >> 32 is >> 0. The resulting byte
	// pattern is NOT a plain big-endian encoding, but it is exactly
	// what the real IDE sends, so this port reproduces it bit-for-bit
	// (pinned by the JS-generated fixture in cursor_test.go).
	ts32 := int32(timestamp)
	var byteArray [6]byte
	for i, shift := range [6]int{40, 32, 24, 16, 8, 0} {
		byteArray[i] = byte((ts32 >> uint(shift&31)) & 0xFF)
	}
	t := 165
	for i := 0; i < len(byteArray); i++ {
		byteArray[i] = byte((int(byteArray[i]^byte(t)) + (i % 256)) & 0xFF)
		t = int(byteArray[i])
	}
	// URL-safe base64 without padding (the JS hand-rolls the alphabet;
	// it is exactly base64url for a 6-byte input).
	encoded := base64.RawURLEncoding.EncodeToString(byteArray[:])
	return encoded + machineID
}

// cursorTimezone mirrors Intl.DateTimeFormat().resolvedOptions().timeZone
// as closely as a Go process can: $TZ, then the zoneinfo name behind
// /etc/localtime, else "UTC".
func cursorTimezone() string {
	if tz := os.Getenv("TZ"); tz != "" {
		return strings.TrimPrefix(tz, ":")
	}
	if target, err := os.Readlink("/etc/localtime"); err == nil {
		if idx := strings.Index(target, "zoneinfo/"); idx >= 0 {
			return target[idx+len("zoneinfo/"):]
		}
	}
	return "UTC"
}

// BuildCursorHeaders ports buildCursorHeaders(). machineID may be
// empty, in which case it is derived from the token exactly like the JS.
func BuildCursorHeaders(accessToken, machineID string, ghostMode bool) map[string]string {
	cleanToken := accessToken
	if strings.Contains(cleanToken, "::") {
		// JS: accessToken.split("::")[1]
		cleanToken = strings.Split(cleanToken, "::")[1]
	}
	effectiveMachineID := machineID
	if effectiveMachineID == "" {
		effectiveMachineID = GenerateHashed64Hex(cleanToken, "machineId")
	}
	sessionID := GenerateSessionID(cleanToken)
	clientKey := GenerateHashed64Hex(cleanToken)
	checksum := GenerateCursorChecksum(effectiveMachineID)

	osName := "linux"
	switch runtime.GOOS {
	case "windows":
		osName = "windows"
	case "darwin":
		osName = "macos"
	}
	arch := "x64"
	if runtime.GOARCH == "arm64" {
		arch = "aarch64"
	}
	ghost := "false"
	if ghostMode {
		ghost = "true"
	}
	return map[string]string{
		"authorization":               "Bearer " + cleanToken,
		"connect-accept-encoding":     "gzip",
		"connect-protocol-version":    "1",
		"content-type":                "application/connect+proto",
		"user-agent":                  "connect-es/1.6.1",
		"x-amzn-trace-id":             "Root=" + cursorNewUUID(),
		"x-client-key":                clientKey,
		"x-cursor-checksum":           checksum,
		"x-cursor-client-version":     "3.12.17",
		"x-cursor-client-commit":      "0fb762053c34788bb7760d5673f8a6d4c8589d50",
		"x-cursor-client-type":        "ide",
		"x-cursor-client-os":          osName,
		"x-cursor-client-arch":        arch,
		"x-cursor-client-device-type": "desktop",
		"x-cursor-config-version":     cursorNewUUID(),
		"x-cursor-timezone":           cursorTimezone(),
		"x-ghost-mode":                ghost,
		"x-request-id":                cursorNewUUID(),
		"x-session-id":                sessionID,
	}
}
