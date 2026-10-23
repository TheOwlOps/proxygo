package oauthsvc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"time"
)

// Port of src/lib/oauth/providers/xiaomi-mimo.js (X25519 ECDH + AES-256-GCM
// encrypted callback) and the session-cookie codec of
// src/lib/mimoLoginSession.js (used by the xiaomi-mimo login routes).

// XiaomiGenerateKeyPair creates the X25519 keypair for the OAuth handshake.
// PublicKey is base64 SPKI DER (what the platform expects in `pk`);
// PrivateKeyDER is PKCS#8 DER.
func XiaomiGenerateKeyPair() (publicKeyB64 string, privateKeyDER []byte, err error) {
	priv, err := ecdh.X25519().GenerateKey(randReader())
	if err != nil {
		return "", nil, err
	}
	privDER, err := x509MarshalPKCS8(priv)
	if err != nil {
		return "", nil, err
	}
	pubRaw := priv.PublicKey().Bytes()
	spki := append([]byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00}, pubRaw...)
	return base64.StdEncoding.EncodeToString(spki), privDER, nil
}

// XiaomiDecryptCallback decrypts the `u` callback parameter:
// nonce(12) || ephemeralPubRaw(32) || ciphertext || gcmTag(16),
// key = SHA256(ECDH(private, ephemeral)).
func XiaomiDecryptCallback(privateKeyDER []byte, encryptedB64 string) (map[string]any, error) {
	raw, err := base64.StdEncoding.DecodeString(encryptedB64)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(encryptedB64)
		if err != nil {
			return nil, errf("Invalid Xiaomi callback payload encoding")
		}
	}
	if len(raw) < 12+32+16+1 {
		return nil, errf("Encrypted payload too short: %d bytes", len(raw))
	}
	nonce := raw[:12]
	ephemeralRaw := raw[12:44]
	ciphertextAndTag := raw[44:]

	privAny, err := parsePKCS8(privateKeyDER)
	if err != nil {
		return nil, err
	}
	priv, ok := privAny.(*ecdh.PrivateKey)
	if !ok {
		return nil, errf("Xiaomi private key is not X25519")
	}
	ephemeral, err := ecdh.X25519().NewPublicKey(ephemeralRaw)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(ephemeral)
	if err != nil {
		return nil, err
	}
	key := sha256.Sum256(shared)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertextAndTag, nil)
	if err != nil {
		return nil, errf("Xiaomi callback decryption failed: %v", err)
	}
	var parsed map[string]any
	if json.Unmarshal(plain, &parsed) != nil || parsed == nil {
		return nil, errf("Decrypted payload is not a valid object")
	}
	out := map[string]any{}
	if v := strOf(parsed, "uid"); v != "" {
		out["uid"] = v
	} else {
		out["uid"] = nil
	}
	if v := strOf(parsed, "sk"); v != "" {
		out["sk"] = v
	} else {
		out["sk"] = nil
	}
	out["url"] = strOf(parsed, "url")
	if out["url"] == "" {
		out["url"] = XiaomiDefaultAPIURL
	}
	return out, nil
}

// XiaomiBuildAuthorizeURL ports buildAuthorizeUrl.
func XiaomiBuildAuthorizeURL(publicKey, redirectURI, keyName string) string {
	q := "pk=" + urlEscape(publicKey) + "&redirect_uri=" + urlEscape(redirectURI) + "&kn=" + XiaomiKeyName
	if keyName != "" {
		q += "&key_name=" + urlEscape(keyName)
	}
	return XiaomiPlatformURL + "/authorize?" + q
}

// XiaomiKeyNameForMachine ports getKeyName (deterministic per machine).
func XiaomiKeyNameForMachine() string {
	host, _ := os.Hostname()
	sum := sha256.Sum256([]byte(os.Getenv("GOOS") + "-" + host))
	return "9router-xmd-" + hexEncode(sum[:])[:8]
}

// ---- MiMo login session cookie (src/lib/mimoLoginSession.js) ----

// MimoRegionBases maps region codes to MiMo server bases.
var MimoRegionBases = map[string]string{
	"cn":  "https://mimo-server-cn.xiaomimimo.com",
	"sgp": "https://mimo-server-sgp.xiaomimimo.com",
	"ams": "https://mimo-server-ams.xiaomimimo.com",
	"ru":  "https://mimo-server-ru.xiaomimimo.com",
	"in":  "https://mimo-server-in.xiaomimimo.com",
}

// MimoRegionBase returns the server base for a region (default sgp).
func MimoRegionBase(region string) string {
	if base, ok := MimoRegionBases[region]; ok {
		return base
	}
	return MimoRegionBases["sgp"]
}

// MimoCookie is one cookie-jar entry [name, value, domain, path].
type MimoCookie struct {
	Name   string `json:"-"`
	Value  string `json:"-"`
	Domain string `json:"-"`
	Path   string `json:"-"`
}

// MimoLoginSession is the decoded 9r_mimo_login cookie payload.
type MimoLoginSession struct {
	State     string
	Region    string
	CreatedAt int64
	ProxyURL  string
	Jar       []MimoCookie
}

const mimoSessionTTL = 15 * time.Minute
const mimoSessionBudget = 2800

var mimoKeepCookieRe = regexp.MustCompile(`(?i)^(passToken|userId|cUserId|deviceId|serviceToken|ssecurity|pass_ua|slh|ph|nonce|ticket|stsToken|p_ck|_u|uLocale|sdkVersion|cUserId_)`)

// EncodeMimoLoginSession serializes a session into the cookie value
// ("v2." + base64url(JSON)), trimming the jar to the byte budget with the
// JS keep-list priority.
func EncodeMimoLoginSession(s *MimoLoginSession) (string, error) {
	jar := make([]any, 0, len(s.Jar))
	for _, c := range s.Jar {
		jar = append(jar, []any{c.Name, c.Value, c.Domain, c.Path})
	}
	payload := map[string]any{
		"s": s.State, "r": s.Region, "t": s.CreatedAt, "p": s.ProxyURL, "j": jar,
	}
	encode := func(p map[string]any) string {
		raw, _ := json.Marshal(p)
		return "v2." + base64.RawURLEncoding.EncodeToString(raw)
	}
	value := encode(payload)
	for len(value) > mimoSessionBudget && len(jar) > 0 {
		// Drop the oldest non-identity cookie first, mirroring the JS trimmer.
		drop := -1
		for i, entry := range jar {
			arr, _ := entry.([]any)
			name, _ := arr[0].(string)
			if !mimoKeepCookieRe.MatchString(name) {
				drop = i
				break
			}
		}
		if drop == -1 {
			drop = 0
		}
		jar = append(jar[:drop], jar[drop+1:]...)
		payload["j"] = jar
		value = encode(payload)
	}
	return value, nil
}

// DecodeMimoLoginSession parses + TTL-checks a session cookie value.
func DecodeMimoLoginSession(value string) (*MimoLoginSession, error) {
	if !strings.HasPrefix(value, "v2.") {
		return nil, errf("Unsupported MiMo login session version")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, "v2."))
	if err != nil {
		return nil, errf("Invalid MiMo login session cookie")
	}
	var payload struct {
		S string     `json:"s"`
		R string     `json:"r"`
		T int64      `json:"t"`
		P string     `json:"p"`
		J [][]string `json:"j"`
	}
	if json.Unmarshal(raw, &payload) != nil {
		return nil, errf("Invalid MiMo login session payload")
	}
	if payload.T > 0 && time.Since(time.UnixMilli(payload.T)) > mimoSessionTTL {
		return nil, errf("MiMo login session expired")
	}
	s := &MimoLoginSession{State: payload.S, Region: payload.R, CreatedAt: payload.T, ProxyURL: payload.P}
	for _, entry := range payload.J {
		c := MimoCookie{}
		if len(entry) > 0 {
			c.Name = entry[0]
		}
		if len(entry) > 1 {
			c.Value = entry[1]
		}
		if len(entry) > 2 {
			c.Domain = entry[2]
		}
		if len(entry) > 3 {
			c.Path = entry[3]
		}
		s.Jar = append(s.Jar, c)
	}
	return s, nil
}

// JarCookie returns a cookie value from the session jar ("" when absent).
func (s *MimoLoginSession) JarCookie(name string) string {
	for _, c := range s.Jar {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// MimoIdentity extracts the login identity from a session jar.
func (s *MimoLoginSession) MimoIdentity() (passToken, userID, cUserID string) {
	return s.JarCookie("passToken"), s.JarCookie("userId"), s.JarCookie("cUserId")
}
