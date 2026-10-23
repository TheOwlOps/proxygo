package oauthsvc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// Port of src/lib/oauth/utils/pkce.js.

// GenerateCodeVerifier returns a base64url verifier from `bytes` random
// bytes (default 32; xAI uses 96).
func GenerateCodeVerifier(bytes int) string {
	if bytes <= 0 {
		bytes = 32
	}
	buf := make([]byte, bytes)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// GenerateCodeChallenge is the S256 challenge for a verifier.
func GenerateCodeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// GenerateState returns the CSRF state value (32 random bytes, base64url).
func GenerateState() string {
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// PKCE is a verifier/challenge/state triple (generatePKCE in the JS).
type PKCE struct {
	CodeVerifier  string
	CodeChallenge string
	State         string
}

// GeneratePKCE mints a full PKCE triple.
func GeneratePKCE(verifierBytes int) PKCE {
	v := GenerateCodeVerifier(verifierBytes)
	return PKCE{CodeVerifier: v, CodeChallenge: GenerateCodeChallenge(v), State: GenerateState()}
}
