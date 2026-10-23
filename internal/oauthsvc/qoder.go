package oauthsvc

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Port of src/lib/oauth/services/qoder.js (QoderService) — the device-token
// flow shared by qoder and qoder-cn (region config comes from the registry).

// QoderConfig resolves a qoder-family provider's endpoints.
func QoderConfig(provider string) Config { return ConfigFor(provider) }

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// QoderInitiateDeviceFlow ports initiateDeviceFlow.
func QoderInitiateDeviceFlow(cfg Config) map[string]any {
	pkce := GeneratePKCE(32)
	nonce := newUUID()
	machineID := newUUID()
	loginURL := cfg.StrOr("loginUrl", "https://qoder.com/device/selectAccounts")
	params := "challenge=" + urlEscape(pkce.CodeChallenge) +
		"&challenge_method=S256&machine_id=" + urlEscape(machineID) +
		"&nonce=" + urlEscape(nonce)
	return map[string]any{
		"verificationUriComplete": loginURL + "?" + params,
		"codeVerifier":            pkce.CodeVerifier,
		"nonce":                   nonce,
		"machineId":               machineID,
	}
}

// QoderPollResult is one pollDeviceToken attempt.
type QoderPollResult struct {
	Status       string // "pending" | "ok"
	AccessToken  string
	RefreshToken string
	UserID       string
	ExpireTimeMs int64
	Raw          map[string]any
}

// QoderPollDeviceToken ports pollDeviceToken (202/404 = pending).
func QoderPollDeviceToken(ctx context.Context, cfg Config, nonce, codeVerifier string) (*QoderPollResult, error) {
	if nonce == "" || codeVerifier == "" {
		return nil, errf("pollDeviceToken: missing nonce or code verifier")
	}
	pollURL := cfg.StrOr("deviceTokenUrl", "https://openapi.qoder.sh/api/v1/deviceToken/poll")
	endpoint := pollURL + "?nonce=" + urlEscape(nonce) + "&verifier=" + urlEscape(codeVerifier) + "&challenge_method=S256"
	status, raw, _, err := Raw(ctx, http.MethodGet, endpoint, nil, "",
		map[string]string{"User-Agent": "Go-http-client/2.0"})
	if err != nil {
		return nil, err
	}
	if status == 202 || status == 404 {
		return &QoderPollResult{Status: "pending"}, nil
	}
	var body map[string]any
	if jsonUnmarshal(raw, &body) != nil {
		if status != http.StatusOK {
			return nil, errf("Qoder device token poll failed: HTTP %d", status)
		}
		return nil, errf("Qoder device token poll: invalid JSON response")
	}
	if status != http.StatusOK {
		msg := strOf(body, "message")
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", status)
		}
		return nil, errf("Qoder device token poll failed: %s", msg)
	}
	token := strOf(body, "token")
	if token == "" {
		return nil, errf("Qoder device token poll returned 200 but no token")
	}
	expireMs := QoderParseExpiry(body["expires_at"], body["expires_in"])
	return &QoderPollResult{
		Status: "ok", AccessToken: token,
		RefreshToken: strOf(body, "refresh_token"),
		UserID:       strOf(body, "user_id"),
		ExpireTimeMs: expireMs,
		Raw:          body,
	}, nil
}

// QoderFetchUserInfo ports fetchUserInfo (best effort).
func QoderFetchUserInfo(ctx context.Context, cfg Config, accessToken string) (name, email, orgID string) {
	userInfoURL := cfg.StrOr("userInfoUrl", "https://openapi.qoder.sh/api/v1/userinfo")
	status, body, err := GetJSON(ctx, userInfoURL, map[string]string{
		"Authorization": "Bearer " + accessToken,
		"User-Agent":    "Go-http-client/2.0",
	})
	if err != nil || status != http.StatusOK {
		return "", "", ""
	}
	name = strings.TrimSpace(firstStr(strOf(body, "name"), strOf(body, "username")))
	email = strings.TrimSpace(strOf(body, "email"))
	orgID = strings.TrimSpace(strOf(body, "organization_id"))
	return name, email, orgID
}

// QoderParseExpiry ports QoderService.parseExpiry.
func QoderParseExpiry(expiresAt, expiresIn any) int64 {
	now := time.Now().UnixMilli()
	if f, ok := expiresAt.(float64); ok && f > 0 {
		return int64(f)
	}
	if s, ok := expiresAt.(string); ok {
		trimmed := strings.TrimSpace(s)
		if trimmed != "" {
			if isAllDigits(trimmed) {
				if ms, err := strconv.ParseInt(trimmed, 10, 64); err == nil && ms > 0 {
					return ms
				}
			}
			if t, err := time.Parse(time.RFC3339, trimmed); err == nil {
				return t.UnixMilli()
			}
		}
	}
	if f, ok := expiresIn.(float64); ok && f >= 0 {
		return now + int64(f)*1000
	}
	return now + 30*24*60*60*1000
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}
