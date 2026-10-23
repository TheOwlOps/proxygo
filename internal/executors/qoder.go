package executors

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// QoderExecutor ports open-sse/executors/qoder.js plus its shared/qoder/*
// and services/qoderModels.js helpers. One class serves both providers —
// exactly like the JS, where executors/index.js registers
// `qoder: new QoderExecutor()` and `qoder-cn: new QoderExecutor("qoder-cn")`
// and the constructor derives region = "cn" for qoder-cn, else "intl".
// NewQoderExecutor(providerID) mirrors that constructor; NewQoderCnExecutor
// is the convenience spelling.
//
// Wire protocol (nothing like DefaultExecutor):
//   - The request body is rebuilt into Qoder's agent shape: system text
//     hoisted out of messages, a chat_context with a mirrored modelConfig,
//     a business block with stable sha256-derived session/record ids, and
//     the model's live model_config block fetched (COSY-signed) from
//     /algo/api/v2/model/list and cached for 1h — a wrong block silently
//     downgrades the model upstream, so an unknown key is a hard 400.
//   - Image/document attachments are rewritten first (shared/qoder/
//     attachments.js): inlined data-URI images are uploaded to
//     /algo/api/v2/image/upload (COSY-signed multipart PUT) and replaced
//     by the returned OSS URL; un-uploadable large binaries become stubs.
//   - The JSON body is shipped through the WAF-bypass encoder
//     (qoderEncodeBody: base64 → thirds-rearranged → custom alphabet)
//     with `&Encode=1` on the URL, and signed with COSY headers computed
//     over the *encoded* bytes: RSA-wrapped AES key + AES-CBC user info,
//     MD5 signature over payload‖key‖timestamp‖body‖sigPath.
//   - PAT credentials (pt-…) cannot sign COSY directly: they are first
//     exchanged for a short-lived job token (jt-…) via the region's
//     jobToken/exchange endpoint (cached until 5min before expiry) and
//     the userId resolved from /api/v1/userinfo. On intl, job-token
//     traffic must go to api2.qoder.sh — api3 rejects jt- with 403.
//   - The response is SSE of {statusCodeValue, body} envelopes whose body
//     is itself an OpenAI chunk; the wrapper unwraps it back to plain
//     OpenAI SSE, coalescing the finish chunk with the later usage-only
//     frame (shared/qoder/sse.js), mapping first-frame errors to real
//     HTTP errors (billing blocks → 403) and closing the stream at the
//     terminal frame instead of waiting out Qoder's keepalive socket.
//
// refreshCredentials returns null in the JS (device tokens don't refresh
// through OAuth; a 401 on chat prompts re-login) — inherited Base
// behaviour matches. No parseError override in the JS either.

type QoderExecutor struct {
	*Base
	providerID string
	region     string // "intl" | "cn"
}

// NewQoderExecutor mirrors the JS constructor: provider "qoder-cn" →
// region cn, anything else → intl.
func NewQoderExecutor(providerID string) *QoderExecutor {
	if providerID == "" {
		providerID = "qoder"
	}
	region := "intl"
	if providerID == "qoder-cn" {
		region = "cn"
	}
	e := &QoderExecutor{providerID: providerID, region: region}
	e.Base = &Base{ProviderID: providerID}
	return e
}

// NewQoderCnExecutor is NewQoderExecutor("qoder-cn").
func NewQoderCnExecutor() *QoderExecutor { return NewQoderExecutor("qoder-cn") }

// --- constants (shared/qoder/constants.js, config/mediaConfig.js) ---

const (
	qoderChatSigPath     = "/api/v2/service/pro/sse/agent_chat_generation"
	qoderImageUploadPath = "/api/v2/image/upload"
	qoderIDEVersion      = "1.0.0"
	qoderClientType      = "5"
	qoderDataPolicy      = "disagree"
	qoderLoginVersion    = "v2"
	qoderMachineOS       = "x86_64_windows"
	qoderMachineType     = "5"

	qoderContextTierEnv      = "QODER_CONTEXT_TIER"
	qoderContextTierHeadroom = 0.15

	qoderMaxPayloadBytes        = 6 * 1024 * 1024  // QODER_MAX_PAYLOAD_BYTES
	qoderInlineFallbackMaxBytes = 512 * 1024       // QODER_INLINE_FALLBACK_MAX_BYTES
	qoderMaxImageBytes          = 10 * 1024 * 1024 // MAX_IMAGE_BYTES

	qoderCatalogTTL       = time.Hour // CACHE_TTL_MS in qoderModels.js
	qoderFetchTimeout     = 15 * time.Second
	qoderPatRefreshBuffer = 5 * time.Minute
	qoderPatDefaultTTL    = 24 * time.Hour
)

// qoderRSAPublicKeyPEM is QODER_RSA_PUBLIC_KEY (Qoder IDE v0.9), used to
// wrap the per-request AES key for COSY signing.
const qoderRSAPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDA8iMH5c02LilrsERw9t6Pv5Nc
4k6Pz1EaDicBMpdpxKduSZu5OANqUq8er4GM95omAGIOPOh+Nx0spthYA2BqGz+l
6HRkPJ7S236FZz73In/KVuLnwI8JJ2CbuJap8kvheCCZpmAWpb/cPx/3Vr/J6I17
XcW+ML9FoCI6AOvOzwIDAQAB
-----END PUBLIC KEY-----`

// --- region bases (qoderRegionBases / qoder*Url) ---

type qoderBaseSet struct {
	chat    string // inference host (model list + chat + upload)
	chatAlt string // intl job-token host (api2)
	openAPI string // device flow + userinfo + PAT exchange
	center  string // token refresh host (unused by the executor)
}

func qoderDefaultBases(region string) qoderBaseSet {
	if region == "cn" {
		return qoderBaseSet{
			chat:    "https://gateway.qoder.com.cn",
			chatAlt: "https://gateway.qoder.com.cn",
			openAPI: "https://openapi.qoder.com.cn",
			center:  "https://gateway.qoder.com.cn",
		}
	}
	return qoderBaseSet{
		chat:    "https://api3.qoder.sh",
		chatAlt: "https://api2.qoder.sh",
		openAPI: "https://openapi.qoder.sh",
		center:  "https://center.qoder.sh",
	}
}

func qoderOriginOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// qoderBasesFor resolves the region's base set, honouring the registry
// oauth block (openApiBaseUrl / centerBaseUrl / chatBaseUrl, carried in
// ProviderInfo.Raw) and the transport baseUrl's origin. A non-Qoder
// origin (tests, future gateways) serves every endpoint from one host,
// mirroring how the JS derives all URLs from the same region table.
func qoderBasesFor(p *ProviderInfo, region string) qoderBaseSet {
	b := qoderDefaultBases(region)
	if p == nil {
		return b
	}
	if oauth, _ := p.Raw["oauth"].(map[string]any); oauth != nil {
		if s := getStr(oauth, "openApiBaseUrl"); s != "" {
			b.openAPI = strings.TrimSuffix(s, "/")
		}
		if s := getStr(oauth, "centerBaseUrl"); s != "" {
			b.center = strings.TrimSuffix(s, "/")
		}
		if s := getStr(oauth, "chatBaseUrl"); s != "" {
			b.chat = strings.TrimSuffix(s, "/")
		}
	}
	if origin := qoderOriginOf(p.BaseURL); origin != "" {
		if strings.Contains(origin, "qoder") {
			b.chat = origin
		} else {
			b.chat, b.chatAlt, b.openAPI, b.center = origin, origin, origin, origin
		}
	}
	return b
}

// qoderInferenceBase ports qoderInferenceBase: CN always uses the single
// gateway host; on intl, job tokens (jt-…) go to api2 while device tokens
// (dt-…) stay on api3. PATs are exchanged before this is consulted.
func qoderInferenceBase(cred Credential, region string, bases qoderBaseSet) string {
	if region == "cn" {
		return bases.chat
	}
	raw := cred.APIKey
	if raw == "" {
		raw = cred.AccessToken
	}
	if raw != "" && !strings.HasPrefix(raw, "pt-") &&
		(strings.HasPrefix(raw, "jt-") || strings.HasPrefix(cred.AccessToken, "jt-")) {
		return bases.chatAlt
	}
	return bases.chat
}

func (e *QoderExecutor) qoderBuildURL(p *ProviderInfo, cred Credential) string {
	base := qoderInferenceBase(cred, e.region, qoderBasesFor(p, e.region))
	return base + "/algo" + qoderChatSigPath + "?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1"
}

// --- body encoding (shared/qoder/encoding.js) ---

const qoderStdAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
const qoderCustomAlphabet = "_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!"

var qoderS2CTable = qoderBuildS2C()

func qoderBuildS2C() [128]int16 {
	var table [128]int16
	for i := range table {
		table[i] = -1
	}
	for i := 0; i < 64 && i < len(qoderStdAlphabet) && i < len(qoderCustomAlphabet); i++ {
		table[qoderStdAlphabet[i]] = int16(qoderCustomAlphabet[i])
	}
	table['='] = int16('$')
	return table
}

// qoderEncodeBody ports qoderEncodeBody: base64 the plaintext, rearrange
// as [tail][mid][head] thirds, then substitute via the custom alphabet.
// The output alphabet is pure ASCII, so the Go string's bytes are the
// latin1 bytes the JS produces.
func qoderEncodeBody(plain []byte) string {
	std := base64.StdEncoding.EncodeToString(plain)
	n := len(std)
	a := n / 3
	rearranged := std[n-a:] + std[a:n-a] + std[:a]
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		c := rearranged[i]
		if int(c) < 128 && qoderS2CTable[c] >= 0 {
			out[i] = byte(qoderS2CTable[c])
		} else {
			out[i] = c
		}
	}
	return string(out)
}

// --- COSY signing (shared/qoder/cosy.js) ---

type qoderCosyCreds struct {
	userID    string
	authToken string
	name      string
	email     string
	machineID string
}

func qoderCosyCredsFrom(cred Credential) qoderCosyCreds {
	name := cred.SpecificString("displayName")
	if name == "" {
		name = cred.ConnectionName // JS credentials.displayName
	}
	return qoderCosyCreds{
		userID:    cred.SpecificString("userId"),
		authToken: cred.AccessToken,
		name:      name,
		email:     cred.SpecificString("email"),
		machineID: cred.SpecificString("machineId"),
	}
}

var (
	qoderRSAPub     *rsa.PublicKey
	qoderRSAPubErr  error
	qoderRSAPubOnce sync.Once
)

func qoderRSAPublicKey() (*rsa.PublicKey, error) {
	qoderRSAPubOnce.Do(func() {
		block, _ := pem.Decode([]byte(qoderRSAPublicKeyPEM))
		if block == nil {
			qoderRSAPubErr = errors.New("cosy: invalid RSA public key PEM")
			return
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			qoderRSAPubErr = err
			return
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			qoderRSAPubErr = errors.New("cosy: RSA public key has wrong type")
			return
		}
		qoderRSAPub = rsaPub
	})
	return qoderRSAPub, qoderRSAPubErr
}

// qoderAESEncryptCBCBase64 ports aesEncryptCbcBase64: AES-128-CBC with
// key == IV == the 16 key bytes and manual PKCS#7 padding.
func qoderAESEncryptCBCBase64(plaintext, keyStr string) (string, error) {
	keyBytes := []byte(keyStr)
	if len(keyBytes) != 16 {
		return "", fmt.Errorf("aes key must be 16 bytes, got %d", len(keyBytes))
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}
	data := []byte(plaintext)
	padding := 16 - (len(data) % 16)
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, keyBytes[:16]).CryptBlocks(out, padded)
	return base64.StdEncoding.EncodeToString(out), nil
}

// qoderRSAEncryptBase64 ports rsaEncryptBase64 (RSA PKCS#1 v1.5).
func qoderRSAEncryptBase64(data string) (string, error) {
	pub, err := qoderRSAPublicKey()
	if err != nil {
		return "", err
	}
	enc, err := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(data))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(enc), nil
}

type qoderUserInfoPayload struct {
	UID   string `json:"uid"`
	Token string `json:"security_oauth_token"`
	Name  string `json:"name"`
	AID   string `json:"aid"`
	Email string `json:"email"`
}

// qoderEncryptUserInfo ports encryptUserInfo: the user-info JSON is
// AES-CBC encrypted under a fresh key (first 16 chars of a UUID, hyphens
// included — matching qodercli), and the key is RSA-wrapped.
func qoderEncryptUserInfo(info qoderUserInfoPayload) (cosyKey, infoB64 string, err error) {
	aesKey := newUUID()[:16]
	plain, err := marshalJSON(info)
	if err != nil {
		return "", "", err
	}
	infoB64, err = qoderAESEncryptCBCBase64(string(plain), aesKey)
	if err != nil {
		return "", "", err
	}
	cosyKey, err = qoderRSAEncryptBase64(aesKey)
	if err != nil {
		return "", "", err
	}
	return cosyKey, infoB64, nil
}

func qoderMD5Hex(b []byte) string {
	sum := md5.Sum(b)
	return hex.EncodeToString(sum[:])
}

// qoderSigPath ports computeSigPath: the URL path minus the "/algo"
// prefix.
func qoderSigPath(requestURL string) string {
	u, err := url.Parse(requestURL)
	if err != nil {
		return ""
	}
	path := u.Path
	if strings.HasPrefix(path, "/algo") {
		return path[len("/algo"):]
	}
	return path
}

// qoderBuildCosyHeaders ports buildCosyHeaders: the full Cosy-* header
// set for one signed request over the exact bytes that will be sent.
func qoderBuildCosyHeaders(body []byte, requestURL string, creds qoderCosyCreds) (map[string]string, error) {
	if creds.userID == "" {
		return nil, errors.New("cosy: user id is empty")
	}
	if creds.authToken == "" {
		return nil, errors.New("cosy: auth token is empty")
	}
	cosyKey, info, err := qoderEncryptUserInfo(qoderUserInfoPayload{
		UID:   creds.userID,
		Token: creds.authToken,
		Name:  creds.name,
		AID:   "",
		Email: creds.email,
	})
	if err != nil {
		return nil, err
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	payloadObj := map[string]any{
		"version":     "v1",
		"requestId":   newUUID(),
		"info":        info,
		"cosyVersion": qoderIDEVersion,
		"ideVersion":  "",
	}
	payloadRaw, err := marshalJSON(payloadObj)
	if err != nil {
		return nil, err
	}
	payloadB64 := base64.StdEncoding.EncodeToString(payloadRaw)

	sigPath := qoderSigPath(requestURL)
	var sigBuf bytes.Buffer
	sigBuf.WriteString(payloadB64)
	sigBuf.WriteByte('\n')
	sigBuf.WriteString(cosyKey)
	sigBuf.WriteByte('\n')
	sigBuf.WriteString(timestamp)
	sigBuf.WriteByte('\n')
	sigBuf.Write(body) // JS interpolates the body as a latin1 string — byte-identical
	sigBuf.WriteByte('\n')
	sigBuf.WriteString(sigPath)
	sig := qoderMD5Hex(sigBuf.Bytes())

	machineID := creds.machineID
	if machineID == "" {
		machineID = newUUID() // generateMachineId
	}
	return map[string]string{
		"Authorization":          "Bearer COSY." + payloadB64 + "." + sig,
		"Cosy-Key":               cosyKey,
		"Cosy-User":              creds.userID,
		"Cosy-Date":              timestamp,
		"Cosy-Version":           qoderIDEVersion,
		"Cosy-Machineid":         machineID,
		"Cosy-Machinetoken":      machineID,
		"Cosy-Machinetype":       qoderMachineType,
		"Cosy-Machineos":         qoderMachineOS,
		"Cosy-Clienttype":        qoderClientType,
		"Cosy-Clientip":          "127.0.0.1",
		"Cosy-Bodyhash":          qoderMD5Hex(body),
		"Cosy-Bodylength":        strconv.Itoa(len(body)),
		"Cosy-Sigpath":           sigPath,
		"Cosy-Data-Policy":       qoderDataPolicy,
		"Cosy-Organization-Id":   "",
		"Cosy-Organization-Tags": "",
		"Login-Version":          qoderLoginVersion,
		"X-Request-Id":           newUUID(),
	}, nil
}

// --- small JS-semantics helpers (qoder-prefixed) ---

// qoderNum coerces a decoded JSON value to a float like JS Number():
// numbers and numeric strings convert, everything else is NaN.
func qoderNum(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case float32:
		return float64(t), true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return f, err == nil
	}
	return 0, false
}

// qoderJSString renders a scalar like JS String(): used where the JS
// stringifies content/code values of unknown shape.
func qoderJSString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		if t == math.Trunc(t) && math.Abs(t) < 1e15 {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.Number:
		return t.String()
	default:
		raw, err := marshalJSON(t)
		if err != nil {
			return fmt.Sprint(t)
		}
		return string(raw)
	}
}

func qoderTruncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// --- message normalization (qoder.js normalizeMessages & friends) ---

func qoderExtractText(content any) string {
	switch c := content.(type) {
	case string:
		return c
	case nil:
		return ""
	case []any:
		var parts []string
		for _, item := range c {
			m, _ := item.(map[string]any)
			if m == nil {
				continue
			}
			if t, ok := m["text"].(string); ok {
				parts = append(parts, t)
			}
		}
		return strings.Join(parts, "\n")
	default:
		return qoderJSString(content)
	}
}

// qoderNormalizeContent ports normalizeContent: text-only content is
// flattened to a plain string; image blocks are preserved as OpenAI
// image_url parts; file/document blocks become short stubs.
func qoderNormalizeContent(content any) any {
	switch c := content.(type) {
	case string:
		return c
	case nil:
		return ""
	case []any:
		// handled below
		_ = c
	default:
		return qoderJSString(content)
	}
	items, _ := content.([]any)
	var blocks []any
	var textParts []string
	hasImage := false
	pushText := func(text string) {
		if text == "" {
			return
		}
		if hasImage || len(blocks) > 0 {
			blocks = append(blocks, map[string]any{"type": "text", "text": text})
		} else {
			textParts = append(textParts, text)
		}
	}
	for _, raw := range items {
		item, _ := raw.(map[string]any)
		if item == nil {
			continue
		}
		typ := getStr(item, "type")
		if typ == "image_url" {
			var imageURL string
			switch v := item["image_url"].(type) {
			case string:
				imageURL = v
			case map[string]any:
				imageURL = getStr(v, "url")
			}
			if imageURL != "" {
				blocks = append(blocks, map[string]any{
					"type":      "image_url",
					"image_url": map[string]any{"url": imageURL},
				})
				hasImage = true
				continue
			}
		}
		if typ == "image" {
			if src, _ := item["source"].(map[string]any); src != nil {
				var imageURL string
				if getStr(src, "type") == "base64" {
					if data := getStr(src, "data"); data != "" {
						mediaType := getStr(src, "media_type")
						if mediaType == "" {
							mediaType = "image/png"
						}
						imageURL = "data:" + mediaType + ";base64," + data
					}
				} else if u := getStr(src, "url"); u != "" {
					imageURL = u
				}
				if imageURL != "" {
					blocks = append(blocks, map[string]any{
						"type":      "image_url",
						"image_url": map[string]any{"url": imageURL},
					})
					hasImage = true
					continue
				}
			}
		}
		if typ == "file" {
			name := "file"
			if f, _ := item["file"].(map[string]any); f != nil {
				if n := getStr(f, "filename"); n != "" {
					name = n
				} else if n := getStr(f, "name"); n != "" {
					name = n
				}
			}
			pushText("[file omitted: " + name + " — Qoder reads documents via its file API, not inlined bytes]")
			continue
		}
		if typ == "document" {
			name := getStr(item, "title")
			if name == "" {
				name = "document"
			}
			pushText("[file omitted: " + name + " — Qoder reads documents via its file API, not inlined bytes]")
			continue
		}
		if t, ok := item["text"].(string); ok && t != "" {
			pushText(t)
		}
	}
	if !hasImage {
		return strings.Join(textParts, "\n")
	}
	if len(textParts) > 0 {
		blocks = append([]any{map[string]any{"type": "text", "text": strings.Join(textParts, "\n")}}, blocks...)
	}
	return blocks
}

// qoderNormalizeMessages ports normalizeMessages: system messages are
// hoisted out of the array (Qoder rejects system in messages).
func qoderNormalizeMessages(messages []any) (out []any, systemText string) {
	var systemParts []string
	out = []any{}
	for _, raw := range messages {
		msg, _ := raw.(map[string]any)
		if msg == nil {
			continue
		}
		if getStr(msg, "role") == "system" {
			if text := qoderExtractText(msg["content"]); text != "" {
				systemParts = append(systemParts, text)
			}
			continue
		}
		cloned := cloneMap(msg)
		cloned["content"] = qoderNormalizeContent(msg["content"])
		out = append(out, cloned)
	}
	return out, strings.Join(systemParts, "\n\n")
}

func qoderLastUserText(messages []any) string {
	for i := len(messages) - 1; i >= 0; i-- {
		msg, _ := messages[i].(map[string]any)
		if msg == nil || getStr(msg, "role") != "user" {
			continue
		}
		switch c := msg["content"].(type) {
		case string:
			return c
		case []any:
			return qoderExtractText(c)
		}
	}
	return ""
}

// qoderStableHash ports stableHash: sha256 over prefix‖(\0 part)*,
// truncated to 16 hex chars.
func qoderStableHash(prefix string, parts ...string) string {
	h := sha256.New()
	h.Write([]byte(prefix))
	for _, p := range parts {
		h.Write([]byte{0})
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// qoderStableChatRecordID ports stableChatRecordId: a content-derived
// record id, stable for identical (model, messages, tools, maxTokens).
func qoderStableChatRecordID(model string, messages []any, tools any, maxTokens int) string {
	h := sha256.New()
	h.Write([]byte("qoder-record\x00"))
	h.Write([]byte(model))
	for _, raw := range messages {
		msg, _ := raw.(map[string]any)
		if msg == nil {
			continue
		}
		if role := getStr(msg, "role"); role != "" {
			h.Write([]byte{0})
			h.Write([]byte(role))
		}
		switch c := msg["content"].(type) {
		case string:
			if c != "" {
				h.Write([]byte{0})
				h.Write([]byte(c))
			}
		case []any:
			h.Write([]byte{0})
			if rawJSON, err := marshalJSON(c); err == nil {
				h.Write(rawJSON)
			}
		}
	}
	if tools != nil {
		h.Write([]byte{0})
		if rawJSON, err := marshalJSON(tools); err == nil {
			h.Write(rawJSON)
		}
	}
	h.Write([]byte("\x00mt=" + strconv.Itoa(maxTokens)))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// --- context-window tiers (shared/qoder/contextTier.js) ---

type qoderTier struct {
	name       string
	tokenCount int
	isDefault  bool
}

var qoderTierCountRe = regexp.MustCompile(`^(\d+(?:\.\d+)?)\s*([KM])?$`)

// qoderParseTierTokenCount ports parseTierTokenCount ("200K" | "1M" |
// "204800" | 204800 → tokens).
func qoderParseTierTokenCount(v any) int {
	if n, ok := qoderNum(v); ok {
		if n > 0 && !math.IsInf(n, 0) && !math.IsNaN(n) {
			return int(math.Floor(n))
		}
		return 0
	}
	s, ok := v.(string)
	if !ok {
		return 0
	}
	m := qoderTierCountRe.FindStringSubmatch(strings.ToUpper(strings.TrimSpace(s)))
	if m == nil {
		return 0
	}
	n, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0
	}
	switch m[2] {
	case "K":
		n *= 1000
	case "M":
		n *= 1000 * 1000
	}
	if n > 0 && !math.IsInf(n, 0) && !math.IsNaN(n) {
		return int(math.Floor(n))
	}
	return 0
}

func qoderTierName(entry map[string]any, tokenCount int) string {
	for _, key := range []string{"name", "label", "display_name", "displayName", "key", "id"} {
		if s := getStr(entry, key); strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	if tokenCount >= 1000000 && tokenCount%1000000 == 0 {
		return strconv.Itoa(tokenCount/1000000) + "M"
	}
	if tokenCount >= 1000 && tokenCount%1000 == 0 {
		return strconv.Itoa(tokenCount/1000) + "K"
	}
	return strconv.Itoa(tokenCount)
}

// qoderGetTiers ports getQoderContextTiers: sorted, deduped by count.
func qoderGetTiers(modelConfig map[string]any) []qoderTier {
	list, _ := modelConfig["context_config"].([]any)
	if list == nil {
		list, _ = modelConfig["contextConfig"].([]any)
	}
	if list == nil {
		return nil
	}
	byCount := map[int]*qoderTier{}
	for _, raw := range list {
		entry, _ := raw.(map[string]any)
		if entry == nil {
			continue
		}
		var count int
		for _, key := range []string{"tokenCount", "token_count", "max_input_tokens", "maxInputTokens", "contextLength", "context_length"} {
			if v, present := entry[key]; present {
				count = qoderParseTierTokenCount(v)
				break
			}
		}
		if count == 0 {
			continue
		}
		isDefault := false
		for _, key := range []string{"isDefault", "is_default", "default"} {
			if b, _ := entry[key].(bool); b {
				isDefault = true
			}
		}
		if prev := byCount[count]; prev != nil {
			prev.isDefault = prev.isDefault || isDefault
		} else {
			byCount[count] = &qoderTier{name: qoderTierName(entry, count), tokenCount: count, isDefault: isDefault}
		}
	}
	var tiers []qoderTier
	for _, t := range byCount {
		tiers = append(tiers, *t)
	}
	sort.Slice(tiers, func(i, j int) bool { return tiers[i].tokenCount < tiers[j].tokenCount })
	return tiers
}

var qoderCJKRe = regexp.MustCompile(`[\x{1100}-\x{11ff}\x{2e80}-\x{9fff}\x{ac00}-\x{d7af}\x{f900}-\x{faff}\x{ff00}-\x{ffef}]`)

// qoderEstimateTokens ports estimateQoderPromptTokens: CJK chars ≈ 1
// token each, everything else ≈ 4 chars/token.
func qoderEstimateTokens(system string, messages []any, tools any) int {
	raw, err := marshalJSON(map[string]any{
		"system":   system,
		"messages": messages,
		"tools":    tools,
	})
	if err != nil {
		return 0
	}
	text := string(raw)
	cjk := len(qoderCJKRe.FindAllString(text, -1))
	total := len([]rune(text))
	return int(math.Ceil(float64(cjk) + float64(total-cjk)/4))
}

type qoderTierChoice struct {
	tier            qoderTier
	estimatedTokens int
	reason          string
}

// qoderResolveTier ports resolveQoderContextTier: nil means "leave the
// payload exactly as before".
func qoderResolveTier(modelConfig map[string]any, system string, messages []any, tools any, preference string) *qoderTierChoice {
	tiers := qoderGetTiers(modelConfig)
	if len(tiers) == 0 {
		return nil
	}
	mode := strings.TrimSpace(preference)
	if mode == "" {
		mode = "auto"
	}
	largest := tiers[len(tiers)-1]
	defaultTier := tiers[0]
	for _, t := range tiers {
		if t.isDefault {
			defaultTier = t
			break
		}
	}
	estimated := qoderEstimateTokens(system, messages, tools)
	need := int(math.Ceil(float64(estimated) * (1 + qoderContextTierHeadroom)))

	switch strings.ToLower(mode) {
	case "max":
		return &qoderTierChoice{tier: largest, estimatedTokens: estimated, reason: "forced:max"}
	case "default":
		return &qoderTierChoice{tier: defaultTier, estimatedTokens: estimated, reason: "forced:default"}
	case "auto":
		// fall through to auto below
	default:
		wanted := strings.ToUpper(strings.ReplaceAll(mode, " ", ""))
		asCount := qoderParseTierTokenCount(wanted)
		for _, t := range tiers {
			if strings.ToUpper(strings.ReplaceAll(t.name, " ", "")) == wanted || (asCount > 0 && t.tokenCount == asCount) {
				return &qoderTierChoice{tier: t, estimatedTokens: estimated, reason: "forced:" + t.name}
			}
		}
		// Unknown tier name → fall through to auto (JS behaviour).
	}

	currentMax := qoderParseTierTokenCount(modelConfig["max_input_tokens"])
	if currentMax == 0 {
		currentMax = qoderParseTierTokenCount(modelConfig["maxInputTokens"])
	}
	currentLimit := currentMax
	if currentLimit == 0 {
		currentLimit = defaultTier.tokenCount
	}
	if need <= currentLimit {
		return nil
	}
	var fits *qoderTier
	for i := range tiers {
		if tiers[i].tokenCount >= need && tiers[i].tokenCount > currentLimit {
			fits = &tiers[i]
			break
		}
	}
	chosen := largest
	reason := "auto:largest"
	if fits != nil {
		chosen = *fits
		reason = "auto:fits"
	}
	if chosen.tokenCount <= currentLimit {
		return nil
	}
	return &qoderTierChoice{tier: chosen, estimatedTokens: estimated, reason: reason}
}

// qoderApplyTier ports applyQoderContextTier: mirrors the IDE's three
// write sites for the chosen tier.
func qoderApplyTier(payload map[string]any, tier qoderTier) {
	params, _ := payload["parameters"].(map[string]any)
	if params == nil {
		params = map[string]any{}
		payload["parameters"] = params
	}
	params["context_length"] = tier.tokenCount

	chatCtx, _ := payload["chat_context"].(map[string]any)
	if chatCtx == nil {
		chatCtx = map[string]any{}
		payload["chat_context"] = chatCtx
	}
	extra, _ := chatCtx["extra"].(map[string]any)
	if extra == nil {
		extra = map[string]any{}
		chatCtx["extra"] = extra
	}
	override, _ := extra["ideModelConfigOverride"].(map[string]any)
	if override == nil {
		override = map[string]any{}
		extra["ideModelConfigOverride"] = override
	}
	override["max_input_tokens"] = tier.tokenCount

	if mc, _ := payload["model_config"].(map[string]any); mc != nil {
		cloned := cloneMap(mc)
		cloned["max_input_tokens"] = tier.tokenCount
		payload["model_config"] = cloned
	}
}

// --- attachment rewriting (shared/qoder/attachments.js) ---

var (
	qoderDataURIRe     = regexp.MustCompile(`^data:([^;]+);base64,([\s\S]+)$`)
	qoderDataURIInText = regexp.MustCompile(`data:[^;]+;base64,[A-Za-z0-9+/=\s]+`)
	qoderImageMimeRe   = regexp.MustCompile(`(?i)^image/`)
)

func qoderParseDataURI(s string) (mimeType, base64Data string, ok bool) {
	m := qoderDataURIRe.FindStringSubmatch(s)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

func qoderDecodedBytes(b64 string) int {
	compact := strings.Join(strings.Fields(b64), "")
	return int(math.Floor(float64(len(compact)) * 3 / 4))
}

func qoderMimeExt(mime string) string {
	m := strings.ToLower(mime)
	switch {
	case strings.Contains(m, "png"):
		return "png"
	case strings.Contains(m, "jpeg"), strings.Contains(m, "jpg"):
		return "jpg"
	case strings.Contains(m, "gif"):
		return "gif"
	case strings.Contains(m, "webp"):
		return "webp"
	case strings.Contains(m, "bmp"):
		return "bmp"
	case strings.Contains(m, "pdf"):
		return "pdf"
	}
	return "bin"
}

// qoderStubText ports stubText: "[file omitted: <label>(, N bytes) — <reason>]".
func qoderStubText(name, mime string, bytes int, reason string) string {
	label := name
	if label == "" {
		label = mime
	}
	if label == "" {
		label = "attachment"
	}
	size := ""
	if bytes > 0 {
		size = ", " + strconv.Itoa(bytes) + " bytes"
	}
	return "[file omitted: " + label + size + " — " + reason + "]"
}

type qoderUploadCtx struct {
	ctx    context.Context
	p      *ProviderInfo
	cred   Credential
	region string
	bases  qoderBaseSet
	cache  map[string]string // sha256 hex → uploaded URL (per request)
}

type qoderUploadOutcome struct {
	url   string
	keep  bool
	stub  bool
	bytes int
	mime  string
}

// qoderUploadImageData ports uploadImageData: cap-check, sha256 memo,
// upload, then keep-inline (≤512KB) or stub on failure.
func qoderUploadImageData(u *qoderUploadCtx, base64Data, mediaType string) qoderUploadOutcome {
	compact := strings.Join(strings.Fields(base64Data), "")
	if compact == "" {
		return qoderUploadOutcome{}
	}
	bytesEst := qoderDecodedBytes(compact)
	if bytesEst > qoderMaxImageBytes {
		return qoderUploadOutcome{stub: true, bytes: bytesEst, mime: mediaType}
	}
	buf, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		return qoderUploadOutcome{stub: true, bytes: bytesEst, mime: mediaType}
	}
	digest := sha256.Sum256(buf)
	digestHex := hex.EncodeToString(digest[:])
	if cached, ok := u.cache[digestHex]; ok {
		return qoderUploadOutcome{url: cached, bytes: bytesEst, mime: mediaType}
	}
	uploaded, uerr := qoderUploadImage(u, buf, mediaType)
	if uerr == nil && uploaded != "" {
		u.cache[digestHex] = uploaded
		return qoderUploadOutcome{url: uploaded, bytes: bytesEst, mime: mediaType}
	}
	if bytesEst <= qoderInlineFallbackMaxBytes {
		return qoderUploadOutcome{keep: true, bytes: bytesEst, mime: mediaType}
	}
	return qoderUploadOutcome{stub: true, bytes: bytesEst, mime: mediaType}
}

// qoderUploadImage ports defaultUploadImage: COSY-signed multipart PUT
// to /algo/api/v2/image/upload on the inference host.
func qoderUploadImage(u *qoderUploadCtx, buf []byte, mediaType string) (string, error) {
	requestID := newUUID()
	uploadURL := qoderInferenceBase(u.cred, u.region, u.bases) + "/algo" + qoderImageUploadPath + "?request_id=" + requestID

	if mediaType == "" {
		mediaType = "application/octet-stream"
	}
	// The JS buildMultipartFile writes the part's Content-Type
	// explicitly (mime/multipart's CreateFormFile would infer it from
	// the file name) — CreatePart with headers reproduces that shape.
	var bodyBuf bytes.Buffer
	mw := multipart.NewWriter(&bodyBuf)
	hdr := map[string][]string{
		"Content-Disposition": {fmt.Sprintf(`form-data; name="file"; filename="image.%s"`, qoderMimeExt(mediaType))},
		"Content-Type":        {mediaType},
	}
	part, err := mw.CreatePart(hdr)
	if err != nil {
		return "", err
	}
	if _, err := part.Write(buf); err != nil {
		return "", err
	}
	if err := mw.Close(); err != nil {
		return "", err
	}
	body := bodyBuf.Bytes()

	cosy, err := qoderBuildCosyHeaders(body, uploadURL, qoderCosyCredsFrom(u.cred))
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(u.ctx, http.MethodPut, uploadURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	for k, v := range cosy {
		req.Header.Set(k, v)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+mw.Boundary())
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	req.Header.Set("AI-CLIENT-TIMESTAMP", strconv.FormatInt(time.Now().Unix(), 10))
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, qoderTruncate(string(raw), 180))
	}
	var parsed map[string]any
	if uerr := unmarshalJSON(raw, &parsed); uerr != nil || parsed == nil {
		return "", errors.New("upload response missing url")
	}
	uploaded := qoderExtractUploadURL(parsed)
	if uploaded == "" {
		return "", errors.New("upload response missing url")
	}
	return uploaded, nil
}

// qoderExtractUploadURL ports extractUrlFromUploadResponse.
func qoderExtractUploadURL(obj map[string]any) string {
	if obj == nil {
		return ""
	}
	result := obj
	if r, _ := obj["result"].(map[string]any); r != nil {
		result = r
	}
	for _, arrVal := range []any{result["imageUrls"], result["image_urls"], obj["imageUrls"], obj["image_urls"]} {
		if arr, ok := arrVal.([]any); ok && len(arr) > 0 {
			if s, ok := arr[0].(string); ok && s != "" {
				return s
			}
		}
	}
	for _, key := range []string{"imageUrl", "image_url", "url", "ossUrl", "oss_url", "originalUrl", "originUrl", "link", "image"} {
		if s, ok := result[key].(string); ok && s != "" {
			return s
		}
		if s, ok := obj[key].(string); ok && s != "" {
			return s
		}
	}
	if bodyStr, ok := obj["body"].(string); ok {
		var inner map[string]any
		if uerr := unmarshalJSON([]byte(bodyStr), &inner); uerr == nil && inner != nil {
			return qoderExtractUploadURL(inner)
		}
	}
	return ""
}

func qoderImageURLBlock(rawURL string) map[string]any {
	return map[string]any{"type": "image_url", "image_url": map[string]any{"url": rawURL}}
}

func qoderTextBlock(text string) map[string]any {
	return map[string]any{"type": "text", "text": text}
}

// qoderRewriteBlock ports rewriteBlock. A nil return drops the block.
func qoderRewriteBlock(block map[string]any, u *qoderUploadCtx) map[string]any {
	typ := getStr(block, "type")

	if typ == "image_url" {
		var raw string
		switch v := block["image_url"].(type) {
		case string:
			raw = v
		case map[string]any:
			raw = getStr(v, "url")
		}
		if raw == "" {
			return nil
		}
		if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
			return qoderImageURLBlock(raw)
		}
		mime, b64, ok := qoderParseDataURI(raw)
		if !ok {
			return qoderTextBlock(qoderStubText("attachment", "", 0, "unreadable data URI"))
		}
		if !qoderImageMimeRe.MatchString(mime) {
			return qoderTextBlock(qoderStubText("file", mime, qoderDecodedBytes(b64), "non-image bytes are not inlined into Qoder context"))
		}
		up := qoderUploadImageData(u, b64, mime)
		if up.url != "" {
			return qoderImageURLBlock(up.url)
		}
		if up.keep {
			return qoderImageURLBlock(raw)
		}
		return qoderTextBlock(qoderStubText("image", mime, up.bytes, "upload failed; not inlined"))
	}

	if typ == "image" {
		src, _ := block["source"].(map[string]any)
		if src != nil {
			if getStr(src, "type") == "url" {
				if raw := getStr(src, "url"); raw != "" {
					return qoderImageURLBlock(raw)
				}
			}
			if getStr(src, "type") == "base64" {
				if data := getStr(src, "data"); data != "" {
					mime := getStr(src, "media_type")
					if mime == "" {
						mime = "image/png"
					}
					up := qoderUploadImageData(u, data, mime)
					if up.url != "" {
						return qoderImageURLBlock(up.url)
					}
					if up.keep {
						return qoderImageURLBlock("data:" + mime + ";base64," + data)
					}
					return qoderTextBlock(qoderStubText("image", mime, up.bytes, "upload failed; not inlined"))
				}
			}
		}
	}

	if typ == "file" {
		if file, _ := block["file"].(map[string]any); file != nil {
			name := getStr(file, "filename")
			if name == "" {
				name = getStr(file, "name")
			}
			if name == "" {
				name = "file"
			}
			var b64, mime string
			if fileData := getStr(file, "file_data"); fileData != "" {
				if m, b, ok := qoderParseDataURI(fileData); ok {
					mime, b64 = m, b
				} else if !strings.HasPrefix(fileData, "data:") {
					b64 = fileData
				}
			}
			if mime == "" {
				mime = getStr(file, "format")
			}
			if mime == "" {
				mime = "application/octet-stream"
			}
			if b64 != "" && qoderImageMimeRe.MatchString(mime) {
				up := qoderUploadImageData(u, b64, mime)
				if up.url != "" {
					return qoderImageURLBlock(up.url)
				}
			}
			return qoderTextBlock(qoderStubText(name, mime, qoderDecodedBytes(b64), "Qoder reads documents via its file API, not inlined bytes"))
		}
	}

	if typ == "document" {
		if src, _ := block["source"].(map[string]any); src != nil {
			name := getStr(block, "title")
			if name == "" {
				name = "document"
			}
			if getStr(src, "type") == "base64" {
				if data := getStr(src, "data"); data != "" {
					mime := getStr(src, "media_type")
					if mime == "" {
						mime = "application/pdf"
					}
					if qoderImageMimeRe.MatchString(mime) {
						up := qoderUploadImageData(u, data, mime)
						if up.url != "" {
							return qoderImageURLBlock(up.url)
						}
					}
					return qoderTextBlock(qoderStubText(name, mime, qoderDecodedBytes(data), "Qoder reads documents via its file API, not inlined bytes"))
				}
			}
		}
	}

	if text, ok := block["text"].(string); ok && strings.Contains(text, "data:") && len(text) > 8192 {
		next := qoderDataURIInText.ReplaceAllStringFunc(text, func(m string) string {
			mime, b64, parsed := qoderParseDataURI(strings.TrimSpace(m))
			bytesEst := len(m)
			if parsed {
				bytesEst = qoderDecodedBytes(b64)
			}
			if bytesEst <= qoderInlineFallbackMaxBytes {
				return m
			}
			return qoderStubText("", mime, bytesEst, "inlined data URI stripped from Qoder context")
		})
		out := cloneMap(block)
		out["text"] = next
		return out
	}

	return block
}

// qoderRewriteContent ports rewriteContent.
func qoderRewriteContent(content any, u *qoderUploadCtx) any {
	if s, ok := content.(string); ok {
		if strings.Contains(s, "data:") && len(s) > 8192 {
			return qoderDataURIInText.ReplaceAllStringFunc(s, func(m string) string {
				mime, b64, parsed := qoderParseDataURI(strings.TrimSpace(m))
				bytesEst := len(m)
				if parsed {
					bytesEst = qoderDecodedBytes(b64)
				}
				if bytesEst <= qoderInlineFallbackMaxBytes {
					return m
				}
				return qoderStubText("", mime, bytesEst, "inlined data URI stripped from Qoder context")
			})
		}
		return s
	}
	items, ok := content.([]any)
	if !ok {
		return content
	}
	var out []any
	for _, raw := range items {
		block, _ := raw.(map[string]any)
		if block == nil {
			out = append(out, raw)
			continue
		}
		next := qoderRewriteBlock(block, u)
		if next == nil {
			continue
		}
		out = append(out, next)
	}
	if len(out) == 0 {
		return ""
	}
	return out
}

// qoderRewriteAttachments ports rewriteQoderMessageAttachments: upload
// inlined images, stub huge files, then enforce the 6MB payload budget.
// Mutates the (already cloned) messages in place; fail-open like the JS
// call site (errors are logged-and-continued there — here the upload
// helper itself degrades to keep/stub, so nothing here can fail).
func qoderRewriteAttachments(u *qoderUploadCtx, messages []any) {
	for _, raw := range messages {
		msg, _ := raw.(map[string]any)
		if msg == nil {
			continue
		}
		if images, ok := msg["images"].([]any); ok {
			// Ollama-style sidecar: fold into content so normalize sees it.
			var extras []any
			for _, img := range images {
				extras = append(extras, qoderImageURLBlock(qoderJSString(img)))
			}
			if content, isArr := msg["content"].([]any); isArr {
				msg["content"] = append(append([]any{}, content...), extras...)
			} else {
				text := ""
				if s, isStr := msg["content"].(string); isStr {
					text = s
				}
				msg["content"] = append([]any{qoderTextBlock(text)}, extras...)
			}
			delete(msg, "images")
		}
		msg["content"] = qoderRewriteContent(msg["content"], u)
	}
	if raw, err := marshalJSON(messages); err == nil && len(raw) > qoderMaxPayloadBytes {
		qoderStripRemainingDataURIs(messages)
	}
}

// qoderStripRemainingDataURIs ports stripRemainingDataUris (the
// over-budget last resort).
func qoderStripRemainingDataURIs(messages []any) {
	for _, raw := range messages {
		msg, _ := raw.(map[string]any)
		if msg == nil {
			continue
		}
		if s, ok := msg["content"].(string); ok && strings.Contains(s, "data:") {
			msg["content"] = qoderDataURIInText.ReplaceAllStringFunc(s, func(m string) string {
				return qoderStubText("", "", len(m), "payload over Qoder size budget")
			})
			continue
		}
		items, ok := msg["content"].([]any)
		if !ok {
			continue
		}
		for i, rawBlock := range items {
			block, _ := rawBlock.(map[string]any)
			if block == nil {
				continue
			}
			if getStr(block, "type") == "image_url" {
				var rawURL string
				switch v := block["image_url"].(type) {
				case string:
					rawURL = v
				case map[string]any:
					rawURL = getStr(v, "url")
				}
				if strings.HasPrefix(rawURL, "data:") {
					items[i] = qoderTextBlock(qoderStubText("image", "", 0, "payload over Qoder size budget"))
					continue
				}
			}
			if text, ok := block["text"].(string); ok && strings.Contains(text, "data:") {
				cloned := cloneMap(block)
				cloned["text"] = qoderDataURIInText.ReplaceAllStringFunc(text, func(m string) string {
					return qoderStubText("", "", len(m), "payload over Qoder size budget")
				})
				items[i] = cloned
			}
		}
	}
}

// --- model catalog + PAT resolution (services/qoderModels.js) ---

type qoderCatalog struct {
	expiresAt  time.Time
	rawConfigs map[string]map[string]any
}

var (
	qoderCatalogMu    sync.Mutex
	qoderCatalogCache = map[string]*qoderCatalog{}
)

type qoderPatEntry struct {
	accessToken string
	userID      string
	expiresAt   time.Time
}

var (
	qoderPatMu    sync.Mutex
	qoderPatCache = map[string]*qoderPatEntry{}
)

// qoderClearCachesForTest resets both caches (tests only).
func qoderClearCachesForTest() {
	qoderCatalogMu.Lock()
	qoderCatalogCache = map[string]*qoderCatalog{}
	qoderCatalogMu.Unlock()
	qoderPatMu.Lock()
	qoderPatCache = map[string]*qoderPatEntry{}
	qoderPatMu.Unlock()
}

// qoderCacheKey ports cacheKey: sha256 of "qoder:<region>:<seed>" where
// the seed is userId ‖ refreshToken ‖ accessToken.
func qoderCacheKey(cred Credential, region string) string {
	seed := cred.SpecificString("userId")
	if seed == "" {
		seed = cred.RefreshToken
	}
	if seed == "" {
		seed = cred.AccessToken
	}
	if seed == "" {
		seed = "anonymous"
	}
	sum := sha256.Sum256([]byte("qoder:" + region + ":" + seed))
	return hex.EncodeToString(sum[:])
}

func qoderIsPAT(token string) bool { return strings.HasPrefix(token, "pt-") }

// qoderExchangeJobToken ports exchangeJobToken: PAT → job token via a
// plain (unsigned) JSON POST to the region's openApi host.
func qoderExchangeJobToken(ctx context.Context, p *ProviderInfo, region, pat string) (*qoderPatEntry, error) {
	bases := qoderBasesFor(p, region)
	exchangeURL := bases.openAPI + "/api/v1/jobToken/exchange"
	body, _ := marshalJSON(map[string]any{"personal_token": pat})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, exchangeURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "qodercli/1.0.0")
	req.Header.Set("Cosy-Version", qoderIDEVersion)
	req.Header.Set("Cosy-ClientType", qoderClientType)
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("qoder PAT exchange failed: %d %s", resp.StatusCode, qoderTruncate(string(raw), 200))
	}
	var data map[string]any
	if uerr := unmarshalJSON(raw, &data); uerr != nil || data == nil {
		return nil, errors.New("qoder PAT exchange returned no job token")
	}
	jobToken := getStr(data, "token")
	if jobToken == "" {
		return nil, errors.New("qoder PAT exchange returned no job token")
	}
	expiresAt := time.Now().Add(qoderPatDefaultTTL)
	if s := getStr(data, "expires_at"); s != "" {
		if parsed, perr := time.Parse(time.RFC3339, s); perr == nil {
			expiresAt = parsed
		}
	} else if n, ok := qoderNum(data["expires_in"]); ok && n > 0 {
		// JS: Date.now() + data.expires_in — the raw value is added as
		// milliseconds; ported as-is.
		expiresAt = time.Now().Add(time.Duration(n) * time.Millisecond)
	}
	return &qoderPatEntry{accessToken: jobToken, expiresAt: expiresAt}, nil
}

// qoderFetchUserIDForJobToken ports fetchUserIdForJobToken ("" on any
// failure — callers fall back to the stored userId).
func qoderFetchUserIDForJobToken(ctx context.Context, p *ProviderInfo, region, jobToken string) string {
	bases := qoderBasesFor(p, region)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, bases.openAPI+"/api/v1/userinfo", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+jobToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "qodercli/1.0.0")
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ""
	}
	var data map[string]any
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if uerr := unmarshalJSON(raw, &data); uerr != nil || data == nil {
		return ""
	}
	if s := getStr(data, "id"); s != "" {
		return s
	}
	if s := getStr(data, "userId"); s != "" {
		return s
	}
	return getStr(data, "user_id")
}

// qoderResolveCredentials ports resolveQoderCredentials: PAT
// connections are exchanged (and cached) into job-token credentials;
// everything else passes through unchanged.
func qoderResolveCredentials(ctx context.Context, p *ProviderInfo, cred Credential, region string) (Credential, error) {
	raw := cred.APIKey
	if raw == "" {
		raw = cred.AccessToken
	}
	if !qoderIsPAT(raw) {
		return cred, nil
	}
	cacheKey := region + ":" + raw
	qoderPatMu.Lock()
	cached := qoderPatCache[cacheKey]
	qoderPatMu.Unlock()
	if cached != nil && time.Until(cached.expiresAt) > qoderPatRefreshBuffer {
		return qoderApplyPatEntry(cred, cached), nil
	}
	entry, err := qoderExchangeJobToken(ctx, p, region, raw)
	if err != nil {
		return cred, err
	}
	entry.userID = qoderFetchUserIDForJobToken(ctx, p, region, entry.accessToken)
	qoderPatMu.Lock()
	qoderPatCache[cacheKey] = entry
	qoderPatMu.Unlock()
	return qoderApplyPatEntry(cred, entry), nil
}

func qoderApplyPatEntry(cred Credential, entry *qoderPatEntry) Credential {
	out := cred
	out.AccessToken = entry.accessToken
	out.APIKey = "" // JS sets apiKey: undefined
	specific := map[string]any{}
	for k, v := range cred.Specific {
		specific[k] = v
	}
	if entry.userID != "" {
		specific["userId"] = entry.userID
	}
	out.Specific = specific
	return out
}

// qoderFetchCatalogRaw ports fetchQoderCatalogRaw: COSY-signed GET of
// /algo/api/v2/model/list on the inference host. The raw per-key config
// blocks are cached for every entry (even enable:false ones — upstream
// still accepts chat for those keys).
func qoderFetchCatalogRaw(ctx context.Context, p *ProviderInfo, cred Credential, region string) *qoderCatalog {
	cosyCreds := qoderCosyCredsFrom(cred)
	if cosyCreds.userID == "" || cosyCreds.authToken == "" {
		return nil
	}
	bases := qoderBasesFor(p, region)
	listURL := qoderInferenceBase(cred, region, bases) + "/algo/api/v2/model/list"
	cosy, err := qoderBuildCosyHeaders(nil, listURL, cosyCreds)
	if err != nil {
		return nil
	}
	fetchCtx, cancel := context.WithTimeout(ctx, qoderFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, listURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	for k, v := range cosy {
		req.Header.Set(k, v)
	}
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil
	}
	var bodyMap map[string]any
	if uerr := unmarshalJSON(raw, &bodyMap); uerr != nil || bodyMap == nil {
		return nil
	}
	chat, _ := bodyMap["chat"].([]any)
	if chat == nil {
		return nil
	}
	cat := &qoderCatalog{rawConfigs: map[string]map[string]any{}}
	for _, rawEntry := range chat {
		entry, _ := rawEntry.(map[string]any)
		if entry == nil {
			continue
		}
		key := getStr(entry, "key")
		if key == "" {
			continue
		}
		cat.rawConfigs[key] = entry
	}
	return cat
}

// qoderResolveModels ports resolveQoderModels: 1h cache per
// credential+region. Concurrent misses are serialised by the cache
// mutex, which gives the JS inflight-promise the same single-flight
// effect (one upstream fetch per credential; waiters share the entry).
func qoderResolveModels(ctx context.Context, p *ProviderInfo, cred Credential, region string, forceRefresh bool) *qoderCatalog {
	if cred.AccessToken == "" || cred.SpecificString("userId") == "" {
		return nil
	}
	key := qoderCacheKey(cred, region)
	qoderCatalogMu.Lock()
	defer qoderCatalogMu.Unlock()
	if !forceRefresh {
		if cached := qoderCatalogCache[key]; cached != nil && cached.expiresAt.After(time.Now()) {
			return cached
		}
	}
	fetched := qoderFetchCatalogRaw(ctx, p, cred, region)
	if fetched == nil {
		return nil
	}
	fetched.expiresAt = time.Now().Add(qoderCatalogTTL)
	qoderCatalogCache[key] = fetched
	return fetched
}

// qoderGetModelConfig ports getQoderModelConfig: a defensive copy of
// the cached config with `key` aligned to the requested alias.
func qoderGetModelConfig(ctx context.Context, p *ProviderInfo, cred Credential, region, modelKey string) map[string]any {
	cat := qoderResolveModels(ctx, p, cred, region, false)
	if cat == nil {
		return nil
	}
	cfg, ok := cat.rawConfigs[modelKey]
	if !ok || cfg == nil {
		return nil
	}
	out := cloneMap(cfg)
	out["key"] = modelKey
	return out
}

// --- request body building (qoder.js buildQoderRequestBody) ---

type qoderBuiltBody struct {
	key         string
	payload     map[string]any
	modelConfig map[string]any
}

func qoderCloneMessages(raw any) []any {
	items, _ := raw.([]any)
	if items == nil {
		return nil
	}
	out := make([]any, 0, len(items))
	for _, item := range items {
		msg, _ := item.(map[string]any)
		if msg == nil {
			out = append(out, item)
			continue
		}
		cloned := cloneMap(msg)
		if content, ok := msg["content"].([]any); ok {
			copied := make([]any, 0, len(content))
			for _, block := range content {
				if bm, _ := block.(map[string]any); bm != nil {
					copied = append(copied, cloneMap(bm))
				} else {
					copied = append(copied, block)
				}
			}
			cloned["content"] = copied
		}
		out = append(out, cloned)
	}
	return out
}

// qoderBuildRequestBody ports buildQoderRequestBody: map the OpenAI
// body into the exact shape Qoder expects.
func qoderBuildRequestBody(ctx context.Context, p *ProviderInfo, cred Credential, region, model string, bodyMap map[string]any) (*qoderBuiltBody, error) {
	qoderKey := strings.TrimPrefix(model, "qoder/")

	modelConfig := qoderGetModelConfig(ctx, p, cred, region, qoderKey)
	if modelConfig == nil {
		// One forced refresh before giving up — the cache may simply
		// not be populated yet on the first ever call.
		if cat := qoderResolveModels(ctx, p, cred, region, true); cat != nil {
			if cfg := cat.rawConfigs[qoderKey]; cfg != nil {
				modelConfig = cloneMap(cfg)
				modelConfig["key"] = qoderKey
			}
		}
	}
	if modelConfig == nil {
		return nil, fmt.Errorf("qoder: model_config for %q not yet known (run a model list fetch or check upstream connectivity)", qoderKey)
	}

	incoming := qoderCloneMessages(bodyMap["messages"])
	if incoming == nil {
		incoming = []any{}
	}
	bases := qoderBasesFor(p, region)
	uploadCtx := &qoderUploadCtx{ctx: ctx, p: p, cred: cred, region: region, bases: bases, cache: map[string]string{}}
	// The JS wraps the rewrite in try/catch (fail-open); the Go rewrite
	// degrades per-block (keep/stub) and cannot fail the request.
	qoderRewriteAttachments(uploadCtx, incoming)

	messages, systemText := qoderNormalizeMessages(incoming)
	tools := bodyMap["tools"]
	isReasoning, _ := modelConfig["is_reasoning"].(bool)
	maxOutputTokens := 0
	if n, ok := qoderNum(modelConfig["max_output_tokens"]); ok {
		maxOutputTokens = int(n)
	}

	maxTokens := 32768
	if maxOutputTokens > 0 {
		maxTokens = maxOutputTokens
	}
	if n, ok := qoderNum(bodyMap["max_tokens"]); ok && n > 0 && int(n) < maxTokens {
		maxTokens = int(n)
	}
	if n, ok := qoderNum(bodyMap["max_completion_tokens"]); ok && n > 0 && int(n) < maxTokens {
		maxTokens = int(n)
	}

	lastUser := qoderLastUserText(messages)
	sessionID := qoderStableHash("qoder-session", cred.SpecificString("userId"), qoderKey)
	recordID := qoderStableChatRecordID(qoderKey, messages, tools, maxTokens)

	// Context-window tier: escalate when the prompt no longer fits the
	// model's current tier (env override QODER_CONTEXT_TIER).
	tierChoice := qoderResolveTier(modelConfig, systemText, messages, tools, os.Getenv(qoderContextTierEnv))

	payloadTools := tools
	if _, isArr := tools.([]any); !isArr {
		payloadTools = []any{}
	}
	payload := map[string]any{
		"request_id":       newUUID(),
		"request_set_id":   recordID,
		"chat_record_id":   recordID,
		"session_id":       sessionID,
		"stream":           true,
		"chat_task":        "FREE_INPUT",
		"is_reply":         true,
		"is_retry":         false,
		"source":           1,
		"version":          "3",
		"session_type":     "qodercli",
		"agent_id":         "agent_common",
		"task_id":          "common",
		"code_language":    "",
		"chat_prompt":      "",
		"image_urls":       nil,
		"aliyun_user_type": "",
		"system":           systemText,
		"messages":         messages,
		"tools":            payloadTools,
		"parameters":       map[string]any{"max_tokens": maxTokens},
		"chat_context": map[string]any{
			"chatPrompt": "",
			"imageUrls":  nil,
			"extra": map[string]any{
				"context": []any{},
				"modelConfig": map[string]any{
					"key":          qoderKey,
					"is_reasoning": isReasoning,
				},
				"originalContent": lastUser,
			},
			"features": []any{},
			"text":     lastUser,
		},
		"model_config": modelConfig,
		"business": map[string]any{
			"product":  "cli",
			"version":  "1.0.0",
			"type":     "agent",
			"stage":    "start",
			"id":       newUUID(),
			"name":     qoderTruncate(lastUser, 30),
			"begin_at": time.Now().UnixMilli(),
		},
	}
	if tierChoice != nil {
		qoderApplyTier(payload, tierChoice.tier)
	}
	return &qoderBuiltBody{key: qoderKey, payload: payload, modelConfig: modelConfig}, nil
}

// qoderIsBillingBlock ports isBillingBlock: pricingUrl marker, parsed
// code 110/112/10605, or the legacy exact JSON shapes.
func qoderIsBillingBlock(inner string) bool {
	if inner == "" {
		return false
	}
	if strings.Contains(strings.ToLower(inner), "pricingurl") {
		return true
	}
	var parsed map[string]any
	if uerr := unmarshalJSON([]byte(inner), &parsed); uerr == nil && parsed != nil {
		code := qoderJSString(parsed["code"])
		if code == "110" || code == "112" || code == "10605" {
			return true
		}
	}
	return qoderBillingLegacyRe.MatchString(inner)
}

var qoderBillingLegacyRe = regexp.MustCompile(`"code"\s*:\s*"(112|10605)"`)

// --- SSE coalescer (shared/qoder/sse.js) ---
//
// Qoder puts finish_reason on the delta and sends token counts on a
// later choices:[] frame; downstream clients only read usage from the
// finish chunk, so finish + usage are coalesced into one terminal
// include_usage-style chunk.

func qoderCanonicalUsage(usage map[string]any) map[string]any {
	if usage == nil {
		return nil
	}
	prompt, hasPrompt := qoderNum(usage["prompt_tokens"])
	if !hasPrompt {
		prompt, hasPrompt = qoderNum(usage["input_tokens"])
	}
	completion, hasCompletion := qoderNum(usage["completion_tokens"])
	if !hasCompletion {
		completion, hasCompletion = qoderNum(usage["output_tokens"])
	}
	if !hasPrompt && !hasCompletion {
		return nil
	}
	details := map[string]any{}
	if d, _ := usage["prompt_tokens_details"].(map[string]any); d != nil {
		for k, v := range d {
			details[k] = v
		}
	}
	cached, hasCached := qoderNum(details["cached_tokens"])
	if !hasCached {
		cached, hasCached = qoderNum(usage["cached_tokens"])
	}
	if !hasCached {
		cached, hasCached = qoderNum(usage["prompt_cache_hit_tokens"])
	}
	if !hasCached {
		cached, hasCached = qoderNum(usage["cache_read_input_tokens"])
	}
	cacheCreation, hasCacheCreation := qoderNum(details["cache_creation_tokens"])
	if !hasCacheCreation {
		cacheCreation, hasCacheCreation = qoderNum(usage["cache_creation_input_tokens"])
	}
	promptTokens, completionTokens := prompt, completion
	total, hasTotal := qoderNum(usage["total_tokens"])
	if !hasTotal {
		total = promptTokens + completionTokens
	}
	out := map[string]any{
		"prompt_tokens":     promptTokens,
		"completion_tokens": completionTokens,
		"total_tokens":      total,
	}
	if hasCached {
		out["cached_tokens"] = cached
		details["cached_tokens"] = cached
	}
	if hasCacheCreation {
		details["cache_creation_tokens"] = cacheCreation
	}
	if len(details) > 0 {
		out["prompt_tokens_details"] = details
	}
	if d, _ := usage["completion_tokens_details"].(map[string]any); d != nil {
		out["completion_tokens_details"] = d
	}
	reasoning, hasReasoning := qoderNum(usage["reasoning_tokens"])
	if !hasReasoning {
		if d, _ := usage["completion_tokens_details"].(map[string]any); d != nil {
			reasoning, hasReasoning = qoderNum(d["reasoning_tokens"])
		}
	}
	if hasReasoning {
		out["reasoning_tokens"] = reasoning
	}
	return out
}

func qoderFinishReasonOf(parsed map[string]any) string {
	choices, _ := parsed["choices"].([]any)
	if len(choices) > 0 {
		if choice, _ := choices[0].(map[string]any); choice != nil {
			if fr := getStr(choice, "finish_reason"); fr != "" {
				return fr
			}
			if delta, _ := choice["delta"].(map[string]any); delta != nil {
				if fr := getStr(delta, "finish_reason"); fr != "" {
					return fr
				}
			}
		}
	}
	return getStr(parsed, "finish_reason")
}

func qoderHasValuableDelta(parsed map[string]any) bool {
	choices, _ := parsed["choices"].([]any)
	if len(choices) == 0 {
		return false
	}
	choice, _ := choices[0].(map[string]any)
	if choice == nil {
		return false
	}
	delta, _ := choice["delta"].(map[string]any)
	if delta == nil {
		return false
	}
	if s, ok := delta["content"].(string); ok && s != "" {
		return true
	}
	if s, ok := delta["reasoning_content"].(string); ok && s != "" {
		return true
	}
	if arr, ok := delta["tool_calls"].([]any); ok && len(arr) > 0 {
		return true
	}
	if delta["role"] != nil {
		return true
	}
	return false
}

type qoderCoalescer struct {
	model            string
	pendingFinish    string
	hasPendingFinish bool
	pendingUsage     map[string]any
	lastID           string
	lastCreated      float64
	hasCreated       bool
	lastModel        string
	doneEmitted      bool
	finishForwarded  bool
}

func qoderEmitJSONFrame(emit func(string), obj map[string]any) {
	raw, err := marshalJSON(obj)
	if err != nil {
		return
	}
	emit("data: " + string(raw) + "\n\n")
}

func (c *qoderCoalescer) emitDone(emit func(string)) {
	if c.doneEmitted {
		return
	}
	emit("data: [DONE]\n\n")
	c.doneEmitted = true
}

func (c *qoderCoalescer) emitTerminal(emit func(string)) {
	if !c.hasPendingFinish && c.pendingUsage == nil {
		return
	}
	id := c.lastID
	if id == "" {
		id = fmt.Sprintf("qoder-%d", time.Now().UnixMilli())
	}
	created := c.lastCreated
	if !c.hasCreated {
		created = float64(time.Now().Unix())
	}
	model := c.lastModel
	if model == "" {
		model = c.model
	}
	finish := c.pendingFinish
	if !c.hasPendingFinish || finish == "" {
		finish = "stop"
	}
	chunk := map[string]any{
		"id":      id,
		"object":  "chat.completion.chunk",
		"created": created,
		"model":   model,
		"choices": []any{map[string]any{
			"index":         0,
			"delta":         map[string]any{},
			"finish_reason": finish,
		}},
	}
	if c.pendingUsage != nil {
		chunk["usage"] = c.pendingUsage
	}
	qoderEmitJSONFrame(emit, chunk)
	c.pendingFinish, c.hasPendingFinish = "", false
	c.pendingUsage = nil
}

// flush ports the coalescer flush: terminal chunk (when warranted) +
// [DONE], exactly once.
func (c *qoderCoalescer) flush(emit func(string)) {
	if c.doneEmitted {
		return
	}
	if c.pendingUsage != nil || (c.hasPendingFinish && !c.finishForwarded) {
		c.emitTerminal(emit)
	}
	c.emitDone(emit)
}

// handleInner ports handleInner for one unwrapped envelope body.
func (c *qoderCoalescer) handleInner(inner string, emit func(string)) {
	if c.doneEmitted {
		return
	}
	if inner == "[DONE]" {
		c.flush(emit)
		return
	}
	var parsed map[string]any
	if uerr := unmarshalJSON([]byte(inner), &parsed); uerr != nil || parsed == nil {
		// Raw (non-JSON) inner text is forwarded as-is (JS emitRaw).
		emit("data: " + strings.ReplaceAll(inner, "\n", "") + "\n\n")
		return
	}
	if s := getStr(parsed, "id"); s != "" {
		c.lastID = s
	}
	if n, ok := qoderNum(parsed["created"]); ok {
		c.lastCreated, c.hasCreated = n, true
	}
	if s := getStr(parsed, "model"); s != "" {
		c.lastModel = s
	}
	if usageRaw, _ := parsed["usage"].(map[string]any); usageRaw != nil {
		if usage := qoderCanonicalUsage(usageRaw); usage != nil {
			c.pendingUsage = usage
		}
	}
	finish := qoderFinishReasonOf(parsed)
	if qoderHasValuableDelta(parsed) {
		emit("data: " + strings.ReplaceAll(inner, "\n", "") + "\n\n")
		if finish != "" {
			c.finishForwarded = true
			if c.pendingUsage != nil {
				c.pendingFinish, c.hasPendingFinish = finish, true
			} else {
				c.pendingFinish, c.hasPendingFinish = "", false
			}
		}
		if c.hasPendingFinish && c.pendingUsage != nil {
			c.emitTerminal(emit)
			c.emitDone(emit)
		}
		return
	}
	if finish != "" {
		c.pendingFinish, c.hasPendingFinish = finish, true
	}
	if (c.hasPendingFinish || c.finishForwarded) && c.pendingUsage != nil {
		if !c.hasPendingFinish {
			c.pendingFinish, c.hasPendingFinish = "stop", true
		}
		c.emitTerminal(emit)
		c.emitDone(emit)
	}
}

// --- envelope unwrapping (qoder.js wrapQoderSSE + peekFirstQoderFrame) ---

func qoderEnvelopeInner(env map[string]any) string {
	switch b := env["body"].(type) {
	case string:
		return b
	case nil:
		return ""
	default:
		raw, err := marshalJSON(b)
		if err != nil {
			return ""
		}
		return string(raw)
	}
}

// qoderEnvelopeStatusPeek ports the peek's status read: Number(x), NaN →
// 200 (a literal 0 is kept, like the JS).
func qoderEnvelopeStatusPeek(env map[string]any) int {
	v, present := env["statusCodeValue"]
	if !present || v == nil {
		return 200
	}
	if n, ok := qoderNum(v); ok {
		return int(n)
	}
	return 200
}

// qoderEnvelopeStatusStream ports the streaming path's status read:
// Number(x) || 200.
func qoderEnvelopeStatusStream(env map[string]any) int {
	if n, ok := qoderNum(env["statusCodeValue"]); ok && n != 0 {
		return int(n)
	}
	return 200
}

type qoderPeek struct {
	isError      bool
	isBilling    bool
	statusVal    int
	message      string
	lines        [][]byte // every byte read, for re-processing
	upstreamDone bool
}

// qoderPeekFirstFrame ports peekFirstQoderFrame: scan lines until the
// first data: frame decides whether the stream starts with an error.
// All consumed lines are preserved for the streaming pass.
func qoderPeekFirstFrame(br *bufio.Reader) qoderPeek {
	var peek qoderPeek
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			peek.lines = append(peek.lines, line)
		}
		eof := err != nil
		if len(line) > 0 {
			trimmed := strings.TrimSpace(string(line))
			if strings.HasPrefix(trimmed, "data:") {
				data := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
				if data == "[DONE]" {
					peek.upstreamDone = eof
					return peek
				}
				var env map[string]any
				if uerr := unmarshalJSON([]byte(data), &env); uerr != nil || env == nil {
					peek.upstreamDone = eof
					return peek
				}
				statusVal := qoderEnvelopeStatusPeek(env)
				inner := qoderEnvelopeInner(env)
				if statusVal != 200 {
					peek.isError = true
					peek.isBilling = qoderIsBillingBlock(inner)
					peek.statusVal = statusVal
					peek.message = inner
					if peek.message == "" {
						peek.message = fmt.Sprintf("upstream status %d", statusVal)
					}
					return peek
				}
				peek.upstreamDone = eof
				return peek
			}
		}
		if eof {
			peek.upstreamDone = true
			return peek
		}
	}
}

// qoderConvertStream re-processes the peeked lines, then drains the
// reader, unwrapping envelopes until a terminal frame (see the JS
// comment: Qoder keeps the socket open after [DONE], so the stream is
// closed eagerly instead of waiting for upstream keepalive).
func qoderConvertStream(br *bufio.Reader, peek qoderPeek, w io.Writer, model string) {
	emit := func(frame string) { _, _ = io.WriteString(w, frame) }
	coal := &qoderCoalescer{model: model, lastModel: model}
	done := false
	syncDone := func() {
		if coal.doneEmitted {
			done = true
		}
	}
	processLine := func(line []byte) {
		if done {
			return
		}
		trimmed := strings.TrimSpace(string(line))
		if trimmed == "" || !strings.HasPrefix(trimmed, "data:") {
			return
		}
		data := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
		if data == "[DONE]" {
			coal.flush(emit)
			syncDone()
			return
		}
		var env map[string]any
		if uerr := unmarshalJSON([]byte(data), &env); uerr != nil || env == nil {
			return
		}
		statusVal := qoderEnvelopeStatusStream(env)
		inner := qoderEnvelopeInner(env)
		if statusVal != 200 {
			if qoderIsBillingBlock(inner) {
				msg := inner
				if msg == "" {
					msg = fmt.Sprintf("qoder billing block (%d)", statusVal)
				}
				qoderEmitJSONFrame(emit, map[string]any{
					"error": map[string]any{
						"message": msg,
						"code":    "qoder_billing_block",
						"status":  403,
						"type":    "quota_error",
					},
				})
				emit("data: [DONE]\n\n")
				done = true
				return
			}
			msg := inner
			if msg == "" {
				msg = fmt.Sprintf("upstream status %d", statusVal)
			}
			now := time.Now()
			qoderEmitJSONFrame(emit, map[string]any{
				"id":      fmt.Sprintf("qoder-error-%d", now.UnixMilli()),
				"object":  "chat.completion.chunk",
				"created": now.Unix(),
				"model":   model,
				"choices": []any{map[string]any{
					"index": 0,
					"delta": map[string]any{
						"content": fmt.Sprintf("\n[qoder error %d: %s]", statusVal, qoderTruncate(msg, 200)),
					},
					"finish_reason": "stop",
				}},
			})
			emit("data: [DONE]\n\n")
			done = true
			return
		}
		if inner == "" {
			return
		}
		coal.handleInner(inner, emit)
		syncDone()
	}

	for _, line := range peek.lines {
		processLine(line)
		if done {
			return
		}
	}
	if peek.upstreamDone {
		if !done {
			coal.flush(emit)
		}
		return
	}
	for !done {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			processLine(line)
		}
		if err != nil {
			break
		}
	}
	if !done {
		coal.flush(emit)
	}
}

// qoderWrapSSE ports wrapQoderSSE: peek the first frame for errors
// before committing to a 200 stream; billing blocks map to 403, other
// upstream statuses pass through (or 502 when out of range).
func qoderWrapSSE(resp *http.Response, model string) *http.Response {
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || resp.Body == nil {
		return resp
	}
	br := bufio.NewReaderSize(resp.Body, 32*1024)
	peek := qoderPeekFirstFrame(br)
	if peek.isError {
		resp.Body.Close()
		status := http.StatusBadGateway
		if peek.isBilling {
			status = http.StatusForbidden
		} else if peek.statusVal >= 400 && peek.statusVal <= 599 {
			status = peek.statusVal
		}
		body, _ := marshalJSON(map[string]any{
			"error": map[string]any{"message": peek.message, "code": peek.statusVal},
		})
		return &http.Response{
			StatusCode: status,
			Status:     http.StatusText(status),
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(body)),
		}
	}
	pr, pw := io.Pipe()
	go func() {
		qoderConvertStream(br, peek, pw, model)
		resp.Body.Close()
		_ = pw.Close()
	}()
	return &http.Response{
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Header: http.Header{
			"Content-Type":  []string{"text/event-stream"},
			"Cache-Control": []string{"no-cache"},
		},
		Body: pr,
	}
}

// qoderSyntheticResponse builds the JS `fakeResp` shape: a JSON
// {error:{message}} response returned without touching upstream.
func qoderSyntheticResponse(status int, message string) *http.Response {
	body, _ := marshalJSON(map[string]any{"error": map[string]any{"message": message}})
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

// --- execute ---

func (e *QoderExecutor) Execute(ctx context.Context, p *ProviderInfo, cred Credential, body []byte) (*ExecResult, error) {
	if p == nil {
		p = &ProviderInfo{ID: e.providerID}
	}
	bodyMap, _ := decodeBody(body)
	if bodyMap == nil {
		bodyMap = map[string]any{}
	}
	model := ModelOf(bodyMap)

	// PAT (pt-…) → exchange for a short-lived job token + userId so
	// COSY signing and the catalog fetch work. Device/job tokens skip
	// this and are used directly.
	rawToken := cred.APIKey
	if rawToken == "" {
		rawToken = cred.AccessToken
	}
	if qoderIsPAT(rawToken) {
		resolved, err := qoderResolveCredentials(ctx, p, cred, e.region)
		if err != nil {
			fake := qoderSyntheticResponse(http.StatusUnauthorized, "qoder PAT exchange failed: "+err.Error())
			return &ExecResult{
				Response:        fake,
				URL:             e.qoderBuildURL(p, cred),
				Headers:         map[string]string{},
				TransformedBody: body,
			}, nil
		}
		cred = resolved
	}

	chatURL := e.qoderBuildURL(p, cred)
	if cred.SpecificString("userId") == "" {
		fake := qoderSyntheticResponse(http.StatusUnauthorized, "qoder credential is missing userId; reconnect the account")
		return &ExecResult{Response: fake, URL: chatURL, Headers: map[string]string{}, TransformedBody: body}, nil
	}
	if cred.AccessToken == "" {
		fake := qoderSyntheticResponse(http.StatusUnauthorized, "qoder credential is missing accessToken; reconnect the account")
		return &ExecResult{Response: fake, URL: chatURL, Headers: map[string]string{}, TransformedBody: body}, nil
	}

	built, err := qoderBuildRequestBody(ctx, p, cred, e.region, model, bodyMap)
	if err != nil {
		fake := qoderSyntheticResponse(http.StatusBadRequest, err.Error())
		return &ExecResult{Response: fake, URL: chatURL, Headers: map[string]string{}, TransformedBody: body}, nil
	}

	plainBody, err := marshalJSON(built.payload)
	if err != nil {
		return nil, err
	}
	encodedBody := []byte(qoderEncodeBody(plainBody))

	cosyHeaders, err := qoderBuildCosyHeaders(encodedBody, chatURL, qoderCosyCredsFrom(cred))
	if err != nil {
		fake := qoderSyntheticResponse(http.StatusUnauthorized, "qoder cosy signing failed: "+err.Error())
		return &ExecResult{Response: fake, URL: chatURL, Headers: map[string]string{}, TransformedBody: body}, nil
	}

	modelSource := getStr(built.modelConfig, "source")
	if modelSource == "" {
		modelSource = "system"
	}
	headers := map[string]string{
		"Content-Type":    "application/json",
		"Accept":          "text/event-stream",
		"Cache-Control":   "no-cache",
		"X-Model-Key":     built.key,
		"X-Model-Source":  modelSource,
		"Accept-Encoding": "identity", // gzip triggers signature validation on Qoder's CDN
	}
	for k, v := range cosyHeaders {
		headers[k] = v
	}

	resp, err := doPost(ctx, chatURL, headers, encodedBody, connectTimeout(p))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Pass error responses through unchanged so chatcore captures them.
		return &ExecResult{Response: resp, URL: chatURL, Headers: headers, TransformedBody: plainBody}, nil
	}
	wrapped := qoderWrapSSE(resp, e.providerID+"/"+built.key)
	return &ExecResult{Response: wrapped, URL: chatURL, Headers: headers, TransformedBody: plainBody}, nil
}
