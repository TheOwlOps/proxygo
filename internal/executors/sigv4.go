package executors

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// AWS SigV4 signing — port of open-sse/utils/awsSigv4.js (signAwsRequest /
// escapeUri), stdlib HMAC-SHA256 only.

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

var uriUnreserved = func(r byte) bool {
	return (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') ||
		r == '-' || r == '_' || r == '.' || r == '~'
}

// escapeURI ports awsSigv4 escapeUri (encodeURIComponent plus the extra
// AWS escapes for !'()*), used for the model id in the Bedrock URL path.
func escapeURI(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if uriUnreserved(c) {
			sb.WriteByte(c)
			continue
		}
		const hexd = "0123456789ABCDEF"
		sb.WriteByte('%')
		sb.WriteByte(hexd[c>>4])
		sb.WriteByte(hexd[c&0xf])
	}
	return sb.String()
}

// awsCredentials are the resolved static credentials used for signing.
type awsCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Region          string
}

// signAWSRequest signs req in place (Authorization + X-Amz-Date +
// X-Amz-Security-Token headers), mirroring signAwsRequest: canonical URI is
// the escaped path (Bedrock model ids are escaped a second time for the
// canonical request — see bedrock.js buildUrl comment), signed headers are
// host + x-amz-date + content-type (+ security token when present).
func signAWSRequest(req *http.Request, body []byte, creds awsCredentials, service string, now time.Time) {
	amzDate := now.UTC().Format("20060102T150405Z")
	dateStamp := now.UTC().Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)
	if creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", creds.SessionToken)
	}

	u := req.URL
	// Canonical URI: escape each path segment (the already-escaped model id
	// gets its % re-escaped, which is what Bedrock expects).
	rawPath := u.EscapedPath()
	if rawPath == "" {
		rawPath = "/"
	}
	canonicalURI := rawPath
	canonicalQuery := canonicalQueryString(u.Query())

	signedHeaderNames := []string{"host", "x-amz-date"}
	if ct := req.Header.Get("Content-Type"); ct != "" {
		signedHeaderNames = append(signedHeaderNames, "content-type")
	}
	if creds.SessionToken != "" {
		signedHeaderNames = append(signedHeaderNames, "x-amz-security-token")
	}
	sort.Strings(signedHeaderNames)
	var canonicalHeaders strings.Builder
	for _, name := range signedHeaderNames {
		var val string
		if name == "host" {
			val = u.Host
		} else {
			val = strings.TrimSpace(req.Header.Get(name))
		}
		canonicalHeaders.WriteString(name + ":" + val + "\n")
	}
	payloadHash := sha256Hex(body)
	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders.String(),
		strings.Join(signedHeaderNames, ";"),
		payloadHash,
	}, "\n")

	scope := dateStamp + "/" + creds.Region + "/" + service + "/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canonicalRequest))

	kDate := hmacSHA256([]byte("AWS4"+creds.SecretAccessKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(creds.Region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))

	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+creds.AccessKeyID+"/"+scope+
		", SignedHeaders="+strings.Join(signedHeaderNames, ";")+", Signature="+signature)
}

func canonicalQueryString(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vals := append([]string{}, q[k]...)
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, escapeURI(k)+"="+escapeURI(v))
		}
	}
	return strings.Join(parts, "&")
}
