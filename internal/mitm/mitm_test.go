package mitm

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestRootCAAndLeaf(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DATA_DIR", dir)

	keyPath, certPath, err := GenerateRootCA()
	if err != nil {
		t.Fatalf("GenerateRootCA: %v", err)
	}
	if keyPath == "" || certPath == "" {
		t.Fatal("empty CA paths")
	}
	if IsCertExpired(certPath) {
		t.Fatal("fresh CA reported expired")
	}
	ca, err := LoadRootCA()
	if err != nil {
		t.Fatalf("LoadRootCA: %v", err)
	}
	if ca.cert.Subject.CommonName != "9Router MITM Root CA" {
		t.Fatalf("CA CN = %q", ca.cert.Subject.CommonName)
	}
	if !ca.cert.IsCA {
		t.Fatal("CA cert is not a CA")
	}

	certPEM, _, err := GenerateLeafCert("api.individual.githubcopilot.com")
	if err != nil {
		t.Fatalf("GenerateLeafCert: %v", err)
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("leaf PEM undecodable")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		DNSName:   "api.individual.githubcopilot.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("leaf verify: %v", err)
	}
	found := false
	for _, n := range leaf.DNSNames {
		if n == "*.api.individual.githubcopilot.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("leaf SANs = %v", leaf.DNSNames)
	}
}

func TestCertExpiredMissing(t *testing.T) {
	t.Setenv("DATA_DIR", t.TempDir())
	if !IsCertExpired(rootCACertPath()) {
		t.Fatal("missing cert must be 'expired'")
	}
}

func TestPasswordEncryptionRoundTrip(t *testing.T) {
	enc := EncryptPassword("s3cret-pw")
	if enc == "" {
		t.Fatal("encrypt returned empty")
	}
	if got := DecryptPassword(enc); got != "s3cret-pw" {
		t.Fatalf("round trip = %q", got)
	}
	if got := DecryptPassword("not:a:valid"); got != "" {
		t.Fatalf("garbage decrypt = %q", got)
	}
	if got := DecryptPassword(""); got != "" {
		t.Fatalf("empty decrypt = %q", got)
	}
}

func TestIsChatRequest(t *testing.T) {
	if !IsChatRequest("antigravity", "/v1internal:streamGenerateContent?alt=sse", nil) {
		t.Fatal("antigravity stream pattern")
	}
	if !IsChatRequest("copilot", "/chat/completions", nil) {
		t.Fatal("copilot pattern")
	}
	if IsChatRequest("copilot", "/models", nil) {
		t.Fatal("copilot /models must not match")
	}
	if !IsChatRequest("kiro", "/generateAssistantResponse", nil) {
		t.Fatal("kiro path pattern")
	}
	if !IsChatRequest("kiro", "/something", map[string]string{"x-amz-target": "AmazonCodeWhispererStreamingService.GenerateAssistantResponse"}) {
		t.Fatal("kiro header pattern")
	}
	if IsChatRequest("kiro", "/something", map[string]string{"x-amz-target": "Other"}) {
		t.Fatal("kiro unrelated header must not match")
	}
	if got := ToolForHost("runtime.us-east-1.kiro.dev"); got != "kiro" {
		t.Fatalf("ToolForHost = %q", got)
	}
	if got := ToolForHost("example.com"); got != "" {
		t.Fatalf("ToolForHost unknown = %q", got)
	}
}

func TestGetMappedModel(t *testing.T) {
	if got := GetMappedModel("gemini-3-pro", "antigravity"); got != "gemini-3-pro-preview" {
		t.Fatalf("synonym = %q", got)
	}
	if got := GetMappedModel("models/gpt-oss-120b-medium", "copilot"); got != "gpt-oss-120b" {
		t.Fatalf("prefix+synonym = %q", got)
	}
	if got := GetMappedModel("totally-unknown", "copilot"); got != "totally-unknown" {
		t.Fatalf("fallback = %q", got)
	}
	InitDBHooks(nil, nil, func(tool string) (map[string]string, bool) {
		if tool == "copilot" {
			return map[string]string{"gpt-5": "cc/gpt-5"}, true
		}
		return nil, false
	})
	defer InitDBHooks(nil, nil, nil)
	if got := GetMappedModel("gpt-5", "copilot"); got != "cc/gpt-5" {
		t.Fatalf("alias = %q", got)
	}
}

func TestStatusShape(t *testing.T) {
	t.Setenv("DATA_DIR", t.TempDir())
	st := GetMitmStatus()
	if st["running"] != false {
		t.Fatalf("running = %v", st["running"])
	}
	if st["certExists"] != false {
		t.Fatalf("certExists = %v", st["certExists"])
	}
	dns, ok := st["dnsStatus"].(map[string]bool)
	if !ok || len(dns) != 4 {
		t.Fatalf("dnsStatus = %v", st["dnsStatus"])
	}
}
