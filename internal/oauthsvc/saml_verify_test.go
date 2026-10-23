package oauthsvc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// --- SAML XMLDSig verification tests -------------------------------------
//
// These build a real SAML Response, sign it with an enveloped
// RSA-SHA256 signature (goxmldsig signing side, same library the
// verifier uses), and run the full ValidateSAMLResponse path:
// the happy path must verify, and tampered / wrong-cert / unsigned
// responses must be rejected.
//
// Signing uses exclusive C14N (xml-exc-c14n), as real IdPs do for
// SAML assertions: goxmldsig's default C14N 1.1 signing
// canonicalizer digests the element subtree in isolation (ignoring
// in-scope ancestor namespaces), which no spec-conformant IdP does,
// so it cannot produce a signature any validator could verify for a
// nested assertion.

type samlTestIdP struct {
	key     *rsa.PrivateKey
	cert    *x509.Certificate
	certDER []byte
	certPEM string
}

func newSAMLTestIdP(t *testing.T) *samlTestIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test IdP"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return &samlTestIdP{key: key, cert: cert, certDER: der, certPEM: pemStr}
}

const samlTestResponseXML = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" InResponseTo="_req1" Destination="http://localhost:20128/api/auth/saml/acs">` +
	`<saml:Issuer>https://idp.example.com</saml:Issuer>` +
	`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
	`<saml:Assertion ID="_assert1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">` +
	`<saml:Issuer>https://idp.example.com</saml:Issuer>` +
	`<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID></saml:Subject>` +
	`<saml:AttributeStatement>` +
	`<saml:Attribute Name="email"><saml:AttributeValue>user@example.com</saml:AttributeValue></saml:Attribute>` +
	`<saml:Attribute Name="displayName"><saml:AttributeValue>Test User</saml:AttributeValue></saml:Attribute>` +
	`</saml:AttributeStatement>` +
	`</saml:Assertion></samlp:Response>`

// signSAML parses xml, enveloped-signs the named element ("Assertion"
// or "Response") with the IdP key, and returns the serialized document.
func signSAML(t *testing.T, idp *samlTestIdP, xmlStr, element string) string {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromString(xmlStr); err != nil {
		t.Fatalf("parse response xml: %v", err)
	}
	target := findByLocalName(doc.Root(), element)
	if target == nil {
		t.Fatalf("element %s not found", element)
	}
	ctx, err := dsig.NewSigningContext(idp.key, [][]byte{idp.certDER})
	if err != nil {
		t.Fatalf("signing context: %v", err)
	}
	ctx.IdAttribute = "ID"
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	// Exclusive C14N needs the element's namespace context on the
	// element itself (a real IdP emits the assertion with its
	// in-scope declarations resolvable), so sign a detached copy
	// carrying the inherited declarations.
	signTarget := target
	if target.Parent() != nil {
		signTarget = detachedWithInheritedNamespaces(target)
	}
	// SignEnveloped returns a signed COPY of the element; swap it
	// into the document in place of the original.
	signedEl, err := ctx.SignEnveloped(signTarget)
	if err != nil {
		t.Fatalf("sign enveloped: %v", err)
	}
	if parent := target.Parent(); parent != nil {
		parent.RemoveChild(target)
		parent.AddChild(signedEl)
	} else {
		doc.SetRoot(signedEl)
	}
	out, err := doc.WriteToString()
	if err != nil {
		t.Fatalf("serialize signed doc: %v", err)
	}
	if !strings.Contains(out, "Signature") {
		t.Fatalf("signed doc has no Signature element: %s", out)
	}
	return out
}

func samlCfgFor(idp *samlTestIdP) SAMLRuntimeConfig {
	return SAMLRuntime(map[string]any{
		"samlEntryPoint": "https://idp.example.com/sso",
		"samlCert":       idp.certPEM,
	}, "http://localhost:20128")
}

func TestSAMLVerifyAssertionSigned(t *testing.T) {
	idp := newSAMLTestIdP(t)
	signed := signSAML(t, idp, samlTestResponseXML, "Assertion")
	b64 := base64.StdEncoding.EncodeToString([]byte(signed))

	profile, verified, err := ValidateSAMLResponse(b64, samlCfgFor(idp), "_req1")
	if err != nil {
		t.Fatalf("validate signed response: %v", err)
	}
	if !verified {
		t.Fatal("signatureVerified must be true for a validly signed assertion")
	}
	if profile == nil || profile.Email != "user@example.com" || profile.DisplayName != "Test User" {
		t.Fatalf("profile = %+v", profile)
	}
}

func TestSAMLVerifyResponseSigned(t *testing.T) {
	idp := newSAMLTestIdP(t)
	// Response-level signature only: covers the assertion
	// (wantAssertionsSigned satisfied via the signed response).
	signed := signSAML(t, idp, samlTestResponseXML, "Response")
	b64 := base64.StdEncoding.EncodeToString([]byte(signed))

	_, verified, err := ValidateSAMLResponse(b64, samlCfgFor(idp), "_req1")
	if err != nil {
		t.Fatalf("validate response-signed response: %v", err)
	}
	if !verified {
		t.Fatal("signatureVerified must be true when the Response is signed")
	}
}

func TestSAMLVerifyTamperedAssertionFails(t *testing.T) {
	idp := newSAMLTestIdP(t)
	signed := signSAML(t, idp, samlTestResponseXML, "Assertion")
	tampered := strings.ReplaceAll(signed, "user@example.com", "attacker@example.com")
	b64 := base64.StdEncoding.EncodeToString([]byte(tampered))

	_, verified, err := ValidateSAMLResponse(b64, samlCfgFor(idp), "_req1")
	if err == nil {
		t.Fatal("tampered assertion must fail verification")
	}
	if verified {
		t.Fatal("verified must be false for a tampered assertion")
	}
	if !strings.Contains(err.Error(), "saml_signature_invalid") {
		t.Fatalf("error should be saml_signature_invalid, got: %v", err)
	}
}

func TestSAMLVerifyWrongCertFails(t *testing.T) {
	signer := newSAMLTestIdP(t)
	other := newSAMLTestIdP(t)
	signed := signSAML(t, signer, samlTestResponseXML, "Assertion")
	b64 := base64.StdEncoding.EncodeToString([]byte(signed))

	// Configured IdP cert is a different cert than the signing cert.
	_, verified, err := ValidateSAMLResponse(b64, samlCfgFor(other), "_req1")
	if err == nil {
		t.Fatal("response signed by an untrusted key must fail verification")
	}
	if verified {
		t.Fatal("verified must be false for an untrusted signing cert")
	}
	if !strings.Contains(err.Error(), "saml_signature_invalid") {
		t.Fatalf("error should be saml_signature_invalid, got: %v", err)
	}
}

func TestSAMLVerifyUnsignedFails(t *testing.T) {
	idp := newSAMLTestIdP(t)
	b64 := base64.StdEncoding.EncodeToString([]byte(samlTestResponseXML))

	// wantAssertionsSigned: an unsigned response is rejected even
	// though it is structurally fine.
	_, verified, err := ValidateSAMLResponse(b64, samlCfgFor(idp), "_req1")
	if err == nil {
		t.Fatal("unsigned response must fail (wantAssertionsSigned)")
	}
	if verified {
		t.Fatal("verified must be false for an unsigned response")
	}
	if !strings.Contains(err.Error(), "saml_signature_missing") {
		t.Fatalf("error should be saml_signature_missing, got: %v", err)
	}
}
