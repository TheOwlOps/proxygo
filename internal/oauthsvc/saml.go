package oauthsvc

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Port of src/lib/auth/saml.js — dashboard SAML SSO.
//
// @node-saml/node-saml verifies the XMLDSig signature of the
// SAMLResponse against the IdP certificate. Go's stdlib has no
// XMLDSig implementation, so this port uses
// github.com/russellhaering/goxmldsig (see saml_verify.go): the
// response is parsed, its signature(s) are verified against the
// configured IdP cert (settings `samlCert`), and InResponseTo /
// Conditions / Audience are checked exactly as before.
// SAMLAssertionsVerified is therefore true, and the api layer only
// creates a dashboard session from a signature-verified assertion.

// SAMLAssertionsVerified reports whether this build can verify SAML
// assertion signatures. It is true: XMLDSig verification is
// implemented in saml_verify.go via goxmldsig.
const SAMLAssertionsVerified = true

// SAMLRuntimeConfig mirrors getSAMLRuntimeConfig's normalized shape.
type SAMLRuntimeConfig struct {
	EntryPoint     string
	Cert           string
	Issuer         string
	AttributeEmail string
	AttributeName  string
	BaseURL        string
}

// SAMLRuntime builds the runtime config from settings.
func SAMLRuntime(settings map[string]any, publicOrigin string) SAMLRuntimeConfig {
	get := func(k string) string {
		if settings == nil {
			return ""
		}
		return strOf(settings, k)
	}
	base := strings.TrimRight(strings.TrimSpace(get("samlBaseUrl")), "/")
	if base == "" {
		base = strings.TrimRight(publicOrigin, "/")
	}
	issuer := strings.TrimSpace(get("samlIssuer"))
	if issuer == "" {
		issuer = "urn:9router:sp"
	}
	return SAMLRuntimeConfig{
		EntryPoint:     strings.TrimSpace(get("samlEntryPoint")),
		Cert:           strings.TrimSpace(get("samlCert")),
		Issuer:         issuer,
		AttributeEmail: strings.TrimSpace(get("samlAttributeEmail")),
		AttributeName:  strings.TrimSpace(get("samlAttributeName")),
		BaseURL:        base,
	}
}

// SAMLConfigured mirrors isSAMLConfigured.
func SAMLConfigured(cfg SAMLRuntimeConfig) bool {
	return cfg.EntryPoint != "" && cfg.Cert != ""
}

// SAMLACSURL / SAMLMetadataURL mirror the route URL builders.
func SAMLACSURL(cfg SAMLRuntimeConfig) string      { return cfg.BaseURL + "/api/auth/saml/acs" }
func SAMLMetadataURL(cfg SAMLRuntimeConfig) string { return cfg.BaseURL + "/api/auth/saml/metadata" }

var base64JunkRe = regexp.MustCompile(`[^A-Za-z0-9+/=]`)

// FormatX509Certificate ports formatX509Certificate: strip PEM armor and
// any non-base64 junk, re-wrap at 64 columns.
func FormatX509Certificate(cert string) string {
	body := strings.TrimSpace(cert)
	body = strings.ReplaceAll(body, "-----BEGIN CERTIFICATE-----", "")
	body = strings.ReplaceAll(body, "-----END CERTIFICATE-----", "")
	body = base64JunkRe.ReplaceAllString(body, "")
	if body == "" {
		return ""
	}
	var lines []string
	for len(body) > 64 {
		lines = append(lines, body[:64])
		body = body[64:]
	}
	lines = append(lines, body)
	return "-----BEGIN CERTIFICATE-----\n" + strings.Join(lines, "\n") + "\n-----END CERTIFICATE-----"
}

// CertLooksValid reports whether a cert string parses as PEM X.509 after
// formatting (used by the saml/test route).
func CertLooksValid(cert string) bool {
	formatted := FormatX509Certificate(cert)
	if formatted == "" {
		return false
	}
	// The JS test route validates via node-saml's cert handling; a strict
	// parse happens in x509 — done by the caller through Format + decode.
	_, err := base64.StdEncoding.DecodeString(base64JunkRe.ReplaceAllString(
		strings.ReplaceAll(strings.ReplaceAll(formatted,
			"-----BEGIN CERTIFICATE-----", ""), "-----END CERTIFICATE-----", ""), ""))
	return err == nil
}

// BuildSAMLAuthnRequestURL ports the redirect-binding start: deflate +
// base64 the AuthnRequest, unsigned (the JS SP has no private key either).
func BuildSAMLAuthnRequestURL(cfg SAMLRuntimeConfig, requestID string, issueInstant time.Time) (string, error) {
	acs := SAMLACSURL(cfg)
	xmlReq := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
		`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + xmlEscape(requestID) + `" Version="2.0" ` +
		`IssueInstant="` + issueInstant.UTC().Format("2006-01-02T15:04:05Z") + `" ` +
		`Destination="` + xmlEscape(cfg.EntryPoint) + `" AssertionConsumerServiceURL="` + xmlEscape(acs) + `" ` +
		`ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">` +
		`<saml:Issuer>` + xmlEscape(cfg.Issuer) + `</saml:Issuer>` +
		`<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>` +
		`</samlp:AuthnRequest>`
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return "", err
	}
	if _, err := w.Write([]byte(xmlReq)); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	q := url.Values{
		"SAMLRequest": {base64.StdEncoding.EncodeToString(buf.Bytes())},
		"RelayState":  {requestID},
	}
	sep := "?"
	if strings.Contains(cfg.EntryPoint, "?") {
		sep = "&"
	}
	return cfg.EntryPoint + sep + q.Encode(), nil
}

// GenerateSAMLMetadata ports the SP metadata document.
func GenerateSAMLMetadata(cfg SAMLRuntimeConfig) string {
	return `<?xml version="1.0" encoding="UTF-8"?>` +
		`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + xmlEscape(cfg.Issuer) + `">` +
		`<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="false" WantAssertionsSigned="true">` +
		`<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>` +
		`<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="` + xmlEscape(SAMLACSURL(cfg)) + `" index="0" isDefault="true"/>` +
		`</md:SPSSODescriptor></md:EntityDescriptor>`
}

// SAMLProfile is the extracted assertion identity.
type SAMLProfile struct {
	NameID      string
	Email       string
	DisplayName string
	Attributes  map[string][]string
}

// ValidateSAMLResponse ports the ACS-side parse + structural checks of
// validateSAMLResponse, including XMLDSig signature verification
// against the IdP cert (see saml_verify.go): signatureVerified is
// true on success; any signature problem is returned as an error
// prefixed "saml_signature_missing:" / "saml_signature_invalid:".
func ValidateSAMLResponse(samlResponseB64 string, cfg SAMLRuntimeConfig, expectedInResponseTo string) (profile *SAMLProfile, signatureVerified bool, err error) {
	raw, derr := base64.StdEncoding.DecodeString(samlResponseB64)
	if derr != nil {
		raw, derr = base64.RawStdEncoding.DecodeString(samlResponseB64)
		if derr != nil {
			return nil, false, errf("SAMLResponse is not valid base64")
		}
	}
	doc := string(raw)

	// InResponseTo on the Response or Assertion element.
	if expectedInResponseTo != "" {
		if irt := findXMLAttr(doc, "InResponseTo"); irt != "" && irt != expectedInResponseTo {
			return nil, false, errf("SAML InResponseTo mismatch")
		}
	}
	// Conditions NotOnOrAfter expiry.
	if noa := findXMLAttr(doc, "NotOnOrAfter"); noa != "" {
		if t, perr := time.Parse(time.RFC3339, noa); perr == nil && time.Now().After(t) {
			return nil, false, errf("SAML assertion expired")
		}
	}
	// Audience restriction must contain the SP issuer when present.
	if strings.Contains(doc, "<saml:Audience>") || strings.Contains(doc, "<Audience>") {
		aud := findXMLElementText(doc, "Audience")
		if aud != "" && aud != cfg.Issuer {
			return nil, false, errf("SAML audience mismatch")
		}
	}

	// XMLDSig verification against the IdP cert (wantAssertionsSigned,
	// mirroring the node-saml configuration in saml.js). The profile
	// below is only ever extracted from a signature-verified document.
	if verr := verifySAMLResponseSignature(doc, cfg); verr != nil {
		return nil, false, verr
	}

	p := &SAMLProfile{Attributes: map[string][]string{}}
	p.NameID = findXMLElementText(doc, "NameID")
	// Attribute extraction: <Attribute Name="…"><AttributeValue>…</…>
	attrRe := regexp.MustCompile(`(?s)<(?:\w+:)?Attribute[^>]*\sName="([^"]+)"[^>]*>(.*?)</(?:\w+:)?Attribute>`)
	valRe := regexp.MustCompile(`(?s)<(?:\w+:)?AttributeValue[^>]*>(.*?)</(?:\w+:)?AttributeValue>`)
	for _, m := range attrRe.FindAllStringSubmatch(doc, -1) {
		name := m[1]
		for _, vm := range valRe.FindAllStringSubmatch(m[2], -1) {
			p.Attributes[name] = append(p.Attributes[name], strings.TrimSpace(stripTags(vm[1])))
		}
	}
	p.Email = PickSAMLEmail(p, cfg)
	p.DisplayName = PickSAMLDisplayName(p, cfg)
	return p, true, nil
}

// PickSAMLEmail mirrors pickSamlEmail's claim preference order.
func PickSAMLEmail(p *SAMLProfile, cfg SAMLRuntimeConfig) string {
	candidates := []string{}
	if cfg.AttributeEmail != "" {
		candidates = append(candidates, cfg.AttributeEmail)
	}
	candidates = append(candidates,
		"email", "emailAddress", "mail",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn",
		"upn", "userPrincipalName",
	)
	for _, c := range candidates {
		if vals := p.Attributes[c]; len(vals) > 0 && vals[0] != "" {
			return vals[0]
		}
	}
	if strings.Contains(p.NameID, "@") {
		return p.NameID
	}
	return ""
}

// PickSAMLDisplayName mirrors pickSamlDisplayName.
func PickSAMLDisplayName(p *SAMLProfile, cfg SAMLRuntimeConfig) string {
	candidates := []string{}
	if cfg.AttributeName != "" {
		candidates = append(candidates, cfg.AttributeName)
	}
	candidates = append(candidates,
		"displayName", "name", "cn",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
		"givenName",
	)
	for _, c := range candidates {
		if vals := p.Attributes[c]; len(vals) > 0 && vals[0] != "" {
			return vals[0]
		}
	}
	return firstStr(p.Email, p.NameID)
}

func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func findXMLAttr(doc, name string) string {
	re := regexp.MustCompile(name + `="([^"]*)"`)
	m := re.FindStringSubmatch(doc)
	if m == nil {
		return ""
	}
	return m[1]
}

func findXMLElementText(doc, local string) string {
	re := regexp.MustCompile(`(?s)<(?:\w+:)?` + local + `(?:\s[^>]*)?>(.*?)</(?:\w+:)?` + local + `>`)
	m := re.FindStringSubmatch(doc)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(stripTags(m[1]))
}

var tagRe = regexp.MustCompile(`<[^>]*>`)

func stripTags(s string) string { return tagRe.ReplaceAllString(s, "") }

var _ = io.EOF
