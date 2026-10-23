package oauthsvc

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// XMLDSig verification for SAML responses, using
// github.com/russellhaering/goxmldsig (the Go ecosystem's standard
// XMLDSig validator; Go's stdlib has none). This closes the gap that
// @node-saml/node-saml covers in the JS build (see saml.js
// createSamlInstance) — semantics mirrored from that configuration:
//
//   - Trusted cert: settings `samlCert` (the IdP X.509 cert), passed
//     to node-saml as `idpCert` (and `cert`).
//   - `wantAssertionsSigned: true` and `wantAuthnResponseSigned` unset
//     (node-saml default false): the assertion must be signature-
//     protected — either the Assertion carries its own enveloped
//     signature, or the whole Response is signed (the signed response
//     covers the assertion). A Response-level signature is not
//     required, but every signature present in the document must
//     verify (digest + RSA signature over the canonicalized
//     SignedInfo) against the IdP cert, and the signed element
//     counted for coverage must be the Response or the Assertion
//     itself, so a valid signature over some unrelated element does
//     not satisfy the requirement.
//
// Errors are prefixed so the ACS route (which redirects with the
// error text, exactly like the JS route) keeps signature failures
// distinguishable: "saml_signature_missing: …" when the required
// signature is absent, "saml_signature_invalid: …" when a present
// signature (or the configured cert) fails verification.
func verifySAMLResponseSignature(docXML string, cfg SAMLRuntimeConfig) error {
	pemCert := FormatX509Certificate(cfg.Cert)
	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		return errf("saml_signature_invalid: IdP certificate (samlCert) is not valid PEM")
	}
	idpCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errf("saml_signature_invalid: IdP certificate (samlCert) does not parse: %v", err)
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromString(docXML); err != nil {
		return errf("saml_signature_invalid: SAMLResponse is not well-formed XML: %v", err)
	}
	root := doc.Root()
	if root == nil {
		return errf("saml_signature_invalid: SAMLResponse has no root element")
	}
	assertion := findByLocalName(root, "Assertion")

	vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{idpCert},
	})
	// SAML identifies elements with the "ID" attribute (goxmldsig
	// defaults to "Id").
	vc.IdAttribute = "ID"

	// Collect the parent element of every Signature element in the
	// document: for an enveloped signature the parent is the signed
	// element. node-saml validates every signature in the document,
	// and so does this port — a failing signature anywhere fails the
	// whole response.
	sigParents := map[*etree.Element]bool{}
	var walk func(el *etree.Element)
	walk = func(el *etree.Element) {
		for _, child := range el.ChildElements() {
			if child.Tag == "Signature" {
				sigParents[el] = true
			}
			walk(child)
		}
	}
	walk(root)

	if len(sigParents) == 0 {
		return errf("saml_signature_missing: no XML signature found in SAMLResponse (wantAssertionsSigned)")
	}
	covered := false
	for parent := range sigParents {
		if _, err := vc.Validate(detachedWithInheritedNamespaces(parent)); err != nil {
			return errf("saml_signature_invalid: %v", err)
		}
		if parent == root || (assertion != nil && parent == assertion) {
			covered = true
		}
	}
	if !covered {
		return errf("saml_signature_missing: neither the Response nor the Assertion is signed (wantAssertionsSigned)")
	}
	return nil
}

// detachedWithInheritedNamespaces copies el and re-declares on the
// copy every namespace declaration that is in scope for el in the
// original document (declared on el's ancestors). goxmldsig's
// Validate works on a detached copy of the element, which would
// otherwise lose e.g. the xmlns:saml declaration that lives on the
// Response root — but the IdP computed the reference digest over the
// element in its full in-document context, where inclusive C14N
// renders exactly these in-scope declarations at the apex.
// Declarations already present on el itself win (nearest scope), and
// C14N sorts declarations, so insertion order is irrelevant.
func detachedWithInheritedNamespaces(el *etree.Element) *etree.Element {
	cp := el.Copy()
	declared := map[string]bool{}
	for _, a := range cp.Attr {
		if a.Space == "xmlns" {
			declared[a.Key] = true
		}
		if a.Space == "" && a.Key == "xmlns" {
			declared[""] = true
		}
	}
	for p := el.Parent(); p != nil; p = p.Parent() {
		for _, a := range p.Attr {
			switch {
			case a.Space == "xmlns" && !declared[a.Key]:
				cp.Attr = append(cp.Attr, a)
				declared[a.Key] = true
			case a.Space == "" && a.Key == "xmlns" && !declared[""]:
				cp.Attr = append(cp.Attr, a)
				declared[""] = true
			}
		}
	}
	return cp
}

// findByLocalName returns the first descendant (including el itself)
// with the given local tag name.
func findByLocalName(el *etree.Element, tag string) *etree.Element {
	if el.Tag == tag {
		return el
	}
	for _, child := range el.ChildElements() {
		if found := findByLocalName(child, tag); found != nil {
			return found
		}
	}
	return nil
}
