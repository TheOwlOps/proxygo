package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// Session claims parity (dashboardSession.js createDashboardAuthToken
// with claims): tokens minted with SSO identity claims verify, parse
// back, and surface through GET /api/auth/status.

func TestSessionTokenWithOIDCClaimsSurfacesInStatus(t *testing.T) {
	e := newTestEnv(t)
	token := CreateSessionTokenWithClaims(e.store, map[string]any{
		"oidc": true, "oidcSub": "sub-123", "oidcEmail": "alice@example.com", "oidcName": "Alice A",
	})
	if !VerifySessionToken(e.store, token) {
		t.Fatal("claims token does not verify")
	}
	rec := e.do(t, "GET", "/api/auth/status", "", "auth_token="+token, false)
	if rec.Code != 200 {
		t.Fatalf("status code %d body %s", rec.Code, rec.Body.String())
	}
	out := decode(t, rec)
	if out["authenticated"] != true {
		t.Errorf("authenticated = %v", out["authenticated"])
	}
	if out["oidcLogin"] != true {
		t.Errorf("oidcLogin = %v, want true", out["oidcLogin"])
	}
	if out["oidcEmail"] != "alice@example.com" {
		t.Errorf("oidcEmail = %v", out["oidcEmail"])
	}
	if out["oidcName"] != "Alice A" {
		t.Errorf("oidcName = %v", out["oidcName"])
	}
	if out["displayName"] != "Alice A" {
		t.Errorf("displayName = %v", out["displayName"])
	}
	if out["loginMethod"] != "OIDC" {
		t.Errorf("loginMethod = %v", out["loginMethod"])
	}
	if out["samlLogin"] != false {
		t.Errorf("samlLogin = %v, want false", out["samlLogin"])
	}
}

func TestSessionTokenWithSAMLClaimsSurfacesInStatus(t *testing.T) {
	e := newTestEnv(t)
	token := CreateSessionTokenWithClaims(e.store, map[string]any{
		"saml": true, "samlEmail": "bob@corp.example", "samlName": "Bob B",
	})
	rec := e.do(t, "GET", "/api/auth/status", "", "auth_token="+token, false)
	out := decode(t, rec)
	if out["samlLogin"] != true {
		t.Errorf("samlLogin = %v, want true", out["samlLogin"])
	}
	if out["samlEmail"] != "bob@corp.example" {
		t.Errorf("samlEmail = %v", out["samlEmail"])
	}
	if out["samlName"] != "Bob B" {
		t.Errorf("samlName = %v", out["samlName"])
	}
	if out["loginMethod"] != "SAML" {
		t.Errorf("loginMethod = %v", out["loginMethod"])
	}
	if out["oidcLogin"] != false {
		t.Errorf("oidcLogin = %v, want false", out["oidcLogin"])
	}
}

func TestPlainSessionTokenHasNoSSOClaims(t *testing.T) {
	e := newTestEnv(t)
	token := CreateSessionToken(e.store)
	rec := e.do(t, "GET", "/api/auth/status", "", "auth_token="+token, false)
	out := decode(t, rec)
	if out["authenticated"] != true {
		t.Errorf("authenticated = %v", out["authenticated"])
	}
	if out["oidcLogin"] != false || out["samlLogin"] != false {
		t.Errorf("plain token SSO flags = %v/%v, want false/false", out["oidcLogin"], out["samlLogin"])
	}
	if out["oidcEmail"] != nil || out["samlEmail"] != nil {
		t.Errorf("plain token emails = %v/%v, want nil/nil", out["oidcEmail"], out["samlEmail"])
	}
	if out["loginMethod"] != "Password" {
		t.Errorf("loginMethod = %v", out["loginMethod"])
	}
}

func TestSetSessionCookieWithClaims(t *testing.T) {
	e := newTestEnv(t)
	req := httptest.NewRequest("GET", "/api/auth/oidc/callback", nil)
	rec := httptest.NewRecorder()
	SetSessionCookieWithClaims(rec, req, e.store, map[string]any{
		"oidc": true, "oidcSub": "sub-9", "oidcEmail": nil, "oidcName": "No Email",
	})
	var cookieVal string
	for _, c := range rec.Header().Values("Set-Cookie") {
		if strings.HasPrefix(c, "auth_token=") {
			cookieVal = strings.Split(strings.TrimPrefix(c, "auth_token="), ";")[0]
		}
	}
	if cookieVal == "" {
		t.Fatal("no auth_token cookie set")
	}
	if !VerifySessionToken(e.store, cookieVal) {
		t.Fatal("cookie token does not verify")
	}
	// Parse the claims back via a status request.
	rec2 := e.do(t, "GET", "/api/auth/status", "", "auth_token="+cookieVal, false)
	out := decode(t, rec2)
	if out["oidcLogin"] != true || out["oidcName"] != "No Email" {
		t.Errorf("status from cookie = oidcLogin %v oidcName %v", out["oidcLogin"], out["oidcName"])
	}
	if out["oidcEmail"] != nil {
		t.Errorf("oidcEmail = %v, want nil (JS stamps null when absent)", out["oidcEmail"])
	}
}
