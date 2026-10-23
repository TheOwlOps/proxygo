package oauthsvc

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"io"
)

// Small indirection helpers used by the Xiaomi ECDH port.
func randReader() io.Reader { return rand.Reader }

func x509MarshalPKCS8(key any) ([]byte, error) { return x509.MarshalPKCS8PrivateKey(key) }

func parsePKCS8(der []byte) (any, error) { return x509.ParsePKCS8PrivateKey(der) }

func hexEncode(b []byte) string { return hex.EncodeToString(b) }
