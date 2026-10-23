package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Root CA port (cert/rootCA.js + cert/generate.js) using Go's x509 —
// same on-disk layout (rootCA.key / rootCA.crt in MITM_DIR), same names
// and validity windows (CA 10y, leaf 1y, 30-day early-expiry rule).

func rootCAKeyPath() string  { return filepath.Join(Dir(), "rootCA.key") }
func rootCACertPath() string { return filepath.Join(Dir(), "rootCA.crt") }

// IsCertExpired: unreadable, or expiring within 30 days (rootCA.js).
func IsCertExpired(certPath string) bool {
	raw, err := os.ReadFile(certPath)
	if err != nil {
		return true
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return true
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true
	}
	return cert.NotAfter.Before(time.Now().Add(30 * 24 * time.Hour))
}

// GenerateRootCA creates the root CA once; regenerates when expired.
func GenerateRootCA() (keyPath, certPath string, err error) {
	keyPath, certPath = rootCAKeyPath(), rootCACertPath()
	if _, kerr := os.Stat(keyPath); kerr == nil {
		if _, cerr := os.Stat(certPath); cerr == nil && !IsCertExpired(certPath) {
			return keyPath, certPath, nil
		}
		_ = os.Remove(keyPath)
		_ = os.Remove(certPath)
	}
	ensureDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "ProxyGo MITM Root CA",
			Organization: []string{"ProxyGo"},
			Country:      []string{"US"},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return "", "", err
	}
	return keyPath, certPath, nil
}

type rootCA struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
	der  []byte
	pem  string
}

var (
	caOnce sync.Once
	caVal  *rootCA
	caErr  error
)

// LoadRootCA loads (generating first when missing) the root CA.
func LoadRootCA() (*rootCA, error) {
	caOnce.Do(func() {
		if _, _, err := GenerateRootCA(); err != nil {
			caErr = err
			return
		}
		keyRaw, err := os.ReadFile(rootCAKeyPath())
		if err != nil {
			caErr = err
			return
		}
		kb, _ := pem.Decode(keyRaw)
		if kb == nil {
			caErr = fmt.Errorf("Root CA not found. Generate it first.")
			return
		}
		key, err := x509.ParsePKCS1PrivateKey(kb.Bytes)
		if err != nil {
			// Try PKCS#8 (foreign-produced keys).
			k8, err2 := x509.ParsePKCS8PrivateKey(kb.Bytes)
			if err2 != nil {
				caErr = err
				return
			}
			var ok bool
			key, ok = k8.(*rsa.PrivateKey)
			if !ok {
				caErr = fmt.Errorf("root CA key is not RSA")
				return
			}
		}
		certRaw, err := os.ReadFile(rootCACertPath())
		if err != nil {
			caErr = err
			return
		}
		cb, _ := pem.Decode(certRaw)
		if cb == nil {
			caErr = fmt.Errorf("unparsable root CA cert")
			return
		}
		cert, err := x509.ParseCertificate(cb.Bytes)
		if err != nil {
			caErr = err
			return
		}
		caVal = &rootCA{key: key, cert: cert, der: cb.Bytes, pem: string(certRaw)}
	})
	return caVal, caErr
}

// GenerateCert is cert/generate.js generateCert().
func GenerateCert() error {
	_, _, err := GenerateRootCA()
	return err
}

var leafSerial int64 = 1000
var leafMu sync.Mutex

// GenerateLeafCert issues a per-domain leaf (SAN domain + *.domain),
// signed by the root CA (rootCA.js generateLeafCert).
func GenerateLeafCert(domain string) (certPEM, keyPEM string, err error) {
	ca, err := LoadRootCA()
	if err != nil {
		return "", "", err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	leafMu.Lock()
	leafSerial++
	serial := leafSerial
	leafMu.Unlock()
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    now,
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{domain, "*." + domain},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return "", "", err
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return certPEM, keyPEM, nil
}

// GetCertForDomain is cert/generate.js getCertForDomain: leaf PEM pair
// (key, cert) or an error.
func GetCertForDomain(domain string) (keyPEM, certPEM string, err error) {
	certPEM, keyPEM, err = GenerateLeafCert(domain)
	if err != nil {
		return "", "", err
	}
	return keyPEM, certPEM, nil
}
