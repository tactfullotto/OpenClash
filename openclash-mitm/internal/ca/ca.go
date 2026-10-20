// Package ca manages the MITM root certificate and issues per-host leaf
// certificates signed by it.
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	caValidity = 10 * 365 * 24 * time.Hour
	// Apple rejects TLS server certificates valid for more than 398 days.
	leafValidity = 397 * 24 * time.Hour
	maxCacheSize = 2048
)

type inflightCert struct {
	done chan struct{}
	cert *tls.Certificate
	err  error
}

// Authority holds the root CA and a cache of issued leaf certificates.
type Authority struct {
	Cert    *x509.Certificate
	CertPEM []byte
	key     crypto.Signer
	leafKey *ecdsa.PrivateKey
	leafSKI []byte

	mu       sync.Mutex
	cache    map[string]*tls.Certificate
	inflight map[string]*inflightCert
}

// Generate creates a new RSA-2048 root CA and writes it to certPath/keyPath.
// The private key file is written with mode 0600.
func Generate(certPath, keyPath, commonName string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	if commonName == "" {
		commonName = fmt.Sprintf("OpenClash MITM CA %08X", serial.Uint64()&0xffffffff)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	ski := sha1.Sum(pubDER)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"OpenClash"}},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		SubjectKeyId:          ski[:],
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return writeFileAtomic(certPath, certPEM, 0o644)
}

// Load reads a PEM encoded CA certificate and private key.
func Load(certPath, keyPath string) (*Authority, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse CA key pair: %w", err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	if !cert.IsCA {
		return nil, errors.New("certificate is not a CA")
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("CA private key does not support signing")
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	var leafSKI []byte
	if pubDER, err := x509.MarshalPKIXPublicKey(&leafKey.PublicKey); err == nil {
		sum := sha1.Sum(pubDER)
		leafSKI = sum[:]
	}
	return &Authority{
		Cert:     cert,
		CertPEM:  certPEM,
		key:      signer,
		leafKey:  leafKey,
		leafSKI:  leafSKI,
		cache:    make(map[string]*tls.Certificate),
		inflight: make(map[string]*inflightCert),
	}, nil
}

// LoadOrGenerate loads the CA, generating a new one if either file is missing.
func LoadOrGenerate(certPath, keyPath string) (*Authority, bool, error) {
	_, errCert := os.Stat(certPath)
	_, errKey := os.Stat(keyPath)
	generated := false
	if errors.Is(errCert, os.ErrNotExist) || errors.Is(errKey, os.ErrNotExist) {
		if err := Generate(certPath, keyPath, ""); err != nil {
			return nil, false, err
		}
		generated = true
	}
	a, err := Load(certPath, keyPath)
	return a, generated, err
}

// CertDER returns the DER encoding of the root certificate.
func (a *Authority) CertDER() []byte { return a.Cert.Raw }

// Fingerprint returns the SHA-1 fingerprint shown by iOS/Android settings.
func (a *Authority) Fingerprint() string {
	sum := sha1.Sum(a.Cert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// CertificateFor returns a leaf certificate valid for host, issuing one if needed.
func (a *Authority) CertificateFor(host string) (*tls.Certificate, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return nil, errors.New("empty host")
	}
	now := time.Now()
	a.mu.Lock()
	if c, ok := a.cache[host]; ok && now.Before(c.Leaf.NotAfter.Add(-time.Hour)) {
		a.mu.Unlock()
		return c, nil
	}
	if call, ok := a.inflight[host]; ok {
		a.mu.Unlock()
		<-call.done
		return call.cert, call.err
	}
	call := &inflightCert{done: make(chan struct{})}
	a.inflight[host] = call
	a.mu.Unlock()

	c, err := a.issue(host)

	a.mu.Lock()
	call.cert = c
	call.err = err
	delete(a.inflight, host)
	close(call.done)
	if err == nil {
		if len(a.cache) >= maxCacheSize {
			a.evictLocked(now)
		}
		a.cache[host] = c
	}
	a.mu.Unlock()
	return c, err
}

func (a *Authority) evictLocked(now time.Time) {
	cutoff := now.Add(time.Hour)
	for k, c := range a.cache {
		if !cutoff.Before(c.Leaf.NotAfter) {
			delete(a.cache, k)
		}
	}
	if len(a.cache) < maxCacheSize {
		return
	}
	target := maxCacheSize / 8
	if target < 1 {
		target = 1
	}
	for k := range a.cache {
		delete(a.cache, k)
		if target--; target <= 0 {
			break
		}
	}
}

func (a *Authority) issue(host string) (*tls.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	notAfter := now.Add(leafValidity)
	if notAfter.After(a.Cert.NotAfter) {
		notAfter = a.Cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host, Organization: []string{"OpenClash MITM"}},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		AuthorityKeyId:        a.Cert.SubjectKeyId,
		SubjectKeyId:          a.leafSKI,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.Cert, &a.leafKey.PublicKey, a.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, a.Cert.Raw},
		PrivateKey:  a.leafKey,
		Leaf:        leaf,
	}, nil
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
