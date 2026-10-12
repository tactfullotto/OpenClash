package ca

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateLoadAndIssue(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "sub", "ca.key")
	a, generated, err := LoadOrGenerate(certPath, keyPath)
	if err != nil || !generated {
		t.Fatalf("LoadOrGenerate: %v generated=%v", err, generated)
	}
	if st, _ := os.Stat(keyPath); st.Mode().Perm() != 0o600 {
		t.Errorf("key mode = %v", st.Mode().Perm())
	}
	again, generated, err := LoadOrGenerate(certPath, keyPath)
	if err != nil || generated || again.Fingerprint() != a.Fingerprint() {
		t.Fatal("existing CA must be reused")
	}

	pool := x509.NewCertPool()
	pool.AddCert(a.Cert)
	for _, host := range []string{"weatherkit.apple.com", "10.0.0.1"} {
		c, err := a.CertificateFor(host)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: pool}); err != nil {
			t.Errorf("%s: leaf does not verify: %v", host, err)
		}
		if c.Leaf.NotAfter.Sub(c.Leaf.NotBefore) > 398*24*time.Hour {
			t.Errorf("%s: leaf validity exceeds Apple's limit", host)
		}
	}
	c1, _ := a.CertificateFor("A.example.com.")
	c2, _ := a.CertificateFor("a.example.com")
	if c1 != c2 {
		t.Error("leaf certificates should be cached per normalised host")
	}
}
