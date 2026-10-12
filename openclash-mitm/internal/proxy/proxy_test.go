package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vernesong/OpenClash/openclash-mitm/internal/ca"
	"github.com/vernesong/OpenClash/openclash-mitm/internal/stash"
)

// fakeUpstream mimics mihomo's mitm-out listener: it accepts CONNECT for any
// host and connects to origin instead.
func fakeUpstream(t *testing.T, origin string, seen *atomic.Int32) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != http.MethodConnect {
					c.Close()
					return
				}
				seen.Add(1)
				o, err := net.Dial("tcp", origin)
				if err != nil {
					c.Close()
					return
				}
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
				pipe(&bufConn{Conn: c, r: br}, o)
			}(c)
		}
	}()
	return ln.Addr().String()
}

type env struct {
	client   *http.Client
	origin   *httptest.Server
	authorit *ca.Authority
	tunnels  *atomic.Int32
}

func setup(t *testing.T, override string) *env {
	t.Helper()
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gzip":
			w.Header().Set("Content-Encoding", "gzip")
			zw := gzip.NewWriter(w)
			_, _ = zw.Write([]byte(`{"vip":false,"n":1}`))
			_ = zw.Close()
			return
		case "/echo-body":
			b, _ := io.ReadAll(r.Body)
			_, _ = w.Write(b)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Origin", "1")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"path": r.URL.RequestURI(), "host": r.Host, "headers": r.Header, "proto": r.Proto, "vip": false,
		})
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	t.Cleanup(origin.Close)

	dir := t.TempDir()
	authority, _, err := ca.LoadOrGenerate(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	o, err := stash.Parse("test", []byte(override))
	if err != nil {
		t.Fatal(err)
	}
	engine, warns := stash.Compile([]*stash.Override{o}, nil)
	if len(warns) > 0 {
		t.Fatalf("warnings: %v", warns)
	}
	var tunnels atomic.Int32
	upstream := fakeUpstream(t, origin.Listener.Addr().String(), &tunnels)
	srv := New(Config{Upstream: upstream, SkipServerCertVerify: true, MaxBodySize: 1 << 20, BypassTTL: time.Minute},
		authority, engine, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx, ln) }()

	pool := x509.NewCertPool()
	pool.AddCert(authority.Cert)
	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			TLSClientConfig:   &tls.Config{RootCAs: pool},
			ForceAttemptHTTP2: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       10 * time.Second,
	}
	return &env{client: client, origin: origin, authorit: authority, tunnels: &tunnels}
}

const testOverride = `
http:
  mitm:
    - "*.mitm.test"
  url-rewrite:
    - ^https://api\.mitm\.test/ad - reject-dict
    - ^https://api\.mitm\.test/old/(.*) https://api.mitm.test/new/$1 302
    - ^https://api\.mitm\.test/inner/(.*) https://api.mitm.test/rewritten/$1 transparent
  header-rewrite:
    - ^https://api\.mitm\.test request-add X-Added yes
    - ^https://api\.mitm\.test request-del X-Secret
    - ^https://api\.mitm\.test response-add X-Rewritten 1
  body-rewrite:
    - ^https://api\.mitm\.test/json response-jq '.vip = true | del(.headers)'
    - ^https://api\.mitm\.test/gzip response-replace-regex '"vip":false' '"vip":true'
    - ^https://api\.mitm\.test/echo-body request-replace-regex hello bye
`

func getJSON(t *testing.T, c *http.Client, req *http.Request) (*http.Response, map[string]any) {
	t.Helper()
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(body, &m)
	return resp, m
}

func TestMITMRewrites(t *testing.T) {
	e := setup(t, testOverride)

	req, _ := http.NewRequest(http.MethodGet, "https://api.mitm.test/path?q=1", nil)
	req.Header.Set("X-Secret", "s")
	resp, m := getJSON(t, e.client, req)
	if resp.TLS == nil || resp.TLS.PeerCertificates[0].Issuer.CommonName != e.authorit.Cert.Subject.CommonName {
		t.Fatal("response was not served with the MITM certificate")
	}
	if resp.ProtoMajor != 2 {
		t.Errorf("client side protocol = %s, want HTTP/2", resp.Proto)
	}
	headers := m["headers"].(map[string]any)
	if headers["X-Added"] == nil || headers["X-Secret"] != nil {
		t.Errorf("request headers not rewritten: %v", headers)
	}
	if m["host"] != "api.mitm.test" || m["path"] != "/path?q=1" {
		t.Errorf("origin saw host=%v path=%v", m["host"], m["path"])
	}
	if resp.Header.Get("X-Rewritten") != "1" || resp.Header.Get("X-Origin") != "1" {
		t.Errorf("response headers = %v", resp.Header)
	}

	req, _ = http.NewRequest(http.MethodGet, "https://api.mitm.test/ad/banner", nil)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != "{}" {
		t.Errorf("reject-dict = %d %q", resp.StatusCode, b)
	}

	req, _ = http.NewRequest(http.MethodGet, "https://api.mitm.test/old/a?b=1", nil)
	resp, err = e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "https://api.mitm.test/new/a?b=1" {
		t.Errorf("302 = %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	req, _ = http.NewRequest(http.MethodGet, "https://api.mitm.test/inner/x", nil)
	_, m = getJSON(t, e.client, req)
	if m["path"] != "/rewritten/x" {
		t.Errorf("transparent rewrite path = %v", m["path"])
	}

	req, _ = http.NewRequest(http.MethodGet, "https://api.mitm.test/json", nil)
	resp, m = getJSON(t, e.client, req)
	if m["vip"] != true || m["headers"] != nil {
		t.Errorf("jq body = %v", m)
	}
	if resp.Header.Get("X-Rewritten") != "1" {
		t.Error("response header rule must still apply with body rewrite")
	}

	req, _ = http.NewRequest(http.MethodGet, "https://api.mitm.test/gzip", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err = e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != `{"vip":true,"n":1}` || resp.Header.Get("Content-Encoding") != "" {
		t.Errorf("gzip body = %q encoding=%q", b, resp.Header.Get("Content-Encoding"))
	}

	req, _ = http.NewRequest(http.MethodPost, "https://api.mitm.test/echo-body", strings.NewReader("hello world"))
	resp, err = e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "bye world" {
		t.Errorf("request body = %q", b)
	}

	if e.tunnels.Load() == 0 {
		t.Error("upstream traffic did not go through the mitm-out proxy")
	}
}

func TestNonMITMHostIsTunnelled(t *testing.T) {
	e := setup(t, testOverride)
	tr := e.client.Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	c := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	resp, err := c.Get("https://plain.other.test/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	issuer := resp.TLS.PeerCertificates[0].Issuer.CommonName
	if issuer == e.authorit.Cert.Subject.CommonName {
		t.Error("non MITM host was decrypted")
	}
	if resp.Header.Get("X-Rewritten") != "" {
		t.Error("rewrite applied to tunnelled host")
	}
}

func TestRejectedCertTriggersBypass(t *testing.T) {
	e := setup(t, testOverride)
	tr := e.client.Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: x509.NewCertPool()}
	c := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	if _, err := c.Get("https://pinned.mitm.test/"); err == nil {
		t.Fatal("expected certificate error from untrusted CA")
	}
	tr2 := tr.Clone()
	tr2.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	resp, err := (&http.Client{Transport: tr2, Timeout: 10 * time.Second}).Get("https://pinned.mitm.test/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.TLS.PeerCertificates[0].Issuer.CommonName == e.authorit.Cert.Subject.CommonName {
		t.Error("host should be tunnelled after the client rejected the certificate")
	}
}

func TestSilentAbortNeedsRepeatsForBypass(t *testing.T) {
	e := setup(t, testOverride)
	pu, err := e.client.Transport.(*http.Transport).Proxy(&http.Request{URL: &url.URL{Scheme: "https", Host: "pinned.mitm.test"}})
	if err != nil || pu == nil {
		t.Fatalf("proxy url: %v %v", pu, err)
	}
	abort := func() {
		raw, err := net.Dial("tcp", pu.Host)
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		fmt.Fprintf(raw, "CONNECT pinned.mitm.test:443 HTTP/1.1\r\nHost: pinned.mitm.test:443\r\n\r\n")
		br := bufio.NewReader(raw)
		resp, err := http.ReadResponse(br, nil)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("CONNECT: %v %v", resp, err)
		}
		tc := tls.Client(raw, &tls.Config{ServerName: "pinned.mitm.test", InsecureSkipVerify: true,
			VerifyConnection: func(tls.ConnectionState) error { raw.Close(); return io.EOF }})
		_ = tc.Handshake()
		time.Sleep(50 * time.Millisecond)
	}
	issuer := func() string {
		resp, err := e.client.Get("https://pinned.mitm.test/")
		if err != nil {
			return "error: " + err.Error()
		}
		resp.Body.Close()
		return resp.TLS.PeerCertificates[0].Issuer.CommonName
	}
	abort()
	if got := issuer(); got != e.authorit.Cert.Subject.CommonName {
		t.Fatalf("a single silent abort must not bypass decryption, issuer=%q", got)
	}
	for i := 0; i < abortThreshold; i++ {
		abort()
	}
	tr := e.client.Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	resp, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Get("https://pinned.mitm.test/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.TLS.PeerCertificates[0].Issuer.CommonName == e.authorit.Cert.Subject.CommonName {
		t.Error("repeated silent aborts should bypass decryption")
	}
}

func TestPlainHTTPRewrite(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Header.Get("X-Added") + "|" + r.Host))
	}))
	defer plain.Close()
	dir := t.TempDir()
	authority, _, _ := ca.LoadOrGenerate(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	o, _ := stash.Parse("t", []byte(`
http:
  header-rewrite:
    - ^http://web\.test request-add X-Added plain
`))
	engine, _ := stash.Compile([]*stash.Override{o}, nil)
	var tunnels atomic.Int32
	srv := New(Config{Upstream: fakeUpstream(t, plain.Listener.Addr().String(), &tunnels)}, authority, engine, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	// mihomo's http outbound tunnels port 80 with CONNECT as well.
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("CONNECT web.test:80 HTTP/1.1\r\nHost: web.test:80\r\n\r\n"))
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT failed: %v %v", resp, err)
	}
	_, _ = c.Write([]byte("GET /x HTTP/1.1\r\nHost: web.test\r\nConnection: close\r\n\r\n"))
	resp, err = http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(b, []byte("plain|web.test")) {
		t.Errorf("plain HTTP body = %q", b)
	}
}

func TestCertHandler(t *testing.T) {
	dir := t.TempDir()
	authority, _, _ := ca.LoadOrGenerate(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	srv := httptest.NewServer(CertHandler(authority))
	defer srv.Close()
	for path, ctype := range map[string]string{
		"/": "text/html; charset=utf-8", "/ca.crt": "application/x-x509-ca-cert",
		"/ca.pem": "application/x-pem-file", "/ca.mobileconfig": "application/x-apple-aspen-config",
	} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != ctype {
			t.Errorf("%s: %d %s", path, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		if path == "/ca.crt" {
			if _, err := x509.ParseCertificate(b); err != nil {
				t.Errorf("ca.crt is not DER: %v", err)
			}
		}
		if path == "/ca.mobileconfig" && !strings.Contains(string(b), "com.apple.security.root") {
			t.Error("mobileconfig payload missing")
		}
	}
	if resp, _ := http.Get(srv.URL + "/ca.key"); resp.StatusCode != 404 {
		t.Error("private key must never be served")
	}
}
