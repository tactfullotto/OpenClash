// Package proxy implements the MITM HTTP proxy that mihomo forwards the
// selected hostnames to.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vernesong/OpenClash/openclash-mitm/internal/ca"
	"github.com/vernesong/OpenClash/openclash-mitm/internal/rewrite"
	"github.com/vernesong/OpenClash/openclash-mitm/internal/script"
)

// Config controls the proxy server.
type Config struct {
	// Listen is the address mihomo sends CONNECT requests to.
	Listen string
	// Upstream is the HTTP proxy (mihomo's mitm-out listener) used for every
	// outgoing connection. Empty means dial directly.
	Upstream string
	// SkipServerCertVerify disables verification of origin certificates.
	SkipServerCertVerify bool
	// MaxBodySize is the largest body buffered for body-rewrite.
	MaxBodySize int64
	// BypassTTL is how long a host is tunnelled without decryption after a
	// client rejected the MITM certificate. Zero disables the behaviour.
	BypassTTL time.Duration
}

type ctxKey struct{}

type connInfo struct {
	host string
	port int
}

func (ci *connInfo) authority() string { return net.JoinHostPort(ci.host, strconv.Itoa(ci.port)) }

// Server is the MITM proxy.
type Server struct {
	cfg       Config
	ca        *ca.Authority
	log       *slog.Logger
	engine    atomic.Pointer[rewrite.Engine]
	scripts   *script.Runner
	transport *http.Transport
	dialer    net.Dialer

	front   *http.Server
	intercS *http.Server
	intercL *chanListener
	meta    sync.Map // net.Conn -> *connInfo
	bypass  sync.Map // host -> time.Time

	abortMu sync.Mutex
	aborts  map[string]*abortCount
}

type abortCount struct {
	n     int
	first time.Time
}

// A silent close/reset can be a user cancelling a request, so it only counts
// as a certificate rejection when it repeats.
const (
	abortThreshold = 3
	abortWindow    = time.Minute
)

// New creates a proxy server using the given CA and rewrite engine.
// scripts may be nil when no JavaScript rules are needed.
func New(cfg Config, authority *ca.Authority, engine *rewrite.Engine, scripts *script.Runner, log *slog.Logger) *Server {
	if cfg.MaxBodySize <= 0 {
		cfg.MaxBodySize = 4 << 20
	}
	s := &Server{cfg: cfg, ca: authority, log: log, scripts: scripts, aborts: map[string]*abortCount{}}
	s.dialer = net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	s.engine.Store(engine)
	s.transport = &http.Transport{
		DialContext:           s.dialUpstream,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: cfg.SkipServerCertVerify},
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return s
}

// SetEngine atomically replaces the rewrite rules.
func (s *Server) SetEngine(e *rewrite.Engine) { s.engine.Store(e) }

// ListenAndServe serves until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}

// Serve serves proxy requests on ln until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.intercL = newChanListener(ln.Addr())
	s.intercS = &http.Server{
		Handler:           http.HandlerFunc(s.serveIntercepted),
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if v, ok := s.meta.Load(c); ok {
				return context.WithValue(ctx, ctxKey{}, v)
			}
			return ctx
		},
		ConnState: func(c net.Conn, st http.ConnState) {
			if st == http.StateClosed || st == http.StateHijacked {
				s.meta.Delete(c)
			}
		},
	}
	s.front = &http.Server{
		Handler:           http.HandlerFunc(s.serveFront),
		ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
	}
	go func() { _ = s.intercS.Serve(s.intercL) }()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = s.front.Shutdown(sctx)
		_ = s.intercS.Shutdown(sctx)
	}()
	err := s.front.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) serveFront(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		if r.URL.IsAbs() {
			s.serveIntercepted(w, r)
			return
		}
		http.Error(w, "openclash-mitm is a proxy", http.StatusBadRequest)
		return
	}
	host, port, err := splitHostPort(r.Host, 443)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		conn.Close()
		return
	}
	go s.handleTunnel(&bufConn{Conn: conn, r: rw.Reader}, &connInfo{host: host, port: port})
}

func (s *Server) handleTunnel(c *bufConn, info *connInfo) {
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	first, err := c.r.Peek(1)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			// Server speaks first; the bufio.Reader is empty but remembers
			// the timeout, so tunnel the raw connection instead.
			s.passthrough(c.Conn, info, "no client data")
			return
		}
		c.Close()
		return
	}
	if first[0] == 0x16 {
		if !s.shouldDecrypt(info) {
			s.passthrough(c, info, "")
			return
		}
		s.decryptTLS(c, info)
		return
	}
	if looksLikeHTTP(c.r) {
		s.meta.Store(net.Conn(c), info)
		if err := s.intercL.push(c); err != nil {
			c.Close()
		}
		return
	}
	s.passthrough(c, info, "not HTTP")
}

func (s *Server) shouldDecrypt(info *connInfo) bool {
	if until, ok := s.bypass.Load(info.host); ok {
		if time.Now().Before(until.(time.Time)) {
			return false
		}
		s.bypass.Delete(info.host)
	}
	return s.engine.Load().Hosts.Match(info.host, info.port)
}

func (s *Server) decryptTLS(c *bufConn, info *connInfo) {
	tlsConn := tls.Server(c, &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = info.host
			}
			return s.ca.CertificateFor(name)
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	err := tlsConn.HandshakeContext(ctx)
	cancel()
	if err != nil {
		if s.cfg.BypassTTL > 0 && s.clientRejectedCert(info.host, err) {
			s.bypass.Store(info.host, time.Now().Add(s.cfg.BypassTTL))
			s.log.Warn("client rejected MITM certificate, host is tunnelled without decryption for a while; trust the CA on the device or remove the host if the app pins certificates",
				"host", info.host, "bypass", s.cfg.BypassTTL, "err", err)
		} else {
			s.log.Debug("TLS handshake failed", "host", info.host, "err", err)
		}
		tlsConn.Close()
		return
	}
	s.log.Info("decrypting", "host", info.authority(), "alpn", tlsConn.ConnectionState().NegotiatedProtocol)
	s.meta.Store(net.Conn(tlsConn), info)
	if err := s.intercL.push(tlsConn); err != nil {
		tlsConn.Close()
	}
}

func (s *Server) clientRejectedCert(host string, err error) bool {
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "remote error") {
		for _, alert := range []string{"bad certificate", "unknown certificate", "certificate unknown", "unknown ca", "certificate required", "unsupported certificate", "access denied"} {
			if strings.Contains(msg, alert) {
				return true
			}
		}
		return false
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !strings.Contains(msg, "connection reset") {
		return false
	}
	s.abortMu.Lock()
	defer s.abortMu.Unlock()
	now := time.Now()
	a := s.aborts[host]
	if a == nil || now.Sub(a.first) > abortWindow {
		if len(s.aborts) > 4096 {
			s.aborts = map[string]*abortCount{}
		}
		a = &abortCount{first: now}
		s.aborts[host] = a
	}
	a.n++
	if a.n >= abortThreshold {
		delete(s.aborts, host)
		return true
	}
	return false
}

func (s *Server) passthrough(c net.Conn, info *connInfo, reason string) {
	up, err := s.dialUpstream(context.Background(), "tcp", info.authority())
	if err != nil {
		s.log.Warn("tunnel upstream dial failed", "host", info.authority(), "err", err)
		c.Close()
		return
	}
	if reason != "" {
		s.log.Debug("tunnelling", "host", info.authority(), "reason", reason)
	}
	pipe(c, up)
}

func (s *Server) serveIntercepted(w http.ResponseWriter, r *http.Request) {
	info, _ := r.Context().Value(ctxKey{}).(*connInfo)
	origURL := requestURL(r, info)
	eng := s.engine.Load()
	reqScripts := eng.MatchScripts(rewrite.PhaseRequest, origURL)
	respScripts := eng.MatchScripts(rewrite.PhaseResponse, origURL)
	s.log.Info("request", "method", r.Method, "url", origURL,
		"req_scripts", len(reqScripts), "resp_scripts", len(respScripts))

	target := origURL
	// Defer reject until after request scripts so hijack rules like BoxJS can
	// answer locally, then still block fall-through to the real upstream site.
	var deferredReject *rewrite.URLRule
	if rule := eng.MatchURL(origURL); rule != nil {
		switch {
		case rule.Action.IsReject():
			deferredReject = rule
		case rule.Action == rewrite.Action302 || rule.Action == rewrite.Action307:
			loc := rule.Rewrite(origURL)
			s.log.Info("url-rewrite", "action", rule.Action, "url", origURL, "location", loc, "source", rule.Source)
			code := http.StatusFound
			if rule.Action == rewrite.Action307 {
				code = http.StatusTemporaryRedirect
			}
			w.Header().Set("Location", loc)
			w.WriteHeader(code)
			return
		case rule.Action == rewrite.ActionTransparent:
			target = rule.Rewrite(origURL)
			s.log.Info("url-rewrite", "action", rule.Action, "url", origURL, "target", target, "source", rule.Source)
		}
	}

	if s.scripts != nil && eng.HasScripts(rewrite.PhaseRequest, origURL) {
		outcome := s.runRequestScripts(w, r, eng, &origURL, &target)
		switch outcome {
		case scriptAbort:
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(http.StatusForbidden)
			return
		case scriptRespond:
			return
		}
	}

	if deferredReject != nil {
		s.log.Info("url-rewrite", "action", deferredReject.Action, "url", origURL, "source", deferredReject.Source)
		writeReject(w, deferredReject.Action)
		return
	}

	targetURL, err := parseURL(target)
	if err != nil {
		http.Error(w, "bad rewrite target: "+err.Error(), http.StatusBadGateway)
		return
	}

	if applied := eng.ApplyHeaders(rewrite.PhaseRequest, origURL, r.Header); len(applied) > 0 {
		s.log.Info("header-rewrite", "phase", "request", "url", origURL, "rules", len(applied))
	}
	if eng.HasBodyRules(rewrite.PhaseRequest, origURL) {
		s.rewriteRequestBody(r, eng, origURL)
	}
	rewriteRespBody := eng.HasBodyRules(rewrite.PhaseResponse, origURL)
	runRespScripts := s.scripts != nil && eng.HasScripts(rewrite.PhaseResponse, origURL)
	needRespBody := rewriteRespBody || runRespScripts

	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL = targetURL
			pr.Out.Host = targetURL.Host
			if needRespBody {
				// Let the transport negotiate gzip and decode it transparently.
				pr.Out.Header.Del("Accept-Encoding")
			}
		},
		Transport:     s.transport,
		FlushInterval: 50 * time.Millisecond,
		ModifyResponse: func(resp *http.Response) error {
			if applied := eng.ApplyHeaders(rewrite.PhaseResponse, origURL, resp.Header); len(applied) > 0 {
				s.log.Info("header-rewrite", "phase", "response", "url", origURL, "rules", len(applied))
			}
			if rewriteRespBody {
				s.rewriteResponseBody(resp, eng, origURL)
			}
			if runRespScripts {
				if aborted := s.runResponseScripts(resp, r, eng, origURL); aborted {
					resp.Body = io.NopCloser(bytes.NewReader(nil))
					resp.StatusCode = http.StatusForbidden
					resp.ContentLength = 0
					resp.Header.Set("Content-Length", "0")
					resp.Header.Del("Content-Encoding")
					resp.Header.Del("Transfer-Encoding")
				}
			}
			s.log.Info("response", "status", resp.StatusCode, "url", origURL,
				"body_rewrite", rewriteRespBody, "resp_scripts", len(respScripts))
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if !errors.Is(err, context.Canceled) {
				s.log.Warn("upstream request failed", "url", target, "err", err)
			}
			w.WriteHeader(http.StatusBadGateway)
		},
		ErrorLog: slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
	}
	rp.ServeHTTP(w, r)
}

type scriptOutcome int

const (
	scriptContinue scriptOutcome = iota
	scriptAbort
	scriptRespond
)

func (s *Server) runRequestScripts(w http.ResponseWriter, r *http.Request, eng *rewrite.Engine, origURL, target *string) scriptOutcome {
	rules := eng.MatchScripts(rewrite.PhaseRequest, *origURL)
	if len(rules) == 0 {
		return scriptContinue
	}
	var body []byte
	bodyLoaded := false
	ensureBody := func(rule *rewrite.ScriptRule) ([]byte, bool) {
		if !rule.RequireBody {
			return nil, true
		}
		if bodyLoaded {
			return body, true
		}
		bodyLoaded = true
		if r.Body == nil || r.Body == http.NoBody {
			body = nil
			return body, true
		}
		limit := s.cfg.MaxBodySize
		if rule.MaxSize > 0 && rule.MaxSize < limit {
			limit = rule.MaxSize
		}
		b, ok, err := readLimited(r.Body, limit)
		if err != nil {
			r.Body = io.NopCloser(bytes.NewReader(b))
			s.log.Warn("script skipped, read request body failed", "name", rule.Name, "err", err)
			return nil, false
		}
		if !ok {
			r.Body = struct {
				io.Reader
				io.Closer
			}{io.MultiReader(bytes.NewReader(b), r.Body), r.Body}
			s.log.Warn("script skipped, request body too large", "name", rule.Name, "limit", limit)
			return nil, false
		}
		r.Body.Close()
		body = b
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		r.Header.Set("Content-Length", strconv.Itoa(len(body)))
		return body, true
	}

	for _, rule := range rules {
		b, ok := ensureBody(rule)
		if !ok {
			continue
		}
		in := script.Input{URL: *origURL, Method: r.Method, Headers: r.Header.Clone()}
		if rule.RequireBody {
			in.Body = b
		}
		res, err := s.scripts.Run(rule, in)
		if err != nil {
			s.log.Warn("script failed", "name", rule.Name, "phase", "request", "err", err)
			continue
		}
		switch res.Kind {
		case script.ResultAbort:
			s.log.Info("script", "phase", "request", "name", rule.Name, "action", "abort")
			return scriptAbort
		case script.ResultNoop:
			continue
		case script.ResultMutate:
			s.log.Info("script", "phase", "request", "name", rule.Name, "action", "mutate")
			if res.Response != nil {
				writeScriptResponse(w, res.Response)
				return scriptRespond
			}
			if res.URL != "" {
				*origURL = res.URL
				*target = res.URL
			}
			if res.Headers != nil {
				r.Header = res.Headers
			}
			if res.BodySet {
				body = res.Body
				bodyLoaded = true
				r.Body = io.NopCloser(bytes.NewReader(body))
				r.ContentLength = int64(len(body))
				r.Header.Set("Content-Length", strconv.Itoa(len(body)))
			}
		}
	}
	return scriptContinue
}

func (s *Server) runResponseScripts(resp *http.Response, req *http.Request, eng *rewrite.Engine, url string) (aborted bool) {
	rules := eng.MatchScripts(rewrite.PhaseResponse, url)
	if len(rules) == 0 {
		return false
	}
	var body []byte
	bodyLoaded := false
	ensureBody := func(rule *rewrite.ScriptRule) ([]byte, bool) {
		if !rule.RequireBody {
			return nil, true
		}
		if bodyLoaded {
			return body, true
		}
		bodyLoaded = true
		if resp.Body == nil || resp.Body == http.NoBody || resp.StatusCode == http.StatusNoContent ||
			resp.StatusCode == http.StatusNotModified || req.Method == http.MethodHead {
			body = nil
			return body, true
		}
		limit := s.cfg.MaxBodySize
		if rule.MaxSize > 0 && rule.MaxSize < limit {
			limit = rule.MaxSize
		}
		raw, ok, err := readLimited(resp.Body, limit)
		if err != nil {
			resp.Body = io.NopCloser(bytes.NewReader(raw))
			s.log.Warn("script skipped, read response body failed", "name", rule.Name, "err", err)
			return nil, false
		}
		if !ok {
			resp.Body = struct {
				io.Reader
				io.Closer
			}{io.MultiReader(bytes.NewReader(raw), resp.Body), resp.Body}
			s.log.Warn("script skipped, response body too large", "name", rule.Name, "limit", limit)
			return nil, false
		}
		resp.Body.Close()
		decoded, encoding, err := decodeBody(raw, resp.Header.Get("Content-Encoding"))
		if err != nil {
			resp.Body = io.NopCloser(bytes.NewReader(raw))
			s.log.Warn("script skipped, decode response failed", "name", rule.Name, "err", err)
			return nil, false
		}
		if encoding != "" {
			resp.Header.Del("Content-Encoding")
		}
		body = decoded
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
		resp.Header.Del("Transfer-Encoding")
		return body, true
	}

	for _, rule := range rules {
		b, ok := ensureBody(rule)
		if !ok {
			continue
		}
		in := script.Input{
			URL: url, Method: req.Method, Headers: req.Header.Clone(),
			HasResponse: true, Status: resp.StatusCode, RespHeaders: resp.Header.Clone(),
		}
		if rule.RequireBody {
			in.RespBody = b
		}
		res, err := s.scripts.Run(rule, in)
		if err != nil {
			s.log.Warn("script failed", "name", rule.Name, "phase", "response", "err", err)
			continue
		}
		switch res.Kind {
		case script.ResultAbort:
			s.log.Info("script", "phase", "response", "name", rule.Name, "action", "abort")
			return true
		case script.ResultNoop:
			continue
		case script.ResultMutate:
			s.log.Info("script", "phase", "response", "name", rule.Name, "action", "mutate")
			if res.Status > 0 {
				resp.StatusCode = res.Status
				resp.Status = fmt.Sprintf("%d %s", res.Status, http.StatusText(res.Status))
			}
			if res.Headers != nil {
				resp.Header = res.Headers
			}
			if res.BodySet {
				body = res.Body
				bodyLoaded = true
				resp.Body = io.NopCloser(bytes.NewReader(body))
				resp.ContentLength = int64(len(body))
				resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
				resp.Header.Del("Content-Encoding")
				resp.Header.Del("Transfer-Encoding")
			}
		}
	}
	return false
}

func writeScriptResponse(w http.ResponseWriter, dr *script.DoneResponse) {
	if dr == nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	status := dr.Status
	if status == 0 {
		status = http.StatusOK
	}
	for k, vs := range dr.Headers {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(dr.Body)))
	w.WriteHeader(status)
	_, _ = w.Write(dr.Body)
}

func (s *Server) rewriteRequestBody(r *http.Request, eng *rewrite.Engine, url string) {
	if r.Body == nil || r.Body == http.NoBody {
		return
	}
	if enc := r.Header.Get("Content-Encoding"); enc != "" && enc != "identity" {
		s.log.Warn("body-rewrite skipped, encoded request body", "url", url, "encoding", enc)
		return
	}
	body, ok, err := readLimited(r.Body, s.cfg.MaxBodySize)
	if err != nil {
		r.Body = io.NopCloser(bytes.NewReader(body))
		return
	}
	if !ok {
		s.log.Warn("body-rewrite skipped, request body too large", "url", url, "limit", s.cfg.MaxBodySize)
		r.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(body), r.Body), r.Body}
		return
	}
	r.Body.Close()
	out, applied, errs := eng.ApplyBody(rewrite.PhaseRequest, url, body)
	for _, e := range errs {
		s.log.Warn("body-rewrite failed", "phase", "request", "url", url, "err", e)
	}
	if len(applied) > 0 {
		s.log.Info("body-rewrite", "phase", "request", "url", url, "rules", len(applied))
	}
	r.Body = io.NopCloser(bytes.NewReader(out))
	r.ContentLength = int64(len(out))
	r.Header.Set("Content-Length", strconv.Itoa(len(out)))
}

func (s *Server) rewriteResponseBody(resp *http.Response, eng *rewrite.Engine, url string) {
	if resp.Body == nil || resp.Body == http.NoBody || resp.StatusCode == http.StatusNoContent ||
		resp.StatusCode == http.StatusNotModified || resp.Request.Method == http.MethodHead {
		return
	}
	body, ok, err := readLimited(resp.Body, s.cfg.MaxBodySize)
	if err != nil {
		s.log.Warn("body-rewrite skipped, read response failed", "url", url, "err", err)
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return
	}
	if !ok {
		s.log.Warn("body-rewrite skipped, response body too large", "url", url, "limit", s.cfg.MaxBodySize)
		resp.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(body), resp.Body), resp.Body}
		return
	}
	resp.Body.Close()
	decoded, encoding, err := decodeBody(body, resp.Header.Get("Content-Encoding"))
	if err != nil {
		s.log.Warn("body-rewrite skipped", "url", url, "err", err)
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return
	}
	out, applied, errs := eng.ApplyBody(rewrite.PhaseResponse, url, decoded)
	for _, e := range errs {
		s.log.Warn("body-rewrite failed", "phase", "response", "url", url, "err", e)
	}
	if len(applied) == 0 {
		out = body
	} else {
		s.log.Info("body-rewrite", "phase", "response", "url", url, "rules", len(applied))
		if encoding != "" {
			resp.Header.Del("Content-Encoding")
		}
	}
	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
	resp.Header.Del("Transfer-Encoding")
}

// dialUpstream opens a TCP connection to addr through the upstream HTTP proxy.
func (s *Server) dialUpstream(ctx context.Context, _, addr string) (net.Conn, error) {
	if s.cfg.Upstream == "" {
		return s.dialer.DialContext(ctx, "tcp", addr)
	}
	c, err := s.dialer.DialContext(ctx, "tcp", s.cfg.Upstream)
	if err != nil {
		return nil, fmt.Errorf("dial upstream %s: %w", s.cfg.Upstream, err)
	}
	deadline := time.Now().Add(15 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	if _, err := fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr); err != nil {
		c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("upstream CONNECT %s: %w", addr, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		c.Close()
		return nil, fmt.Errorf("upstream CONNECT %s: %s", addr, resp.Status)
	}
	_ = c.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		return &bufConn{Conn: c, r: br}, nil
	}
	return c, nil
}

func looksLikeHTTP(r *bufio.Reader) bool {
	b, _ := r.Peek(8)
	i := bytes.IndexByte(b, ' ')
	if i < 3 {
		return false
	}
	for _, ch := range b[:i] {
		if ch < 'A' || ch > 'Z' {
			return false
		}
	}
	return true
}

func splitHostPort(hostport string, defPort int) (string, int, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		if strings.Contains(err.Error(), "missing port") {
			return strings.Trim(hostport, "[]"), defPort, nil
		}
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port %q", portStr)
	}
	return host, port, nil
}
