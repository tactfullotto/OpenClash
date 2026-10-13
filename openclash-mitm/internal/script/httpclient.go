package script

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPClient is the Go backing for $httpClient.*; requests go through upstream
// when configured (mihomo mitm-out).
type HTTPClient struct {
	Upstream string
	Client   *http.Client
}

func newHTTPClient(upstream string, skipVerify bool) *HTTPClient {
	hc := &HTTPClient{Upstream: upstream}
	transport := &http.Transport{
		Proxy:               hc.proxy,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: skipVerify},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        32,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	}
	hc.Client = &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	return hc
}

func (h *HTTPClient) proxy(req *http.Request) (*url.URL, error) {
	if h.Upstream == "" {
		return nil, nil
	}
	u, err := url.Parse("http://" + h.Upstream)
	if err != nil {
		return nil, err
	}
	return u, nil
}

type httpRequest struct {
	Method       string
	URL          string
	Headers      map[string]string
	Body         []byte
	Timeout      time.Duration
	Insecure     bool
	BinaryMode   bool
	AutoRedirect bool
}

type httpResponse struct {
	Status  int
	Headers map[string]string
	Body    any // string or []byte
}

func (h *HTTPClient) do(method string, opts any) (resp *httpResponse, errMsg string) {
	req, err := parseHTTPOpts(method, opts)
	if err != nil {
		return nil, err.Error()
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var bodyReader io.Reader
	if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, bodyReader)
	if err != nil {
		return nil, err.Error()
	}
	for k, v := range req.Headers {
		if strings.EqualFold(k, "X-Stash-Selected-Proxy") {
			continue
		}
		httpReq.Header.Set(k, v)
	}
	client := h.Client
	if req.Insecure || req.AutoRedirect {
		tr := h.Client.Transport.(*http.Transport).Clone()
		if req.Insecure {
			tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		client = &http.Client{Transport: tr, Timeout: timeout}
		if !req.AutoRedirect {
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		}
	}
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, err.Error()
	}
	defer httpResp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(httpResp.Body, 8<<20))
	if err != nil {
		return nil, err.Error()
	}
	headers := map[string]string{}
	for k, vs := range httpResp.Header {
		if len(vs) > 0 {
			headers[k] = vs[0]
		}
	}
	out := &httpResponse{Status: httpResp.StatusCode, Headers: headers}
	if req.BinaryMode {
		out.Body = b
	} else {
		out.Body = string(b)
	}
	return out, ""
}

func parseHTTPOpts(method string, opts any) (*httpRequest, error) {
	req := &httpRequest{Method: strings.ToUpper(method), Timeout: 5 * time.Second}
	switch v := opts.(type) {
	case string:
		req.URL = v
	case map[string]any:
		if u, ok := v["url"].(string); ok {
			req.URL = u
		}
		if m, ok := v["method"].(string); ok && m != "" {
			req.Method = strings.ToUpper(m)
		}
		if h, ok := v["headers"].(map[string]any); ok {
			req.Headers = map[string]string{}
			for hk, hv := range h {
				req.Headers[hk] = fmt.Sprint(hv)
			}
		}
		if t, ok := asFloat(v["timeout"]); ok && t > 0 {
			req.Timeout = time.Duration(t * float64(time.Second))
		}
		if b, ok := v["insecure"].(bool); ok {
			req.Insecure = b
		}
		if b, ok := v["binary-mode"].(bool); ok {
			req.BinaryMode = b
		}
		if b, ok := v["auto-redirect"].(bool); ok {
			req.AutoRedirect = b
		}
		if body, ok := v["body"]; ok && body != nil {
			switch bv := body.(type) {
			case string:
				req.Body = []byte(bv)
			case []byte:
				req.Body = bv
			default:
				b, err := json.Marshal(bv)
				if err != nil {
					return nil, err
				}
				req.Body = b
				if req.Headers == nil {
					req.Headers = map[string]string{}
				}
				if _, ok := req.Headers["Content-Type"]; !ok {
					req.Headers["Content-Type"] = "application/json"
				}
			}
		}
	default:
		return nil, fmt.Errorf("$httpClient expects url string or options object")
	}
	if req.URL == "" {
		return nil, fmt.Errorf("$httpClient missing url")
	}
	if req.Method == "" {
		req.Method = http.MethodGet
	}
	return req, nil
}

func asFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}
