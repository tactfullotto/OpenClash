package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/vernesong/OpenClash/openclash-mitm/internal/rewrite"
)

// transparentGIF is a 1x1 transparent GIF used by reject-img.
var transparentGIF, _ = base64.StdEncoding.DecodeString("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")

// requestURL reconstructs the absolute URL the client asked for. Default
// ports are omitted so patterns like ^https://host/ match.
func requestURL(r *http.Request, info *connInfo) string {
	if info == nil && r.URL.IsAbs() {
		return r.URL.String()
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if host == "" && info != nil {
		host = info.authority()
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		if (scheme == "https" && p == "443") || (scheme == "http" && p == "80") {
			host = h
			if strings.Contains(h, ":") {
				host = "[" + h + "]"
			}
		}
	} else if info != nil && !((scheme == "https" && info.port == 443) || (scheme == "http" && info.port == 80)) {
		host = net.JoinHostPort(strings.Trim(host, "[]"), fmt.Sprint(info.port))
	}
	return scheme + "://" + host + r.URL.RequestURI()
}

func parseURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("missing host in %q", s)
	}
	return u, nil
}

func writeReject(w http.ResponseWriter, action rewrite.URLAction) {
	h := w.Header()
	switch action {
	case rewrite.ActionReject200:
		h.Set("Content-Length", "0")
		w.WriteHeader(http.StatusOK)
	case rewrite.ActionRejectImg:
		h.Set("Content-Type", "image/gif")
		h.Set("Content-Length", fmt.Sprint(len(transparentGIF)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(transparentGIF)
	case rewrite.ActionRejectDict:
		h.Set("Content-Type", "application/json")
		h.Set("Content-Length", "2")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	case rewrite.ActionRejectArray:
		h.Set("Content-Type", "application/json")
		h.Set("Content-Length", "2")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("[]"))
	default:
		h.Set("Content-Length", "0")
		w.WriteHeader(http.StatusNotFound)
	}
}

// readLimited reads at most limit bytes. ok is false when the body is larger;
// the bytes read so far are returned so the caller can stitch the stream back.
func readLimited(r io.Reader, limit int64) (data []byte, ok bool, err error) {
	data, err = io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return data, false, err
	}
	return data, int64(len(data)) <= limit, nil
}

// decodeBody undoes Content-Encoding. It returns the encoding that was removed.
func decodeBody(body []byte, encoding string) ([]byte, string, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		return body, "", nil
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, "", fmt.Errorf("gzip: %w", err)
		}
		defer zr.Close()
		out, err := io.ReadAll(zr)
		if err != nil {
			return nil, "", fmt.Errorf("gzip: %w", err)
		}
		return out, encoding, nil
	case "deflate":
		// HTTP "deflate" is meant to be zlib wrapped, but raw deflate is common.
		if zr, err := zlib.NewReader(bytes.NewReader(body)); err == nil {
			if out, err := io.ReadAll(zr); err == nil {
				return out, encoding, nil
			}
		}
		out, err := io.ReadAll(flate.NewReader(bytes.NewReader(body)))
		if err != nil {
			return nil, "", fmt.Errorf("deflate: %w", err)
		}
		return out, encoding, nil
	}
	return nil, "", fmt.Errorf("unsupported Content-Encoding %q", encoding)
}
