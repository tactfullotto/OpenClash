package script

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Provider describes a script-providers entry from a Stash override.
type Provider struct {
	URL      string            `yaml:"url"`
	Interval int               `yaml:"interval"`
	Payload  string            `yaml:"payload"`
	Path     string            `yaml:"path"`
	Headers  map[string]string `yaml:"headers"`
}

// Loader resolves script source by name from providers, with disk cache.
type Loader struct {
	Dir    string
	Client *http.Client

	mu    sync.Mutex
	cache map[string]cachedScript
}

type cachedScript struct {
	code    string
	fetched time.Time
}

// NewLoader creates a script loader that caches under dir.
func NewLoader(dir string, client *http.Client) (*Loader, error) {
	if dir == "" {
		dir = os.TempDir()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	return &Loader{Dir: dir, Client: client, cache: map[string]cachedScript{}}, nil
}

// Load returns the JavaScript source for name using provider.
func (l *Loader) Load(name string, p Provider) (string, error) {
	if p.Path != "" {
		b, err := os.ReadFile(p.Path)
		if err == nil && len(b) > 0 {
			return string(b), nil
		}
		if err != nil && !os.IsNotExist(err) {
			return "", err
		}
	}
	if strings.TrimSpace(p.Payload) != "" && p.URL == "" {
		if p.Path != "" {
			_ = os.MkdirAll(filepath.Dir(p.Path), 0o755)
			_ = os.WriteFile(p.Path, []byte(p.Payload), 0o644)
		}
		return p.Payload, nil
	}

	interval := time.Duration(p.Interval) * time.Second
	if interval <= 0 {
		interval = 24 * time.Hour
	}

	l.mu.Lock()
	if c, ok := l.cache[name]; ok && time.Since(c.fetched) < interval && c.code != "" {
		code := c.code
		l.mu.Unlock()
		return code, nil
	}
	l.mu.Unlock()

	cacheFile := l.cachePath(name, p)
	if fi, err := os.Stat(cacheFile); err == nil && time.Since(fi.ModTime()) < interval {
		b, err := os.ReadFile(cacheFile)
		if err == nil && len(b) > 0 {
			l.remember(name, string(b))
			return string(b), nil
		}
	}

	if p.URL != "" {
		code, err := l.download(p)
		if err != nil {
			if b, rerr := os.ReadFile(cacheFile); rerr == nil && len(b) > 0 {
				l.remember(name, string(b))
				return string(b), nil
			}
			if strings.TrimSpace(p.Payload) != "" {
				return p.Payload, nil
			}
			return "", err
		}
		_ = os.MkdirAll(filepath.Dir(cacheFile), 0o755)
		_ = os.WriteFile(cacheFile, []byte(code), 0o644)
		if p.Path != "" {
			_ = os.MkdirAll(filepath.Dir(p.Path), 0o755)
			_ = os.WriteFile(p.Path, []byte(code), 0o644)
		}
		l.remember(name, code)
		return code, nil
	}

	if strings.TrimSpace(p.Payload) != "" {
		return p.Payload, nil
	}
	if b, err := os.ReadFile(cacheFile); err == nil && len(b) > 0 {
		return string(b), nil
	}
	return "", fmt.Errorf("script provider %q has no url, payload or cached file", name)
}

func (l *Loader) remember(name, code string) {
	l.mu.Lock()
	l.cache[name] = cachedScript{code: code, fetched: time.Now()}
	l.mu.Unlock()
}

func (l *Loader) cachePath(name string, p Provider) string {
	if p.Path != "" {
		return p.Path
	}
	sum := sha1.Sum([]byte(name + "\n" + p.URL))
	safe := sanitize(name)
	return filepath.Join(l.Dir, safe+"_"+hex.EncodeToString(sum[:8])+".js")
}

func (l *Loader) download(p Provider) (string, error) {
	req, err := http.NewRequest(http.MethodGet, p.URL, nil)
	if err != nil {
		return "", err
	}
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "openclash-mitm")
	}
	resp, err := l.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("download %s: HTTP %d", p.URL, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", err
	}
	if len(b) == 0 {
		return "", fmt.Errorf("download %s: empty body", p.URL)
	}
	return string(b), nil
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
		if b.Len() >= 48 {
			break
		}
	}
	if b.Len() == 0 {
		return "script"
	}
	return b.String()
}
