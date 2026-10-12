package rewrite

import (
	"regexp"
	"strconv"
	"strings"
)

// HostMatcher decides which CONNECT targets are decrypted. It follows the
// Surge/Stash hostname list semantics: "*" and "?" are wildcards, a leading
// "-" excludes matching hosts, and an optional ":port" suffix restricts the
// pattern to that port. Patterns without a port apply to port 443 only.
type HostMatcher struct {
	include []hostPattern
	exclude []hostPattern
}

type hostPattern struct {
	raw  string
	re   *regexp.Regexp
	port int // 0 = default (443), -1 = any port
}

// NewHostMatcher compiles the given hostname patterns. Invalid entries are
// returned as errors but do not prevent the remaining patterns from loading.
func NewHostMatcher(patterns []string) (*HostMatcher, []error) {
	m := &HostMatcher{}
	var errs []error
	for _, raw := range patterns {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		exclude := strings.HasPrefix(p, "-")
		p = strings.TrimPrefix(p, "-")
		hp, err := compileHostPattern(p)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		hp.raw = raw
		if exclude {
			m.exclude = append(m.exclude, hp)
		} else {
			m.include = append(m.include, hp)
		}
	}
	return m, errs
}

func compileHostPattern(p string) (hostPattern, error) {
	hp := hostPattern{}
	host := strings.ToLower(p)
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host[:i], ":") {
		portStr := host[i+1:]
		host = host[:i]
		if portStr == "*" || portStr == "0" {
			hp.port = -1
		} else {
			port, err := strconv.Atoi(portStr)
			if err != nil || port < 1 || port > 65535 {
				return hp, &PatternError{Pattern: p, Reason: "invalid port"}
			}
			hp.port = port
		}
	}
	// Mihomo-style "+.example.com" means example.com and all subdomains.
	if strings.HasPrefix(host, "+.") {
		base := regexp.QuoteMeta(host[2:])
		hp.re = regexp.MustCompile(`^(?:.+\.)?` + base + `$`)
		return hp, nil
	}
	var b strings.Builder
	b.WriteString("^")
	for _, r := range host {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return hp, &PatternError{Pattern: p, Reason: err.Error()}
	}
	hp.re = re
	return hp, nil
}

func (hp hostPattern) match(host string, port int) bool {
	switch hp.port {
	case -1:
	case 0:
		if port != 443 {
			return false
		}
	default:
		if port != hp.port {
			return false
		}
	}
	return hp.re.MatchString(host)
}

// Match reports whether host:port should be decrypted.
func (m *HostMatcher) Match(host string, port int) bool {
	if m == nil {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, p := range m.exclude {
		if p.match(host, port) {
			return false
		}
	}
	for _, p := range m.include {
		if p.match(host, port) {
			return true
		}
	}
	return false
}

// Empty reports whether no hostname will ever be decrypted.
func (m *HostMatcher) Empty() bool { return m == nil || len(m.include) == 0 }

// PatternError describes an invalid hostname or rewrite pattern.
type PatternError struct {
	Pattern string
	Reason  string
}

func (e *PatternError) Error() string { return e.Pattern + ": " + e.Reason }
