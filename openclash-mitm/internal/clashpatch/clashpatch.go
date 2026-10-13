// Package clashpatch injects the MITM engine into a mihomo configuration.
package clashpatch

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/vernesong/OpenClash/openclash-mitm/internal/stash"
)

const (
	// ProxyName is the mihomo proxy that points at the MITM engine.
	ProxyName = "OpenClash-MITM"
	// ListenerName is the mihomo inbound the engine sends decrypted traffic
	// back through, so it is routed by the original rules.
	ListenerName = "openclash-mitm-out"
)

var builtinPolicies = map[string]bool{
	"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true, "COMPATIBLE": true,
}

// Options describes what to inject.
type Options struct {
	EnginePort int
	OutPort    int
	// SourceCIDRs limits decryption and override rules to these LAN clients.
	// Empty means every client.
	SourceCIDRs []string
	// ExtraHosts are appended to the http.mitm lists of the overrides.
	ExtraHosts []string
	// BlockQUIC rejects UDP/443 to decrypted hosts so clients fall back to TCP.
	BlockQUIC bool
}

// Result summarises the patch for logging.
type Result struct {
	Hosts         int
	Rules         int
	RuleProviders int
	Warnings      []string
}

// PatchFile rewrites the mihomo config at path in place.
func PatchFile(path string, overrides []*stash.Override, opts Options) (*Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out, res, err := Patch(data, overrides, opts)
	if err != nil {
		return nil, err
	}
	tmp := path + ".mitm.tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		return nil, err
	}
	return res, os.Rename(tmp, path)
}

// Patch returns the patched mihomo config.
func Patch(config []byte, overrides []*stash.Override, opts Options) ([]byte, *Result, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(config, &doc); err != nil {
		return nil, nil, fmt.Errorf("parse config: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil, fmt.Errorf("config is not a YAML mapping")
	}
	root := doc.Content[0]
	res := &Result{}
	warn := func(format string, a ...any) { res.Warnings = append(res.Warnings, fmt.Sprintf(format, a...)) }

	src, err := sourceExpr(opts.SourceCIDRs)
	if err != nil {
		return nil, nil, err
	}

	proxies := seqOf(root, "proxies")
	removeNamed(proxies, ProxyName)
	listeners := seqOf(root, "listeners")
	removeNamed(listeners, ListenerName)

	policies := map[string]bool{ProxyName: true}
	for k := range builtinPolicies {
		policies[k] = true
	}
	for _, key := range []string{"proxies", "proxy-groups"} {
		if seq := get(root, key); seq != nil && seq.Kind == yaml.SequenceNode {
			for _, item := range seq.Content {
				if n := get(item, "name"); n != nil {
					policies[n.Value] = true
				}
			}
		}
	}

	providers := mapOf(root, "rule-providers")
	providerNames := map[string]bool{}
	for i := 0; i+1 < len(providers.Content); i += 2 {
		providerNames[providers.Content[i].Value] = true
	}
	for _, o := range overrides {
		for name, node := range o.RuleProviders {
			if providerNames[name] {
				continue
			}
			pn, err := convertProvider(node)
			if err != nil {
				warn("%s: rule-provider %s skipped: %v", o.DisplayName(), name, err)
				continue
			}
			providers.Content = append(providers.Content, scalar(name), pn)
			providerNames[name] = true
			res.RuleProviders++
		}
	}
	if len(providers.Content) == 0 {
		deleteKey(root, "rule-providers")
	}

	var injected []string
	for _, o := range overrides {
		for _, raw := range o.Rules {
			rule, err := convertOverrideRule(raw, policies, providerNames, src)
			if err != nil {
				warn("%s: rule %q skipped: %v", o.DisplayName(), raw, err)
				continue
			}
			injected = append(injected, rule)
		}
	}

	hostList := stash.MITMHosts(overrides, opts.ExtraHosts)
	hostList = append(hostList, stash.ForceHTTPEngineHosts(overrides)...)
	hostExprs, hostWarns := hostMatchers(hostList)
	res.Warnings = append(res.Warnings, hostWarns...)
	res.Hosts = len(hostExprs)
	if len(hostExprs) > 0 {
		// Only pin force-http-engine hosts (e.g. boxjs.com). Pinning every
		// MITM hostname breaks overrides like WeatherKit that must still dial
		// the real origin after decryption.
		injectDNSHosts(root, stash.ForceHTTPEngineHosts(overrides))

		hosts := anyOf(hostExprs)
		if opts.BlockQUIC {
			q := and(simple("NETWORK", "UDP"), simple("DST-PORT", "443"), hosts)
			if src != nil {
				q.Children = append(q.Children, src)
			}
			injected = append(injected, q.top("REJECT"))
		}
		route := and(hosts)
		if src != nil {
			route.Children = append(route.Children, src)
		}
		route.Children = append(route.Children, &ruleExpr{Type: "NOT", Children: []*ruleExpr{simple("IN-NAME", ListenerName)}})
		injected = append(injected, route.top(ProxyName))

		proxies.Content = append(proxies.Content, mapping(
			"name", ProxyName, "type", "http", "server", "127.0.0.1", "port", opts.EnginePort,
		))
		listener := mapping("name", ListenerName, "type", "mixed", "listen", "127.0.0.1", "port", opts.OutPort, "udp", false)
		listener.Content = append(listener.Content, scalar("users"), &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle})
		listeners.Content = append(listeners.Content, listener)
	}
	res.Rules = len(injected)
	if len(listeners.Content) == 0 {
		deleteKey(root, "listeners")
	}

	rules := seqOf(root, "rules")
	kept := rules.Content[:0]
	for _, n := range rules.Content {
		if !strings.Contains(n.Value, "IN-NAME,"+ListenerName) {
			kept = append(kept, n)
		}
	}
	nodes := make([]*yaml.Node, 0, len(injected)+len(kept))
	for _, r := range injected {
		nodes = append(nodes, scalar(r))
	}
	rules.Content = append(nodes, kept...)

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, nil, err
	}
	return buf.Bytes(), res, nil
}

func convertOverrideRule(raw string, policies, providers map[string]bool, src *ruleExpr) (string, error) {
	expr, policy, err := parseTopRule(raw)
	if err != nil {
		return "", err
	}
	if expr.Type == "MATCH" {
		return "", fmt.Errorf("MATCH rules are not merged")
	}
	if !policies[policy] {
		return "", fmt.Errorf("policy %q does not exist in the config", policy)
	}
	topParams := expr.Params
	if isLogic(expr.Type) {
		expr.Params = nil
	}
	expr, err = convert(expr)
	if err != nil {
		return "", err
	}
	for _, rs := range expr.ruleSets() {
		if !providers[rs] {
			return "", fmt.Errorf("rule-provider %q does not exist", rs)
		}
	}
	if src == nil {
		if isLogic(expr.Type) {
			expr.Params = topParams
		}
		return expr.top(policy), nil
	}
	wrapped := and(expr, src)
	if isLogic(expr.Type) {
		wrapped.Params = topParams
	}
	return wrapped.top(policy), nil
}

func sourceExpr(cidrs []string) (*ruleExpr, error) {
	var subs []*ruleExpr
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !strings.Contains(c, "/") {
			ip := net.ParseIP(c)
			if ip == nil {
				return nil, fmt.Errorf("invalid source address %q", c)
			}
			if ip.To4() != nil {
				c += "/32"
			} else {
				c += "/128"
			}
		}
		if _, _, err := net.ParseCIDR(c); err != nil {
			return nil, fmt.Errorf("invalid source address %q", c)
		}
		subs = append(subs, simple("SRC-IP-CIDR", c))
	}
	if len(subs) == 0 {
		return nil, nil
	}
	return anyOf(subs), nil
}

func anyOf(subs []*ruleExpr) *ruleExpr {
	if len(subs) == 1 {
		return subs[0]
	}
	return &ruleExpr{Type: "OR", Children: subs}
}

// hostMatchers converts Stash hostname patterns into coarse mihomo matchers.
// Over-matching is harmless: the engine applies the exact Stash semantics and
// tunnels anything it should not decrypt.
func hostMatchers(hosts []string) ([]*ruleExpr, []string) {
	var (
		out   []*ruleExpr
		warns []string
		seen  = map[string]bool{}
	)
	add := func(e *ruleExpr) {
		k := e.sub()
		if !seen[k] {
			seen[k] = true
			out = append(out, e)
		}
	}
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || strings.HasPrefix(h, "-") {
			continue
		}
		if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[:i], ":") {
			h = h[:i]
		}
		h = strings.Trim(h, "[]")
		switch {
		case net.ParseIP(h) != nil:
			bits := "/32"
			if net.ParseIP(h).To4() == nil {
				bits = "/128"
			}
			add(simple("IP-CIDR", h+bits, "no-resolve"))
		case strings.HasPrefix(h, "+."):
			add(simple("DOMAIN-SUFFIX", h[2:]))
		case strings.HasPrefix(h, "*.") && !strings.ContainsAny(h[2:], "*?"):
			add(simple("DOMAIN-SUFFIX", h[2:]))
		case !strings.ContainsAny(h, "*?"):
			add(simple("DOMAIN", h))
		default:
			if h == "*" {
				warns = append(warns, "mitm hostname * decrypts every HTTPS connection of the selected clients")
			}
			add(simple("DOMAIN-REGEX", globRegex(h)))
		}
	}
	return out, warns
}

func globRegex(glob string) string {
	var b strings.Builder
	b.WriteString("^")
	for _, r := range glob {
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
	return b.String()
}

// convertProvider adapts a Stash rule-provider to mihomo.
func convertProvider(node yaml.Node) (*yaml.Node, error) {
	var m map[string]any
	if err := node.Decode(&m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, fmt.Errorf("empty provider")
	}
	u, _ := m["url"].(string)
	if _, ok := m["type"]; !ok {
		if u == "" {
			return nil, fmt.Errorf("provider has neither type nor url")
		}
		m["type"] = "http"
	}
	if _, ok := m["behavior"]; !ok {
		m["behavior"] = "classical"
	}
	if _, ok := m["format"]; !ok && u != "" {
		if pu, err := url.Parse(u); err == nil {
			p := strings.ToLower(pu.Path)
			switch {
			case strings.HasSuffix(p, ".yaml"), strings.HasSuffix(p, ".yml"):
				m["format"] = "yaml"
			case strings.HasSuffix(p, ".mrs"):
				m["format"] = "mrs"
			case strings.HasSuffix(p, ".list"), strings.HasSuffix(p, ".txt"), strings.HasSuffix(p, ".conf"):
				m["format"] = "text"
			}
		}
	}
	if _, ok := m["interval"]; !ok && m["type"] == "http" {
		m["interval"] = 86400
	}
	var out yaml.Node
	if err := out.Encode(m); err != nil {
		return nil, err
	}
	return &out, nil
}

// mitmDNSHost is a fake-ip inside Clash's default fake-ip-range so hijacked
// domains never resolve to a public website when DNS leaks.
const mitmDNSHost = "198.18.0.2"

// injectDNSHosts writes Clash hosts entries for MITM hostnames.
func injectDNSHosts(root *yaml.Node, hostList []string) {
	hosts := mapOf(root, "hosts")
	seen := map[string]bool{}
	for _, raw := range hostList {
		key := clashHostKey(raw)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		if n := get(hosts, key); n != nil {
			n.Kind, n.Tag, n.Value = yaml.ScalarNode, "!!str", mitmDNSHost
			continue
		}
		hosts.Content = append(hosts.Content, scalar(key), scalar(mitmDNSHost))
	}
}

func clashHostKey(raw string) string {
	h := strings.TrimSpace(raw)
	if h == "" || h == "*" || strings.HasPrefix(h, "-") {
		return ""
	}
	if i := strings.LastIndex(h, ":"); i > 0 {
		// strip :port when the suffix looks numeric
		if port := h[i+1:]; port != "" && strings.Trim(port, "0123456789") == "" {
			h = h[:i]
		}
	}
	h = strings.TrimPrefix(h, "*.")
	if h == "" {
		return ""
	}
	if strings.HasPrefix(raw, "*.") || strings.Contains(raw, "*.") {
		return "+." + h
	}
	return h
}

func get(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func deleteKey(m *yaml.Node, key string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return
		}
	}
}

func ensure(m *yaml.Node, key string, kind yaml.Kind, tag string) *yaml.Node {
	if n := get(m, key); n != nil {
		if n.Kind == kind {
			return n
		}
		*n = yaml.Node{Kind: kind, Tag: tag}
		return n
	}
	n := &yaml.Node{Kind: kind, Tag: tag}
	m.Content = append(m.Content, scalar(key), n)
	return n
}

func seqOf(m *yaml.Node, key string) *yaml.Node { return ensure(m, key, yaml.SequenceNode, "!!seq") }
func mapOf(m *yaml.Node, key string) *yaml.Node { return ensure(m, key, yaml.MappingNode, "!!map") }

func removeNamed(seq *yaml.Node, name string) {
	kept := seq.Content[:0]
	for _, item := range seq.Content {
		if n := get(item, "name"); n != nil && n.Value == name {
			continue
		}
		kept = append(kept, item)
	}
	seq.Content = kept
}

func scalar(v string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v} }

func mapping(kv ...any) *yaml.Node {
	m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for i := 0; i+1 < len(kv); i += 2 {
		var v yaml.Node
		_ = v.Encode(kv[i+1])
		m.Content = append(m.Content, scalar(kv[i].(string)), &v)
	}
	return m
}
