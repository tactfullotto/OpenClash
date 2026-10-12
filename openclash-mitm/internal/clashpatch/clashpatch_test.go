package clashpatch

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/vernesong/OpenClash/openclash-mitm/internal/stash"
)

const baseConfig = `mixed-port: 7890
proxies:
  - &hk {name: HK, type: ss, server: 1.2.3.4, port: 443, cipher: aes-128-gcm, password: x}
proxy-groups:
  - name: Proxy
    type: select
    proxies: [HK, DIRECT]
rule-providers:
  existing:
    type: http
    behavior: domain
    url: https://example.com/existing.yaml
rules:
  - DOMAIN-SUFFIX,apple.com,Proxy
  - MATCH,DIRECT
`

type patched struct {
	Proxies       []map[string]any          `yaml:"proxies"`
	Listeners     []map[string]any          `yaml:"listeners"`
	RuleProviders map[string]map[string]any `yaml:"rule-providers"`
	Rules         []string                  `yaml:"rules"`
}

func run(t *testing.T, config string, overrides []*stash.Override, opts Options) (patched, *Result, []byte) {
	t.Helper()
	out, res, err := Patch([]byte(config), overrides, opts)
	if err != nil {
		t.Fatal(err)
	}
	var p patched
	if err := yaml.Unmarshal(out, &p); err != nil {
		t.Fatalf("patched config is invalid: %v\n%s", err, out)
	}
	return p, res, out
}

func weatherKit(t *testing.T) *stash.Override {
	o, err := stash.Load("../stash/testdata/iRingo.WeatherKit.stoverride")
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestPatchWeatherKitAllClients(t *testing.T) {
	p, res, _ := run(t, baseConfig, []*stash.Override{weatherKit(t)}, Options{EnginePort: 7899, OutPort: 7898, BlockQUIC: true})
	want := []string{
		"DOMAIN,weather-analytics-events.apple.com,REJECT-DROP",
		"DOMAIN-SUFFIX,tthr.apple.com,REJECT-DROP",
		"DOMAIN,tether.edge.apple,REJECT-DROP",
		"AND,((OR,((IP-ASN,714,no-resolve),(IP-ASN,6185,no-resolve))),(AND,((NETWORK,UDP),(DST-PORT,443)))),REJECT-DROP",
		"AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN,weatherkit.apple.com)),REJECT",
		"AND,((DOMAIN,weatherkit.apple.com),(NOT,((IN-NAME,openclash-mitm-out)))),OpenClash-MITM",
		"DOMAIN-SUFFIX,apple.com,Proxy",
		"MATCH,DIRECT",
	}
	if strings.Join(p.Rules, "\n") != strings.Join(want, "\n") {
		t.Errorf("rules:\n%s\nwant:\n%s", strings.Join(p.Rules, "\n"), strings.Join(want, "\n"))
	}
	if res.Hosts != 1 || res.Rules != 6 {
		t.Errorf("result = %+v", res)
	}
	last := p.Proxies[len(p.Proxies)-1]
	if last["name"] != ProxyName || last["type"] != "http" || last["port"] != 7899 {
		t.Errorf("proxy = %v", last)
	}
	if len(p.Listeners) != 1 || p.Listeners[0]["name"] != ListenerName || p.Listeners[0]["port"] != 7898 || p.Listeners[0]["listen"] != "127.0.0.1" {
		t.Errorf("listeners = %v", p.Listeners)
	}
}

func TestPatchScopedToClients(t *testing.T) {
	p, _, _ := run(t, baseConfig, []*stash.Override{weatherKit(t)}, Options{
		EnginePort: 7899, OutPort: 7898, SourceCIDRs: []string{"192.168.1.20", "192.168.1.128/25"},
	})
	src := "(OR,((SRC-IP-CIDR,192.168.1.20/32),(SRC-IP-CIDR,192.168.1.128/25)))"
	if p.Rules[0] != "AND,((DOMAIN,weather-analytics-events.apple.com),"+src+"),REJECT-DROP" {
		t.Errorf("override rule not scoped: %s", p.Rules[0])
	}
	route := p.Rules[4]
	if route != "AND,((DOMAIN,weatherkit.apple.com),"+src+",(NOT,((IN-NAME,openclash-mitm-out)))),OpenClash-MITM" {
		t.Errorf("route = %s", route)
	}
	for _, r := range p.Rules {
		if strings.HasPrefix(r, "AND,((NETWORK,UDP)") {
			t.Errorf("QUIC rule present although BlockQUIC is false: %s", r)
		}
	}
}

func TestPatchValidatesOverrideRules(t *testing.T) {
	o, err := stash.Parse("inline", []byte(`
name: demo
http:
  mitm: ["*.demo.com", "-skip.demo.com", "api-?.demo.net", "10.0.0.1:8443"]
  force-http-engine: ["plain.demo.org:80"]
rules:
  - DOMAIN,a.com,Proxy
  - DOMAIN,b.com,NoSuchGroup
  - RULE-SET,stash-set,REJECT
  - RULE-SET,missing-set,REJECT
  - URL-REGEX,^http://x,REJECT
  - PROTOCOL,STUN,REJECT
  - DEST-PORT,8080,DIRECT
  - IP-CIDR,1.1.1.1/32,REJECT,no-resolve
  - MATCH,Proxy
rule-providers:
  stash-set:
    behavior: domain
    url: https://example.com/set.list
  existing:
    behavior: classical
    url: https://example.com/overridden.yaml
`))
	if err != nil {
		t.Fatal(err)
	}
	p, res, _ := run(t, baseConfig, []*stash.Override{o}, Options{EnginePort: 1, OutPort: 2, SourceCIDRs: []string{"192.168.1.2"}})
	src := "(SRC-IP-CIDR,192.168.1.2/32)"
	want := []string{
		"AND,((DOMAIN,a.com)," + src + "),Proxy",
		"AND,((RULE-SET,stash-set)," + src + "),REJECT",
		"AND,((DST-PORT,8080)," + src + "),DIRECT",
		"AND,((IP-CIDR,1.1.1.1/32,no-resolve)," + src + "),REJECT",
	}
	for i, w := range want {
		if p.Rules[i] != w {
			t.Errorf("rule %d = %s, want %s", i, p.Rules[i], w)
		}
	}
	if len(res.Warnings) != 5 {
		t.Errorf("warnings = %v", res.Warnings)
	}
	route := p.Rules[len(want)]
	for _, part := range []string{"(DOMAIN-SUFFIX,demo.com)", `(DOMAIN-REGEX,^api-.\.demo\.net$)`, "(IP-CIDR,10.0.0.1/32,no-resolve)", "(DOMAIN,plain.demo.org)"} {
		if !strings.Contains(route, part) {
			t.Errorf("route %s missing %s", route, part)
		}
	}
	if strings.Contains(route, "skip.demo.com") {
		t.Errorf("excluded host leaked into route: %s", route)
	}
	sp := p.RuleProviders["stash-set"]
	if sp["type"] != "http" || sp["format"] != "text" || sp["behavior"] != "domain" || sp["interval"] != 86400 {
		t.Errorf("converted provider = %v", sp)
	}
	if p.RuleProviders["existing"]["url"] != "https://example.com/existing.yaml" {
		t.Error("existing provider must not be replaced")
	}
}

func TestPatchIsIdempotentAndKeepsAnchors(t *testing.T) {
	opts := Options{EnginePort: 7899, OutPort: 7898, BlockQUIC: true}
	_, _, once := run(t, baseConfig, []*stash.Override{weatherKit(t)}, opts)
	p, _, twice := run(t, string(once), nil, opts)
	if strings.Count(string(twice), "IN-NAME,openclash-mitm-out") != 0 {
		t.Errorf("stale route rule kept:\n%s", twice)
	}
	for _, px := range p.Proxies {
		if px["name"] == ProxyName {
			t.Error("stale MITM proxy kept")
		}
	}
	if p.Listeners != nil {
		t.Errorf("stale listener kept: %v", p.Listeners)
	}
	if !strings.Contains(string(once), "&hk") {
		t.Error("YAML anchors were dropped")
	}
}

func TestPatchNoHosts(t *testing.T) {
	p, res, _ := run(t, "rules:\n  - MATCH,DIRECT\n", nil, Options{EnginePort: 1, OutPort: 2, BlockQUIC: true})
	if res.Hosts != 0 || len(p.Rules) != 1 || p.Listeners != nil {
		t.Errorf("unexpected patch without hosts: %+v %+v", res, p)
	}
}

func TestParseTopRuleRoundTrip(t *testing.T) {
	for _, r := range []string{
		"DOMAIN,a.com,DIRECT",
		"IP-CIDR,1.1.1.1/32,REJECT,no-resolve",
		"AND,((OR,((IP-ASN,714,no-resolve),(IP-ASN,6185,no-resolve))),(NETWORK,UDP)),REJECT-DROP",
		"NOT,((DOMAIN,a.com)),Proxy",
		"MATCH,DIRECT",
	} {
		e, policy, err := parseTopRule(r)
		if err != nil {
			t.Fatalf("%s: %v", r, err)
		}
		if got := e.top(policy); got != r {
			t.Errorf("round trip %s -> %s", r, got)
		}
	}
	for _, bad := range []string{"DOMAIN", "AND,((DOMAIN,a.com),DIRECT", "AND,(),DIRECT"} {
		if _, _, err := parseTopRule(bad); err == nil {
			t.Errorf("%s: expected error", bad)
		}
	}
}

func TestInvalidSource(t *testing.T) {
	if _, _, err := Patch([]byte("rules: []\n"), nil, Options{SourceCIDRs: []string{"not-an-ip"}}); err == nil {
		t.Error("expected error for invalid source")
	}
}
