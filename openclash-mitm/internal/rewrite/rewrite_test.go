package rewrite

import (
	"net/http"
	"reflect"
	"testing"
)

func TestTokenize(t *testing.T) {
	cases := map[string][]string{
		`^https://a.com/x - reject`:                                        {`^https://a.com/x`, `-`, `reject`},
		`^https://a response-jq '.a = "b c"'`:                              {`^https://a`, `response-jq`, `.a = "b c"`},
		`^https://a response-replace-regex "\"vip\":false" "\"vip\":true"`: {`^https://a`, `response-replace-regex`, `"vip":false`, `"vip":true`},
		`^https?:\/\/a\.com\/(\d+)  https://b.com/$1   302`:                {`^https?:\/\/a\.com\/(\d+)`, `https://b.com/$1`, `302`},
	}
	for in, want := range cases {
		got, err := tokenize(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("tokenize(%s) = %q, want %q", in, got, want)
		}
	}
	if _, err := tokenize(`a 'b`); err == nil {
		t.Error("expected error for unterminated quote")
	}
}

func TestHostMatcher(t *testing.T) {
	m, errs := NewHostMatcher([]string{"weatherkit.apple.com", "*.example.com", "-skip.example.com", "api.?.cn", "alt.com:8443", "+.suffix.org", "any.net:*"})
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	cases := []struct {
		host string
		port int
		want bool
	}{
		{"weatherkit.apple.com", 443, true},
		{"WeatherKit.Apple.com.", 443, true},
		{"weatherkit.apple.com", 8443, false},
		{"a.example.com", 443, true},
		{"a.b.example.com", 443, true},
		{"example.com", 443, false},
		{"skip.example.com", 443, false},
		{"api.x.cn", 443, true},
		{"api.xy.cn", 443, false},
		{"alt.com", 8443, true},
		{"alt.com", 443, false},
		{"suffix.org", 443, true},
		{"a.suffix.org", 443, true},
		{"any.net", 9000, true},
		{"other.com", 443, false},
	}
	for _, c := range cases {
		if got := m.Match(c.host, c.port); got != c.want {
			t.Errorf("Match(%s, %d) = %v, want %v", c.host, c.port, got, c.want)
		}
	}
}

func TestURLRewrite(t *testing.T) {
	r, err := ParseURLRewrite(`^https?:\/\/(www\.)?g\.cn\/(.*) https://www.google.com/$2 302`, "t")
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Rewrite("http://www.g.cn/search?q=1"); got != "https://www.google.com/search?q=1" {
		t.Errorf("rewrite = %s", got)
	}
	for _, line := range []string{`^https://ad\.com - reject`, `^https://ad\.com reject-dict`, `^https://(?!keep)ad - reject-img`} {
		r, err := ParseURLRewrite(line, "t")
		if err != nil {
			t.Fatalf("%s: %v", line, err)
		}
		if !r.Action.IsReject() {
			t.Errorf("%s: expected reject action", line)
		}
	}
	if _, err := ParseURLRewrite(`^https://a.com - 302`, "t"); err == nil {
		t.Error("302 without target should fail")
	}
	if _, err := ParseURLRewrite(`^https://a.com https://b.com bogus`, "t"); err == nil {
		t.Error("unknown action should fail")
	}
}

func TestHeaderRewrite(t *testing.T) {
	var e Engine
	for _, line := range []string{
		`^https://a\.com request-add X-Test hello world`,
		`^https://a\.com request-del Cookie`,
		`^https://a\.com request-replace User-Agent Stash/2.0`,
		`^https://a\.com request-replace X-Missing nope`,
		`^https://a\.com request-replace-regex Accept-Language ^zh-CN en-US`,
		`^https://a\.com response-add X-Resp 1`,
		`^https://other\.com request-add X-Other 1`,
	} {
		r, err := ParseHeaderRewrite(line, "t")
		if err != nil {
			t.Fatalf("%s: %v", line, err)
		}
		e.Header = append(e.Header, r)
	}
	h := http.Header{"Cookie": {"a=1"}, "User-Agent": {"curl"}, "Accept-Language": {"zh-CN,zh;q=0.9"}}
	applied := e.ApplyHeaders(PhaseRequest, "https://a.com/x", h)
	if len(applied) != 4 {
		t.Errorf("applied %d rules, want 4: %v", len(applied), applied)
	}
	want := http.Header{"X-Test": {"hello world"}, "User-Agent": {"Stash/2.0"}, "Accept-Language": {"en-US,zh;q=0.9"}}
	if !reflect.DeepEqual(h, want) {
		t.Errorf("headers = %v, want %v", h, want)
	}
	rh := http.Header{}
	e.ApplyHeaders(PhaseResponse, "https://a.com/x", rh)
	if rh.Get("X-Resp") != "1" {
		t.Errorf("response header missing: %v", rh)
	}
}

func TestBodyRewrite(t *testing.T) {
	var e Engine
	for _, line := range []string{
		`^https://a\.com/vip response-replace-regex '"vip":false' '"vip":true' '"level":\d+' '"level":9'`,
		`^https://a\.com/json response-jq '.data.ads = [] | .id'`,
		`^https://a\.com/json response-jq 'del(.data.ads)'`,
		`^https://a\.com/req request-jq '.debug = true'`,
	} {
		r, err := ParseBodyRewrite(line, "t")
		if err != nil {
			t.Fatalf("%s: %v", line, err)
		}
		e.Body = append(e.Body, r)
	}
	out, applied, errs := e.ApplyBody(PhaseResponse, "https://a.com/vip", []byte(`{"vip":false,"level":1}`))
	if len(errs) > 0 || len(applied) != 1 || string(out) != `{"vip":true,"level":9}` {
		t.Errorf("regex body = %s applied=%v errs=%v", out, applied, errs)
	}

	// The first jq rule turns the body into the id; big integers must survive.
	out, applied, errs = e.ApplyBody(PhaseResponse, "https://a.com/json", []byte(`{"id":12345678901234567890,"data":{"ads":[1],"x":"<b>"}}`))
	if len(applied) != 1 || len(errs) != 1 || string(out) != `12345678901234567890` {
		t.Errorf("jq body = %s applied=%v errs=%v", out, applied, errs)
	}

	out, _, _ = e.ApplyBody(PhaseRequest, "https://a.com/req", []byte(`{"a":"<x>"}`))
	if string(out) != `{"a":"<x>","debug":true}` {
		t.Errorf("request jq = %s", out)
	}
	if !e.HasBodyRules(PhaseRequest, "https://a.com/req") || e.HasBodyRules(PhaseRequest, "https://a.com/vip") {
		t.Error("HasBodyRules mismatch")
	}

	if _, err := ParseBodyRewrite(`^https://a response-replace-regex only-one`, "t"); err == nil {
		t.Error("odd replace pairs should fail")
	}
	if _, err := ParseBodyRewrite(`^https://a response-jq '.a ='`, "t"); err == nil {
		t.Error("bad jq should fail")
	}
}
