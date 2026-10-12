package stash

import (
	"strings"
	"testing"
)

func TestLoadWeatherKit(t *testing.T) {
	o, err := Load("testdata/iRingo.WeatherKit.stoverride")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(o.DisplayName(), "WeatherKit") {
		t.Errorf("name = %q", o.DisplayName())
	}
	if len(o.HTTP.MITM) != 1 || o.HTTP.MITM[0] != "weatherkit.apple.com" {
		t.Errorf("mitm = %v", o.HTTP.MITM)
	}
	if len(o.HTTP.Script) != 5 || !o.HTTP.Script[4].BinaryMode {
		t.Errorf("scripts = %+v", o.HTTP.Script)
	}
	if len(o.Rules) != 4 {
		t.Errorf("rules = %v", o.Rules)
	}

	e, warns := Compile([]*Override{o}, []string{"extra.example.com"})
	if !e.Hosts.Match("weatherkit.apple.com", 443) || !e.Hosts.Match("extra.example.com", 443) {
		t.Error("mitm hosts not compiled")
	}
	if len(warns) != 1 || !strings.Contains(warns[0].Msg, "5 script") {
		t.Errorf("warnings = %v", warns)
	}
}

func TestCompileRewrites(t *testing.T) {
	o, err := Parse("inline", []byte(`
name: demo
http:
  mitm:
    - "*.demo.com"
    - "*.demo.com"
  url-rewrite:
    - ^https://ad\.demo\.com - reject
    - ^https://bad - unknown-action
  header-rewrite:
    - ^https://api\.demo\.com request-add X-A 1
  body-rewrite:
    - ^https://api\.demo\.com response-jq '.vip = true'
`))
	if err != nil {
		t.Fatal(err)
	}
	e, warns := Compile([]*Override{o}, nil)
	if len(e.URL) != 1 || len(e.Header) != 1 || len(e.Body) != 1 {
		t.Errorf("compiled url=%d header=%d body=%d", len(e.URL), len(e.Header), len(e.Body))
	}
	if len(warns) != 1 || !strings.Contains(warns[0].Msg, "url-rewrite skipped") {
		t.Errorf("warnings = %v", warns)
	}
	if got := MITMHosts([]*Override{o}, nil); len(got) != 1 {
		t.Errorf("hosts not de-duplicated: %v", got)
	}
}
