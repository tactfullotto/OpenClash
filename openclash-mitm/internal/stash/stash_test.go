package stash

import (
	"strings"
	"testing"

	"github.com/vernesong/OpenClash/openclash-mitm/internal/rewrite"
	"github.com/vernesong/OpenClash/openclash-mitm/internal/script"
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
	if len(o.ScriptProviders) != 4 {
		t.Errorf("script-providers = %d", len(o.ScriptProviders))
	}

	// Without network downloads, remote script providers are skipped with warnings.
	e, warns := Compile([]*Override{o}, []string{"extra.example.com"}, nil)
	if !e.Hosts.Match("weatherkit.apple.com", 443) || !e.Hosts.Match("extra.example.com", 443) {
		t.Error("mitm hosts not compiled")
	}
	if len(e.Scripts) != 0 {
		t.Errorf("expected no scripts without loader downloads, got %d", len(e.Scripts))
	}
	if len(warns) < 5 {
		t.Errorf("warnings = %v", warns)
	}
}

func TestCompileScriptPayload(t *testing.T) {
	o, err := Parse("inline", []byte(`
name: demo
http:
  mitm:
    - "api.demo.com"
  script:
    - match: ^https://api\.demo\.com/x
      name: demo-script
      type: response
      require-body: true
script-providers:
  demo-script:
    payload: |
      $done({body: '{"ok":true}'});
`))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	loader, err := script.NewLoader(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	e, warns := Compile([]*Override{o}, nil, &CompileOptions{Loader: loader})
	if len(warns) != 0 {
		t.Fatalf("warnings: %v", warns)
	}
	if len(e.Scripts) != 1 || e.Scripts[0].Name != "demo-script" {
		t.Fatalf("scripts = %+v", e.Scripts)
	}
	if !e.HasScripts(rewrite.PhaseResponse, "https://api.demo.com/x") {
		t.Error("script should match")
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
	e, warns := Compile([]*Override{o}, nil, nil)
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
