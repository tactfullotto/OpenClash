// Package stash loads Stash override (.stoverride) files.
package stash

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/vernesong/OpenClash/openclash-mitm/internal/rewrite"
	"github.com/vernesong/OpenClash/openclash-mitm/internal/script"
)

// Script is a http.script entry.
type Script struct {
	Match       string `yaml:"match"`
	Name        string `yaml:"name"`
	Type        string `yaml:"type"`
	RequireBody bool   `yaml:"require-body"`
	BinaryMode  bool   `yaml:"binary-mode"`
	Timeout     int    `yaml:"timeout"`
	MaxSize     int    `yaml:"max-size"`
	Argument    any    `yaml:"argument"`
}

// ScriptProvider is a script-providers entry.
type ScriptProvider = script.Provider

// HTTP is the http section of an override.
type HTTP struct {
	MITM            []string `yaml:"mitm"`
	ForceHTTPEngine []string `yaml:"force-http-engine"`
	URLRewrite      []string `yaml:"url-rewrite"`
	HeaderRewrite   []string `yaml:"header-rewrite"`
	BodyRewrite     []string `yaml:"body-rewrite"`
	Script          []Script `yaml:"script"`
}

// Override is a parsed .stoverride file.
type Override struct {
	Path            string                    `yaml:"-"`
	Name            string                    `yaml:"name"`
	Desc            string                    `yaml:"desc"`
	HTTP            HTTP                      `yaml:"http"`
	Rules           []string                  `yaml:"rules"`
	RuleProviders   map[string]yaml.Node      `yaml:"rule-providers"`
	ScriptProviders map[string]ScriptProvider `yaml:"script-providers"`
}

// DisplayName returns the override name, falling back to the file name.
func (o *Override) DisplayName() string {
	if n := strings.TrimSpace(o.Name); n != "" {
		return n
	}
	return filepath.Base(o.Path)
}

// Load parses a single override file.
func Load(path string) (*Override, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(path, data)
}

// Parse parses override content. path is only used for messages.
func Parse(path string, data []byte) (*Override, error) {
	o := &Override{}
	if err := yaml.Unmarshal(data, o); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	o.Path = path
	return o, nil
}

// LoadAll parses every path. Files that fail to load are reported and skipped.
func LoadAll(paths []string) ([]*Override, []error) {
	var (
		out  []*Override
		errs []error
	)
	for _, p := range paths {
		o, err := Load(p)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, o)
	}
	return out, errs
}

// MITMHosts returns the merged, de-duplicated http.mitm list plus extra.
func MITMHosts(overrides []*Override, extra []string) []string {
	var all []string
	for _, o := range overrides {
		all = append(all, o.HTTP.MITM...)
	}
	all = append(all, extra...)
	return dedupe(all)
}

// ForceHTTPEngineHosts returns the merged http.force-http-engine list.
func ForceHTTPEngineHosts(overrides []*Override) []string {
	var all []string
	for _, o := range overrides {
		all = append(all, o.HTTP.ForceHTTPEngine...)
	}
	return dedupe(all)
}

// Warning is a non fatal problem found while compiling overrides.
type Warning struct {
	Source string
	Msg    string
}

func (w Warning) String() string { return w.Source + ": " + w.Msg }

// CompileOptions controls optional script loading while compiling.
type CompileOptions struct {
	Loader *script.Loader
}

// Compile builds the rewrite engine from the overrides. extraHosts are
// appended to the http.mitm list. opts may be nil; without a Loader, script
// rules that need a remote provider are skipped with a warning.
func Compile(overrides []*Override, extraHosts []string, opts *CompileOptions) (*rewrite.Engine, []Warning) {
	var warns []Warning
	hosts, errs := rewrite.NewHostMatcher(MITMHosts(overrides, extraHosts))
	for _, err := range errs {
		warns = append(warns, Warning{Source: "mitm", Msg: err.Error()})
	}
	e := &rewrite.Engine{Hosts: hosts}
	var loader *script.Loader
	if opts != nil {
		loader = opts.Loader
	}
	for _, o := range overrides {
		src := o.DisplayName()
		for _, line := range o.HTTP.URLRewrite {
			r, err := rewrite.ParseURLRewrite(line, src)
			if err != nil {
				warns = append(warns, Warning{Source: src, Msg: "url-rewrite skipped: " + err.Error()})
				continue
			}
			e.URL = append(e.URL, r)
		}
		for _, line := range o.HTTP.HeaderRewrite {
			r, err := rewrite.ParseHeaderRewrite(line, src)
			if err != nil {
				warns = append(warns, Warning{Source: src, Msg: "header-rewrite skipped: " + err.Error()})
				continue
			}
			e.Header = append(e.Header, r)
		}
		for _, line := range o.HTTP.BodyRewrite {
			r, err := rewrite.ParseBodyRewrite(line, src)
			if err != nil {
				warns = append(warns, Warning{Source: src, Msg: "body-rewrite skipped: " + err.Error()})
				continue
			}
			e.Body = append(e.Body, r)
		}
		for _, sc := range o.HTTP.Script {
			code, err := resolveScript(loader, o, sc.Name)
			if err != nil {
				warns = append(warns, Warning{Source: src, Msg: fmt.Sprintf("script %q skipped: %v", sc.Name, err)})
				continue
			}
			rule, err := rewrite.NewScriptRule(sc.Match, sc.Name, sc.Type, src, sc.RequireBody, sc.BinaryMode, sc.Timeout, sc.MaxSize, sc.Argument, code)
			if err != nil {
				warns = append(warns, Warning{Source: src, Msg: fmt.Sprintf("script %q skipped: %v", sc.Name, err)})
				continue
			}
			e.Scripts = append(e.Scripts, rule)
		}
	}
	return e, warns
}

func resolveScript(loader *script.Loader, o *Override, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("missing script name")
	}
	p, ok := o.ScriptProviders[name]
	if !ok {
		return "", fmt.Errorf("no script-providers entry")
	}
	if loader == nil {
		if strings.TrimSpace(p.Payload) != "" {
			return p.Payload, nil
		}
		if p.Path != "" {
			b, err := os.ReadFile(p.Path)
			if err != nil {
				return "", err
			}
			return string(b), nil
		}
		return "", fmt.Errorf("script loader not configured")
	}
	return loader.Load(name, p)
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[strings.ToLower(s)] {
			continue
		}
		seen[strings.ToLower(s)] = true
		out = append(out, s)
	}
	return out
}
