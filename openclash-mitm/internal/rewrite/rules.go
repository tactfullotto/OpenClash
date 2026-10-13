// Package rewrite implements Stash style http rewrite rules: url-rewrite,
// header-rewrite and body-rewrite.
package rewrite

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/itchyny/gojq"
)

const regexTimeout = 2 * time.Second

// Phase selects whether a rule applies to the request or the response.
type Phase int

const (
	PhaseRequest Phase = iota
	PhaseResponse
)

func (p Phase) String() string {
	if p == PhaseRequest {
		return "request"
	}
	return "response"
}

// URLAction is the action of a url-rewrite rule.
type URLAction string

const (
	ActionReject      URLAction = "reject"
	ActionReject200   URLAction = "reject-200"
	ActionRejectImg   URLAction = "reject-img"
	ActionRejectDict  URLAction = "reject-dict"
	ActionRejectArray URLAction = "reject-array"
	Action302         URLAction = "302"
	Action307         URLAction = "307"
	ActionTransparent URLAction = "transparent"
)

var urlActions = map[string]URLAction{
	"reject": ActionReject, "reject-200": ActionReject200, "reject-img": ActionRejectImg,
	"reject-dict": ActionRejectDict, "reject-array": ActionRejectArray,
	"302": Action302, "307": Action307, "transparent": ActionTransparent,
}

// IsReject reports whether the action answers the request locally.
func (a URLAction) IsReject() bool { return strings.HasPrefix(string(a), "reject") }

// URLRule is a compiled url-rewrite entry.
type URLRule struct {
	Raw         string
	Source      string
	pattern     *regexp2.Regexp
	Replacement string
	Action      URLAction
}

// HeaderOp is the operation of a header-rewrite rule.
type HeaderOp string

const (
	HeaderAdd          HeaderOp = "add"
	HeaderDel          HeaderOp = "del"
	HeaderReplace      HeaderOp = "replace"
	HeaderReplaceRegex HeaderOp = "replace-regex"
)

// HeaderRule is a compiled header-rewrite entry.
type HeaderRule struct {
	Raw     string
	Source  string
	pattern *regexp2.Regexp
	Phase   Phase
	Op      HeaderOp
	Name    string
	Value   string
	valueRe *regexp2.Regexp
}

// BodyOp is the operation of a body-rewrite rule.
type BodyOp string

const (
	BodyReplaceRegex BodyOp = "replace-regex"
	BodyJQ           BodyOp = "jq"
)

type replacePair struct {
	re   *regexp2.Regexp
	with string
}

// BodyRule is a compiled body-rewrite entry.
type BodyRule struct {
	Raw     string
	Source  string
	pattern *regexp2.Regexp
	Phase   Phase
	Op      BodyOp
	pairs   []replacePair
	jq      *gojq.Code
}

func compileRegex(expr string) (*regexp2.Regexp, error) {
	re, err := regexp2.Compile(expr, regexp2.None)
	if err != nil {
		return nil, err
	}
	re.MatchTimeout = regexTimeout
	return re, nil
}

func matches(re *regexp2.Regexp, s string) bool {
	ok, err := re.MatchString(s)
	return err == nil && ok
}

// ParseURLRewrite parses "<regex> <replacement|-> <action>".
func ParseURLRewrite(line, source string) (*URLRule, error) {
	tok, err := tokenize(line)
	if err != nil {
		return nil, err
	}
	var pattern, replacement, action string
	switch len(tok) {
	case 2:
		pattern, action = tok[0], tok[1]
	case 3:
		pattern, replacement, action = tok[0], tok[1], tok[2]
	default:
		return nil, fmt.Errorf("url-rewrite expects 3 fields, got %d", len(tok))
	}
	act, ok := urlActions[strings.ToLower(action)]
	if !ok {
		return nil, fmt.Errorf("unsupported url-rewrite action %q", action)
	}
	if !act.IsReject() && (replacement == "" || replacement == "-") {
		return nil, fmt.Errorf("url-rewrite action %s needs a replacement URL", act)
	}
	re, err := compileRegex(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex %q: %w", pattern, err)
	}
	return &URLRule{Raw: line, Source: source, pattern: re, Replacement: replacement, Action: act}, nil
}

// ParseHeaderRewrite parses "<regex> <request|response>-<op> <name> [args...]".
func ParseHeaderRewrite(line, source string) (*HeaderRule, error) {
	tok, err := tokenize(line)
	if err != nil {
		return nil, err
	}
	if len(tok) < 3 {
		return nil, fmt.Errorf("header-rewrite expects at least 3 fields, got %d", len(tok))
	}
	phase, op, err := splitPhaseOp(tok[1])
	if err != nil {
		return nil, err
	}
	rule := &HeaderRule{Raw: line, Source: source, Phase: phase, Op: HeaderOp(op), Name: http.CanonicalHeaderKey(tok[2])}
	switch rule.Op {
	case HeaderDel:
	case HeaderAdd, HeaderReplace:
		if len(tok) < 4 {
			return nil, fmt.Errorf("header %s needs a value", op)
		}
		rule.Value = strings.Join(tok[3:], " ")
	case HeaderReplaceRegex:
		if len(tok) < 4 {
			return nil, fmt.Errorf("header replace-regex needs a regex and a replacement")
		}
		if rule.valueRe, err = compileRegex(tok[3]); err != nil {
			return nil, fmt.Errorf("invalid regex %q: %w", tok[3], err)
		}
		rule.Value = strings.Join(tok[4:], " ")
	default:
		return nil, fmt.Errorf("unsupported header-rewrite type %q", tok[1])
	}
	if rule.pattern, err = compileRegex(tok[0]); err != nil {
		return nil, fmt.Errorf("invalid regex %q: %w", tok[0], err)
	}
	return rule, nil
}

// ParseBodyRewrite parses "<regex> <request|response>-replace-regex <re> <with> [<re> <with>...]"
// and "<regex> <request|response>-jq <expression>".
func ParseBodyRewrite(line, source string) (*BodyRule, error) {
	tok, err := tokenize(line)
	if err != nil {
		return nil, err
	}
	if len(tok) < 3 {
		return nil, fmt.Errorf("body-rewrite expects at least 3 fields, got %d", len(tok))
	}
	phase, op, err := splitPhaseOp(tok[1])
	if err != nil {
		return nil, err
	}
	rule := &BodyRule{Raw: line, Source: source, Phase: phase, Op: BodyOp(op)}
	switch rule.Op {
	case BodyReplaceRegex:
		args := tok[2:]
		if len(args)%2 != 0 {
			return nil, fmt.Errorf("body replace-regex needs regex/replacement pairs")
		}
		for i := 0; i < len(args); i += 2 {
			re, err := compileRegex(args[i])
			if err != nil {
				return nil, fmt.Errorf("invalid regex %q: %w", args[i], err)
			}
			rule.pairs = append(rule.pairs, replacePair{re: re, with: args[i+1]})
		}
	case BodyJQ:
		q, err := gojq.Parse(strings.Join(tok[2:], " "))
		if err != nil {
			return nil, fmt.Errorf("invalid jq expression: %w", err)
		}
		if rule.jq, err = gojq.Compile(q); err != nil {
			return nil, fmt.Errorf("invalid jq expression: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported body-rewrite type %q", tok[1])
	}
	if rule.pattern, err = compileRegex(tok[0]); err != nil {
		return nil, fmt.Errorf("invalid regex %q: %w", tok[0], err)
	}
	return rule, nil
}

func splitPhaseOp(s string) (Phase, string, error) {
	s = strings.ToLower(s)
	switch {
	case strings.HasPrefix(s, "request-"):
		return PhaseRequest, strings.TrimPrefix(s, "request-"), nil
	case strings.HasPrefix(s, "response-"):
		return PhaseResponse, strings.TrimPrefix(s, "response-"), nil
	case strings.HasPrefix(s, "header-"):
		return PhaseRequest, strings.TrimPrefix(s, "header-"), nil
	}
	return 0, "", fmt.Errorf("unsupported rewrite type %q", s)
}

// Rewrite applies the url-rewrite rule to url.
func (r *URLRule) Rewrite(url string) string {
	out, err := r.pattern.Replace(url, r.Replacement, -1, 1)
	if err != nil {
		return url
	}
	return out
}

// ScriptRule is a compiled http.script entry with its JavaScript source loaded.
type ScriptRule struct {
	Source      string // override display name
	Name        string
	Phase       Phase
	pattern     *regexp2.Regexp
	RequireBody bool
	BinaryMode  bool
	Timeout     time.Duration
	MaxSize     int64
	Argument    any
	Code        string
}

// Match reports whether the script applies to url.
func (r *ScriptRule) Match(url string) bool { return matches(r.pattern, url) }

// Engine is a compiled, immutable set of rewrite rules.
type Engine struct {
	Hosts   *HostMatcher
	URL     []*URLRule
	Header  []*HeaderRule
	Body    []*BodyRule
	Scripts []*ScriptRule
}

// MatchScripts returns every script of the phase that matches url, in order.
func (e *Engine) MatchScripts(phase Phase, url string) []*ScriptRule {
	var out []*ScriptRule
	for _, r := range e.Scripts {
		if r.Phase == phase && r.Match(url) {
			out = append(out, r)
		}
	}
	return out
}

// HasScripts reports whether any script of the phase matches url.
func (e *Engine) HasScripts(phase Phase, url string) bool {
	return len(e.MatchScripts(phase, url)) > 0
}

// NewScriptRule compiles a script match pattern.
func NewScriptRule(match, name, typ, source string, requireBody, binaryMode bool, timeoutSec, maxSize int, argument any, code string) (*ScriptRule, error) {
	phase := PhaseRequest
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "", "request":
		phase = PhaseRequest
	case "response":
		phase = PhaseResponse
	default:
		return nil, fmt.Errorf("unsupported script type %q", typ)
	}
	re, err := compileRegex(match)
	if err != nil {
		return nil, fmt.Errorf("invalid script match %q: %w", match, err)
	}
	to := time.Duration(timeoutSec) * time.Second
	if to <= 0 {
		to = 10 * time.Second
	}
	ms := int64(maxSize)
	if ms < 0 {
		ms = 0
	}
	return &ScriptRule{
		Source: source, Name: name, Phase: phase, pattern: re,
		RequireBody: requireBody, BinaryMode: binaryMode,
		Timeout: to, MaxSize: ms, Argument: argument, Code: code,
	}, nil
}

// MatchURL returns the first url-rewrite rule matching url.
func (e *Engine) MatchURL(url string) *URLRule {
	for _, r := range e.URL {
		if matches(r.pattern, url) {
			return r
		}
	}
	return nil
}

// ApplyHeaders runs every header rule of the phase that matches url and
// returns the raw rules that were applied.
func (e *Engine) ApplyHeaders(phase Phase, url string, h http.Header) []string {
	var applied []string
	for _, r := range e.Header {
		if r.Phase != phase || !matches(r.pattern, url) {
			continue
		}
		switch r.Op {
		case HeaderAdd:
			h.Add(r.Name, r.Value)
		case HeaderDel:
			h.Del(r.Name)
		case HeaderReplace:
			if _, ok := h[r.Name]; !ok {
				continue
			}
			h.Set(r.Name, r.Value)
		case HeaderReplaceRegex:
			vals, ok := h[r.Name]
			if !ok {
				continue
			}
			for i, v := range vals {
				if nv, err := r.valueRe.Replace(v, r.Value, -1, -1); err == nil {
					vals[i] = nv
				}
			}
		}
		applied = append(applied, r.Raw)
	}
	return applied
}

// HasBodyRules reports whether any body rule of the phase matches url.
func (e *Engine) HasBodyRules(phase Phase, url string) bool {
	for _, r := range e.Body {
		if r.Phase == phase && matches(r.pattern, url) {
			return true
		}
	}
	return false
}

// ApplyBody runs every body rule of the phase matching url. Rules that fail
// (for example jq on a non JSON body) are reported in errs and skipped.
func (e *Engine) ApplyBody(phase Phase, url string, body []byte) (out []byte, applied []string, errs []error) {
	out = body
	for _, r := range e.Body {
		if r.Phase != phase || !matches(r.pattern, url) {
			continue
		}
		next, err := r.apply(out)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", r.Raw, err))
			continue
		}
		out = next
		applied = append(applied, r.Raw)
	}
	return out, applied, errs
}

func (r *BodyRule) apply(body []byte) ([]byte, error) {
	switch r.Op {
	case BodyReplaceRegex:
		s := string(body)
		for _, p := range r.pairs {
			ns, err := p.re.Replace(s, p.with, -1, -1)
			if err != nil {
				return nil, err
			}
			s = ns
		}
		return []byte(s), nil
	case BodyJQ:
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		var input any
		if err := dec.Decode(&input); err != nil {
			return nil, fmt.Errorf("body is not JSON: %w", err)
		}
		iter := r.jq.Run(input)
		v, ok := iter.Next()
		if !ok {
			return nil, fmt.Errorf("jq produced no output")
		}
		if err, isErr := v.(error); isErr {
			return nil, err
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(v); err != nil {
			return nil, err
		}
		return bytes.TrimRight(buf.Bytes(), "\n"), nil
	}
	return body, nil
}
