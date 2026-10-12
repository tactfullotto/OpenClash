package clashpatch

import (
	"fmt"
	"strings"
)

// ruleExpr is a parsed rule. Logic rules (AND/OR/NOT) carry children, other
// rules carry a payload. Params are trailing options such as no-resolve.
type ruleExpr struct {
	Type     string
	Payload  string
	Params   []string
	Children []*ruleExpr
}

func isLogic(t string) bool { return t == "AND" || t == "OR" || t == "NOT" }

// parseTopRule parses "TYPE,PAYLOAD,POLICY[,params]", "MATCH,POLICY" or a
// logic rule "AND,((...),(...)),POLICY[,params]".
func parseTopRule(s string) (expr *ruleExpr, policy string, err error) {
	s = strings.TrimSpace(s)
	typ, rest, ok := strings.Cut(s, ",")
	if !ok {
		return nil, "", fmt.Errorf("malformed rule %q", s)
	}
	typ = strings.ToUpper(strings.TrimSpace(typ))
	if typ == "MATCH" || typ == "FINAL" {
		return &ruleExpr{Type: "MATCH"}, strings.TrimSpace(rest), nil
	}
	if isLogic(typ) {
		group, tail, err := cutGroup(rest)
		if err != nil {
			return nil, "", fmt.Errorf("%q: %w", s, err)
		}
		children, err := parseChildren(group)
		if err != nil {
			return nil, "", fmt.Errorf("%q: %w", s, err)
		}
		fields := splitFields(strings.TrimPrefix(tail, ","))
		if len(fields) == 0 || fields[0] == "" {
			return nil, "", fmt.Errorf("missing policy in %q", s)
		}
		return &ruleExpr{Type: typ, Children: children, Params: fields[1:]}, fields[0], nil
	}
	fields := splitFields(rest)
	if len(fields) < 2 {
		return nil, "", fmt.Errorf("missing policy in %q", s)
	}
	return &ruleExpr{Type: typ, Payload: fields[0], Params: fields[2:]}, fields[1], nil
}

// parseSubRule parses the inside of "(TYPE,PAYLOAD[,params])".
func parseSubRule(s string) (*ruleExpr, error) {
	typ, rest, ok := strings.Cut(strings.TrimSpace(s), ",")
	if !ok {
		return nil, fmt.Errorf("malformed sub rule %q", s)
	}
	typ = strings.ToUpper(strings.TrimSpace(typ))
	if isLogic(typ) {
		group, tail, err := cutGroup(rest)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(tail) != "" {
			return nil, fmt.Errorf("unexpected %q after logic sub rule", tail)
		}
		children, err := parseChildren(group)
		if err != nil {
			return nil, err
		}
		return &ruleExpr{Type: typ, Children: children}, nil
	}
	fields := splitFields(rest)
	return &ruleExpr{Type: typ, Payload: fields[0], Params: fields[1:]}, nil
}

// cutGroup splits "((a),(b)),tail" into "(a),(b)" and ",tail".
func cutGroup(s string) (group, tail string, err error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "(") {
		return "", "", fmt.Errorf("expected '(' in %q", s)
	}
	depth := 0
	for i, r := range s {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return s[1:i], s[i+1:], nil
			}
		}
	}
	return "", "", fmt.Errorf("unbalanced parentheses in %q", s)
}

// parseChildren parses "(A,x),(B,y)".
func parseChildren(s string) ([]*ruleExpr, error) {
	var out []*ruleExpr
	depth, start := 0, -1
	for i, r := range s {
		switch r {
		case '(':
			if depth == 0 {
				start = i + 1
			}
			depth++
		case ')':
			depth--
			if depth == 0 && start >= 0 {
				child, err := parseSubRule(s[start:i])
				if err != nil {
					return nil, err
				}
				out = append(out, child)
				start = -1
			}
			if depth < 0 {
				return nil, fmt.Errorf("unbalanced parentheses in %q", s)
			}
		}
	}
	if depth != 0 {
		return nil, fmt.Errorf("unbalanced parentheses in %q", s)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty logic rule %q", s)
	}
	return out, nil
}

func splitFields(s string) []string {
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// sub renders the expression as a logic sub rule, without surrounding parens.
func (e *ruleExpr) sub() string {
	if isLogic(e.Type) {
		parts := make([]string, len(e.Children))
		for i, c := range e.Children {
			parts[i] = "(" + c.sub() + ")"
		}
		return e.Type + ",(" + strings.Join(parts, ",") + ")"
	}
	return strings.Join(append([]string{e.Type, e.Payload}, e.Params...), ",")
}

// top renders the expression as a top level rule targeting policy.
func (e *ruleExpr) top(policy string) string {
	if e.Type == "MATCH" {
		return "MATCH," + policy
	}
	if isLogic(e.Type) {
		return strings.Join(append([]string{e.sub(), policy}, e.Params...), ",")
	}
	return strings.Join(append([]string{e.Type, e.Payload, policy}, e.Params...), ",")
}

// mihomoRuleTypes lists the rule types mihomo understands.
var mihomoRuleTypes = map[string]bool{
	"DOMAIN": true, "DOMAIN-SUFFIX": true, "DOMAIN-KEYWORD": true, "DOMAIN-REGEX": true,
	"DOMAIN-WILDCARD": true, "GEOSITE": true, "GEOIP": true, "SRC-GEOIP": true,
	"IP-ASN": true, "SRC-IP-ASN": true, "IP-CIDR": true, "IP-CIDR6": true, "SRC-IP-CIDR": true,
	"IP-SUFFIX": true, "SRC-IP-SUFFIX": true, "SRC-PORT": true, "DST-PORT": true,
	"IN-PORT": true, "IN-USER": true, "IN-NAME": true, "IN-TYPE": true, "DSCP": true,
	"PROCESS-NAME": true, "PROCESS-PATH": true, "PROCESS-NAME-REGEX": true,
	"PROCESS-PATH-REGEX": true, "UID": true, "NETWORK": true, "RULE-SET": true,
	"SUB-RULE": true, "AND": true, "OR": true, "NOT": true, "MATCH": true,
}

func and(children ...*ruleExpr) *ruleExpr { return &ruleExpr{Type: "AND", Children: children} }

func simple(typ, payload string, params ...string) *ruleExpr {
	return &ruleExpr{Type: typ, Payload: payload, Params: params}
}

// convert rewrites Stash-only rule types into mihomo equivalents.
func convert(e *ruleExpr) (*ruleExpr, error) {
	switch e.Type {
	case "DEST-PORT":
		e.Type = "DST-PORT"
	case "PROTOCOL":
		switch strings.ToUpper(e.Payload) {
		case "TCP":
			return simple("NETWORK", "TCP"), nil
		case "UDP":
			return simple("NETWORK", "UDP"), nil
		case "QUIC":
			return and(simple("NETWORK", "UDP"), simple("DST-PORT", "443")), nil
		case "HTTP":
			return and(simple("NETWORK", "TCP"), simple("DST-PORT", "80")), nil
		case "HTTPS":
			return and(simple("NETWORK", "TCP"), simple("DST-PORT", "443")), nil
		}
		return nil, fmt.Errorf("PROTOCOL,%s has no mihomo equivalent", e.Payload)
	}
	if !mihomoRuleTypes[e.Type] {
		return nil, fmt.Errorf("rule type %s is not supported by mihomo", e.Type)
	}
	for i, c := range e.Children {
		nc, err := convert(c)
		if err != nil {
			return nil, err
		}
		e.Children[i] = nc
	}
	return e, nil
}

// ruleSets returns the RULE-SET names referenced by e.
func (e *ruleExpr) ruleSets() []string {
	if e.Type == "RULE-SET" {
		return []string{e.Payload}
	}
	var out []string
	for _, c := range e.Children {
		out = append(out, c.ruleSets()...)
	}
	return out
}
