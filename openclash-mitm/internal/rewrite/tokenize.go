package rewrite

import (
	"fmt"
	"strings"
)

// tokenize splits a Stash rewrite line on whitespace. Single and double quotes
// group a token; inside double quotes \" yields a literal quote. Backslashes
// are otherwise preserved so regular expressions survive untouched.
func tokenize(line string) ([]string, error) {
	var (
		tokens  []string
		cur     strings.Builder
		inToken bool
		quote   rune
	)
	runes := []rune(line)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch {
		case quote != 0:
			if r == '\\' && quote == '"' && i+1 < len(runes) && runes[i+1] == '"' {
				cur.WriteRune('"')
				i++
				continue
			}
			if r == quote {
				quote = 0
				continue
			}
			cur.WriteRune(r)
		case r == '"' || r == '\'':
			quote = r
			inToken = true
		case r == ' ' || r == '\t':
			if inToken {
				tokens = append(tokens, cur.String())
				cur.Reset()
				inToken = false
			}
		default:
			cur.WriteRune(r)
			inToken = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote in %q", line)
	}
	if inToken {
		tokens = append(tokens, cur.String())
	}
	return tokens, nil
}
