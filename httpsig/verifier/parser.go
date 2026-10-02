package verifier

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

type signatureInput struct {
	Label      string
	Components []string
	KeyID      string
	Algorithm  string
	Created    int64
	Expires    int64
	// Params is the raw inner list with parameters, exactly as received. It
	// is the value of the "@signature-params" line in the signature base.
	Params string
}

// parseSignatureInput parses the first member of a Signature-Input
// dictionary. It implements the subset of RFC 8941 that RFC 9421 needs: an
// inner list of quoted component names followed by parameters. Component
// parameters (e.g. ;sf, ;key) are not supported and are rejected.
func parseSignatureInput(header string) (signatureInput, error) {
	var out signatureInput

	members, err := splitDictionary(header)
	if err != nil {
		return out, fmt.Errorf("invalid Signature-Input header: %w", err)
	}
	if len(members) == 0 {
		return out, fmt.Errorf("invalid Signature-Input header: no members")
	}
	out.Label = members[0].key
	out.Params = members[0].value

	p := &sfParser{s: out.Params}
	if !p.consume('(') {
		return out, fmt.Errorf("invalid Signature-Input component list")
	}
	for {
		p.skipSpaces()
		if p.consume(')') {
			break
		}
		if p.eof() {
			return out, fmt.Errorf("unterminated Signature-Input component list")
		}
		component, err := p.parseString()
		if err != nil {
			return out, fmt.Errorf("invalid component: %w", err)
		}
		if p.peek() == ';' {
			return out, fmt.Errorf("component parameters are not supported (%q)", component)
		}
		if !p.eof() && p.peek() != ' ' && p.peek() != ')' {
			return out, fmt.Errorf("invalid Signature-Input component list")
		}
		out.Components = append(out.Components, component)
	}

	for !p.eof() {
		if !p.consume(';') {
			return out, fmt.Errorf("invalid Signature-Input parameters at %q", p.s[p.i:])
		}
		p.skipSpaces()
		key := p.parseKey()
		if key == "" {
			return out, fmt.Errorf("invalid Signature-Input parameter name")
		}
		if !p.consume('=') {
			continue // bare boolean parameter; none are meaningful here
		}
		switch key {
		case "keyid", "alg", "nonce", "tag":
			val, err := p.parseString()
			if err != nil {
				return out, fmt.Errorf("invalid %s: %w", key, err)
			}
			switch key {
			case "keyid":
				out.KeyID = val
			case "alg":
				out.Algorithm = val
			}
		case "created", "expires":
			val, err := p.parseInteger()
			if err != nil {
				return out, fmt.Errorf("invalid %s: %w", key, err)
			}
			if key == "created" {
				out.Created = val
			} else {
				out.Expires = val
			}
		default:
			if err := p.skipBareItem(); err != nil {
				return out, fmt.Errorf("invalid %s: %w", key, err)
			}
		}
	}
	return out, nil
}

// parseSignature returns the decoded byte sequence stored under label in the
// Signature dictionary.
func parseSignature(header, label string) ([]byte, error) {
	members, err := splitDictionary(header)
	if err != nil {
		return nil, fmt.Errorf("invalid Signature header: %w", err)
	}
	for _, m := range members {
		if m.key != label {
			continue
		}
		val := m.value
		if len(val) < 2 || val[0] != ':' || val[len(val)-1] != ':' {
			return nil, fmt.Errorf("invalid Signature value")
		}
		return base64.StdEncoding.DecodeString(val[1 : len(val)-1])
	}
	return nil, fmt.Errorf("signature label %q not found", label)
}

type dictMember struct {
	key   string
	value string
}

// splitDictionary splits an RFC 8941 dictionary into members, honouring
// quoted strings and parenthesised inner lists so commas inside them do not
// split a member.
func splitDictionary(header string) ([]dictMember, error) {
	var members []dictMember
	depth := 0
	inQuote := false
	start := 0
	flush := func(end int) error {
		raw := strings.Trim(header[start:end], " \t")
		if raw == "" {
			return nil
		}
		eq := strings.IndexByte(raw, '=')
		if eq <= 0 {
			return fmt.Errorf("member %q has no value", raw)
		}
		key := raw[:eq]
		if !isKey(key) {
			return fmt.Errorf("invalid member name %q", key)
		}
		members = append(members, dictMember{key: key, value: raw[eq+1:]})
		return nil
	}
	for i := 0; i < len(header); i++ {
		c := header[i]
		switch {
		case inQuote && c == '\\':
			i++
		case c == '"':
			inQuote = !inQuote
		case inQuote:
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth < 0 {
				return nil, fmt.Errorf("unbalanced parentheses")
			}
		case c == ',' && depth == 0:
			if err := flush(i); err != nil {
				return nil, err
			}
			start = i + 1
		}
	}
	if inQuote || depth != 0 {
		return nil, fmt.Errorf("unterminated string or inner list")
	}
	if err := flush(len(header)); err != nil {
		return nil, err
	}
	return members, nil
}

func isKey(s string) bool {
	if s == "" || !(s[0] == '*' || (s[0] >= 'a' && s[0] <= 'z')) {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte("_-.*", c) >= 0) {
			return false
		}
	}
	return true
}

type sfParser struct {
	s string
	i int
}

func (p *sfParser) eof() bool { return p.i >= len(p.s) }

func (p *sfParser) peek() byte {
	if p.eof() {
		return 0
	}
	return p.s[p.i]
}

func (p *sfParser) consume(c byte) bool {
	if p.peek() == c && !p.eof() {
		p.i++
		return true
	}
	return false
}

func (p *sfParser) skipSpaces() {
	for !p.eof() && p.s[p.i] == ' ' {
		p.i++
	}
}

func (p *sfParser) parseKey() string {
	start := p.i
	for !p.eof() && isKey(p.s[start:p.i+1]) {
		p.i++
	}
	return p.s[start:p.i]
}

func (p *sfParser) parseString() (string, error) {
	if !p.consume('"') {
		return "", fmt.Errorf("expected quoted string")
	}
	var b strings.Builder
	for !p.eof() {
		c := p.s[p.i]
		p.i++
		switch {
		case c == '"':
			return b.String(), nil
		case c == '\\':
			if p.eof() || (p.s[p.i] != '"' && p.s[p.i] != '\\') {
				return "", fmt.Errorf("invalid escape in string")
			}
			b.WriteByte(p.s[p.i])
			p.i++
		case c < 0x20 || c > 0x7e:
			return "", fmt.Errorf("invalid character in string")
		default:
			b.WriteByte(c)
		}
	}
	return "", fmt.Errorf("unterminated string")
}

func (p *sfParser) parseInteger() (int64, error) {
	start := p.i
	if p.peek() == '-' {
		p.i++
	}
	for !p.eof() && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
		p.i++
	}
	return strconv.ParseInt(p.s[start:p.i], 10, 64)
}

// skipBareItem skips the value of a parameter this package does not use.
func (p *sfParser) skipBareItem() error {
	if p.peek() == '"' {
		_, err := p.parseString()
		return err
	}
	for !p.eof() && p.s[p.i] != ';' {
		p.i++
	}
	return nil
}
