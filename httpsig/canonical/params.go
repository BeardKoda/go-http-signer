package canonical

import (
	"fmt"
	"strconv"
	"strings"
)

// SignatureParams are the metadata carried in Signature-Input and covered by
// the "@signature-params" line of the signature base.
type SignatureParams struct {
	Components []string
	Created    int64
	Expires    int64
	KeyID      string
	Algorithm  string
}

// Serialize renders the params as an RFC 8941 inner list with parameters,
// e.g. ("@method" "@path");created=1700000000;keyid="k1";alg="ed25519".
func (p SignatureParams) Serialize() (string, error) {
	var b strings.Builder
	b.WriteByte('(')
	for i, c := range p.Components {
		if i > 0 {
			b.WriteByte(' ')
		}
		s, err := sfString(normalizeComponent(c))
		if err != nil {
			return "", fmt.Errorf("component %q: %w", c, err)
		}
		b.WriteString(s)
	}
	b.WriteByte(')')

	if p.Created != 0 {
		b.WriteString(";created=" + strconv.FormatInt(p.Created, 10))
	}
	if p.Expires != 0 {
		b.WriteString(";expires=" + strconv.FormatInt(p.Expires, 10))
	}
	if p.KeyID != "" {
		s, err := sfString(p.KeyID)
		if err != nil {
			return "", fmt.Errorf("keyid: %w", err)
		}
		b.WriteString(";keyid=" + s)
	}
	if p.Algorithm != "" {
		s, err := sfString(p.Algorithm)
		if err != nil {
			return "", fmt.Errorf("alg: %w", err)
		}
		b.WriteString(";alg=" + s)
	}
	return b.String(), nil
}

// sfString serializes an RFC 8941 string: printable ASCII only, with '"' and
// '\' escaped.
func sfString(s string) (string, error) {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e {
			return "", fmt.Errorf("non-printable or non-ASCII byte 0x%02x", c)
		}
		if c == '"' || c == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	b.WriteByte('"')
	return b.String(), nil
}
