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
}

func parseSignatureInput(header string) (signatureInput, error) {
	var out signatureInput
	parts := strings.Split(header, ";")
	if len(parts) == 0 {
		return out, fmt.Errorf("invalid Signature-Input header")
	}

	first := strings.TrimSpace(parts[0])
	eq := strings.Index(first, "=")
	if eq <= 0 {
		return out, fmt.Errorf("invalid Signature-Input label")
	}
	out.Label = strings.TrimSpace(first[:eq])
	compPart := strings.TrimSpace(first[eq+1:])
	if !strings.HasPrefix(compPart, "(") || !strings.HasSuffix(compPart, ")") {
		return out, fmt.Errorf("invalid Signature-Input component list")
	}
	compPart = strings.TrimSuffix(strings.TrimPrefix(compPart, "("), ")")
	for _, token := range strings.Fields(compPart) {
		component, err := strconv.Unquote(token)
		if err != nil {
			return out, fmt.Errorf("invalid component token %q: %w", token, err)
		}
		out.Components = append(out.Components, component)
	}

	for _, part := range parts[1:] {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idx := strings.Index(part, "=")
		if idx <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(part[:idx]))
		val := strings.TrimSpace(part[idx+1:])
		switch key {
		case "keyid":
			keyID, err := strconv.Unquote(val)
			if err != nil {
				return out, fmt.Errorf("invalid keyid: %w", err)
			}
			out.KeyID = keyID
		case "alg":
			alg, err := strconv.Unquote(val)
			if err != nil {
				return out, fmt.Errorf("invalid alg: %w", err)
			}
			out.Algorithm = alg
		case "created":
			created, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				return out, fmt.Errorf("invalid created: %w", err)
			}
			out.Created = created
		case "expires":
			expires, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				return out, fmt.Errorf("invalid expires: %w", err)
			}
			out.Expires = expires
		}
	}
	return out, nil
}

func parseSignature(header, label string) ([]byte, error) {
	for _, entry := range strings.Split(header, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		idx := strings.Index(entry, "=")
		if idx <= 0 {
			continue
		}
		name := strings.TrimSpace(entry[:idx])
		if name != label {
			continue
		}
		val := strings.TrimSpace(entry[idx+1:])
		if !strings.HasPrefix(val, ":") || !strings.HasSuffix(val, ":") {
			return nil, fmt.Errorf("invalid Signature value")
		}
		raw := strings.TrimSuffix(strings.TrimPrefix(val, ":"), ":")
		return base64.StdEncoding.DecodeString(raw)
	}
	return nil, fmt.Errorf("signature label %q not found", label)
}
