package canonical

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const signatureParamsComponent = "@signature-params"

// BuildSignatureBase builds the RFC 9421 signature base from a request, an
// ordered list of covered components, and the serialized signature parameters.
//
// sigParams is the inner list with parameters exactly as it appears in the
// Signature-Input header after "<label>=". It is appended as the final
// "@signature-params" line, so created, expires, keyid and alg are covered by
// the signature and cannot be altered or stripped in transit.
func BuildSignatureBase(req *http.Request, components []string, sigParams string) (string, error) {
	if req == nil {
		return "", errors.New("request is required")
	}
	if strings.TrimSpace(sigParams) == "" {
		return "", errors.New("signature params are required")
	}

	seen := make(map[string]struct{}, len(components))
	lines := make([]string, 0, len(components)+1)
	for _, component := range components {
		name := normalizeComponent(component)
		if name == "" {
			return "", errors.New("component name cannot be empty")
		}
		if name == signatureParamsComponent {
			return "", fmt.Errorf("%q cannot be listed as a covered component", signatureParamsComponent)
		}
		if _, dup := seen[name]; dup {
			return "", fmt.Errorf("component %q listed more than once", name)
		}
		seen[name] = struct{}{}

		value, err := resolveComponentValue(req, name)
		if err != nil {
			return "", err
		}

		lines = append(lines, fmt.Sprintf("%q: %s", name, value))
	}
	lines = append(lines, fmt.Sprintf("%q: %s", signatureParamsComponent, sigParams))

	return strings.Join(lines, "\n"), nil
}
