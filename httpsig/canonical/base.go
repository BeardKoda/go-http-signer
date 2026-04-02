package canonical

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// BuildSignatureBase builds the HTTP message signature base string from
// a request and an ordered list of components.
func BuildSignatureBase(req *http.Request, components []string) (string, error) {
	if req == nil {
		return "", errors.New("request is required")
	}

	lines := make([]string, 0, len(components))
	for _, component := range components {
		name := normalizeComponent(component)
		if name == "" {
			return "", errors.New("component name cannot be empty")
		}

		value, err := resolveComponentValue(req, name)
		if err != nil {
			return "", err
		}

		lines = append(lines, fmt.Sprintf("%q: %s", name, value))
	}

	return strings.Join(lines, "\n"), nil
}
