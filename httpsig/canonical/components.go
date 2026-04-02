package canonical

import (
	"fmt"
	"net/http"
	"strings"
)

func resolveComponentValue(req *http.Request, component string) (string, error) {
	switch component {
	case "@method":
		return strings.ToLower(strings.TrimSpace(req.Method)), nil
	case "@path":
		if req.URL == nil {
			return "/", nil
		}

		path := strings.TrimSpace(req.URL.EscapedPath())
		if path == "" {
			return "/", nil
		}
		return path, nil
	case "@authority":
		authority := strings.TrimSpace(req.Host)
		if authority == "" && req.URL != nil {
			authority = strings.TrimSpace(req.URL.Host)
		}
		return strings.ToLower(authority), nil
	default:
		if strings.HasPrefix(component, "@") {
			return "", fmt.Errorf("unsupported derived component %q", component)
		}

		values := req.Header.Values(component)
		return canonicalHeaderValue(values), nil
	}
}

func normalizeComponent(component string) string {
	return strings.ToLower(strings.TrimSpace(component))
}

func canonicalHeaderValue(values []string) string {
	if len(values) == 0 {
		return ""
	}

	normalized := make([]string, 0, len(values))
	for _, value := range values {
		normalized = append(normalized, strings.TrimSpace(value))
	}

	return strings.Join(normalized, ", ")
}
