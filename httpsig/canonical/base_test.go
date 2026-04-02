package canonical

import (
	"net/http"
	"net/url"
	"testing"
)

func TestBuildSignatureBase_DeterministicAndOrdered(t *testing.T) {
	t.Parallel()

	req := &http.Request{
		Method: "POST",
		Host:   "API.Example.COM:443",
		URL: &url.URL{
			Scheme:   "https",
			Host:     "ignored.example.com",
			Path:     "/v1/payments",
			RawQuery: "id=123",
		},
		Header: http.Header{
			"Content-Digest": []string{" sha-256=:abc123=: "},
			"X-Custom":       []string{"  first  ", " second "},
		},
	}

	base, err := BuildSignatureBase(req, []string{
		"@method",
		"@path",
		"@authority",
		"content-digest",
		"x-custom",
	})
	if err != nil {
		t.Fatalf("BuildSignatureBase returned error: %v", err)
	}

	want := "\"@method\": post\n" +
		"\"@path\": /v1/payments\n" +
		"\"@authority\": api.example.com:443\n" +
		"\"content-digest\": sha-256=:abc123=:\n" +
		"\"x-custom\": first, second"

	if base != want {
		t.Fatalf("unexpected signature base:\nwant:\n%s\n\ngot:\n%s", want, base)
	}
}

func TestBuildSignatureBase_MissingHeaderHandledSafely(t *testing.T) {
	t.Parallel()

	req := &http.Request{
		Method: "GET",
		URL: &url.URL{
			Path: "/",
		},
		Header: http.Header{},
	}

	base, err := BuildSignatureBase(req, []string{"missing-header"})
	if err != nil {
		t.Fatalf("BuildSignatureBase returned error: %v", err)
	}

	want := "\"missing-header\": "
	if base != want {
		t.Fatalf("unexpected signature base: want %q, got %q", want, base)
	}
}

func TestBuildSignatureBase_UnsupportedDerivedComponent(t *testing.T) {
	t.Parallel()

	req := &http.Request{
		Method: "GET",
		URL: &url.URL{
			Path: "/",
		},
		Header: http.Header{},
	}

	_, err := BuildSignatureBase(req, []string{"@query"})
	if err == nil {
		t.Fatal("expected error for unsupported derived component")
	}
}

func TestBuildSignatureBase_NormalizesComponentNames(t *testing.T) {
	t.Parallel()

	req := &http.Request{
		Method: "GET",
		URL: &url.URL{
			Path: "/ok",
		},
		Header: http.Header{
			"X-Test": []string{"  value  "},
		},
	}

	base, err := BuildSignatureBase(req, []string{"  X-Test  "})
	if err != nil {
		t.Fatalf("BuildSignatureBase returned error: %v", err)
	}

	want := "\"x-test\": value"
	if base != want {
		t.Fatalf("unexpected signature base: want %q, got %q", want, base)
	}
}

func TestBuildSignatureBase_NilRequest(t *testing.T) {
	t.Parallel()

	_, err := BuildSignatureBase(nil, []string{"@method"})
	if err == nil {
		t.Fatal("expected error for nil request")
	}
}
