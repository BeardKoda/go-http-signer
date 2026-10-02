package canonical

import (
	"net/http"
	"net/url"
	"testing"
)

const testParams = `("@method");created=1700000000;keyid="k1";alg="ed25519"`

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
	}, testParams)
	if err != nil {
		t.Fatalf("BuildSignatureBase returned error: %v", err)
	}

	want := "\"@method\": POST\n" +
		"\"@path\": /v1/payments\n" +
		"\"@authority\": api.example.com:443\n" +
		"\"content-digest\": sha-256=:abc123=:\n" +
		"\"x-custom\": first, second\n" +
		"\"@signature-params\": " + testParams

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

	base, err := BuildSignatureBase(req, []string{"missing-header"}, testParams)
	if err != nil {
		t.Fatalf("BuildSignatureBase returned error: %v", err)
	}

	want := "\"missing-header\": \n\"@signature-params\": " + testParams
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

	_, err := BuildSignatureBase(req, []string{"@query"}, testParams)
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

	base, err := BuildSignatureBase(req, []string{"  X-Test  "}, testParams)
	if err != nil {
		t.Fatalf("BuildSignatureBase returned error: %v", err)
	}

	want := "\"x-test\": value\n\"@signature-params\": " + testParams
	if base != want {
		t.Fatalf("unexpected signature base: want %q, got %q", want, base)
	}
}

func TestBuildSignatureBase_RejectsBadComponentLists(t *testing.T) {
	t.Parallel()

	req := &http.Request{Method: "GET", URL: &url.URL{Path: "/"}, Header: http.Header{}}

	cases := map[string][]string{
		"signature-params listed": {"@method", "@signature-params"},
		"duplicate component":     {"@method", "@METHOD"},
	}
	for name, components := range cases {
		if _, err := BuildSignatureBase(req, components, testParams); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := BuildSignatureBase(req, []string{"@method"}, ""); err == nil {
		t.Error("empty params: expected error")
	}
}

func TestBuildSignatureBase_NilRequest(t *testing.T) {
	t.Parallel()

	_, err := BuildSignatureBase(nil, []string{"@method"}, testParams)
	if err == nil {
		t.Fatal("expected error for nil request")
	}
}

func TestSignatureParamsSerialize(t *testing.T) {
	t.Parallel()

	got, err := SignatureParams{
		Components: []string{"@method", " Content-Digest "},
		Created:    1700000000,
		Expires:    1700000300,
		KeyID:      `k"1`,
		Algorithm:  "ed25519",
	}.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	want := `("@method" "content-digest");created=1700000000;expires=1700000300;keyid="k\"1";alg="ed25519"`
	if got != want {
		t.Fatalf("want %s\ngot  %s", want, got)
	}

	if _, err := (SignatureParams{KeyID: "k\n1"}).Serialize(); err == nil {
		t.Fatal("expected error for non-printable keyid")
	}
}
