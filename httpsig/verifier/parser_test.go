package verifier

import (
	"slices"
	"testing"
)

func TestParseSignatureInput(t *testing.T) {
	t.Parallel()

	header := `sig1=("@method" "content-digest");created=1700000000;expires=1700000300;keyid="a,b;c\"d";alg="ed25519";nonce="n1", sig2=("@path");created=1`
	in, err := parseSignatureInput(header)
	if err != nil {
		t.Fatal(err)
	}
	if in.Label != "sig1" {
		t.Errorf("label = %q", in.Label)
	}
	if !slices.Equal(in.Components, []string{"@method", "content-digest"}) {
		t.Errorf("components = %q", in.Components)
	}
	if in.KeyID != `a,b;c"d` || in.Algorithm != "ed25519" || in.Created != 1700000000 || in.Expires != 1700000300 {
		t.Errorf("unexpected params: %+v", in)
	}
	wantParams := `("@method" "content-digest");created=1700000000;expires=1700000300;keyid="a,b;c\"d";alg="ed25519";nonce="n1"`
	if in.Params != wantParams {
		t.Errorf("params = %s", in.Params)
	}
}

func TestParseSignatureInputRejectsMalformed(t *testing.T) {
	t.Parallel()

	for _, header := range []string{
		``,
		`sig1`,
		`Sig1=("@method")`,
		`sig1="@method"`,
		`sig1=("@method"`,
		`sig1=(@method)`,
		`sig1=("@method";sf)`,
		`sig1=("@method");created=abc`,
		`sig1=("@method");keyid=k1`,
		`sig1=("@method");keyid="unterminated`,
	} {
		if _, err := parseSignatureInput(header); err == nil {
			t.Errorf("expected error for %q", header)
		}
	}
}

func TestParseSignatureSelectsLabel(t *testing.T) {
	t.Parallel()

	sig, err := parseSignature(`sigx=:YWJj:, sig1=:ZGVm:`, "sig1")
	if err != nil {
		t.Fatal(err)
	}
	if string(sig) != "def" {
		t.Fatalf("got %q", sig)
	}
	if _, err := parseSignature(`sigx=:YWJj:`, "sig1"); err == nil {
		t.Fatal("expected missing label error")
	}
}
