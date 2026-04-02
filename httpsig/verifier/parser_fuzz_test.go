package verifier

import "testing"

func FuzzParseSignatureInput(f *testing.F) {
	f.Add(`sig1=("@method" "@path");created=1700000000;keyid="k1";alg="ed25519"`)
	f.Add(`sig1=("content-digest")`)
	f.Add(`bad-input`)

	f.Fuzz(func(t *testing.T, header string) {
		_, _ = parseSignatureInput(header)
	})
}

func FuzzParseSignature(f *testing.F) {
	f.Add(`sig1=:YWJj:`, "sig1")
	f.Add(`sigx=:YWJj:, sig1=:ZGVm:`, "sig1")
	f.Add(`broken`, "sig1")

	f.Fuzz(func(t *testing.T, header string, label string) {
		_, _ = parseSignature(header, label)
	})
}
