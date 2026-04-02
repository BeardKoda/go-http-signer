# httpsig-go

Production-oriented Go library for HTTP Message Signatures (RFC 9421).

## Installation

```bash
go get github.com/beardkoda/httpsig-go
```

## Quick Start

```go
// Signing
s := signer.Signer{
    KeyID:      "k1",
    Algorithm:  "ed25519",
    PrivateKey: privateKey,
    Components: []string{"@method", "@path", "@authority", "content-digest"},
}
_ = s.Sign(req)

// Verifying
v := verifier.New(keys.NewStaticKeyStore(map[string]crypto.PublicKey{"k1": publicKey}))
ok, err := v.Verify(req)
```

## Supported Algorithms

- `ed25519` (default)
- `rsa-pss-sha512`

## Security Notes

- Use `content-digest` for tamper detection on request bodies.
- Configure verifier clock skew according to deployment constraints.
- Enable replay cache in production to reject signature reuse.

## Examples

- `examples/client` signed client request
- `examples/server` verification middleware
- `examples/webhook` webhook verification handler
