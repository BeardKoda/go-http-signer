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
v.ReplayCache = verifier.NewInMemoryReplayCache()
ok, err := v.Verify(req)
```

## Supported Algorithms

- `ed25519` (default)
- `rsa-pss-sha512`

## Security Model

- **Signature parameters are signed.** The signature base ends with the
  `@signature-params` line, so `created`, `expires`, `keyid`, `alg` and the
  list of covered components cannot be altered or stripped in transit.
- **Bodies must be signed.** The signer adds `content-digest` (SHA-256) and
  covers it whenever a request has a body. The verifier rejects a body that
  has no `content-digest`, whose digest does not match, or whose digest is
  not among the signed components. Set `DisableBodyDigest` only if you check
  bodies yourself.
- **Signatures expire.** `created` is required by default, and signatures
  older than `MaxAge` (default 5 minutes, plus `AllowedClockSkew`) are
  rejected. `Signer.Expiry` adds an `expires` parameter as well.
- **Replay protection is atomic.** Set `Verifier.ReplayCache`; the in-memory
  cache checks and records each signature under one lock and keeps it for as
  long as the signature could still be accepted. Use a shared store (e.g.
  Redis `SET NX PX`) when running more than one instance.
- **JWKS fetches are rate limited.** Unknown key IDs trigger at most one
  fetch per `MinRefreshInterval` (default 30s), responses are capped at 1 MiB,
  and the last good key set keeps being served if the endpoint goes down.

### RFC 9421 coverage

Supported: `@method`, `@path`, `@authority` and header fields; `created`,
`expires`, `keyid`, `alg` parameters; `ed25519` and `rsa-pss-sha512`.
Not yet supported: other derived components (`@query`, `@target-uri`, ...),
component parameters (`;sf`, `;key`, `;bs`, `;req`), and verifying more than
the first signature in a `Signature-Input` header.

## Examples

Run `go run ./examples/server` in one terminal and `go run ./examples/client`
in another. Both share a hard-coded demo key from `examples/internal/demokey`.

- `examples/client` signs a POST and sends it to the server
- `examples/server` verification middleware with replay protection
- `examples/webhook` verification inside a plain handler (port 8080)
