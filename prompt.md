
Project: Go HTTP Signatures Library (RFC 9421)

⸻

🎯 Objective

Build a production-grade Go library implementing HTTP Message Signatures with:
	•	Signing (client-side)
	•	Verification (server-side)
	•	Middleware support
	•	Replay protection
	•	CLI tool

📦 STEP 0 — Project Setup

Prompt for Cursor:
```
Initialize a Go module named github.com/<your-username>/httpsig-go.

Create the following folder structure:

/httpsig
  /canonical
  /signer
  /verifier
  /algorithms
  /keys
  /middleware
  /internal
/cmd/httpsig-cli
/examples
/tests

Add a Makefile with commands:
- make test
- make build
- make lint

Use Go 1.22+
```

⚙️ STEP 1 — Canonicalization Engine
Implement HTTP message canonicalization based on RFC 9421.

Create:
- canonical/base.go
- canonical/components.go

Support components:
- @method
- @path
- @authority
- content-digest
- header fields

Expose:

func BuildSignatureBase(req *http.Request, components []string) (string, error)

Requirements:
- Normalize headers to lowercase
- Trim whitespace
- Preserve order
- Handle missing headers safely

Output Expectation:
	•	Deterministic base string generation
	•	Fully testable


🔐 STEP 2 — Algorithms Layer
```
Create pluggable signature algorithms.

Define interface:

type Algorithm interface {
    Sign(data []byte, privateKey crypto.PrivateKey) ([]byte, error)
    Verify(data []byte, sig []byte, publicKey crypto.PublicKey) error
    Name() string
}

Implement:
- Ed25519 (default)
- RSA-PSS-SHA512

Allow registration:

func RegisterAlgorithm(name string, algo Algorithm)
```

🔑 STEP 3 — Key Management
```
Implement a KeyStore interface:

type KeyStore interface {
    GetKey(keyID string) (crypto.PublicKey, error)
}

Provide:
- StaticKeyStore (map-based)
- JWKSKeyStore (fetch from URL, cache keys)

Support:
- key rotation
- caching with TTL
```

✍️ STEP 4 — Signer
```
Create signer module.

Struct:

type Signer struct {
    KeyID string
    Algorithm string
    PrivateKey crypto.PrivateKey
    Components []string
}

Method:

func (s *Signer) Sign(req *http.Request) error

Behavior:
- Build signature base
- Sign it
- Add headers:
  - Signature-Input
  - Signature
- Add created timestamp
```

✅ STEP 5 — Verifier
```
Create verifier module.

Struct:

type Verifier struct {
    KeyStore KeyStore
    AllowedClockSkew time.Duration
}

Method:

func (v *Verifier) Verify(req *http.Request) (bool, error)

Behavior:
- Parse Signature-Input
- Extract keyId, algorithm, created, expires
- Rebuild signature base
- Fetch public key
- Verify signature
```

🔁 STEP 6 — Replay Protection
```
Add replay protection.

Define:

type ReplayCache interface {
    Seen(id string) bool
    Store(id string, ttl time.Duration)
}

Provide:
- InMemoryReplayCache (with mutex + TTL)

Integrate into verifier:
- Reject reused signatures
- Use signature + timestamp as key
```

🌐 STEP 7 — Middleware
```
Create middleware for net/http.

Function:

func VerifyMiddleware(v *Verifier, next http.Handler) http.Handler

Behavior:
- Verify request
- Reject with 401 if invalid
- Pass context with verification result

Also create:
- Gin middleware adapter
```

📦 STEP 8 — Content Digest Support
```
Implement content-digest header generation.

Function:

func ComputeContentDigest(body []byte) string

Use SHA-256.

Ensure:
- signer adds digest
- verifier checks digest integrity
```

🧪 STEP 9 — Tests
```
Write comprehensive tests.

Include:
- canonicalization tests
- signing + verification roundtrip
- invalid signature cases
- replay attack tests

Add fuzz tests for header parsing.
```

🧰 STEP 10 — CLI Tool
```
Build CLI in /cmd/httpsig-cli.

Commands:

httpsig sign \
  --key private.pem \
  --url http://localhost:3000 \
  --method POST \
  --body body.json

httpsig verify \
  --key public.pem \
  --file request.json

Use cobra or standard flag package.
```

📚 STEP 11 — Examples
```
Create examples:

/examples/client
- sends signed request

/examples/server
- verifies signed request

/examples/webhook
- webhook verification example
```

🚀 STEP 12 — Performance + Polish
```
Optimize:
- avoid unnecessary allocations
- reuse buffers

Add benchmarks:
- signing performance
- verification performance
```

📄 STEP 13 — Documentation
```
Write README.md:

Include:
- installation
- quick start
- examples
- supported algorithms
- security notes
```

🧠 BONUS (HIGH IMPACT)
```
- Reverse proxy verifier (for API gateways)
- Logging hooks
- Metrics (Prometheus)
```