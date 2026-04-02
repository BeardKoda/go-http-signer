package httpsig

import (
	"crypto/sha256"
	"encoding/base64"
)

// ComputeContentDigest returns an RFC 9530-style digest field value.
func ComputeContentDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}
