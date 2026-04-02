package signer

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	root "github.com/beardkoda/httpsig-go/httpsig"
	"github.com/beardkoda/httpsig-go/httpsig/algorithms"
	"github.com/beardkoda/httpsig-go/httpsig/canonical"
)

type Signer struct {
	KeyID      string
	Algorithm  string
	PrivateKey crypto.PrivateKey
	Components []string
	Now        func() time.Time
}

func (s *Signer) Sign(req *http.Request) error {
	if req == nil {
		return fmt.Errorf("request is required")
	}
	if s.PrivateKey == nil {
		return fmt.Errorf("private key is required")
	}
	components := s.Components
	if len(components) == 0 {
		components = []string{"@method", "@path", "@authority"}
	}

	body, err := readAndRestoreBody(req)
	if err != nil {
		return err
	}
	if len(body) > 0 {
		req.Header.Set("content-digest", root.ComputeContentDigest(body))
	}

	base, err := canonical.BuildSignatureBase(req, components)
	if err != nil {
		return err
	}

	algo, err := algorithms.GetAlgorithm(s.Algorithm)
	if err != nil {
		return err
	}
	sig, err := algo.Sign([]byte(base), s.PrivateKey)
	if err != nil {
		return err
	}

	nowFn := s.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	created := nowFn().Unix()
	label := "sig1"

	req.Header.Set("Signature-Input", buildSignatureInput(label, components, s.KeyID, algo.Name(), created))
	req.Header.Set("Signature", buildSignatureHeader(label, sig))
	return nil
}

func buildSignatureInput(label string, components []string, keyID, algo string, created int64) string {
	parts := make([]string, 0, len(components))
	for _, c := range components {
		parts = append(parts, strconv.Quote(strings.ToLower(strings.TrimSpace(c))))
	}
	return fmt.Sprintf("%s=(%s);created=%d;keyid=%q;alg=%q",
		label,
		strings.Join(parts, " "),
		created,
		keyID,
		algo,
	)
}

func buildSignatureHeader(label string, sig []byte) string {
	return fmt.Sprintf("%s=:%s:", label, base64.StdEncoding.EncodeToString(sig))
}

func readAndRestoreBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}
