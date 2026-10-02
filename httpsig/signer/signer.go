package signer

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"slices"
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
	// Expiry, when positive, adds an expires parameter this far after created.
	Expiry time.Duration
	Now    func() time.Time
}

func (s *Signer) Sign(req *http.Request) error {
	if req == nil {
		return fmt.Errorf("request is required")
	}
	if s.PrivateKey == nil {
		return fmt.Errorf("private key is required")
	}
	components := make([]string, 0, len(s.Components)+1)
	for _, c := range s.Components {
		components = append(components, strings.ToLower(strings.TrimSpace(c)))
	}
	if len(components) == 0 {
		components = append(components, "@method", "@path", "@authority")
	}

	body, err := readAndRestoreBody(req)
	if err != nil {
		return err
	}
	if len(body) > 0 {
		req.Header.Set("content-digest", root.ComputeContentDigest(body))
		// Verifiers reject bodies whose digest is not signed, so always cover it.
		if !slices.Contains(components, "content-digest") {
			components = append(components, "content-digest")
		}
	}

	algo, err := algorithms.GetAlgorithm(s.Algorithm)
	if err != nil {
		return err
	}

	nowFn := s.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	now := nowFn()
	params := canonical.SignatureParams{
		Components: components,
		Created:    now.Unix(),
		KeyID:      s.KeyID,
		Algorithm:  algo.Name(),
	}
	if s.Expiry > 0 {
		params.Expires = now.Add(s.Expiry).Unix()
	}
	sigParams, err := params.Serialize()
	if err != nil {
		return err
	}

	base, err := canonical.BuildSignatureBase(req, components, sigParams)
	if err != nil {
		return err
	}
	sig, err := algo.Sign([]byte(base), s.PrivateKey)
	if err != nil {
		return err
	}

	label := "sig1"
	req.Header.Set("Signature-Input", label+"="+sigParams)
	req.Header.Set("Signature", buildSignatureHeader(label, sig))
	return nil
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
