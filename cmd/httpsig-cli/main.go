package main

import (
	"bytes"
	"crypto"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/beardkoda/httpsig-go/httpsig/keys"
	"github.com/beardkoda/httpsig-go/httpsig/signer"
	"github.com/beardkoda/httpsig-go/httpsig/verifier"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "sign":
		if err := runSign(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "sign error:", err)
			os.Exit(1)
		}
	case "verify":
		if err := runVerify(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "verify error:", err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func runSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	keyFile := fs.String("key", "", "private PEM key path")
	keyID := fs.String("key-id", "default", "key ID")
	urlStr := fs.String("url", "", "request URL")
	method := fs.String("method", http.MethodGet, "request method")
	bodyFile := fs.String("body", "", "request body file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" || *urlStr == "" {
		return fmt.Errorf("--key and --url are required")
	}

	keyPEM, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	priv, err := keys.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return err
	}

	body := []byte(nil)
	if *bodyFile != "" {
		body, err = os.ReadFile(*bodyFile)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequest(*method, *urlStr, bytes.NewReader(body))
	if err != nil {
		return err
	}

	s := signer.Signer{
		KeyID:      *keyID,
		PrivateKey: priv,
		Algorithm:  "ed25519",
		Components: []string{"@method", "@path", "@authority", "content-digest"},
	}
	if err := s.Sign(req); err != nil {
		return err
	}

	fmt.Println("Signature-Input:", req.Header.Get("Signature-Input"))
	fmt.Println("Signature:", req.Header.Get("Signature"))
	if v := req.Header.Get("content-digest"); v != "" {
		fmt.Println("content-digest:", v)
	}
	return nil
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	keyFile := fs.String("key", "", "public PEM key path")
	keyID := fs.String("key-id", "default", "key ID")
	reqFile := fs.String("file", "", "request json file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" || *reqFile == "" {
		return fmt.Errorf("--key and --file are required")
	}

	pubPEM, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	pub, err := keys.ParsePublicKeyPEM(pubPEM)
	if err != nil {
		return err
	}

	raw, err := os.ReadFile(*reqFile)
	if err != nil {
		return err
	}
	var in requestFile
	if err := json.Unmarshal(raw, &in); err != nil {
		return err
	}

	req, err := http.NewRequest(in.Method, in.URL, strings.NewReader(in.Body))
	if err != nil {
		return err
	}
	for k, vals := range in.Headers {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}

	v := verifier.New(keys.NewStaticKeyStore(map[string]crypto.PublicKey{
		*keyID: pub,
	}))
	ok, err := v.Verify(req)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("signature invalid")
	}
	_, _ = io.WriteString(os.Stdout, "signature valid\n")
	return nil
}

type requestFile struct {
	Method  string              `json:"method"`
	URL     string              `json:"url"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
}

func usage() {
	fmt.Println("httpsig sign --key private.pem --url http://localhost:3000 --method POST --body body.json")
	fmt.Println("httpsig verify --key public.pem --file request.json")
}
