package httpsignatures

import (
	"encoding/base64"
	"net/http"
	"strings"
)

const (
	HeaderSignature     = "Signature"
	HeaderAuthorization = "Authorization"
	RequestTarget       = "(request-target)"
	authScheme          = "Signature "
)

type Signer struct {
	algorithm *Algorithm
	headers   HeaderList
}

// NewSigner adds an algorithm to the signer algorithms
func NewSigner(algorithm *Algorithm, hdrs ...string) *Signer {
	hl := HeaderList{}

	for _, header := range hdrs {
		hl[strings.ToLower(header)] = ""
	}

	return &Signer{
		algorithm: algorithm,
		headers:   hl,
	}
}

// SignRequest adds a http signature to the Signature: HTTP Header
func (s Signer) SignRequest(id, key string, r *http.Request) error {
	signature, err := s.createHTTPSignatureString(id, key, r)
	if err != nil {
		return err
	}

	r.Header.Add(HeaderSignature, signature)

	return nil
}

// AuthRequest adds a http signature to the Authorization: HTTP Header
func (s Signer) AuthRequest(id, key string, r *http.Request) error {
	signature, err := s.createHTTPSignatureString(id, key, r)
	if err != nil {
		return err
	}

	r.Header.Add(HeaderAuthorization, authScheme+signature)

	return nil
}

func (s Signer) createHTTPSignatureString(id, keyB64 string, r *http.Request) (string, error) {
	sig := &SignatureParameters{
		KeyID:     id,
		Algorithm: s.algorithm,
		Headers:   s.headers,
	}

	signature, err := sig.CalculateSignature(keyB64, r)
	if err != nil {
		return "", err
	}
	return sig.HTTPSignatureString(signature), nil
}

func (s SignatureParameters) CalculateSignature(keyB64 string, r *http.Request) (string, error) {
	signingString, err := s.Headers.SigningString(r)
	if err != nil {
		return "", err
	}

	byteKey, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return "", err
	}

	hash, err := s.Algorithm.Sign(&byteKey, []byte(signingString))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(*hash), err
}
