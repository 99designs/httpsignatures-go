package httpsignatures

import (
	"encoding/base64"
	"net/http"
)

const (
	HeaderSignature     = "Signature"
	HeaderAuthorization = "Authorization"
	RequestTarget       = "(request-target)"
	authScheme          = "Signature "
)

type Signer struct {
	keyId     string
	keyLookup func(keyId string) string
	algorithm string
	headers   []string
}

// NewSigner adds an algorithm to the signer algorithms
func NewSigner(keyId string, keyLookup func(keyId string) string, algorithm string, headers ...string) *Signer {
	return &Signer{
		keyId:     keyId,
		keyLookup: keyLookup,
		algorithm: algorithm,
		headers:   headers,
	}
}

// SignRequest adds a http signature to the Signature: HTTP Header
func (s Signer) SignRequest(r *http.Request) error {
	signature, err := s.createHTTPSignatureString(r)
	if err != nil {
		return err
	}

	r.Header.Add(HeaderSignature, signature)
	return nil
}

// AuthRequest adds a http signature to the Authorization: HTTP Header
func (s Signer) AuthRequest(r *http.Request) error {
	signature, err := s.createHTTPSignatureString(r)
	if err != nil {
		return err
	}

	r.Header.Add(HeaderAuthorization, authScheme+signature)
	return nil
}

func (s Signer) createHTTPSignatureString(r *http.Request) (string, error) {
	sig := SignatureParameters{}
	sig.FromConfig(s.keyId, s.algorithm, s.headers)

	signature, err := sig.CalculateSignature(s.keyLookup(s.keyId), r)
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
