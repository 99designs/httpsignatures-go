package httpsignatures

import (
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
	if err := sig.fromConfig(s.keyId, s.algorithm, s.headers); err != nil {
		return "", err
	}

	signingString, err := sig.Headers.signingString(r)
	if err != nil {
		return "", err
	}

	signature, err := sig.calculateSignature(s.keyLookup(s.keyId), signingString)
	if err != nil {
		return "", err
	}
	return sig.hTTPSignatureString(signature), nil
}

func (s Signer) VerifyRequest(r *http.Request, keyLookup func(keyId string) string) (bool, error) {
	sig := SignatureParameters{}
	if err := sig.fromRequest(r); err != nil {
		return false, err
	}

	hList := HeaderList{}
	signingString, err := hList.signingString(r)
	if err != nil {
		return false, err
	}

	return sig.Verify(keyLookup(sig.KeyID), signingString)
}
