package httpsignatures

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"net/http"
	"strings"
	"time"
)

// Signer is used to create a signature for a given request.
type Signer struct {
	algorithm *Algorithm
	headers   HeaderList
}

var (
	// DefaultSha1Signer will sign requests with the url and date using the SHA1 algorithm.
	// Users are encouraged to create their own signer with the headers they require.
	DefaultSha1Signer = NewSigner(AlgorithmHmacSha1, RequestTarget, "date")

	// DefaultSha256Signer will sign requests with the url and date using the SHA256 algorithm.
	// Users are encouraged to create their own signer with the headers they require.
	DefaultSha256Signer = NewSigner(AlgorithmHmacSha256, RequestTarget, "date")

	// DefaultSha1Signer will sign requests with the url and date using the SHA1 algorithm.
	// Users are encouraged to create their own signer with the headers they require.
	DefaultRsaSha1Signer = NewSigner(AlgorithmRsaSha1, RequestTarget, "date")

	// DefaultRsaSha256Signer will sign requests with the url and date using the SHA256 algorithm.
	// Users are encouraged to create their own signer with the headers they require.
	DefaultRsaSha256Signer = NewSigner(AlgorithmRsaSha256, RequestTarget, "date")

	// DefaultEcdsaSha256Signer will sign requests with the url and date
	// using the SHA256 algorithm.  Users are encouraged to create their own
	// signer with the headers they require.
	DefaultEcdsaSha256Signer = NewSigner(AlgorithmEcdsaSha256, RequestTarget, "date")
)

func NewSigner(algorithm *Algorithm, headers ...string) *Signer {
	hl := HeaderList{}

	for _, header := range headers {
		hl = append(hl, strings.ToLower(header))
	}

	return &Signer{
		algorithm: algorithm,
		headers:   hl,
	}
}

// SignRequest adds a http signature to the Signature: HTTP Header
func (s Signer) SignRequest(keyId string, key interface{}, r *http.Request) error {
	sig, err := s.buildSignature(keyId, key, r)
	if err != nil {
		return err
	}

	r.Header.Add(headerSignature, sig.String())

	return nil
}

// SignRequestRSA signs a request with an RSA private key.
func (s Signer) SignRequestRSA(keyId string, key *rsa.PrivateKey, r *http.Request) error {
	return s.SignRequest(keyId, key, r)
}

// SignRequestECDSA signs a request with an ECDSA private key.
func (s Signer) SignRequestECDSA(keyId string, key *ecdsa.PrivateKey, r *http.Request) error {
	return s.SignRequest(keyId, key, r)
}

// AuthRequest adds a http signature to the Authorization: HTTP Header
func (s Signer) AuthRequest(keyId string, key interface{}, r *http.Request) error {
	sig, err := s.buildSignature(keyId, key, r)
	if err != nil {
		return err
	}

	r.Header.Add(headerAuthorization, authScheme+sig.String())

	return nil
}

// AuthRequestRSA adds an http signature to the Authorization: HTTP Header using
// an RSA private key to generate the signature.This method should only be
// called when the underlying Algorithm is an RSA backed implementation.
func (s Signer) AuthRequestRSA(keyId string, key *rsa.PrivateKey, r *http.Request) error {
	return s.AuthRequest(keyId, key, r)
}

func (s Signer) buildSignature(keyId string, key interface{}, r *http.Request) (*Signature, error) {
	if r.Header.Get("date") == "" {
		r.Header.Set("date", time.Now().Format(time.RFC1123))
	}

	sig := &Signature{
		KeyID:     keyId,
		Algorithm: s.algorithm,
		Headers:   s.headers,
	}

	err := sig.sign(key, r)
	if err != nil {
		return nil, err
	}

	return sig, nil
}
