package httpsignatures

import (
	"net/http"
	"strings"
	"time"
)

const (
	HeaderSignature     = "Signature"
	HeaderAuthorization = "Authorization"
	RequestTarget       = "(request-target)"
	authScheme          = "Signature "
)

var (
	// DefaultSha1Signer will sign requests with the url and date using the SHA1 algorithm.
	// Users are encouraged to create their own signer with the headers they require.
	DefaultSha1Signer = NewSigner(AlgorithmHmacSha1, RequestTarget, "date")

	// DefaultSha256Signer will sign requests with the url and date using the SHA256 algorithm.
	// Users are encouraged to create their own signer with the headers they require.
	DefaultSha256Signer = NewSigner(AlgorithmHmacSha256, RequestTarget, "date")

	// DefaultEd25519Signer will sign requests with the url and dat using the Ed25519 algorithm.
	// Users are encouraged to create their own signer with the header they require.
	DefaultEd25519Signer = NewSigner(AlgorithmEd25519, RequestTarget, "date")
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
	signature, err := s.createSignature(id, key, r)
	if err != nil {
		return err
	}

	r.Header.Add(HeaderSignature, signature)

	return nil
}

// AuthRequest adds a http signature to the Authorization: HTTP Header
func (s Signer) AuthRequest(id, key string, r *http.Request) error {
	signature, err := s.createSignature(id, key, r)
	if err != nil {
		return err
	}

	r.Header.Add(HeaderAuthorization, authScheme+signature)

	return nil
}

func (s Signer) createSignature(id, keyB64 string, r *http.Request) (string, error) {
	if r.Header.Get("date") == "" {
		r.Header.Set("date", time.Now().UTC().Format(time.RFC1123))
	}

	sig := &SignatureParameters{
		KeyID:     id,
		Algorithm: s.algorithm,
		Headers:   s.headers,
	}

	signature, err := sig.CalculateSignature(keyB64, r)
	if err != nil {
		return "", err
	}
	return sig.SignatureString(signature), nil
}
