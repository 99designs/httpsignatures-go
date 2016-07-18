package httpsignatures

import (
	"net/http"
	"time"
)

// Signer is used to create a signature for a given request.
type Signer struct {
	Algorithm string
	Headers   HeaderList
}

var (
	DefaultSha1Signer   = Signer{ALGORITHM_HMAC_SHA1, HeaderList{REQUEST_TARGET, "date"}}
	DefaultSha256Signer = Signer{ALGORITHM_HMAC_SHA256, HeaderList{REQUEST_TARGET, "date"}}
)

// SignRequest adds a http signature to the Signature: HTTP Header
func (s Signer) SignRequest(id, key string, r *http.Request) error {
	sig, err := s.buildSignature(id, key, r)
	if err != nil {
		return err
	}

	r.Header.Add(HEADER_SIGNATURE, sig.ToString())

	return nil
}

// AuthRequest adds a http signature to the Authorization: HTTP Header
func (s Signer) AuthRequest(id, key string, r *http.Request) error {
	sig, err := s.buildSignature(id, key, r)
	if err != nil {
		return err
	}

	r.Header.Add(HEADER_AUTHORIZATION, AUTH_SCHEME+sig.ToString())

	return nil
}

func (s Signer) buildSignature(id, key string, r *http.Request) (*Signature, error) {
	if r.Header.Get("date") == "" {
		r.Header.Set("date", time.Now().Format(time.RFC1123))
	}

	sig := &Signature{
		KeyID:     id,
		Algorithm: s.Algorithm,
		Headers:   s.Headers,
	}

	err := sig.Sign(key, r)
	if err != nil {
		return nil, err
	}

	return sig, nil
}
