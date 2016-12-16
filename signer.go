package httpsignatures

import (
	"errors"
	"net/http"
	"time"
)

type Signer struct {
	keyId     string
	keyLookup func(keyId string) string
	algorithm string
	headers   []string
}

// NewSigner adds an algorithm to the signer algorithms
func NewSigner(keyId string, keyLookup func(keyId string) string,
	algorithm string, headers ...string) *Signer {
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

	r.Header.Add("Signature", signature)
	return nil
}

// AuthRequest adds a http signature to the Authorization: HTTP Header
func (s Signer) AuthRequest(r *http.Request) error {
	signature, err := s.createHTTPSignatureString(r)
	if err != nil {
		return err
	}

	r.Header.Add("Authorization", "Signature "+signature)
	return nil
}

func (s Signer) createHTTPSignatureString(r *http.Request) (string, error) {
	sig := SignatureParameters{}
	if err := sig.FromConfig(s.keyId, s.algorithm, s.headers); err != nil {
		return "", err
	}

	if err := sig.ParseRequest(r); err != nil {
		return "", err
	}

	signature, err := sig.calculateSignature(s.keyLookup(s.keyId))
	if err != nil {
		return "", err
	}

	return sig.hTTPSignatureString(signature), nil
}

// VerifyRequest verifies the signature added to the request and returns true if it is OK
func VerifyRequest(r *http.Request, keyLookup func(keyId string) string, allowedClockSkew int, headers ...string) (bool, error) {
	sig := SignatureParameters{}

	if err := sig.FromRequest(r); err != nil {
		return false, err
	}

	for _, header := range headers {
		if sig.Headers[header] == "" {
			return false, errors.New("Required header not in header list")
		}
	}

	if allowedClockSkew > -1 {
		if allowedClockSkew == 0 {
			return false, errors.New("You probably misconfigured allowedClockSkew, set to -1 to disable")
		}
		// check if difference between date and date.Now exceeds allowedClockSkew
		if date := sig.Headers["date"]; len(date) != 0 {
			if hdrDate, err := time.Parse(time.RFC1123, date); err == nil {
				if (int)(time.Since(hdrDate).Seconds()) > (allowedClockSkew) {
					return false, errors.New("Allowed clockskew exceeded")
				}
			} else {
				return false, err
			}

		} else {
			return false, errors.New("Date header is missing for clockSkew comparison")
		}
	}

	return sig.Verify(keyLookup(sig.KeyID))
}
