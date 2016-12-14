// httpsignatures is a golang implementation of the http-signatures spec
// found at https://tools.ietf.org/html/draft-cavage-http-signatures
package httpsignatures

import (
	"encoding/base64"
	"errors"
	"net/http"
)

// Verify verifies this signature for the given base64 encodedkey
func (s SignatureParameters) Verify(keyBase64 string, r *http.Request) (bool, error) {
	signingString, err := s.Headers.signingString(r)
	if err != nil {
		return false, err
	}

	if !s.Headers.hasDate() {
		return false, errors.New("No Date Header Supplied")
	}

	byteKey, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return false, err
	}

	byteSignature, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil {
		return false, err
	}
	result, err := s.Algorithm.Verify(&byteKey, []byte(signingString), &byteSignature)
	if err != nil {
		return false, err
	}
	return result, nil
}
