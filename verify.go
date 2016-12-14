// httpsignatures is a golang implementation of the http-signatures spec
// found at https://tools.ietf.org/html/draft-cavage-http-signatures
package httpsignatures

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
)

type VerificationParameters struct {
	SigParams *SignatureParameters
	KeyLookup func(keyID string) string
	Signature string
}

// FromRequest creates a new Signature for the HTTP-Request
// both Signature and Authorization http headers are supported.
func (v *VerificationParameters) FromRequest(r *http.Request) error {
	if sig, ok := r.Header[HeaderSignature]; ok {
		return v.FromString(sig[0])
	}
	if h, ok := r.Header[HeaderAuthorization]; ok {
		return v.FromString(strings.TrimPrefix(h[0], authScheme))
	}
	return ErrorNoSignatureHeader
}

// FromString creates a new Signature from its encoded form,
// eg `keyId="a",algorithm="b",headers="c",signature="d"`
func (v *VerificationParameters) FromString(in string) error {
	var key string
	var value string
	v.SigParams = new(SignatureParameters)

	for _, m := range signatureRegex.FindAllStringSubmatch(in, -1) {
		key = m[1]
		value = m[2]

		if key == "keyId" {
			v.SigParams.KeyID = value
		} else if key == "algorithm" {
			alg, err := algorithmFromString(value)
			if err != nil {
				return err
			}
			v.SigParams.Algorithm = alg
		} else if key == "headers" {
			v.SigParams.Headers.FromString(value)
		} else if key == "signature" {
			v.Signature = value
		}
		// ignore unknown parameters
	}

	if len(v.SigParams.Headers) == 0 {
		v.SigParams.Headers = HeaderList{"date": ""}
	}

	if len(v.Signature) == 0 {
		return errors.New("Missing signature")
	}

	if len(v.SigParams.KeyID) == 0 {
		return errors.New("Missing keyId")
	}

	if v.SigParams.Algorithm == nil {
		return errors.New("Missing algorithm")
	}

	return nil
}

// Verify verifies this signature for the given base64 encodedkey
func (v VerificationParameters) Verify(keyBase64 string, r *http.Request) (bool, error) {
	signingString, err := v.SigParams.Headers.signingString(r)
	if err != nil {
		return false, err
	}

	if !v.SigParams.Headers.hasDate() {
		return false, errors.New("No Date Header Supplied")
	}

	byteKey, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return false, err
	}

	byteSignature, err := base64.StdEncoding.DecodeString(v.Signature)
	if err != nil {
		return false, err
	}
	result, err := v.SigParams.Algorithm.Verify(&byteKey, []byte(signingString), &byteSignature)
	if err != nil {
		return false, err
	}
	return result, nil
}
