// httpsignatures is a golang implementation of the http-signatures spec
// found at https://tools.ietf.org/html/draft-cavage-http-signatures
package httpsignatures

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

type SignatureParameters struct {
	KeyID     string
	Algorithm *Algorithm
	Headers   HeaderList
	Signature string
}

// FromRequest takes the signature string from the HTTP-Request
// both Signature and Authorization http headers are supported.
func (s *SignatureParameters) FromRequest(r *http.Request) error {
	var httpSignatureString string
	if sig, ok := r.Header["Signature"]; ok {
		httpSignatureString = sig[0]
	} else {
		if h, ok := r.Header["Authorization"]; ok {
			httpSignatureString = strings.TrimPrefix(h[0], "Signature ")
		} else {
			return errors.New("No Signature header found in request")
		}
	}
	if err := s.parseSignatureString(httpSignatureString); err != nil {
		return err
	}
	if err := s.ParseRequest(r); err != nil {
		return err
	}

	return nil
}

// FromConfig takes the string configuration and fills the
// SignatureParameters struct
func (s *SignatureParameters) FromConfig(keyId string, algorithm string, headers []string) error {
	if len(keyId) == 0 {
		return errors.New("No keyID configured")
	}
	if len(algorithm) == 0 {
		return errors.New("No algorithm configured")
	}
	s.KeyID = keyId

	alg, err := algorithmFromString(algorithm)
	if err != nil {
		return err
	}
	s.Algorithm = alg

	if len(headers) == 0 {
		s.Headers = HeaderList{"date": ""}
	} else {
		s.Headers = HeaderList{}
		for _, header := range headers {
			s.Headers[header] = ""
		}
	}

	return nil
}

// ParseRequest extracts the header fields from the request required
// by the `headers` parameter in the configuration
func (s *SignatureParameters) ParseRequest(r *http.Request) error {
	if len(s.Headers) == 0 {
		return errors.New("No headers config loaded")
	}
	for header := range s.Headers {
		switch header {
		case "(request-target)":
			if tl, err := requestTargetLine(r); err == nil {
				s.Headers[header] = strings.TrimSpace(tl)
			} else {
				return err
			}
		case "host":
			if host := r.URL.Host; host != "" {
				s.Headers[header] = strings.TrimSpace(host)
			} else {
				return errors.New("Request contains no host")
			}
		default:
			// If there are multiple headers with the same name, add them all.
			if len(r.Header[http.CanonicalHeaderKey(header)]) > 0 {
				var trimmedValues []string
				for _, value := range r.Header[http.CanonicalHeaderKey(header)] {
					trimmedValues = append(trimmedValues, strings.TrimSpace(value))
				}
				s.Headers[header] = strings.Join(trimmedValues, ", ")
			} else {
				return fmt.Errorf("Missing required header '%s'", header)
			}
		}
	}
	return nil
}

// FromString creates a new Signature from its encoded form,
// eg `keyId="a",algorithm="b",headers="c",signature="d"`
func (s *SignatureParameters) parseSignatureString(in string) error {
	var key, value string
	*s = SignatureParameters{}
	signatureRegex := regexp.MustCompile(`(\w+)="([^"]*)"`)

	for _, m := range signatureRegex.FindAllStringSubmatch(in, -1) {
		key = m[1]
		value = m[2]

		if key == "keyId" {
			s.KeyID = value
		} else if key == "algorithm" {
			alg, err := algorithmFromString(value)
			if err != nil {
				return err
			}
			s.Algorithm = alg
		} else if key == "headers" {
			s.Headers.ParseString(value)
		} else if key == "signature" {
			s.Signature = value
		}
		// ignore unknown parameters
	}

	if len(s.Headers) == 0 {
		s.Headers = HeaderList{"date": ""}
	}

	if len(s.Signature) == 0 {
		return errors.New("Missing signature")
	}

	if len(s.KeyID) == 0 {
		return errors.New("Missing keyId")
	}

	if s.Algorithm == nil {
		return errors.New("Missing algorithm")
	}

	return nil
}

// String returns the encoded form of the Signature
func (s SignatureParameters) hTTPSignatureString(signature string) string {
	str := fmt.Sprintf(
		`keyId="%s",algorithm="%s"`,
		s.KeyID,
		s.Algorithm.Name,
	)

	if len(s.Headers) > 0 {
		str += fmt.Sprintf(`,headers="%s"`, s.Headers.toHeadersString())
	}

	str += fmt.Sprintf(`,signature="%s"`, signature)

	return str
}

func (s SignatureParameters) calculateSignature(keyB64 string) (string, error) {
	signingString, err := s.Headers.signingString()
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

// Verify verifies this signature for the given base64 encodedkey
func (s SignatureParameters) Verify(keyBase64 string) (bool, error) {
	signingString, err := s.Headers.signingString()
	if err != nil {
		return false, err
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

// HeaderList contains headers
type HeaderList map[string]string

// ParseString constructs a headerlist from the 'headers' string
func (h *HeaderList) ParseString(list string) {
	*h = HeaderList{}
	list = strings.TrimSpace(list)
	headers := strings.Split(strings.ToLower(string(list)), " ")
	for _, header := range headers {
		// init header map with empty string
		(*h)[header] = ""
	}
}

func (h HeaderList) toHeadersString() string {
	// todo return strings.Join(h, " ")
	list := ""
	for header := range h {
		list += " " + strings.ToLower(header)
	}
	return list
}

func (h HeaderList) signingString() (string, error) {
	signingList := []string{}

	for header, value := range h {
		headerString := fmt.Sprintf("%s: %s", header, value)
		signingList = append(signingList, headerString)
	}

	return strings.Join(signingList, "\n"), nil
}

func requestTargetLine(req *http.Request) (string, error) {
	if req.URL == nil {
		return "", errors.New("URL not in Request")
	}
	if len(req.Method) == 0 {
		return "", errors.New("Method not in Request")
	}

	path := req.URL.Path
	method := strings.ToLower(req.Method)
	return fmt.Sprintf("%s %s", method, path), nil
}

func headerLine(req *http.Request, header string) (string, error) {
	if value := req.Header.Get(header); value != "" {
		return fmt.Sprintf("%s: %s", header, value), nil
	}
	return "", fmt.Errorf("Missing required header '%s'", header)
}
