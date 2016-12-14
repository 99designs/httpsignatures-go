// httpsignatures is a golang implementation of the http-signatures spec
// found at https://tools.ietf.org/html/draft-cavage-http-signatures
package httpsignatures

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

var (
	ErrorNoSignatureHeader = errors.New("No Signature header found in request")

	signatureRegex = regexp.MustCompile(`(\w+)="([^"]*)"`)
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
	if sig, ok := r.Header[HeaderSignature]; ok {
		return s.FromString(sig[0])
	}
	if h, ok := r.Header[HeaderAuthorization]; ok {
		return s.FromString(strings.TrimPrefix(h[0], authScheme))
	}
	return ErrorNoSignatureHeader
}

// FromConfig takes the string configuration and fills the
// SignatureParameters struct
func (s *SignatureParameters) FromConfig(keyId string, algorithm string, headers string) error {
	if len(keyId) == 0 {
		return errors.New("Missing keyId")
	} else {
		s.KeyID = keyId
	}

	if len(algorithm) == 0 {
		return errors.New("Missing algorithm")
	} else {
		alg, err := algorithmFromString(algorithm)
		if err != nil {
			return err
		}
		s.Algorithm = alg
	}

	if len(headers) == 0 {
		s.Headers = HeaderList{"date": ""}
	} else {
		s.Headers.FromString(headers)
	}

	return nil
}

// FromString creates a new Signature from its encoded form,
// eg `keyId="a",algorithm="b",headers="c",signature="d"`
func (s *SignatureParameters) FromString(in string) error {
	var key string
	var value string
	*s = SignatureParameters{}

	for _, m := range signatureRegex.FindAllStringSubmatch(in, -1) {
		key = m[1]
		value = m[2]

		if key == "keyId" {
			(*s).KeyID = value
		} else if key == "algorithm" {
			alg, err := algorithmFromString(value)
			if err != nil {
				return err
			}
			s.Algorithm = alg
		} else if key == "headers" {
			s.Headers.FromString(value)
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
func (sp SignatureParameters) HTTPSignatureString(signature string) string {
	str := fmt.Sprintf(
		`keyId="%s",algorithm="%s"`,
		sp.KeyID,
		sp.Algorithm.Name,
	)

	if len(sp.Headers) > 0 {
		str += fmt.Sprintf(`,headers="%s"`, sp.Headers.ToString())
	}

	str += fmt.Sprintf(`,signature="%s"`, signature)

	return str
}

// HeaderList contains headers
type HeaderList map[string]string

// FromString constructs a headerlist from the 'headers' string
func (h *HeaderList) FromString(list string) {
	if *h == nil {
		*h = HeaderList{}
	}
	list = strings.TrimSpace(list)
	headers := strings.Split(strings.ToLower(string(list)), " ")
	for _, header := range headers {
		// init header map with empty string
		(*h)[header] = ""
	}
}

func (h HeaderList) ToString() string {
	list := ""
	for header := range h {
		list += " " + strings.ToLower(header)
	}
	return list
}

func (h HeaderList) signingString(req *http.Request) (string, error) {
	lines := []string{}

	for header := range h {
		if header == RequestTarget {
			lines = append(lines, requestTargetLine(req))
		} else {
			line, err := headerLine(req, header)
			if err != nil {
				return "", err
			}
			lines = append(lines, line)
		}
	}

	return strings.Join(lines, "\n"), nil
}

func requestTargetLine(req *http.Request) string {
	var url string
	if req.URL != nil {
		url = req.URL.RequestURI()
	}
	return fmt.Sprintf("%s: %s %s", RequestTarget, strings.ToLower(req.Method), url)
}

func headerLine(req *http.Request, header string) (string, error) {
	if value := req.Header.Get(header); value != "" {
		return fmt.Sprintf("%s: %s", header, value), nil
	}
	return "", fmt.Errorf("Missing required header '%s'", header)
}
