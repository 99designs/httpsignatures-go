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

const (
	HeaderSignature     = "Signature"
	headerAuthorization = "Authorization"
	RequestTarget       = "(request-target)"
	authScheme          = "Signature "
)

var (
	ErrorNoSignatureHeader = errors.New("No Signature header found in request")

	signatureRegex = regexp.MustCompile(`(\w+)="([^"]*)"`)
)

// Signature is the hashed key + headers, either from a request or a signer
type Signature struct {
	KeyID     string
	Algorithm *Algorithm
	Headers   HeaderList
	Signature string
}

// FromRequest creates a new Signature from the Request
// both Signature and Authorization http headers are supported.
func FromRequest(r *http.Request) (*Signature, error) {
	if s, ok := r.Header[HeaderSignature]; ok {
		return FromString(s[0])
	}
	if a, ok := r.Header[headerAuthorization]; ok {
		return FromString(strings.TrimPrefix(a[0], authScheme))
	}
	return nil, ErrorNoSignatureHeader
}

// FromString creates a new Signature from its encoded form,
// eg `keyId="a",algorithm="b",headers="c",signature="d"`
func FromString(in string) (*Signature, error) {
	var res Signature = Signature{}
	var key string
	var value string

	for _, m := range signatureRegex.FindAllStringSubmatch(in, -1) {
		key = m[1]
		value = m[2]

		if key == "keyId" {
			res.KeyID = value
		} else if key == "algorithm" {
			alg, err := algorithmFromString(value)
			if err != nil {
				return nil, err
			}
			res.Algorithm = alg
		} else if key == "headers" {
			res.Headers = headerListFromString(value)
		} else if key == "signature" {
			res.Signature = value
		} else {
			return nil, errors.New(fmt.Sprintf("Unexpected key in signature '%s'", key))
		}
	}

	if len(res.Signature) == 0 {
		return nil, errors.New("Missing signature")
	}

	if len(res.KeyID) == 0 {
		return nil, errors.New("Missing keyId")
	}

	if res.Algorithm == nil {
		return nil, errors.New("Missing algorithm")
	}

	return &res, nil
}

// String returns the encoded form of the Signature
func (s Signature) String() string {
	str := fmt.Sprintf(
		`keyId="%s",algorithm="%s",signature="%s"`,
		s.KeyID,
		s.Algorithm.Name,
		s.Signature,
	)

	if len(s.Headers) > 0 {
		str += fmt.Sprintf(`,headers="%s"`, s.Headers.String())
	}

	return str
}

func (s Signature) calculateSignature(key string, r *http.Request) (string, error) {
	signingString, err := s.Headers.signingString(r)
	if err != nil {
		return "", err
	}

	byteKey := []byte(key)
	hash, err := s.Algorithm.Sign(&byteKey, []byte(signingString))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(*hash), err
}

// Sign this signature using the given key
func (s *Signature) Sign(key string, r *http.Request) error {
	signingString, err := s.Headers.signingString(r)
	if err != nil {
		return err
	}

	byteKey := []byte(key)
	hash, err := s.Algorithm.Sign(&byteKey, []byte(signingString))
	if err != nil {
		return err
	}
	s.Signature = base64.StdEncoding.EncodeToString(*hash)
	return nil
}

// Verify verifies this signature for the given key
func (s Signature) Verify(key string, r *http.Request) (bool, error) {
	signingString, err := s.Headers.signingString(r)
	if err != nil {
		return false, err
	}

	if !s.Headers.hasDate() {
		return false, errors.New("No Date Header Supplied")
	}

	byteKey := []byte(key)
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

type HeaderList []string

func headerListFromString(list string) HeaderList {
	return strings.Split(strings.ToLower(string(list)), " ")
}

func (h HeaderList) String() string {
	return strings.ToLower(strings.Join(h, " "))
}

func (h HeaderList) hasDate() bool {
	for _, header := range h {
		if header == "date" {
			return true
		}
	}

	return false
}

func (h HeaderList) signingString(req *http.Request) (string, error) {
	lines := []string{}

	for _, header := range h {
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
	var url string = ""
	if req.URL != nil {
		url = req.URL.RequestURI()
	}

	return fmt.Sprintf("%s: %s %s", RequestTarget, strings.ToLower(req.Method), url)
}

func headerLine(req *http.Request, header string) (string, error) {

	if value := req.Header.Get(header); value != "" {
		return fmt.Sprintf("%s: %s", header, value), nil
	}

	return "", errors.New(fmt.Sprintf("Missing required header '%s'", header))
}
