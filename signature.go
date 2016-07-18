package httpsignatures

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"net/http"
	"regexp"
	"strings"
)

const (
	HEADER_SIGNATURE     = "Signature"
	HEADER_AUTHORIZATION = "Authorization"

	REQUEST_TARGET = "(request-target)"

	AUTH_SCHEME = "Signature "

	ALGORITHM_HMAC_SHA256 = "hmac-sha256"
	ALGORITHM_HMAC_SHA1   = "hmac-sha1"
)

var (
	ErrorNoSignatureHeader = errors.New("No Signature header found in request")
	ErrorUnknownAlgorithm  = errors.New("Unknown Algorithm")

	signatureRegex = regexp.MustCompile(`(\w+)="([^"]*)"`)
)

// Signature is the hashed key + headers, either from a request or a signer
type Signature struct {
	KeyID     string
	Algorithm string
	Headers   HeaderList
	Signature string
}

// NewSignatureFromRequest creates a new Signature from the Request
// both Signature and Authorization http headers are supported.
func NewSignatureFromRequest(r *http.Request) (*Signature, error) {
	if s, ok := r.Header[HEADER_SIGNATURE]; ok {
		return NewSignatureFromString(s[0])
	}
	if a, ok := r.Header[HEADER_AUTHORIZATION]; ok {
		return NewSignatureFromString(strings.TrimPrefix(a[0], AUTH_SCHEME))
	}
	return nil, ErrorNoSignatureHeader
}

// NewSignatureFromString creates a new Signature from its encoded form,
// eg `keyId="a",algorithm="b",headers="c",signature="d"`
func NewSignatureFromString(in string) (*Signature, error) {
	var res Signature = Signature{}
	var key string
	var value string

	for _, m := range signatureRegex.FindAllStringSubmatch(in, -1) {
		key = m[1]
		value = m[2]

		if key == "keyId" {
			res.KeyID = value
		} else if key == "algorithm" {
			res.Algorithm = value
		} else if key == "headers" {
			res.Headers = HeaderListFromString(value)
		} else if key == "signature" {
			res.Signature = value
		} else {
			return nil, errors.New(fmt.Sprintf("Unexpected key in signature '%s'", key))
		}
	}

	if len(res.Signature) == 0 {
		return nil, errors.New("Missing signature")
	}

	if len(res.Algorithm) == 0 {
		return nil, errors.New("Missing algorithm")
	}

	if len(res.KeyID) == 0 {
		return nil, errors.New("Missing keyId")
	}

	return &res, nil
}

// ToString returns the encoded form of the Signature
func (s Signature) ToString() string {
	str := fmt.Sprintf(
		`keyId="%s",algorithm="%s",signature="%s"`,
		s.KeyID,
		s.Algorithm,
		s.Signature,
	)

	if len(s.Headers) > 0 {
		str += fmt.Sprintf(`,headers="%s"`, s.Headers.ToString())
	}

	return str
}

func (s Signature) calculateSignature(key string, r *http.Request) (string, error) {
	hash, err := hasher(s.Algorithm, key)
	if err != nil {
		return "", err
	}

	signingString, err := s.Headers.SigningString(r)
	if err != nil {
		return "", err
	}

	hash.Write([]byte(signingString))

	return base64.StdEncoding.EncodeToString(hash.Sum(nil)), nil
}

// Sign this signature using the given key
func (s *Signature) Sign(key string, r *http.Request) error {
	sig, err := s.calculateSignature(key, r)
	if err != nil {
		return err
	}

	s.Signature = sig
	return nil
}

// IsValid validates this signature for the given key
func (s Signature) IsValid(key string, r *http.Request) bool {
	if !s.Headers.HasDate() {
		return false
	}

	sig, err := s.calculateSignature(key, r)
	if err != nil {
		return false
	}
	return s.Signature == sig
}

type HeaderList []string

func HeaderListFromString(list string) HeaderList {
	return strings.Split(strings.ToLower(string(list)), " ")
}

func (h HeaderList) ToString() string {
	return strings.ToLower(strings.Join(h, " "))
}

func (h HeaderList) HasDate() bool {
	for _, header := range h {
		if header == "date" {
			return true
		}
	}

	return false
}

func (h HeaderList) SigningString(req *http.Request) (string, error) {
	lines := []string{}

	for _, header := range h {
		if header == REQUEST_TARGET {
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

func hasher(alg string, key string) (hash.Hash, error) {
	switch alg {
	case ALGORITHM_HMAC_SHA1:
		return hmac.New(sha1.New, []byte(key)), nil
	case ALGORITHM_HMAC_SHA256:
		return hmac.New(sha256.New, []byte(key)), nil
	default:
		return nil, ErrorUnknownAlgorithm
	}
}

func requestTargetLine(req *http.Request) string {
	var url string = ""
	if req.URL != nil {
		url = req.URL.RequestURI()
	}

	return fmt.Sprintf("%s: %s %s", REQUEST_TARGET, strings.ToLower(req.Method), url)
}

func headerLine(req *http.Request, header string) (string, error) {

	if value := req.Header.Get(header); value != "" {
		return fmt.Sprintf("%s: %s", header, value), nil
	}

	return "", errors.New(fmt.Sprintf("Missing required header '%s'", header))
}
