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

var (
	ErrorNoSignatureHeader = errors.New("No Signature header found in request")

	signatureRegex = regexp.MustCompile(`(\w+)="([^"]*)"`)
)

// Signature is the hashed key + headers, either from a request or a signer
type SignatureParameters struct {
	Algorithm *Algorithm
	KeyID     string
	Headers   HeaderList
}

func (a SignatureParameters) CalculateSignature(keyB64 string, r *http.Request) (string, error) {
	signingString, err := a.Headers.signingString(r)
	if err != nil {
		return "", err
	}

	byteKey, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return "", err
	}
	hash, err := a.Algorithm.Sign(&byteKey, []byte(signingString))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(*hash), err
}

// String returns the encoded form of the Signature
func (sp SignatureParameters) SignatureString(signature string) string {
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

func (h HeaderList) hasDate() bool {
	for header := range h {
		if header == "date" {
			return true
		}
	}
	return false
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
