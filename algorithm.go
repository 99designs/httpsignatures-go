package httpsignatures

import (
	"errors"
)

var (
	AlgorithmHmacSha1   = &Algorithm{"hmac-sha1", Hmac1Sign, Hmac1Verify}
	AlgorithmHmacSha256 = &Algorithm{"hmac-sha256", Hmac256Sign, Hmac256Verify}

	ErrorUnknownAlgorithm = errors.New("Unknown Algorithm")
)

type Algorithm struct {
	Name   string
	Sign   func(privateKey *[]byte, message []byte) (*[]byte, error)
	Verify func(privateKey *[]byte, message []byte, signature *[]byte) (bool, error)
}

func algorithmFromString(name string) (*Algorithm, error) {
	switch name {
	case AlgorithmHmacSha1.Name:
		return AlgorithmHmacSha1, nil
	case AlgorithmHmacSha256.Name:
		return AlgorithmHmacSha256, nil
	}

	return nil, ErrorUnknownAlgorithm
}
