package httpsignatures

import (
	"errors"
)

var (
	AlgorithmHmacSha1   = "hmac-sha1"
	AlgorithmHmacSha256 = "hmac-sha256"
	AlgorithmEd25519    = "ed25519"

	algorithmHmacSha1   = &Algorithm{"hmac-sha1", Hmac1Sign, Hmac1Verify}
	algorithmHmacSha256 = &Algorithm{"hmac-sha256", Hmac256Sign, Hmac256Verify}
	algorithmEd25519    = &Algorithm{"ed25519", Ed25519Sign, Ed25519Verify}

	errorUnknownAlgorithm = errors.New("Unknown Algorithm")
)

// Algorithm exports the main algorithm properties: name, sign, verify
type Algorithm struct {
	Name   string
	Sign   func(privateKey *[]byte, message []byte) (*[]byte, error)
	Verify func(key *[]byte, message []byte, signature *[]byte) (bool, error)
}

func algorithmFromString(name string) (*Algorithm, error) {
	switch name {
	case AlgorithmHmacSha1:
		return algorithmHmacSha1, nil
	case AlgorithmHmacSha256:
		return algorithmHmacSha256, nil
	case AlgorithmEd25519:
		return algorithmEd25519, nil
	}

	return nil, errorUnknownAlgorithm
}
