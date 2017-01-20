package httpsignatures

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
)

var (
	AlgorithmHmacSha256 = &Algorithm{"hmac-sha256", sha256.New, hmacSign}
	AlgorithmHmacSha1 = &Algorithm{"hmac-sha1", sha1.New, hmacSign}
	AlgorithmRsaSha1 = &Algorithm{"rsa-sha1", sha1.New, rsaSha1Sign}
	AlgorithmRsaSha256 = &Algorithm{"rsa-sha256", sha256.New, rsaSha256Sign}

	ErrorUnknownAlgorithm = errors.New("Unknown Algorithm")
)

type Algorithm struct {
	name string
	hash func() hash.Hash
	sign func(hashFunc func() hash.Hash, key string, signingString string) ([]byte, error)
}

func algorithmFromString(name string) (*Algorithm, error) {
	switch name {
	case AlgorithmHmacSha1.name:
		return AlgorithmHmacSha1, nil
	case AlgorithmHmacSha256.name:
		return AlgorithmHmacSha256, nil
	case AlgorithmRsaSha1.name:
		return AlgorithmRsaSha1, nil
	case AlgorithmRsaSha256.name:
		return AlgorithmRsaSha256, nil
	}
	return nil, ErrorUnknownAlgorithm
}

func hmacSign(hashFunc func() hash.Hash, key string, signingString string) ([]byte, error) {
	hash := hmac.New(hashFunc, []byte(key))
	hash.Write([]byte(signingString))
	return hash.Sum(nil), nil
}

func rsaSha1Sign(hashFunc func() hash.Hash, key string, signingString string) ([]byte, error) {
	return rsaSign(hashFunc, key, signingString, crypto.SHA1)
}

func rsaSha256Sign(hashFunc func() hash.Hash, key string, signingString string) ([]byte, error) {
	return rsaSign(hashFunc, key, signingString, crypto.SHA256)
}

func rsaSign(hashFunc func() hash.Hash, key string, signingString string, hashType crypto.Hash) ([]byte, error) {
	private_key, err := parsePrivateKey([]byte(key[:]))
	if err != nil {
		return nil, err
	}
	hash := hashFunc()
	hash.Write([]byte(signingString))
	d := hash.Sum(nil)
	singed_hash, err := rsa.SignPKCS1v15(rand.Reader, private_key, hashType, d)
	if err != nil {
		return nil, err
	}
	return singed_hash, nil
}

func parsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		rsa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return rsa, nil
	case "PRIVATE KEY":
		rsaz, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return rsaz.(*rsa.PrivateKey), nil
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
}
