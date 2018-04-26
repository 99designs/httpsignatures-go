package httpsignatures

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math/big"
)

var (
	AlgorithmHmacSha256  = &Algorithm{"hmac-sha256", hmacSign(crypto.SHA256), hmacVerify(crypto.SHA256)}
	AlgorithmHmacSha1    = &Algorithm{"hmac-sha1", hmacSign(crypto.SHA1), hmacVerify(crypto.SHA1)}
	AlgorithmRsaSha256   = &Algorithm{"rsa-sha256", rsaSign(crypto.SHA256), rsaVerify(crypto.SHA256)}
	AlgorithmRsaSha1     = &Algorithm{"rsa-sha1", rsaSign(crypto.SHA1), rsaVerify(crypto.SHA1)}
	AlgorithmEcdsaSha256 = &Algorithm{"ecdsa-sha256", ecdsaSign(crypto.SHA256), ecdsaVerify(crypto.SHA256)}

	ErrorUnknownAlgorithm = errors.New("Unknown Algorithm")
)

// signFn signs message m using key k.
type signFn func(k interface{}, m []byte) ([]byte, error)

// verifyFn verifies that signature s, for message m was signed by key k.
type verifyFn func(k interface{}, m []byte, s []byte) bool

type Algorithm struct {
	name string

	sign   signFn
	verify verifyFn
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
	case AlgorithmEcdsaSha256.name:
		return AlgorithmEcdsaSha256, nil
	}

	return nil, ErrorUnknownAlgorithm
}

// hmacSign returns a function that will HMAC sign some message using the given
// hash function.
func hmacSign(h crypto.Hash) signFn {
	return func(k interface{}, m []byte) ([]byte, error) {
		hash := hmac.New(h.New, []byte(k.(string)))
		hash.Write(m)
		return hash.Sum(nil), nil
	}
}

// hmacVerify returns a function that will verify that the signature signed with
// the given hashfn matches the calculated signature.
func hmacVerify(h crypto.Hash) verifyFn {
	sign := hmacSign(h)
	return func(k interface{}, m []byte, s []byte) bool {
		calculatedSignature, err := sign(k, m)
		if err != nil {
			return false
		}

		return hmac.Equal(calculatedSignature, s)
	}
}

// rsaSign returns a function that will sign a message with an RSA private key,
// using the given hash function.
func rsaSign(h crypto.Hash) signFn {
	return func(k interface{}, m []byte) ([]byte, error) {
		hash := h.New()
		hash.Write(m)
		hashed := hash.Sum(nil)
		return rsa.SignPKCS1v15(rand.Reader, k.(*rsa.PrivateKey), h, hashed[:])
	}
}

// rsaVerify returns a function that will verify that a message was signed with
// an RSA private key.
func rsaVerify(h crypto.Hash) verifyFn {
	return func(k interface{}, m []byte, s []byte) bool {
		hash := h.New()
		hash.Write(m)
		hashed := hash.Sum(nil)
		return rsa.VerifyPKCS1v15(k.(*rsa.PublicKey), h, hashed[:], s) == nil
	}
}

// ecdsaSign returns a function that will sign a message with an RSA private key,
// using the given hash function.
//
// http://self-issued.info/docs/draft-ietf-jose-json-web-algorithms-00.html#DefiningECDSA
func ecdsaSign(h crypto.Hash) signFn {
	return func(k interface{}, m []byte) ([]byte, error) {
		privateKey := k.(*ecdsa.PrivateKey)

		hash := h.New()
		hash.Write(m)
		hashed := hash.Sum(nil)

		r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed[:])
		if err != nil {
			return nil, err
		}

		rBytes := pad(r.Bytes(), 32)
		sBytes := pad(s.Bytes(), 32)

		sig := append(rBytes, sBytes...)

		return sig, nil
	}
}

// pad left pads the byte array with 0's until b is of length l.
func pad(b []byte, l int) []byte {
	r := l - len(b)
	p := bytes.Repeat([]byte{0}, r)
	return append(p, b...)
}

// ecdsaVerify returns a function that will verify that a message was signed with
// an ECDSA private key.
func ecdsaVerify(h crypto.Hash) verifyFn {
	return func(k interface{}, m []byte, sig []byte) bool {
		if len(sig) != 64 {
			return false
		}

		hash := h.New()
		hash.Write(m)
		hashed := hash.Sum(nil)

		r := new(big.Int)
		s := new(big.Int)
		l := len(sig) / 2

		r.SetBytes(sig[0:l])
		s.SetBytes(sig[l:])

		return ecdsa.Verify(k.(*ecdsa.PublicKey), hashed[:], r, s)
	}
}
