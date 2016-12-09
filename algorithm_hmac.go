package httpsignatures

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"hash"
)

const (
	Hmac1SignatureSize   = 20
	Hmac256SignatureSize = 32
)

func Hmac1Sign(privateKey *[]byte, message []byte) (*[]byte, error) {
	return Sign(privateKey, message, sha1.New, Hmac1SignatureSize)
}

func Hmac256Sign(privateKey *[]byte, message []byte) (*[]byte, error) {
	return Sign(privateKey, message, sha256.New, Hmac256SignatureSize)
}

func Hmac1Verify(privateKey *[]byte, message []byte, sig *[]byte) (bool, error) {
	return Verify(privateKey, message, sha1.New, sig, Hmac1SignatureSize)
}

func Hmac256Verify(privateKey *[]byte, message []byte, sig *[]byte) (bool, error) {
	return Verify(privateKey, message, sha256.New, sig, Hmac256SignatureSize)
}

func Sign(privateKey *[]byte, message []byte, hashFunc func() hash.Hash, signatureSize int) (*[]byte, error) {
	hash := hmac.New(hashFunc, *privateKey)
	hash.Write(message)

	signature := make([]byte, signatureSize)
	copy(signature[:], hash.Sum(nil))
	return &signature, nil
}

func Verify(privateKey *[]byte, message []byte, hashFunc func() hash.Hash, sig *[]byte, signatureSize int) (bool, error) {
	calcSign, err := Sign(privateKey, message, hashFunc, signatureSize)
	if err != nil {
		return false, err
	}

	return bytes.Equal(*calcSign, *sig), err
}
