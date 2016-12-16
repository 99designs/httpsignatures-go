package httpsignatures

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"hash"

	"errors"
)

const (
	hmac1SignatureSize   = 20
	hmac256SignatureSize = 32
)

func Hmac1Sign(privateKey *[]byte, message []byte) (*[]byte, error) {
	return Sign(privateKey, message, sha1.New, hmac1SignatureSize)
}

func Hmac256Sign(privateKey *[]byte, message []byte) (*[]byte, error) {
	return Sign(privateKey, message, sha256.New, hmac256SignatureSize)
}

func Hmac1Verify(privateKey *[]byte, message []byte, sig *[]byte) (bool, error) {
	return Verify(privateKey, message, sha1.New, sig, hmac1SignatureSize)
}

func Hmac256Verify(privateKey *[]byte, message []byte, sig *[]byte) (bool, error) {
	return Verify(privateKey, message, sha256.New, sig, hmac256SignatureSize)
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

	if bytes.Equal(*calcSign, *sig) {
		return true, nil
	} else {
		return false, errors.New(ErrorSignatureDdoNotMatch)
	}
}
