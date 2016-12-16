package httpsignatures

import (
	"errors"

	ed25519 "github.com/agl/ed25519"
)

// Ed25519Sign signs the message with the ed25519 ECDSA using the private Key
func Ed25519Sign(privateKey *[]byte, message []byte) (*[]byte, error) {
	var pKey [ed25519.PrivateKeySize]byte
	var libSig *[ed25519.SignatureSize]byte
	copy(pKey[:], *privateKey)
	libSig = ed25519.Sign(&pKey, message)
	sig := make([]byte, len(libSig))
	copy(sig, (*libSig)[:])
	return &sig, nil
}

// Ed25519Verify verifies the message with the ed25519 ECDSA using the public Key
func Ed25519Verify(publicKey *[]byte, message []byte, signature *[]byte) (bool, error) {
	var pubKey [ed25519.PublicKeySize]byte
	copy(pubKey[:], *publicKey)
	var sig [ed25519.SignatureSize]byte
	copy(sig[:], *signature)
	if ed25519.Verify(&pubKey, message, &sig) {
		return true, nil
	} else {
		return false, errors.New(ErrorSignatureDdoNotMatch)
	}
}
