package httpsignatures

import (
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	plainText        = "what do ya want for nothing?"
	hmacKey          = "SmVmZQ=="
	hmacSHA1Cypher   = "7/zfauXrL6LSdBbV8YTfnCWafHk="
	hmacSHA256Cypher = "W9zBRr9gdU5qBCQmCJV1x1oAPwidJzmDnexYuWTsOEM="

	ed25519TestPrivateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7aie8zrakLWKjqNAqbw1zZTIVdx3iQ6Y6wEihi1naKQ=="
	ed25519TestPublicKey  = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="
	ed25519TestCypher     = "NMJEuJZU1b8iKQgS5MeFcTH3rU26gkJEz0l32hYZk0A5m08uprteyphXIk4Gqlf3bYL9dqBQU4Q/8mb82DVeCQ=="
)

var (
	TestHmacSha1   = &TestAlgorithmData{"hmac-sha1", hmacKey, hmacKey, hmacSHA1Cypher}
	TestHmacSha256 = &TestAlgorithmData{"hmac-sha256", hmacKey, hmacKey, hmacSHA256Cypher}
	TestEd25519    = &TestAlgorithmData{"ed25519", ed25519TestPrivateKey, ed25519TestPublicKey, ed25519TestCypher}
)

type TestAlgorithmData struct {
	Name       string
	PrivateKey string
	PublicKey  string
	Cypher     string
}

func getTestAlgorithmDataFromString(name string) (*TestAlgorithmData, error) {
	switch name {
	case TestHmacSha1.Name:
		return TestHmacSha1, nil
	case TestHmacSha256.Name:
		return TestHmacSha256, nil
	case TestEd25519.Name:
		return TestEd25519, nil
	}

	return nil, errorUnknownAlgorithm
}

// Test
func TestAllAlgorithms(t *testing.T) {
	algorithmList := []string{"hmac-sha1", "hmac-sha256", "ed25519"}

	for _, a := range algorithmList {
		algorithm, err := algorithmFromString(a)
		assert.Nil(t, err)

		algData, err := getTestAlgorithmDataFromString(a)
		assert.Nil(t, err)

		privKey, _ := base64.StdEncoding.DecodeString(algData.PrivateKey)
		signature, err := algorithm.Sign(&privKey, ([]byte)(plainText))
		assert.Nil(t, err)

		signatureB64 := base64.StdEncoding.EncodeToString(*signature)
		assert.Equal(t, algData.Cypher, signatureB64)

		pubKey, _ := base64.StdEncoding.DecodeString(algData.PublicKey)
		valid, err := algorithm.Verify(&pubKey, ([]byte)(plainText), signature)
		assert.True(t, valid)
		assert.Nil(t, err)
	}
}
