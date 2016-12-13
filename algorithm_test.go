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
)

var (
	TestHmacSha1   = &TestAlgorithmData{"hmac-sha1", hmacKey, hmacKey, hmacSHA1Cypher}
	TestHmacSha256 = &TestAlgorithmData{"hmac-sha256", hmacKey, hmacKey, hmacSHA256Cypher}
)

type TestAlgorithmData struct {
	Name       string
	PublicKey  string
	PrivateKey string
	Cypher     string
}

func getTestAlgorithmDataFromString(name string) (*TestAlgorithmData, error) {
	switch name {
	case TestHmacSha1.Name:
		return TestHmacSha1, nil
	case TestHmacSha256.Name:
		return TestHmacSha256, nil
	}

	return nil, ErrorUnknownAlgorithm
}

// Test
func TestAllAlgorithms(t *testing.T) {
	algorithmList := []string{"hmac-sha1", "hmac-sha256"}

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
