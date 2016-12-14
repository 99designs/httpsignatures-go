package httpsignatures

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func TestVerifySignatureFromAuthorizationHeader(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date":              []string{testDate},
			HeaderAuthorization: []string{authScheme + testSignature},
		},
	}

	var s SignatureParameters
	err := s.FromRequest(r)
	assert.Nil(t, err)
	assert.Equal(t, "Test", s.KeyID)
	assert.Equal(t, AlgorithmHmacSha256, s.Algorithm)
	assert.Equal(t, testHash, s.Signature)

	valid, err := s.Verify(testKey, r)
	assert.Nil(t, err)
	assert.Equal(t, true, valid)
}

func TestVerifySignatureFromSignatureHeader(t *testing.T) {
	r := http.Request{
		Header: http.Header{
			"Date":          []string{testDate},
			HeaderSignature: []string{testSignature},
		},
	}

	var s SignatureParameters
	err := s.FromRequest(&r)
	assert.Nil(t, err)

	assert.Equal(t, "Test", s.KeyID)
	assert.Equal(t, AlgorithmHmacSha256, s.Algorithm)
	assert.Equal(t, testHash, s.Signature)

	valid, err := s.Verify(testKey, &r)
	assert.Nil(t, err)
	assert.Equal(t, true, valid)
}
