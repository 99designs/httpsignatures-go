package httpsignatures

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSignSha1(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{"Thu, 05 Jan 2012 21:31:40 GMT"},
		},
	}

	err := DefaultSha1Signer.SignRequest(testKeyID, testKey, r)
	assert.Nil(t, err)

	var v VerificationParameters
	err = v.FromRequest(r)
	assert.Nil(t, err)

	assert.Equal(t, testKeyID, v.SigParams.KeyID)
	assert.Equal(t, DefaultSha1Signer.algorithm, v.SigParams.Algorithm)
	assert.Equal(t, DefaultSha1Signer.headers, v.SigParams.Headers)

	assert.Equal(t,
		"RIdBXxLb6gWsu3bZtq3rQWSR1nk=",
		v.Signature,
	)
}

func TestSignSha256(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{"Thu, 05 Jan 2012 21:31:40 GMT"},
		},
	}

	err := DefaultSha256Signer.SignRequest(testKeyID, testKey, r)
	assert.Nil(t, err)

	var v VerificationParameters
	err = v.FromRequest(r)
	assert.Nil(t, err)

	assert.Equal(t, testKeyID, v.SigParams.KeyID)
	assert.Equal(t, DefaultSha256Signer.algorithm, v.SigParams.Algorithm)
	assert.Equal(t, DefaultSha256Signer.headers, v.SigParams.Headers)

	assert.Equal(t,
		"mIX1nFtRDhvv8HIUSNpE3NQZZ6EIY98ObNkJM+Oq7AU=",
		v.Signature,
	)
}

func TestSignEd25519(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{"Thu, 05 Jan 2012 21:31:40 GMT"},
		},
	}

	err := DefaultEd25519Signer.SignRequest(testKeyID, testEd25519PrivateKey, r)
	assert.Nil(t, err)

	s, err := FromRequest(r)
	assert.Nil(t, err)

	assert.Equal(t, testKeyID, s.KeyID)
	assert.Equal(t, DefaultEd25519Signer.algorithm, s.Algorithm)
	assert.Equal(t, DefaultEd25519Signer.headers, s.Headers)

	assert.Equal(t,
		ed25519TestSignature,
		s.Signature,
	)
}

func TestSignWithMissingDateHeader(t *testing.T) {
	r := &http.Request{Header: http.Header{}}

	err := DefaultSha1Signer.AuthRequest(testKeyID, testKey, r)
	assert.Nil(t, err)

	assert.NotEqual(t, "", r.Header.Get("date"))
}

func TestSignWithMissingHeader(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{"Thu, 05 Jan 2012 21:31:40 GMT"},
		},
	}

	s := NewSigner(AlgorithmHmacSha1, "foo")

	err := s.SignRequest(testKeyID, testKey, r)
	assert.Equal(t, "Missing required header 'foo'", err.Error())
}
