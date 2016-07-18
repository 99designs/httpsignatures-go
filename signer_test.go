package httpsignatures_test

import (
	"net/http"
	"testing"

	"github.com/99designs/httpsignatures-go"
	"github.com/stretchr/testify/assert"
)

func Example_signing() {
	r, _ := http.NewRequest("GET", "http://example.com/some-api", nil)

	// Sign using the 'Signature' header
	httpsignatures.DefaultSha256Signer.SignRequest("KeyId", "Key", r)
	// OR Sign using the 'Authorization' header
	httpsignatures.DefaultSha256Signer.AuthRequest("KeyId", "Key", r)

	http.DefaultClient.Do(r)
}

func TestSignSha1(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{"Thu, 05 Jan 2012 21:31:40 GMT"},
		},
	}

	err := httpsignatures.DefaultSha1Signer.SignRequest(TEST_KEY_ID, TEST_KEY, r)
	assert.Nil(t, err)

	s, err := httpsignatures.NewSignatureFromRequest(r)
	assert.Nil(t, err)

	assert.Equal(t, TEST_KEY_ID, s.KeyID)
	assert.Equal(t, httpsignatures.DefaultSha1Signer.Algorithm, s.Algorithm)
	assert.Equal(t, httpsignatures.DefaultSha1Signer.Headers, s.Headers)

	assert.Equal(t,
		"RIdBXxLb6gWsu3bZtq3rQWSR1nk=",
		s.Signature,
	)
}

func TestSignSha256(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{"Thu, 05 Jan 2012 21:31:40 GMT"},
		},
	}

	err := httpsignatures.DefaultSha256Signer.SignRequest(TEST_KEY_ID, TEST_KEY, r)
	assert.Nil(t, err)

	s, err := httpsignatures.NewSignatureFromRequest(r)
	assert.Nil(t, err)

	assert.Equal(t, TEST_KEY_ID, s.KeyID)
	assert.Equal(t, httpsignatures.DefaultSha256Signer.Algorithm, s.Algorithm)
	assert.Equal(t, httpsignatures.DefaultSha256Signer.Headers, s.Headers)

	assert.Equal(t,
		"mIX1nFtRDhvv8HIUSNpE3NQZZ6EIY98ObNkJM+Oq7AU=",
		s.Signature,
	)
}

func TestSignWithMissingDateHeader(t *testing.T) {
	r := &http.Request{Header: http.Header{}}

	err := httpsignatures.DefaultSha1Signer.AuthRequest(TEST_KEY_ID, TEST_KEY, r)
	assert.Nil(t, err)

	assert.NotEqual(t, "", r.Header.Get("date"))
}

func TestSignWithMissingHeader(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{"Thu, 05 Jan 2012 21:31:40 GMT"},
		},
	}

	s := httpsignatures.Signer{httpsignatures.ALGORITHM_HMAC_SHA1, httpsignatures.HeaderList{"foo"}}

	err := s.SignRequest(TEST_KEY_ID, TEST_KEY, r)
	assert.Equal(t, "Missing required header 'foo'", err.Error())
}
