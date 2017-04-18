package httpsignatures

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSignHmacSha1(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{"Thu, 05 Jan 2012 21:31:40 GMT"},
		},
	}

	err := DefaultSha1Signer.SignRequest(TEST_KEY_ID, TEST_KEY, r)
	assert.Nil(t, err)

	s, err := FromRequest(r)
	assert.Nil(t, err)

	assert.Equal(t, TEST_KEY_ID, s.KeyID)
	assert.Equal(t, DefaultSha1Signer.algorithm, s.Algorithm)
	assert.Equal(t, DefaultSha1Signer.headers, s.Headers)

	assert.Equal(t,
		"RIdBXxLb6gWsu3bZtq3rQWSR1nk=",
		s.Signature,
	)
}

func TestSignHmacSha256(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{"Thu, 05 Jan 2012 21:31:40 GMT"},
		},
	}

	err := DefaultSha256Signer.SignRequest(TEST_KEY_ID, TEST_KEY, r)
	assert.Nil(t, err)

	s, err := FromRequest(r)
	assert.Nil(t, err)

	assert.Equal(t, TEST_KEY_ID, s.KeyID)
	assert.Equal(t, DefaultSha256Signer.algorithm, s.Algorithm)
	assert.Equal(t, DefaultSha256Signer.headers, s.Headers)

	assert.Equal(t,
		"mIX1nFtRDhvv8HIUSNpE3NQZZ6EIY98ObNkJM+Oq7AU=",
		s.Signature,
	)
}

func TestSignRsaSha1(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{"Thu, 05 Jan 2012 21:31:40 GMT"},
		},
	}

	err := DefaultRsaSha1Signer.SignRequest(TEST_KEY_ID, RSA_TEST_KEY, r)
	assert.Nil(t, err)

	s, err := FromRequest(r)
	assert.Nil(t, err)

	assert.Equal(t, TEST_KEY_ID, s.KeyID)
	assert.Equal(t, DefaultRsaSha1Signer.algorithm, s.Algorithm)
	assert.Equal(t, DefaultRsaSha1Signer.headers, s.Headers)

	assert.Equal(t,
		"GvZYUHYZQJ3aYh9FulOG2TQj10ix3wWZ08bXbIxkPXrxDkW55b7yZSbY38HxzLMA9+Nso4xuduQi0eJSDZxadCOs8GHEV/hXyVVX1xUF4Yw8tiWYeu8bRkdWworRP5/L+Xl3g7AFwfKPRWWe6MlY7Vqi8oxt2q2rd3Z+35q4LWDgcvblu0Q5mv8IbtfTP0Z4ncwnQRWRGoe8nVP1v66Thook68eNHszmPRINgTrSDwQbl5jQWvkQv0vznBlj9yxGa3XVO+CoL5r896YrMTrE8JRhj7NHZ1vqOZUIRIK6xgfzjWz0geTUrXS/WIT3hvHLPBMzE8TGaZtlVGycMzD/9g==",
		s.Signature,
	)
}

func TestSignRsaSha256(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{"Thu, 05 Jan 2012 21:31:40 GMT"},
		},
	}

	err := DefaultRsaSha256Signer.SignRequest(TEST_KEY_ID, RSA_TEST_KEY, r)
	assert.Nil(t, err)

	s, err := FromRequest(r)
	assert.Nil(t, err)

	assert.Equal(t, TEST_KEY_ID, s.KeyID)
	assert.Equal(t, DefaultRsaSha256Signer.algorithm, s.Algorithm)
	assert.Equal(t, DefaultRsaSha256Signer.headers, s.Headers)

	assert.Equal(t,
		"eVyldHIP+4DotKk28VzSXv7q9ZK0HHcTorxHr0aBsyKYElOUMbISOLbaEOJrOsycH7d7NYr3J985ugGOx5mDzamDy3LyjpCK63tZkawqxdEJA2YZE4Ccu1zX8mlutHCMId6/hM8t4tW86La0lxPo6v7Q9mxwkbZn22lVy4qfjOVEiUrSN6phFIWhwi5/3AhhiMtqnD0Lm3iQDB1YKKBCUPmdrC8PTZGTIha3c7NRRnyVxqOUt16EzHDA8QEZ7TmxnIfv3+v5/sC4mCgW8cW/lo3uiBlCF8mtV6MW7H1NIiGcLrHmCA4PaxoSCLHAZRqKlzvA7/TbffG9T8/JOR3hVg==",
		s.Signature,
	)
}

func TestSignWithMissingDateHeader(t *testing.T) {
	r := &http.Request{Header: http.Header{}}

	err := DefaultSha1Signer.AuthRequest(TEST_KEY_ID, TEST_KEY, r)
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

	err := s.SignRequest(TEST_KEY_ID, TEST_KEY, r)
	assert.Equal(t, "Missing required header 'foo'", err.Error())
}
