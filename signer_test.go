package httpsignatures

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSignHmacSha1(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{"Thu, 05 Jan 2012 21:31:40 GMT"},
		},
	}

	err := DefaultSha1Signer.SignRequest(TEST_KEY_ID, TEST_KEY_HMAC, r)
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

	err := DefaultSha256Signer.SignRequest(TEST_KEY_ID, TEST_KEY_HMAC, r)
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

	block, _ := pem.Decode([]byte(TEST_PRIVATE_KEY))
	privateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	err := DefaultRsaSha1Signer.SignRequestRSA(TEST_KEY_ID, privateKey, r)
	assert.Nil(t, err)

	s, err := FromRequest(r)
	assert.Nil(t, err)

	assert.Equal(t, TEST_KEY_ID, s.KeyID)

	assert.Equal(t,
		"KcypPq/UJBlvY9WR/zb6pGS2vkhlzKX1OUjtImOG8d4CynptmMxXWuzi3LeJW8jOnEmjC00Ga2tOruaSDo8MuDlXEy7JrYIqqD39XYKt5pFQ7dScpZARIrQ4H0n8bn4uIQFLMxkNt2aeuDogyUPcRMxBr6mVe0OHw8MY1y5xdpQ=",
		s.Signature,
	)
}

func TestSignRsaSha256(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{"Thu, 05 Jan 2012 21:31:40 GMT"},
		},
	}

	block, _ := pem.Decode([]byte(TEST_PRIVATE_KEY))
	privateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	err := DefaultRsaSha256Signer.SignRequestRSA(TEST_KEY_ID, privateKey, r)
	assert.Nil(t, err)

	s, err := FromRequest(r)
	assert.Nil(t, err)

	assert.Equal(t, TEST_KEY_ID, s.KeyID)

	assert.Equal(t,
		"TQZq1wGaOdAT3kiSOUq29jh6UG0DgZH2TW6aHYVNrHwKiACi1b9U58la/0SeDqEt6mKe836tHVKXouzNM5LaRiXWW13lZstdg/rXYxZ6N46jZKwVKRXcw9sc6/nZfjnDsxWs6/Zi4Si8hdEZx4CczUjPWBGDi+EaY+PPyZWSibs=",
		s.Signature,
	)
}

// Tests conformance with the test cases provided in the RFC document.
func TestSignRsaSha256_RFC(t *testing.T) {
	block, _ := pem.Decode([]byte(TEST_PRIVATE_KEY))
	privateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	tests := []struct {
		signer    *Signer
		signature string
	}{
		// https://tools.ietf.org/html/draft-cavage-http-signatures-08#appendix-C.1
		{
			NewSigner(AlgorithmRsaSha256, "date"),
			"jKyvPcxB4JbmYY4mByyBY7cZfNl4OW9HpFQlG7N4YcJPteKTu4MWCLyk+gIr0wDgqtLWf9NLpMAMimdfsH7FSWGfbMFSrsVTHNTk0rK3usrfFnti1dxsM4jl0kYJCKTGI/UWkqiaxwNiKqGcdlEDrTcUhhsFsOIo8VhddmZTZ8w=",
		},

		// https://tools.ietf.org/html/draft-cavage-http-signatures-08#appendix-C.2
		{
			NewSigner(AlgorithmRsaSha256, RequestTarget, "host", "date"),
			"HUxc9BS3P/kPhSmJo+0pQ4IsCo007vkv6bUm4Qehrx+B1Eo4Mq5/6KylET72ZpMUS80XvjlOPjKzxfeTQj4DiKbAzwJAb4HX3qX6obQTa00/qPDXlMepD2JtTw33yNnm/0xV7fQuvILN/ys+378Ysi082+4xBQFwvhNvSoVsGv4=",
		},

		// https://tools.ietf.org/html/draft-cavage-http-signatures-08#appendix-C.3
		{
			NewSigner(AlgorithmRsaSha256, RequestTarget, "host", "date", "content-type", "digest", "content-length"),
			"Ef7MlxLXoBovhil3AlyjtBwAL9g4TN3tibLj7uuNB3CROat/9KaeQ4hW2NiJ+pZ6HQEOx9vYZAyi+7cmIkmJszJCut5kQLAwuX+Ms/mUFvpKlSo9StS2bMXDBNjOh4Auj774GFj4gwjS+3NhFeoqyr/MuN6HsEnkvn6zdgfE2i0=",
		},
	}

	for _, tt := range tests {
		r := newRFCRequest()

		err := tt.signer.SignRequestRSA(TEST_KEY_ID, privateKey, r)
		assert.Nil(t, err)

		s, err := FromRequest(r)
		assert.Nil(t, err)

		assert.Equal(t, TEST_KEY_ID, s.KeyID)

		assert.Equal(t,
			tt.signature,
			s.Signature,
		)
	}
}

func TestSignWithMissingDateHeader(t *testing.T) {
	r := &http.Request{Header: http.Header{}}

	err := DefaultSha1Signer.AuthRequest(TEST_KEY_ID, TEST_KEY_HMAC, r)
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

	err := s.SignRequest(TEST_KEY_ID, TEST_KEY_HMAC, r)
	assert.Equal(t, "Missing required header 'foo'", err.Error())
}

// newRFCRequest generates an http.Request that matches the test request in the
// RFC https://tools.ietf.org/html/draft-cavage-http-signatures-08#appendix-C
func newRFCRequest() *http.Request {
	r, _ := http.NewRequest("POST", "/foo?param=value&pet=dog", strings.NewReader(`{"hello": "world"}`))
	r.Header.Set("Host", "example.com")
	// The date in the RFC is wrong (2014 instead of 2012).
	//
	// See https://goo.gl/QrvrTE
	r.Header.Set("Date", "Thu, 05 Jan 2014 21:31:40 GMT")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=")
	r.Header.Set("Content-Length", "18")
	return r
}
