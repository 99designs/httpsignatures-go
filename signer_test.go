package httpsignatures

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
	"time"
)

var (
	defaultKeyLookup = func(keyId string) string {
		return testKey
	}

	// DefaultSha1Signer will sign requests with date using the SHA1 algorithm.
	// Users are encouraged to create their own signer with the headers they require.
	DefaultSha1Signer = NewSigner(testKeyID, defaultKeyLookup, "hmac-sha1")

	// DefaultSha256Signer will sign requests with date using the SHA256 algorithm.
	// Users are encouraged to create their own signer with the headers they require.
	DefaultSha256Signer = NewSigner(testKeyID, defaultKeyLookup, "hmac-sha256")
)

const (
	testSignature  = `keyId="Test",algorithm="hmac-sha256",signature="QgoCZTOayhvFBl1QLXmFOZIVMXC0Dujs5ODsYVruDPI="`
	testSha256Hash = `QgoCZTOayhvFBl1QLXmFOZIVMXC0Dujs5ODsYVruDPI=`
	testSha1Hash   = `06tbjUif0/069JeDM7gWFUOjz04=`
	testKey        = "U29tZXRoaW5nUmFuZG9t"
	testDate       = "Thu, 05 Jan 2012 21:31:40 GMT"
	testKeyID      = "Test"

	ed25519TestSignature = "yK9kWXAdp40MJzmjZnXhJcRaCClqgf9VpLrBUqCG6ywv85gCc0t4w/anI6zp5txyC13ICWMtNU22b+6AO1IQAA=="
)

// Signing

func TestSignSha1(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{"Thu, 05 Jan 2012 21:31:40 GMT"},
		},
	}

	// SignRequest places Signature header in request
	err := DefaultSha1Signer.SignRequest(r)
	assert.Nil(t, err)

	// Read Signature header from request and verify fields
	var s SignatureParameters
	err = s.FromRequest(r)
	assert.Nil(t, err)
	assert.Equal(t, testKeyID, s.KeyID)
	assert.Equal(t, algorithmHmacSha1, s.Algorithm)
	assert.Equal(t, HeaderList{"date": "Thu, 05 Jan 2012 21:31:40 GMT"}, s.Headers)
	assert.Equal(t,
		"06tbjUif0/069JeDM7gWFUOjz04=",
		s.Signature,
	)
}

func TestSignSha256(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{"Thu, 05 Jan 2012 21:31:40 GMT"},
		},
	}

	// SignRequest places Signature header in request
	err := DefaultSha256Signer.SignRequest(r)
	assert.Nil(t, err)

	// Read Signature header from request and verify fields
	var s SignatureParameters
	err = s.FromRequest(r)
	assert.Nil(t, err)
	assert.Equal(t, testKeyID, s.KeyID)
	assert.Equal(t, algorithmHmacSha256, s.Algorithm)
	assert.Equal(t, HeaderList{"date": "Thu, 05 Jan 2012 21:31:40 GMT"}, s.Headers)
	assert.Equal(t,
		"QgoCZTOayhvFBl1QLXmFOZIVMXC0Dujs5ODsYVruDPI=",
		s.Signature,
	)
}

func TestValidEd25119RequestIsValid(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{"Thu, 05 Jan 2012 21:31:40 GMT"},
		},
	}

	// SignRequest places Signature header in request
	keyLookUp := func(keyId string) string {
		return ed25519TestPrivateKey
	}
	signer := NewSigner(ed25519TestPublicKey, keyLookUp, "ed25519")
	err := signer.SignRequest(r)
	assert.Nil(t, err)

	// Read Signature header from request and verify fields
	var s SignatureParameters
	err = s.FromRequest(r)
	assert.Nil(t, err)
	assert.Equal(t, ed25519TestPublicKey, s.KeyID)
	assert.Equal(t, algorithmEd25519, s.Algorithm)
	assert.Equal(t, HeaderList{"date": "Thu, 05 Jan 2012 21:31:40 GMT"}, s.Headers)
	assert.Equal(t,
		ed25519TestSignature,
		s.Signature,
	)
}

func TestSignSha256OmitHeaderLeadingTrailingWhitespace(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{"          Thu, 05 Jan 2012 21:31:40 GMT         "},
		},
	}

	// SignRequest places Signature header in request
	err := DefaultSha256Signer.SignRequest(r)
	assert.Nil(t, err)

	// Read Signature header from request and verify fields
	var s SignatureParameters
	err = s.FromRequest(r)
	assert.Nil(t, err)
	assert.Equal(t, HeaderList{"date": "Thu, 05 Jan 2012 21:31:40 GMT"}, s.Headers)
	assert.Equal(t,
		"QgoCZTOayhvFBl1QLXmFOZIVMXC0Dujs5ODsYVruDPI=",
		s.Signature,
	)
}

func TestSignSha256DoubleHeaderField(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Cache-Control": []string{"max-age=60", "must-revalidate"},
			"Date":          []string{"Thu, 05 Jan 2012 21:31:40 GMT"},
		},
	}

	// SignRequest places Signature header in request
	signer := NewSigner(testKeyID, defaultKeyLookup, "hmac-sha256", "cache-control", "date")
	err := signer.SignRequest(r)
	assert.Nil(t, err)

	// Read Signature header from request and verify fields
	var s SignatureParameters
	err = s.FromRequest(r)
	assert.Nil(t, err)
	assert.Equal(t, HeaderList{"date": "Thu, 05 Jan 2012 21:31:40 GMT",
		"cache-control": "max-age=60, must-revalidate"}, s.Headers)
}

func TestSignWithMissingDateHeader(t *testing.T) {
	r := &http.Request{
		Header: http.Header{},
	}

	err := DefaultSha1Signer.AuthRequest(r)
	assert.EqualError(t, err, `Missing required header 'date'`)
}

func TestSignWithMissingHeader(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{"Thu, 05 Jan 2012 21:31:40 GMT"},
		},
	}

	s := NewSigner(testKeyID, defaultKeyLookup, "hmac-sha1", "foo")

	err := s.SignRequest(r)
	assert.Equal(t, "Missing required header 'foo'", err.Error())
}

// Verifying
func TestValidRequestIsValid(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{testDate},
		},
	}
	err := DefaultSha256Signer.SignRequest(r)
	assert.Nil(t, err)

	var s SignatureParameters
	err = s.FromRequest(r)
	assert.Nil(t, err)

	res, err := s.Verify(testKey)
	assert.True(t, res)
	assert.Nil(t, err)
}

func TestNotValidIfRequestHeadersChange(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{testDate},
		},
	}
	err := DefaultSha256Signer.SignRequest(r)
	assert.Nil(t, err)

	r.Header.Set("Date", "Thu, 05 Jan 2012 21:31:41 GMT")
	var s SignatureParameters
	err = s.FromRequest(r)
	assert.Nil(t, err)

	res, err := s.Verify(testKey)
	assert.False(t, res)
	assert.Nil(t, err)
}

func TestNotValidIfClockSkewExceeded(t *testing.T) {
	allowedClockSkew := 300
	duration, err := time.ParseDuration(fmt.Sprintf("-%ds", allowedClockSkew))
	assert.Nil(t, err)
	r := &http.Request{
		Header: http.Header{
			"Date": []string{time.Now().Add(duration).Format(time.RFC1123)},
		},
	}
	err = DefaultSha256Signer.SignRequest(r)
	assert.Nil(t, err)

	_, err = VerifyRequest(r, defaultKeyLookup, allowedClockSkew)
	assert.Nil(t, err)

	_, err = VerifyRequest(r, defaultKeyLookup, allowedClockSkew-1)
	assert.EqualError(t, err, "Allowed clockskew exceeded")

	_, err = VerifyRequest(r, defaultKeyLookup, 0)
	assert.EqualError(t, err, "You probably misconfigured allowedClockSkew, set to -1 to disable")
}

func TestVerifyRequiredHeaderList(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{time.Now().Format(time.RFC1123)},
		},
	}
	err := DefaultSha256Signer.SignRequest(r)
	assert.Nil(t, err)

	_, err = VerifyRequest(r, defaultKeyLookup, -1, "(request-target)")
	assert.EqualError(t, err, "Required header not in header list")

	_, err = VerifyRequest(r, defaultKeyLookup, -1, "date")
	assert.Nil(t, err)
}
