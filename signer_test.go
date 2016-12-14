package httpsignatures

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
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
	testSignature = `keyId="Test",algorithm="hmac-sha256",signature="QgoCZTOayhvFBl1QLXmFOZIVMXC0Dujs5ODsYVruDPI="`
	testHash      = `QgoCZTOayhvFBl1QLXmFOZIVMXC0Dujs5ODsYVruDPI=`
	testKey       = "U29tZXRoaW5nUmFuZG9t"
	testDate      = "Thu, 05 Jan 2012 21:31:40 GMT"
	testKeyID     = "Test"
)

func TestSignSha1(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{"Thu, 05 Jan 2012 21:31:40 GMT"},
		},
	}

	err := DefaultSha1Signer.SignRequest(r)
	assert.Nil(t, err)

	var s SignatureParameters
	err = s.fromRequest(r)
	assert.Nil(t, err)

	assert.Equal(t, testKeyID, s.KeyID)
	assert.Equal(t, AlgorithmHmacSha1, s.Algorithm)
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

	err := DefaultSha256Signer.SignRequest(r)
	assert.Nil(t, err)

	var s SignatureParameters
	err = s.fromRequest(r)
	assert.Nil(t, err)

	assert.Equal(t, testKeyID, s.KeyID)
	assert.Equal(t, AlgorithmHmacSha256, s.Algorithm)
	assert.Equal(t, HeaderList{"date": "Thu, 05 Jan 2012 21:31:40 GMT"}, s.Headers)

	assert.Equal(t,
		"QgoCZTOayhvFBl1QLXmFOZIVMXC0Dujs5ODsYVruDPI=",
		s.Signature,
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

// Test
// func TestCreateSignatureWithNoSignature(t *testing.T) {
// 	r := http.Request{
// 		Header: http.Header{
// 			"Date": []string{testDate},
// 		},
// 	}

// 	var v VerificationParameters
// 	err := v.FromRequest(&r)
// 	assert.Equal(t, ErrorNoSignatureHeader, err)
// 	sigParam := SignatureParameters{Headers: HeaderList{"date": testDate}}
// 	assert.Equal(t, VerificationParameters{SigParams: &sigParam, Signature: ""}, v)
// 	assert.Equal(t, SignatureParameters{}, v)
// }

// func TestValidRequestIsValid(t *testing.T) {
// 	r := &http.Request{
// 		Header: http.Header{
// 			"Date": []string{testDate},
// 		},
// 	}
// 	err := DefaultSha256Signer.SignRequest(testKeyID, testKey, r)
// 	assert.Nil(t, err)

// 	var s SignatureParameters
// 	err = s.FromRequest(r)
// 	assert.Nil(t, err)

// 	res, err := s.Verify(testKey, r)
// 	assert.True(t, res)
// 	assert.Nil(t, err)
// }

// func TestNotValidIfRequestHeadersChange(t *testing.T) {
// 	r := &http.Request{
// 		Header: http.Header{
// 			"Date": []string{testDate},
// 		},
// 	}
// 	err := DefaultSha256Signer.SignRequest(testKeyID, testKey, r)
// 	assert.Nil(t, err)

// 	r.Header.Set("Date", "Thu, 05 Jan 2012 21:31:41 GMT")
// 	var s SignatureParameters
// 	err = s.FromRequest(r)
// 	assert.Nil(t, err)

// 	res, err := s.Verify(testKey, r)
// 	assert.False(t, res)
// 	assert.Nil(t, err)
// }

// func TestNotValidIfRequestIsMissingDate(t *testing.T) {
// 	r := &http.Request{
// 		Header: http.Header{},
// 	}

// 	signer := Signer{AlgorithmHmacSha1, HeaderList{RequestTarget}}

// 	err := signer.SignRequest(testKeyID, testKey, r)
// 	assert.Nil(t, err)

// 	var signature SignatureParameters
// 	err = signature.FromRequest(r)
// 	assert.Nil(t, err)

// 	res, err := signature.Verify(testKey, r)
// 	assert.False(t, res)
// 	assert.EqualError(t, err, "No Date Header Supplied")
// }

// func TestVerifySignatureFromAuthorizationHeader(t *testing.T) {
// 	r := &http.Request{
// 		Header: http.Header{
// 			"Date":              []string{testDate},
// 			HeaderAuthorization: []string{authScheme + testSignature},
// 		},
// 	}

// 	var s SignatureParameters
// 	err := s.fromRequest(r)
// 	assert.Nil(t, err)
// 	assert.Equal(t, "Test", s.KeyID)
// 	assert.Equal(t, AlgorithmHmacSha256, s.Algorithm)
// 	assert.Equal(t, testHash, s.Signature)

// 	valid, err := s.Verify(testKey, r)
// 	assert.Nil(t, err)
// 	assert.Equal(t, true, valid)
// }

// func TestVerifySignatureFromSignatureHeader(t *testing.T) {
// 	r := http.Request{
// 		Header: http.Header{
// 			"Date":          []string{testDate},
// 			HeaderSignature: []string{testSignature},
// 		},
// 	}

// 	var s SignatureParameters
// 	err := s.fromRequest(&r)
// 	assert.Nil(t, err)

// 	assert.Equal(t, "Test", s.KeyID)
// 	assert.Equal(t, AlgorithmHmacSha256, s.Algorithm)
// 	assert.Equal(t, testHash, s.Signature)

// 	valid, err := s.Verify(testKey, &r)
// 	assert.Nil(t, err)
// 	assert.Equal(t, true, valid)
// }
