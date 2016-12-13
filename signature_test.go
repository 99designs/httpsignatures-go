package httpsignatures

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

const (
	testSignature = `keyId="Test",algorithm="hmac-sha256",signature="QgoCZTOayhvFBl1QLXmFOZIVMXC0Dujs5ODsYVruDPI="`
	// testHash      = `JldXnt8W9t643M2Sce10gqCh/+E7QIYLiI+bSjnFBGCti7s+mPPvOjVb72sbd1FjeOUwPTDpKbrQQORrm+xBYfAwCxF3LBSSzORvyJ5nRFCFxfJ3nlQD6Kdxhw8wrVZX5nSem4A/W3C8qH5uhFTRwF4ruRjh+ENHWuovPgO/HGQ=`
	testHash  = `QgoCZTOayhvFBl1QLXmFOZIVMXC0Dujs5ODsYVruDPI=`
	testKey   = "U29tZXRoaW5nUmFuZG9t"
	testDate  = "Thu, 05 Jan 2012 21:31:40 GMT"
	testKeyID = "Test"
)

// Test
func TestVerifySignatureFromAuthorizationHeader(t *testing.T) {

	r := &http.Request{
		Header: http.Header{
			"Date":              []string{testDate},
			HeaderAuthorization: []string{authScheme + testSignature},
		},
	}

	var v VerificationParameters
	err := v.FromRequest(r)
	assert.Nil(t, err)
	assert.Equal(t, "Test", v.SigParams.KeyID)
	assert.Equal(t, AlgorithmHmacSha256, v.SigParams.Algorithm)
	assert.Equal(t, testHash, v.Signature)

	valid, err := v.Verify(testKey, r)
	assert.Nil(t, err)
	assert.Equal(t, true, valid)
}

func TestCreateSignatureFromSignatureHeaderHeader(t *testing.T) {
	r := http.Request{
		Header: http.Header{
			"Date":          []string{testDate},
			HeaderSignature: []string{testSignature},
		},
	}

	var v VerificationParameters
	err := v.FromRequest(&r)
	assert.Nil(t, err)

	assert.Equal(t, "Test", v.SigParams.KeyID)
	assert.Equal(t, AlgorithmHmacSha256, v.SigParams.Algorithm)
	// assert.Equal(t, testHash, v.Signature)

	valid, err := v.Verify(testKey, &r)
	assert.Nil(t, err)
	assert.Equal(t, true, valid)
}

// func TestCreateSignatureWithNoSignature(t *testing.T) {
// 	r := http.Request{
// 		Header: http.Header{
// 			"Date": []string{testDate},
// 		},
// 	}

// 	var s SignatureParameters
// 	err := s.FromRequest(&r)
// 	assert.Equal(t, ErrorNoSignatureHeader, err)
// 	assert.Equal(t, SignatureParameters{}, s)
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
