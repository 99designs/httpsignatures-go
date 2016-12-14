package httpsignatures

// import (
// 	"github.com/stretchr/testify/assert"
// 	"net/http"
// 	"testing"
// )

const (
	testSignature = `keyId="Test",algorithm="hmac-sha256",signature="QgoCZTOayhvFBl1QLXmFOZIVMXC0Dujs5ODsYVruDPI="`
	testHash      = `QgoCZTOayhvFBl1QLXmFOZIVMXC0Dujs5ODsYVruDPI=`
	testKey       = "U29tZXRoaW5nUmFuZG9t"
	testDate      = "Thu, 05 Jan 2012 21:31:40 GMT"
	testKeyID     = "Test"
)

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
