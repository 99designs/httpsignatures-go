package httpsignatures

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

const (
	testSignature         = `keyId="Test",algorithm="hmac-sha256",signature="JldXnt8W9t643M2Sce10gqCh/+E7QIYLiI+bSjnFBGCti7s+mPPvOjVb72sbd1FjeOUwPTDpKbrQQORrm+xBYfAwCxF3LBSSzORvyJ5nRFCFxfJ3nlQD6Kdxhw8wrVZX5nSem4A/W3C8qH5uhFTRwF4ruRjh+ENHWuovPgO/HGQ="`
	testHash              = `JldXnt8W9t643M2Sce10gqCh/+E7QIYLiI+bSjnFBGCti7s+mPPvOjVb72sbd1FjeOUwPTDpKbrQQORrm+xBYfAwCxF3LBSSzORvyJ5nRFCFxfJ3nlQD6Kdxhw8wrVZX5nSem4A/W3C8qH5uhFTRwF4ruRjh+ENHWuovPgO/HGQ=`
	testKey               = "U29tZXRoaW5nUmFuZG9t"
	testDate              = "Thu, 05 Jan 2012 21:31:40 GMT"
	testKeyID             = "Test"
	testEd25519PrivateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7aie8zrakLWKjqNAqbw1zZTIVdx3iQ6Y6wEihi1naKQ=="
	testEd25519PublicKey  = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="
	ed25519TestSignature  = "ZDU6lMmO4fQp8wWTTviRyywsngZZYbpUVpVRQVwBtp5U/zwsJFm1eLsYxpFnpribcvKvM+nWNKBUKaH+R8RgAw=="
)

func TestCreateSignatureFromAuthorizationHeader(t *testing.T) {
	r := http.Request{
		Header: http.Header{
			"Date":              []string{testDate},
			headerAuthorization: []string{authScheme + testSignature},
		},
	}

	s, err := FromRequest(&r)
	assert.Nil(t, err)

	assert.Equal(t, "Test", s.KeyID)
	assert.Equal(t, AlgorithmHmacSha256, s.Algorithm)
	assert.Equal(t, testHash, s.Signature)

	assert.Equal(t, s.String(), testSignature)
}

func TestCreateSignatureFromSignatureHeaderHeader(t *testing.T) {
	r := http.Request{
		Header: http.Header{
			"Date":          []string{testDate},
			HeaderSignature: []string{testSignature},
		},
	}

	s, err := FromRequest(&r)
	assert.Nil(t, err)

	assert.Equal(t, "Test", s.KeyID)
	assert.Equal(t, AlgorithmHmacSha256, s.Algorithm)
	assert.Equal(t, testHash, s.Signature)

	assert.Equal(t, s.String(), testSignature)
}

func TestCreateSignatureWithNoSignature(t *testing.T) {
	r := http.Request{
		Header: http.Header{
			"Date": []string{testDate},
		},
	}

	s, err := FromRequest(&r)
	assert.Equal(t, ErrorNoSignatureHeader, err)
	assert.Nil(t, s)
}

func TestCreateWithMissingSignature(t *testing.T) {
	s, err := FromString(`keyId="Test",algorithm="hmac-sha256"`)
	assert.Equal(t, "Missing signature", err.Error())
	assert.Nil(t, s)
}

func TestCreateWithMissingAlgorithm(t *testing.T) {
	s, err := FromString(`keyId="Test",signature="fffff"`)
	assert.Equal(t, "Missing algorithm", err.Error())
	assert.Nil(t, s)
}

func TestCreateWithMissingKeyId(t *testing.T) {
	s, err := FromString(`algorithm="hmac-sha256",signature="fffff"`)
	assert.Equal(t, "Missing keyId", err.Error())
	assert.Nil(t, s)
}

func TestCreateWithInvalidKey(t *testing.T) {
	s, err := FromString(`keyId="Test",algorithm="hmac-sha256",signature="fffff",garbage="bob"`)
	assert.Equal(t, "Unexpected key in signature 'garbage'", err.Error())
	assert.Nil(t, s)
}

func TestValidRequestIsValid(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{testDate},
		},
	}
	err := DefaultSha256Signer.SignRequest(testKeyID, testKey, r)
	assert.Nil(t, err)

	sig, err := FromRequest(r)
	assert.Nil(t, err)

	res, err := sig.Verify(testKey, r)
	assert.True(t, res)
	assert.Nil(t, err)
}

func TestValidEd25119RequestIsValid(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{testDate},
		},
	}
	err := DefaultEd25519Signer.SignRequest(testKeyID, testEd25519PrivateKey, r)
	assert.Nil(t, err)

	sig, err := FromRequest(r)
	assert.Nil(t, err)

	res, err := sig.Verify(testEd25519PublicKey, r)
	assert.True(t, res)
	assert.Nil(t, err)
}

func TestNotValidIfRequestHeadersChange(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{testDate},
		},
	}
	err := DefaultSha256Signer.SignRequest(testKeyID, testKey, r)
	assert.Nil(t, err)

	r.Header.Set("Date", "Thu, 05 Jan 2012 21:31:41 GMT")
	sig, err := FromRequest(r)
	assert.Nil(t, err)

	res, err := sig.Verify(testKey, r)
	assert.False(t, res)
	assert.Nil(t, err)
}

func TestNotValidIfRequestIsMissingDate(t *testing.T) {
	r := &http.Request{
		Header: http.Header{},
	}

	s := Signer{AlgorithmHmacSha1, HeaderList{RequestTarget}}

	err := s.SignRequest(testKeyID, testKey, r)
	assert.Nil(t, err)

	sig, err := FromRequest(r)
	assert.Nil(t, err)

	res, err := sig.Verify(testKey, r)
	assert.False(t, res)
	assert.EqualError(t, err, "No Date Header Supplied")
}
