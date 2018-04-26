package httpsignatures

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	// HMAC
	TEST_SIGNATURE_HMAC_SHA256 = `keyId="Test",algorithm="hmac-sha256",signature="JldXnt8W9t643M2Sce10gqCh/+E7QIYLiI+bSjnFBGCti7s+mPPvOjVb72sbd1FjeOUwPTDpKbrQQORrm+xBYfAwCxF3LBSSzORvyJ5nRFCFxfJ3nlQD6Kdxhw8wrVZX5nSem4A/W3C8qH5uhFTRwF4ruRjh+ENHWuovPgO/HGQ="`
	TEST_HASH_HMAC_SHA256      = `JldXnt8W9t643M2Sce10gqCh/+E7QIYLiI+bSjnFBGCti7s+mPPvOjVb72sbd1FjeOUwPTDpKbrQQORrm+xBYfAwCxF3LBSSzORvyJ5nRFCFxfJ3nlQD6Kdxhw8wrVZX5nSem4A/W3C8qH5uhFTRwF4ruRjh+ENHWuovPgO/HGQ=`
	TEST_KEY_HMAC              = "SomethingRandom"

	// RSA
	TEST_SIGNATURE_RSA_SHA256 = `keyId="Test",algorithm="rsa-sha256",signature="jKyvPcxB4JbmYY4mByyBY7cZfNl4OW9HpFQlG7N4YcJPteKTu4MWCLyk+gIr0wDgqtLWf9NLpMAMimdfsH7FSWGfbMFSrsVTHNTk0rK3usrfFnti1dxsM4jl0kYJCKTGI/UWkqiaxwNiKqGcdlEDrTcUhhsFsOIo8VhddmZTZ8w="`
	TEST_HASH_RSA_SHA256      = `jKyvPcxB4JbmYY4mByyBY7cZfNl4OW9HpFQlG7N4YcJPteKTu4MWCLyk+gIr0wDgqtLWf9NLpMAMimdfsH7FSWGfbMFSrsVTHNTk0rK3usrfFnti1dxsM4jl0kYJCKTGI/UWkqiaxwNiKqGcdlEDrTcUhhsFsOIo8VhddmZTZ8w=`
	TEST_PRIVATE_KEY          = `-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F
UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB
AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA
QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK
kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg
f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u
412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc
mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7
kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA
gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW
G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI
7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==
-----END RSA PRIVATE KEY-----`
	TEST_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
oYi+1hqp1fIekaxsyQIDAQAB
-----END PUBLIC KEY-----`

	TEST_DATE   = "Thu, 05 Jan 2012 21:31:40 GMT"
	TEST_KEY_ID = "Test"
)

func TestCreateSignatureFromAuthorizationHeader(t *testing.T) {
	r := http.Request{
		Header: http.Header{
			"Date":              []string{TEST_DATE},
			headerAuthorization: []string{authScheme + TEST_SIGNATURE_HMAC_SHA256},
		},
	}

	s, err := FromRequest(&r)
	assert.Nil(t, err)

	assert.Equal(t, "Test", s.KeyID)
	assert.Equal(t, AlgorithmHmacSha256, s.Algorithm)
	assert.Equal(t, TEST_HASH_HMAC_SHA256, s.Signature)

	assert.Equal(t, s.String(), TEST_SIGNATURE_HMAC_SHA256)
}

func TestCreateSignatureFromSignatureHeaderHeader(t *testing.T) {
	r := http.Request{
		Header: http.Header{
			"Date":          []string{TEST_DATE},
			headerSignature: []string{TEST_SIGNATURE_HMAC_SHA256},
		},
	}

	s, err := FromRequest(&r)
	assert.Nil(t, err)

	assert.Equal(t, "Test", s.KeyID)
	assert.Equal(t, AlgorithmHmacSha256, s.Algorithm)
	assert.Equal(t, TEST_HASH_HMAC_SHA256, s.Signature)

	assert.Equal(t, s.String(), TEST_SIGNATURE_HMAC_SHA256)
}

func TestCreateSignatureWithNoSignature(t *testing.T) {
	r := http.Request{
		Header: http.Header{
			"Date": []string{TEST_DATE},
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

func TestValidRequestIsValid_HmacSha256(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{TEST_DATE},
		},
	}
	err := DefaultSha256Signer.SignRequest(TEST_KEY_ID, TEST_KEY_HMAC, r)
	assert.Nil(t, err)

	sig, err := FromRequest(r)
	assert.Nil(t, err)

	assert.True(t, sig.IsValid(TEST_KEY_HMAC, r))
}

func TestValidRequestIsValid_RsaSha256(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{TEST_DATE},
		},
	}

	block, _ := pem.Decode([]byte(TEST_PRIVATE_KEY))
	privateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	err := DefaultRsaSha256Signer.SignRequestRSA(TEST_KEY_ID, privateKey, r)
	assert.Nil(t, err)

	sig, err := FromRequest(r)
	assert.Nil(t, err)

	assert.True(t, sig.IsValidRSA(&privateKey.PublicKey, r))
}

func TestValidRequestIsValid_EcdsaSha256(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{TEST_DATE},
		},
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	err = DefaultEcdsaSha256Signer.SignRequestECDSA(TEST_KEY_ID, privateKey, r)
	assert.Nil(t, err)

	sig, err := FromRequest(r)
	assert.Nil(t, err)

	assert.True(t, sig.IsValidECDSA(&privateKey.PublicKey, r))
}

func TestNotValidIfRequestHeadersChange(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{TEST_DATE},
		},
	}
	err := DefaultSha256Signer.SignRequest(TEST_KEY_ID, TEST_KEY_HMAC, r)
	assert.Nil(t, err)

	r.Header.Set("Date", "Thu, 05 Jan 2012 21:31:41 GMT")
	sig, err := FromRequest(r)
	assert.Nil(t, err)

	assert.False(t, sig.IsValid(TEST_KEY_HMAC, r))
}

func TestNotValidIfRequestIsMissingDate(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{TEST_DATE},
		},
	}

	s := Signer{AlgorithmHmacSha1, HeaderList{RequestTarget}}

	err := s.SignRequest(TEST_KEY_ID, TEST_KEY_HMAC, r)
	assert.Nil(t, err)

	sig, err := FromRequest(r)
	assert.Nil(t, err)

	assert.False(t, sig.IsValid(TEST_KEY_HMAC, r))
}
