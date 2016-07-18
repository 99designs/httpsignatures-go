package httpsignatures

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	TEST_SIGNATURE = `keyId="Test",algorithm="hmac-sha256",signature="JldXnt8W9t643M2Sce10gqCh/+E7QIYLiI+bSjnFBGCti7s+mPPvOjVb72sbd1FjeOUwPTDpKbrQQORrm+xBYfAwCxF3LBSSzORvyJ5nRFCFxfJ3nlQD6Kdxhw8wrVZX5nSem4A/W3C8qH5uhFTRwF4ruRjh+ENHWuovPgO/HGQ="`
	TEST_HASH      = `JldXnt8W9t643M2Sce10gqCh/+E7QIYLiI+bSjnFBGCti7s+mPPvOjVb72sbd1FjeOUwPTDpKbrQQORrm+xBYfAwCxF3LBSSzORvyJ5nRFCFxfJ3nlQD6Kdxhw8wrVZX5nSem4A/W3C8qH5uhFTRwF4ruRjh+ENHWuovPgO/HGQ=`
	TEST_KEY       = "SomethingRandom"
	TEST_DATE      = "Thu, 05 Jan 2012 21:31:40 GMT"
	TEST_KEY_ID    = "Test"
)

func TestCreateSignatureFromAuthorizationHeader(t *testing.T) {
	r := http.Request{
		Header: http.Header{
			"Date":              []string{TEST_DATE},
			headerAuthorization: []string{authScheme + TEST_SIGNATURE},
		},
	}

	s, err := FromRequest(&r)
	assert.Nil(t, err)

	assert.Equal(t, "Test", s.KeyID)
	assert.Equal(t, AlgorithmHmacSha256, s.Algorithm)
	assert.Equal(t, TEST_HASH, s.Signature)

	assert.Equal(t, s.String(), TEST_SIGNATURE)
}

func TestCreateSignatureFromSignatureHeaderHeader(t *testing.T) {
	r := http.Request{
		Header: http.Header{
			"Date":          []string{TEST_DATE},
			headerSignature: []string{TEST_SIGNATURE},
		},
	}

	s, err := FromRequest(&r)
	assert.Nil(t, err)

	assert.Equal(t, "Test", s.KeyID)
	assert.Equal(t, AlgorithmHmacSha256, s.Algorithm)
	assert.Equal(t, TEST_HASH, s.Signature)

	assert.Equal(t, s.String(), TEST_SIGNATURE)
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

func TestValidRequestIsValid(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{TEST_DATE},
		},
	}
	err := DefaultSha256Signer.SignRequest(TEST_KEY_ID, TEST_KEY, r)
	assert.Nil(t, err)

	sig, err := FromRequest(r)
	assert.Nil(t, err)

	assert.True(t, sig.IsValid(TEST_KEY, r))
}

func TestNotValidIfRequestHeadersChange(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{TEST_DATE},
		},
	}
	err := DefaultSha256Signer.SignRequest(TEST_KEY_ID, TEST_KEY, r)
	assert.Nil(t, err)

	r.Header.Set("Date", "Thu, 05 Jan 2012 21:31:41 GMT")
	sig, err := FromRequest(r)
	assert.Nil(t, err)

	assert.False(t, sig.IsValid(TEST_KEY, r))
}

func TestNotValidIfRequestIsMissingDate(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{TEST_DATE},
		},
	}

	s := Signer{AlgorithmHmacSha1, HeaderList{RequestTarget}}

	err := s.SignRequest(TEST_KEY_ID, TEST_KEY, r)
	assert.Nil(t, err)

	sig, err := FromRequest(r)
	assert.Nil(t, err)

	assert.False(t, sig.IsValid(TEST_KEY, r))
}
