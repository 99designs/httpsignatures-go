package httpsignatures_test

import (
	"net/http"
	"testing"

	"github.com/99designs/httpsignatures-go"
	"github.com/stretchr/testify/assert"
)

const (
	TEST_SIGNATURE = `keyId="Test",algorithm="rsa-sha256",signature="JldXnt8W9t643M2Sce10gqCh/+E7QIYLiI+bSjnFBGCti7s+mPPvOjVb72sbd1FjeOUwPTDpKbrQQORrm+xBYfAwCxF3LBSSzORvyJ5nRFCFxfJ3nlQD6Kdxhw8wrVZX5nSem4A/W3C8qH5uhFTRwF4ruRjh+ENHWuovPgO/HGQ="`
	TEST_HASH      = `JldXnt8W9t643M2Sce10gqCh/+E7QIYLiI+bSjnFBGCti7s+mPPvOjVb72sbd1FjeOUwPTDpKbrQQORrm+xBYfAwCxF3LBSSzORvyJ5nRFCFxfJ3nlQD6Kdxhw8wrVZX5nSem4A/W3C8qH5uhFTRwF4ruRjh+ENHWuovPgO/HGQ=`
	TEST_KEY       = "SomethingRandom"
	TEST_DATE      = "Thu, 05 Jan 2012 21:31:40 GMT"
	TEST_KEY_ID    = "Test"
)

func Example_verification() {
	_ = func(w http.ResponseWriter, r *http.Request) {
		sig, err := httpsignatures.NewSignatureFromRequest(r)
		if err != nil {
			// Probably a malformed header
			http.Error(w, "Bad Request", http.StatusBadRequest)
			panic(err)
		}

		// if you have headers that must be signed check
		// that they are in sig.Headers

		var key string // = lookup using sig.KeyID
		if !sig.IsValid(key, r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// request was signed correctly.
	}
}

func TestCreateSignatureFromAuthorizationHeader(t *testing.T) {
	r := http.Request{
		Header: http.Header{
			"Date": []string{TEST_DATE},
			httpsignatures.HEADER_AUTHORIZATION: []string{httpsignatures.AUTH_SCHEME + TEST_SIGNATURE},
		},
	}

	s, err := httpsignatures.NewSignatureFromRequest(&r)
	assert.Nil(t, err)

	assert.Equal(t, "Test", s.KeyID)
	assert.Equal(t, "rsa-sha256", s.Algorithm)
	assert.Equal(t, TEST_HASH, s.Signature)

	assert.Equal(t, s.ToString(), TEST_SIGNATURE)
}

func TestCreateSignatureFromSignatureHeaderHeader(t *testing.T) {
	r := http.Request{
		Header: http.Header{
			"Date": []string{TEST_DATE},
			httpsignatures.HEADER_SIGNATURE: []string{TEST_SIGNATURE},
		},
	}

	s, err := httpsignatures.NewSignatureFromRequest(&r)
	assert.Nil(t, err)

	assert.Equal(t, "Test", s.KeyID)
	assert.Equal(t, "rsa-sha256", s.Algorithm)
	assert.Equal(t, TEST_HASH, s.Signature)

	assert.Equal(t, s.ToString(), TEST_SIGNATURE)
}

func TestCreateSignatureWithNoSignature(t *testing.T) {
	r := http.Request{
		Header: http.Header{
			"Date": []string{TEST_DATE},
		},
	}

	s, err := httpsignatures.NewSignatureFromRequest(&r)
	assert.Equal(t, httpsignatures.ErrorNoSignatureHeader, err)
	assert.Nil(t, s)
}

func TestCreateWithMissingSignature(t *testing.T) {
	s, err := httpsignatures.NewSignatureFromString(`keyId="Test",algorithm="rsa-sha256"`)
	assert.Equal(t, "Missing signature", err.Error())
	assert.Nil(t, s)
}

func TestCreateWithMissingAlgorithm(t *testing.T) {
	s, err := httpsignatures.NewSignatureFromString(`keyId="Test",signature="fffff"`)
	assert.Equal(t, "Missing algorithm", err.Error())
	assert.Nil(t, s)
}

func TestCreateWithMissingKeyId(t *testing.T) {
	s, err := httpsignatures.NewSignatureFromString(`algorithm="rsa-sha256",signature="fffff"`)
	assert.Equal(t, "Missing keyId", err.Error())
	assert.Nil(t, s)
}

func TestCreateWithInvalidKey(t *testing.T) {
	s, err := httpsignatures.NewSignatureFromString(`keyId="Test",algorithm="rsa-sha256",signature="fffff",garbage="bob"`)
	assert.Equal(t, "Unexpected key in signature 'garbage'", err.Error())
	assert.Nil(t, s)
}

func TestInvalidAlgorithm(t *testing.T) {
	s, err := httpsignatures.NewSignatureFromString(`keyId="Test",algorithm="hmac-turtles",signature="test"`)
	assert.Nil(t, err)

	err = s.Sign("foo", &http.Request{})
	assert.Equal(t, "Unknown Algorithm", err.Error())
}

func TestValidRequestIsValid(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{TEST_DATE},
		},
	}
	err := httpsignatures.DefaultSha256Signer.SignRequest(TEST_KEY_ID, TEST_KEY, r)
	assert.Nil(t, err)

	sig, err := httpsignatures.NewSignatureFromRequest(r)
	assert.Nil(t, err)

	assert.True(t, sig.IsValid(TEST_KEY, r))
}

func TestNotValidIfRequestHeadersChange(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{TEST_DATE},
		},
	}
	err := httpsignatures.DefaultSha256Signer.SignRequest(TEST_KEY_ID, TEST_KEY, r)
	assert.Nil(t, err)

	r.Header.Set("Date", "Thu, 05 Jan 2012 21:31:41 GMT")
	sig, err := httpsignatures.NewSignatureFromRequest(r)
	assert.Nil(t, err)

	assert.False(t, sig.IsValid(TEST_KEY, r))
}

func TestNotValidIfRequestIsMissingDate(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{TEST_DATE},
		},
	}

	s := httpsignatures.Signer{httpsignatures.ALGORITHM_HMAC_SHA1, httpsignatures.HeaderList{httpsignatures.REQUEST_TARGET}}

	err := s.SignRequest(TEST_KEY_ID, TEST_KEY, r)
	assert.Nil(t, err)

	sig, err := httpsignatures.NewSignatureFromRequest(r)
	assert.Nil(t, err)

	assert.False(t, sig.IsValid(TEST_KEY, r))
}
