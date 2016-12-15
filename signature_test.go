package httpsignatures

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/url"
	"testing"
)

// Verification
// Test Signature String From Request Parser
func TestRequestParserMissingSignatureShouldFail(t *testing.T) {
	var s SignatureParameters
	err := s.parseSignatureString(`keyId="Test",algorithm="hmac-sha256"`)
	assert.EqualError(t, err, "Missing signature")
}

func TestRequestParserMissingAlgorithmShouldFail(t *testing.T) {
	var s SignatureParameters
	err := s.parseSignatureString(`keyId="Test",signature="fffff"`)
	assert.EqualError(t, err, "Missing algorithm")
}

func TestRequestParserMissingKeyIdShouldFail(t *testing.T) {
	var s SignatureParameters
	err := s.parseSignatureString(`algorithm="hmac-sha256",signature="fffff"`)
	assert.EqualError(t, err, "Missing keyId")
}

func TestRequestParserDualHeaderShouldPickLastOne(t *testing.T) {
	var s SignatureParameters
	err := s.parseSignatureString(`keyId="Test",algorithm="hmac-sha256",signature="fffff",signature="abcde"`)
	assert.Nil(t, err)
	sigParam := SignatureParameters{KeyID: "Test", Algorithm: AlgorithmHmacSha256, Headers: HeaderList{"date": ""}, Signature: "abcde"}
	assert.Equal(t, sigParam, s)
}

func TestRequestParserMissingDateHeader(t *testing.T) {
	const DefaultTestAuthHeader string = `keyId="Test",algorithm="hmac-sha256",signature="fffff",headers="(request-target) host"`
	r := &http.Request{
		Header: http.Header{
			"Date":          []string{testDate},
			"Authorization": []string{DefaultTestAuthHeader},
		},
		Method: http.MethodPost,
		URL: &url.URL{
			Host: "example.com",
			Path: "/foo?param=value&pet=dog",
		},
	}

	var s SignatureParameters
	err := s.FromRequest(r)
	assert.Nil(t, err)
	sigParam := SignatureParameters{KeyID: "Test", Algorithm: AlgorithmHmacSha256,
		Headers: HeaderList{"(request-target)": "post /foo?param=value&pet=dog", "host": "example.com"}, Signature: "fffff"}
	assert.Equal(t, sigParam, s)
}

func TestRequestParserInvalidKeyShouldBeIgnored(t *testing.T) {
	const DefaultTestAuthHeader string = `Signature keyId="Test",algorithm="hmac-sha256",
		garbage="bob",signature="fffff"`
	r := &http.Request{
		Header: http.Header{
			"Date":          []string{testDate},
			"Authorization": []string{DefaultTestAuthHeader},
		},
		Method: http.MethodPost,
		URL: &url.URL{
			Host: "example.com",
			Path: "/foo?param=value&pet=dog",
		},
	}

	var s SignatureParameters
	err := s.FromRequest(r)
	assert.Nil(t, err)
	sigParam := SignatureParameters{KeyID: "Test", Algorithm: AlgorithmHmacSha256, Headers: HeaderList{"date": testDate}, Signature: "fffff"}
	assert.Equal(t, sigParam, s)
}

// todo , change hmac back to RSA from example in http-signatures-draft-05
const DefaultTestAuthHeader string = `Signature keyId="Test",algorithm="hmac-sha256",
		signature="ATp0r26dbMIxOopqw0OfABDT7CKMIoENumuruOtarj8n/97Q3htHFYpH8yOSQk3Z5zh8UxUym6FYTb5+
		A0Nz3NRsXJibnYi7brE/4tx5But9kkFGzG+xpUmimN4c3TMN7OFH//+r8hBf7BT9/GmHDUVZT2JzWGLZES2xDOUuMtA="`

func TestRequestParserLoadHeaderMissingDateHeader(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Authorization": []string{DefaultTestAuthHeader},
		},
		Method: http.MethodPost,
		URL: &url.URL{
			Host: "example.com",
			Path: "/foo?param=value&pet=dog",
		},
	}

	var s SignatureParameters
	err := s.FromRequest(r) // the date header will be implicitly required
	assert.EqualError(t, err, "Missing required header 'date'")
}

// Signing

// Test Signature String Config Parser
func TestConfigParserMissingAlgorithmShouldFail(t *testing.T) {
	var s SignatureParameters
	err := s.FromConfig("Test", "", nil)
	assert.EqualError(t, err, "No algorithm configured")
}

func TestConfigParserMissingKeyIdShouldFail(t *testing.T) {
	var s SignatureParameters
	err := s.FromConfig("", "hmac-sha256", nil)
	assert.EqualError(t, err, "No keyID configured")
}

func TestConfigParserNotRequiredDateHeader(t *testing.T) {
	var s SignatureParameters
	err := s.FromConfig("Test", "hmac-sha256", []string{"(request-target)", "host"})
	assert.Nil(t, err) // It's okay to not require the date header for the signature
	sigParam := SignatureParameters{KeyID: "Test", Algorithm: AlgorithmHmacSha256, Headers: HeaderList{"(request-target)": "", "host": ""}}
	assert.Equal(t, sigParam, s)
}

func TestConfigParserMissingDateHeader(t *testing.T) {
	var s SignatureParameters
	err := s.FromConfig("Test", "hmac-sha256", nil) // the date header will be implicitly required
	assert.Nil(t, err)

	sigParam := SignatureParameters{KeyID: "Test", Algorithm: AlgorithmHmacSha256, Headers: HeaderList{"date": ""}}
	assert.Equal(t, sigParam, s)

	r := &http.Request{
		Header: http.Header{
			"Authorization": []string{DefaultTestAuthHeader},
		},
		Method: http.MethodPost,
		URL: &url.URL{
			Host: "example.com",
			Path: "/foo?param=value&pet=dog",
		},
	}
	err = s.ParseRequest(r) // it is not okay to have no date header when required
	assert.EqualError(t, err, "Missing required header 'date'")
}

// Test Parse SignatureParameters from Request
func TestParseRequestWithNoSignatureShouldFail(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{testDate},
		},
	}

	var s SignatureParameters
	err := s.FromRequest(r)
	assert.EqualError(t, err, "No Signature header found in request")
}

func TestParseRequestWithNoHostShouldFail(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date":          []string{testDate},
			"Authorization": []string{DefaultTestAuthHeader},
		},
		Method: http.MethodPost,
	}

	_, err := requestTargetLine(r)
	assert.EqualError(t, err, "URL not in Request")
}

func TestParseRequestWithNoMethodShouldFail(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date":          []string{testDate},
			"Authorization": []string{DefaultTestAuthHeader},
		},
		URL: &url.URL{
			Host: "example.com",
			Path: "/foo?param=value&pet=dog",
		},
	}

	_, err := requestTargetLine(r)
	assert.EqualError(t, err, "Method not in Request")
}
