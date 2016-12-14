package httpsignatures

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

// Test Signature String From Request Parser
func TestRequestParserMissingSignatureShouldFail(t *testing.T) {
	var s SignatureParameters
	err := s.FromString(`keyId="Test",algorithm="hmac-sha256"`)
	assert.Equal(t, "Missing signature", err.Error())
	sigParam := SignatureParameters{KeyID: "Test", Algorithm: AlgorithmHmacSha256, Headers: HeaderList{"date": ""}}
	assert.Equal(t, sigParam, s)
}

func TestRequestParserMissingAlgorithmShouldFail(t *testing.T) {
	var s SignatureParameters
	err := s.FromString(`keyId="Test",signature="fffff"`)
	assert.Equal(t, "Missing algorithm", err.Error())
	sigParam := SignatureParameters{KeyID: "Test", Headers: HeaderList{"date": ""}, Signature: "fffff"}
	assert.Equal(t, sigParam, s)
}

func TestRequestParserMissingKeyIdShouldFail(t *testing.T) {
	var s SignatureParameters
	err := s.FromString(`algorithm="hmac-sha256",signature="fffff"`)
	assert.Equal(t, "Missing keyId", err.Error())
	sigParam := SignatureParameters{Algorithm: AlgorithmHmacSha256, Headers: HeaderList{"date": ""}, Signature: "fffff"}
	assert.Equal(t, sigParam, s)
}

func TestRequestParserDualHeaderShouldPickLastOne(t *testing.T) {
	var s SignatureParameters
	err := s.FromString(`keyId="Test",algorithm="hmac-sha256",signature="fffff",signature="abcde"`)
	assert.Nil(t, err)
	sigParam := SignatureParameters{KeyID: "Test", Algorithm: AlgorithmHmacSha256, Headers: HeaderList{"date": ""}, Signature: "abcde"}
	assert.Equal(t, sigParam, s)
}

func TestRequestParserMissingDateHeader(t *testing.T) {
	var s SignatureParameters
	err := s.FromString(`keyId="Test",algorithm="hmac-sha256",signature="fffff",headers="(request-target) host"`)
	assert.Nil(t, err)
	sigParam := SignatureParameters{KeyID: "Test", Algorithm: AlgorithmHmacSha256, Headers: HeaderList{"(request-target)": "", "host": ""}, Signature: "fffff"}
	assert.Equal(t, sigParam, s)
}

func TestRequestParserInvalidKeyShouldBeIgnored(t *testing.T) {
	var s SignatureParameters
	err := s.FromString(`keyId="Test",algorithm="hmac-sha256",garbage="bob",signature="fffff"`)
	assert.Nil(t, err)
	sigParam := SignatureParameters{KeyID: "Test", Algorithm: AlgorithmHmacSha256, Headers: HeaderList{"date": ""}, Signature: "fffff"}
	assert.Equal(t, sigParam, s)
}

// Test Signature String Config Parser
func TestConfigParserMissingAlgorithmShouldFail(t *testing.T) {
	var s SignatureParameters
	err := s.FromConfig("Test", "", "")
	assert.Equal(t, "Missing algorithm", err.Error())
}

func TestConfigParserMissingKeyIdShouldFail(t *testing.T) {
	var s SignatureParameters
	err := s.FromConfig("", "hmac-sha256", "")
	assert.Equal(t, "Missing keyId", err.Error())
}

func TestConfigParserMissingDateHeader(t *testing.T) {
	var s SignatureParameters
	err := s.FromConfig("Test", "hmac-sha256", "(request-target)", "host")
	assert.Nil(t, err)
	sigParam := SignatureParameters{KeyID: "Test", Algorithm: AlgorithmHmacSha256, Headers: HeaderList{"(request-target)": "", "host": ""}}
	assert.Equal(t, sigParam, s)
}
