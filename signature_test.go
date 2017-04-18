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
	RSA_TEST_KEY   = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAptqthxnWUoN6J/9RhspO9uKmsYUTT150rGyLln/Keq0E4vam
7Pj3B6Xh3reGbyjSz0NQkfLftalRKqNse0TH5TLGMYXz5mtxm+jZkuTqE73wgRDF
3jW0gCoFGy0qKXckunvKOpwkNVDuMZZ1DLgLbUGi1XTVpH8r4hHWsVfrupzJnfo4
ptAGEPlH9VRoYZd5sNg3OIxQaUYtNZr3dpywzwXwPF1VvWCw1K9cENZhkFS5CW/l
PuZXCFOPDgO1hTJMLWE+aZ7TElYOH/i+1/4igBdPn0G0awBR+OoGF0wN4JpUXDSQ
D9F6nyFRDKaxx5aFYdme+QrzQTyYNPQ18hjf2wIDAQABAoIBABcw68+MWsqrNY5b
oWQ/uEv+YrbnzTBJ66OPjrNDXcxBQh2dtMPZMtSgTM2c6pWGsg5Wx9sRS+C/AOYR
QuG7RKFptjxp5uWO54KJEbymDpbh3ozB3Q6unkD2FjGZzHNo+PTmgcw1qZ6zeffw
dqJm7keoSM6sZ4lul5XbbuDFXKFaMMbz1VRVVdFnAvmKQZfwd6/noeKiuyMyG3g8
v7VikhsEA3pX7uOVDs2vbj5Pq5lDYZ22k0FD0BS6uPUyzrhDyn+nF2I2GWS8PePX
xRsrw05BgGLi5mcI4XPpxLY53T4yc1RYBKvmtGJsZ26/QeOo/ER7ogd8hV/EwjuM
S30PNbECgYEA/kQklql7ri7+qG6HZ07avD2DTQqC9LIOXc6WsoBIRV13geKL/H9a
uXSrxlLbkWYqt8yd2zzVvo+0mbm+Nixe2huPmawbQjsQoLA0hSC7+g8djboDz91Q
SHsHTDYzNUw6SDqRsypQpUJIOQvvwxodcPlW8RaHW4JAafXPMygkTjkCgYEAp/3x
9ClD+4MTinYLVdRfY4j9r4TjkI2sXf4nfD06fnQcSVsZWD6AqGjqmjfJA+f6w+lu
KHo1NJonlLzac4qOScGCTgCrSbbSPUq8IgaZk4ufqnIek6TH/wPEaY7ZLVb59Wam
Z0+yrpqDqVMf2uUJyiTlFdajfqtHx9Oo5vvnnrMCgYAqd7Msvs37f7nk4+EVriP2
gMenXHQW7o5buJ+O3MI1Y7EMLox29cZvZz8xdrFZjZjg7foHnheNJm9hpZZRcgO9
phDL9+TtoPPcAtIi0h7TWybyfvkYBLzd/j5vyjWvVzX8zlt7czvY/kMV1BqNmZUF
Q3/z8HFXJWAg0n9y6ed2cQKBgQCROs/+heI4wIOXMx/vjo78jMTMBXV6VZBLHdpi
5Mf55EVEAZaynC476Z/PvSRx1Q4ManSKV8RBend3daDhPEpwZvNQnfF2469zv3VP
cSc5z/4zqz7V4yHnTAl0PENyl/u19I0tSVAu9HOYYb1rTpCdCjJmI83qRwbiMRCW
x/XgUwKBgBd+kQkrjhhn/vbhG1EtHgAgszyuMCl+nXlvWGrIP24nSfDxH8UBjhhg
LvbPDIsyREqu3KgddzwdUgCu1PX7adl3mEJXfg62QhqU707+eo6OAGkyUJWDofyi
46RZixuecH3thF1BnNNdYi0QI0UTLkZgpKWGE9mXTp4xxzHg0sfs
-----END RSA PRIVATE KEY-----`
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
