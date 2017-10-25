package httpsignatures_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"

	"github.com/99designs/httpsignatures-go"
)

const (
	ExamplePrivateKey = `-----BEGIN RSA PRIVATE KEY-----
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
	ExamplePublicyKey = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
oYi+1hqp1fIekaxsyQIDAQAB
-----END PUBLIC KEY-----`
)

func Example_signing() {
	r, _ := http.NewRequest("GET", "http://example.com/some-api", nil)

	// Sign using the 'Signature' header
	httpsignatures.DefaultSha256Signer.SignRequest("KeyId", "Key", r)
	// OR Sign using the 'Authorization' header
	httpsignatures.DefaultSha256Signer.AuthRequest("KeyId", "Key", r)

	http.DefaultClient.Do(r)
}

func Example_signingRSA() {
	block, _ := pem.Decode([]byte(ExamplePrivateKey))
	privateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	r, _ := http.NewRequest("GET", "http://example.com/some-api", nil)

	// Sign using the 'Signature' header
	httpsignatures.DefaultRsaSha256Signer.SignRequestRSA("KeyId", privateKey, r)
	// OR Sign using the 'Authorization' header
	httpsignatures.DefaultRsaSha256Signer.AuthRequestRSA("KeyId", privateKey, r)

	http.DefaultClient.Do(r)
}

func Example_customSigning() {
	signer := httpsignatures.NewSigner(
		httpsignatures.AlgorithmHmacSha256,
		httpsignatures.RequestTarget, "date", "content-length",
	)

	r, _ := http.NewRequest("GET", "http://example.com/some-api", nil)

	signer.SignRequest("KeyId", "Key", r)

	http.DefaultClient.Do(r)
}

func Example_verification() {
	_ = func(w http.ResponseWriter, r *http.Request) {
		sig, err := httpsignatures.FromRequest(r)
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

func Example_verificationRSA() {
	_ = func(w http.ResponseWriter, r *http.Request) {
		sig, err := httpsignatures.FromRequest(r)
		if err != nil {
			// Probably a malformed header
			http.Error(w, "Bad Request", http.StatusBadRequest)
			panic(err)
		}

		// if you have headers that must be signed check
		// that they are in sig.Headers

		var pemPublicKeyBytes []byte // = lookup using sig.KeyID
		block, _ := pem.Decode(pemPublicKeyBytes)
		publicKey, _ := x509.ParsePKIXPublicKey(block.Bytes)

		if !sig.IsValidRSA(publicKey.(*rsa.PublicKey), r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// request was signed correctly.
	}
}
