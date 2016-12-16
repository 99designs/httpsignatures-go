package httpsignatures_test

import (
	"net/http"

	"github.com/mvaneijk/httpsignatures-go"
)

func keyLookup(keyId string) string {
	return keyId
}

func Example_signing() {
	r, _ := http.NewRequest("GET", "http://example.com/some-api", nil)

	signer := httpsignatures.NewSigner("keyId", keyLookup, httpsignatures.AlgorithmHmacSha256)
	// Sign using the 'Signature' header
	signer.SignRequest(r)
	// OR Sign using the 'Authorization' header
	signer.AuthRequest(r)

	http.DefaultClient.Do(r)
}

func Example_customSigning() {
	signer := httpsignatures.NewSigner(
		"keyId",
		keyLookup,
		httpsignatures.AlgorithmHmacSha256,
		httpsignatures.HeaderRequestTarget,
		httpsignatures.HeaderDate,
		"content-length",
	)

	r, _ := http.NewRequest("GET", "http://example.com/some-api", nil)

	signer.SignRequest(r)

	http.DefaultClient.Do(r)
}

func Example_verification() {
	_ = func(w http.ResponseWriter, r *http.Request) {

		_, err := httpsignatures.VerifyRequest(r, keyLookup, 300,
			httpsignatures.HeaderRequestTarget)

		if err != nil {
			// Probably a malformed header
			http.Error(w, "Bad Request", http.StatusBadRequest)
			panic(err)
		}

		// request was signed correctly.

	}
}
