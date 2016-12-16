package httpsignatures_test

import (
	"errors"
	"net/http"

	"github.com/mvaneijk/httpsignatures-go"
)

func Example_signing() {
	r, _ := http.NewRequest("GET", "http://example.com/some-api", nil)

	signer := httpsignatures.NewSigner(httpsignatures.AlgorithmHmacSha256)
	// Sign using the 'Signature' header
	signer.SignRequest(r, "keyId", "key")
	// OR Sign using the 'Authorization' header
	signer.AuthRequest(r, "keyId", "key")

	http.DefaultClient.Do(r)
}

func Example_customSigning() {
	signer := httpsignatures.NewSigner(
		httpsignatures.AlgorithmHmacSha256,
		httpsignatures.HeaderRequestTarget,
		httpsignatures.HeaderDate,
		"content-length",
	)

	r, _ := http.NewRequest("GET", "http://example.com/some-api", nil)

	signer.SignRequest(r, "keyId", "key")

	http.DefaultClient.Do(r)
}

func Example_verification() {
	_ = func(w http.ResponseWriter, r *http.Request) {

		keyLookUp := func(keyId string) (string, error) {
			key := keyId
			// check if keyId exists
			if len(keyId) == 0 {
				return "", errors.New("No keyId supplied")
			}
			// add check to see if keyId is allowed to access

			// if all goes well:
			return key, nil
		}

		_, err := httpsignatures.VerifyRequest(r, keyLookUp, 300,
			httpsignatures.HeaderRequestTarget)

		if err != nil {
			httpErr, msg := httpsignatures.ErrorToHTTPCode(err.Error())
			if httpErr == http.StatusInternalServerError {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			} else {
				http.Error(w, msg, httpErr)
			}
			panic(err)
		}

		// request was signed correctly.

	}
}
