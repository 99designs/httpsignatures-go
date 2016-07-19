package httpsignatures_test

import (
	"net/http"

	"github.com/99designs/httpsignatures-go"
)

func Example_signing() {
	r, _ := http.NewRequest("GET", "http://example.com/some-api", nil)

	// Sign using the 'Signature' header
	httpsignatures.DefaultSha256Signer.SignRequest("KeyId", "Key", r)
	// OR Sign using the 'Authorization' header
	httpsignatures.DefaultSha256Signer.AuthRequest("KeyId", "Key", r)

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
