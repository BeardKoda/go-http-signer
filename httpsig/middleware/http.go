package middleware

import (
	"context"
	"net/http"

	"github.com/beardkoda/httpsig-go/httpsig/verifier"
)

type contextKey string

const VerificationResultKey contextKey = "httpsig.verified"

func VerifyMiddleware(v *verifier.Verifier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok, err := v.Verify(r)
		if err != nil || !ok {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), VerificationResultKey, ok)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
