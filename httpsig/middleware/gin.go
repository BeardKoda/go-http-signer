package middleware

import (
	"net/http"

	"github.com/beardkoda/httpsig-go/httpsig/verifier"
	"github.com/gin-gonic/gin"
)

func GinVerifyMiddleware(v *verifier.Verifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		ok, err := v.Verify(c.Request)
		if err != nil || !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid signature"})
			return
		}
		c.Set(string(VerificationResultKey), true)
		c.Next()
	}
}
