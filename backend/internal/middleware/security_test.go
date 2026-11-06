package middleware

import (
	"github.com/gin-gonic/gin"
	"net/http/httptest"
	"testing"
)

func TestDuplicateOriginsRejectedOnReadsAndMutations(t *testing.T) {
	for _, method := range []string{"GET", "POST", "OPTIONS"} {
		r := gin.New()
		r.Use(CORS([]string{"http://localhost:3000"}), CSRF([]string{"http://localhost:3000"}))
		r.Any("/", func(c *gin.Context) { c.Status(204) })
		req := httptest.NewRequest(method, "/", nil)
		req.Header.Add("Origin", "http://localhost:3000")
		req.Header.Add("Origin", "https://attacker.invalid")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != 403 {
			t.Fatal("duplicate origin accepted", method, w.Code)
		}
	}
}
