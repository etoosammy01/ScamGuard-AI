package middleware

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRecoveryRedactsPanic(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(Recovery())
	r.GET("/", func(c *gin.Context) { panic("secret database password") })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 500 || strings.Contains(w.Body.String(), "secret") {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestCORSAllowsConfiguredOriginDeletePreflightOnly(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(CORS([]string{"http://localhost:3000"}))
	r.DELETE("/api/v1/scans", func(c *gin.Context) { c.Status(204) })
	request := httptest.NewRequest("OPTIONS", "/api/v1/scans", nil)
	request.Header.Set("Origin", "http://localhost:3000")
	request.Header.Set("Access-Control-Request-Method", "DELETE")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, request)
	if w.Code != 204 || !strings.Contains(w.Header().Get("Access-Control-Allow-Methods"), "DELETE") {
		t.Fatal(w.Code, w.Header())
	}
	request = httptest.NewRequest("OPTIONS", "/api/v1/scans", nil)
	request.Header.Set("Origin", "https://untrusted.invalid")
	request.Header.Set("Access-Control-Request-Method", "DELETE")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, request)
	if w.Code != 403 {
		t.Fatal("unconfigured origin accepted", w.Code)
	}
}
