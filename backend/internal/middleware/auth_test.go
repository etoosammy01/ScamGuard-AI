package middleware

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/etoosammy01/ScamGuard-AI/backend/internal/models"
	"github.com/gin-gonic/gin"
)

func TestCSRF(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	for _, tt := range []struct {
		method  string
		origins []string
		code    int
	}{{"POST", nil, 403}, {"POST", []string{"null"}, 403}, {"POST", []string{"https://evil.example"}, 403}, {"PATCH", []string{"http://localhost:3000"}, 200}, {"POST", []string{"http://localhost:3000", "http://localhost:3000"}, 403}, {"GET", nil, 200}} {
		r := gin.New()
		r.Use(CSRF([]string{"http://localhost:3000"}))
		r.Any("/", func(c *gin.Context) { c.Status(200) })
		w := httptest.NewRecorder()
		req := httptest.NewRequest(tt.method, "/", nil)
		for _, origin := range tt.origins {
			req.Header.Add("Origin", origin)
		}
		r.ServeHTTP(w, req)
		if w.Code != tt.code {
			t.Fatal(w.Code, tt)
		}
	}
}
func TestRateLimit(t *testing.T) {
	l := NewRateLimiter(2, time.Minute)
	now := time.Now()
	l.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		ok, retry := l.allow("test-ip")
		if ok != (i < 2) || retry < 1 {
			t.Fatal(i, ok, retry)
		}
	}
	now = now.Add(61 * time.Second)
	if ok, _ := l.allow("test-ip"); !ok {
		t.Fatal("window did not reset")
	}
	l.capacity = 1
	if ok, _ := l.allow("new-ip"); ok {
		t.Fatal("unbounded limiter storage")
	}
}
func TestAdminAuthorization(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	for _, role := range []string{"user", "admin"} {
		r := gin.New()
		r.Use(func(c *gin.Context) { c.Set(models.IdentityKey, models.Identity{Role: role}) }, AdminOnly())
		r.GET("/", func(c *gin.Context) { c.Status(204) })
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
		want := 403
		if role == "admin" {
			want = 204
		}
		if w.Code != want {
			t.Fatal(w.Code)
		}
	}
}
