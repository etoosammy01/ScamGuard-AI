package router

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/etoosammy01/ScamGuard-AI/backend/internal/database"
)

type fakeDB struct{ err error }

func (f fakeDB) Ping(ctx context.Context) error {
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 2100*time.Millisecond {
		return errors.New("missing bounded timeout")
	}
	return f.err
}
func TestHealth(t *testing.T) {
	r := New(fakeDB{}, []string{"http://localhost:3000"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/health", nil))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	var got map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got["status"] != "ok" || got["service"] != "scamguard-api" || got["version"] != "1.0.0" {
		t.Fatal(got)
	}
}
func TestReadiness(t *testing.T) {
	for _, tt := range []struct {
		name string
		db   fakeDB
		code int
	}{{"available", fakeDB{}, 200}, {"unavailable", fakeDB{errors.New("password=secret")}, 503}} {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			New(tt.db, nil).ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/health/ready", nil))
			if w.Code != tt.code {
				t.Fatal(w.Code)
			}
			if tt.code == 503 && w.Body.String() != `{"error":{"code":"database_unavailable","message":"Service is not ready"}}` {
				t.Fatal(w.Body.String())
			}
		})
	}
}
func TestCORS(t *testing.T) {
	for _, tt := range []struct {
		origin, method, requested string
		code                      int
		allow                     bool
	}{{"http://localhost:3000", "GET", "", 200, true}, {"https://evil.example", "GET", "", 403, false}, {"null", "GET", "", 403, false}, {"", "GET", "", 200, false}, {"http://localhost:3000", "OPTIONS", "GET", 204, true}, {"http://localhost:3000", "OPTIONS", "POST", 405, true}} {
		t.Run(tt.origin+tt.method+tt.requested, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, "/api/v1/health", nil)
			req.Header.Set("Origin", tt.origin)
			req.Header.Set("Access-Control-Request-Method", tt.requested)
			New(fakeDB{}, []string{"http://localhost:3000"}).ServeHTTP(w, req)
			if w.Code != tt.code {
				t.Fatal(w.Code)
			}
			if (w.Header().Get("Access-Control-Allow-Origin") != "") != tt.allow {
				t.Fatal(w.Header())
			}
			if w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("missing security headers")
			}
		})
	}
}
func TestDatabaseReadinessIntegration(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set TEST_DATABASE_URL for PostgreSQL integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	New(pool, nil).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/health/ready", nil))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	pool.Close()
	w = httptest.NewRecorder()
	New(pool, nil).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/health/ready", nil))
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
}
