package handlers

import (
	"context"
	"github.com/gin-gonic/gin"
	"net/http/httptest"
	"testing"
	"time"
)

type waitingDB struct{}

func (waitingDB) Ping(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
func TestReadinessTimeout(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.GET("/ready", Ready(waitingDB{}))
	w := httptest.NewRecorder()
	start := time.Now()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/ready", nil))
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("readiness exceeded timeout: %v", elapsed)
	}
}
