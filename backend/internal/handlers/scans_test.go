package handlers

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/etoosammy01/ScamGuard-AI/backend/internal/models"
	"github.com/gin-gonic/gin"
)

type testScanStore struct {
	owner  string
	result models.ScanResult
	err    error
}

func (s *testScanStore) Create(_ context.Context, owner string, result models.ScanResult) (models.ScanResult, error) {
	s.owner, s.result = owner, result
	return result, s.err
}

type testScanService struct{}

func (testScanService) Message(string) models.ScanResult {
	return models.ScanResult{ScanType: "message", RiskLevel: "low"}
}
func (testScanService) URL(v string) (models.ScanResult, error) {
	if v == "bad" {
		return models.ScanResult{}, errors.New("invalid")
	}
	return models.ScanResult{ScanType: "url", RiskLevel: "low"}, nil
}

func TestScanHandlerValidationAndOwner(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	for _, tt := range []struct {
		body string
		code int
	}{{`{"content":" "}`, 400}, {`{"content":"text","role":"admin"}`, 400}, {`{"content":"` + strings.Repeat("x", 17000) + `"}`, 400}, {`{"content":"valid message"}`, 201}} {
		store := &testScanStore{}
		r := gin.New()
		r.Use(func(c *gin.Context) { c.Set(models.IdentityKey, models.Identity{ID: "authenticated-user"}) })
		r.POST("/scan", (&ScanHandler{Store: store, Service: testScanService{}}).Message)
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/scan", strings.NewReader(tt.body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != tt.code {
			t.Fatalf("want %d got %d %s", tt.code, w.Code, w.Body.String())
		}
		if tt.code == 201 && store.owner != "authenticated-user" {
			t.Fatal("scan not owned by authenticated user")
		}
	}
}

func TestInvalidURLAndStorageFailureAreGeneric(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	for _, tt := range []struct {
		url  string
		fail bool
		code int
	}{{"bad", false, 400}, {"https://example.com", true, 503}} {
		store := &testScanStore{}
		if tt.fail {
			store.err = errors.New("secret database detail")
		}
		r := gin.New()
		r.Use(func(c *gin.Context) { c.Set(models.IdentityKey, models.Identity{ID: "user"}) })
		r.POST("/scan", (&ScanHandler{Store: store, Service: testScanService{}}).URL)
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/scan", strings.NewReader(`{"url":"`+tt.url+`"}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != tt.code || strings.Contains(w.Body.String(), "secret") {
			t.Fatal(w.Code, w.Body.String())
		}
	}
}
