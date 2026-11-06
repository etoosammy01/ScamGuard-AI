package handlers

import (
	"context"
	"encoding/csv"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/etoosammy01/ScamGuard-AI/backend/internal/models"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/repository"
	"github.com/gin-gonic/gin"
)

type fakeHistoryStore struct {
	owner      string
	filter     models.ScanFilter
	deleted    string
	deletedAll int64
	rows       []models.ScanResult
	err        error
}

func (s *fakeHistoryStore) List(_ context.Context, owner string, f models.ScanFilter) (models.ScanPage, error) {
	s.owner, s.filter = owner, f
	return models.ScanPage{Items: s.rows, Page: f.Page, PageSize: f.PageSize, Total: int64(len(s.rows))}, s.err
}
func (s *fakeHistoryStore) Get(_ context.Context, owner, id string) (models.ScanResult, error) {
	s.owner = owner
	if s.err != nil {
		return models.ScanResult{}, s.err
	}
	if owner != "owner" {
		return models.ScanResult{}, repository.ErrNotFound
	}
	return models.ScanResult{ScanID: id, OriginalContentAvailable: false}, nil
}
func (s *fakeHistoryStore) Delete(_ context.Context, owner, id string) error {
	s.owner, s.deleted = owner, id
	return s.err
}
func (s *fakeHistoryStore) DeleteAll(_ context.Context, owner string) (int64, error) {
	s.owner = owner
	return s.deletedAll, s.err
}
func (s *fakeHistoryStore) Stats(_ context.Context, owner string) (models.DashboardStats, error) {
	s.owner = owner
	return models.DashboardStats{TotalScans: 2, Activity: []models.ScanActivity{}}, s.err
}
func (s *fakeHistoryStore) Export(_ context.Context, owner string, f models.ScanFilter, _ int) ([]models.ScanResult, error) {
	s.owner, s.filter = owner, f
	return s.rows, s.err
}

func historyRouter(store *fakeHistoryStore) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set(models.IdentityKey, models.Identity{ID: "owner"}); c.Next() })
	h := &ScanHistory{Store: store}
	r.GET("/scans", h.List)
	r.GET("/scans/export", h.Export)
	r.DELETE("/scans", h.DeleteAll)
	r.GET("/scans/:id", h.Get)
	r.DELETE("/scans/:id", h.Delete)
	r.GET("/stats", h.Stats)
	return r
}

func TestHistoryFiltersPaginationAndOwner(t *testing.T) {
	store := &fakeHistoryStore{rows: []models.ScanResult{}}
	r := historyRouter(store)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/scans?risk_level=critical&scan_type=url&category=phishing&page=3&page_size=50&from=2026-01-01&to=2026-01-31&search=bank", nil))
	if w.Code != 200 || store.owner != "owner" || store.filter.Page != 3 || store.filter.PageSize != 50 || store.filter.ScanType != "url" || store.filter.RiskLevel != "critical" || store.filter.Category != "phishing" || store.filter.From == nil || store.filter.To == nil {
		t.Fatalf("filter handling failed code=%d filter=%+v body=%s", w.Code, store.filter, w.Body.String())
	}
	for _, path := range []string{"/scans?page_size=101", "/scans?risk_level=extreme", "/scans?from=2026-03-01&to=2026-02-01", "/scans?search=" + strings.Repeat("x", 101), "/scans?page=0", "/scans?unexpected=x"} {
		w = httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 400 {
			t.Errorf("%s status=%d", path, w.Code)
		}
	}
}

func TestHistoryGetDeleteBulkDeleteAndStats(t *testing.T) {
	store := &fakeHistoryStore{deletedAll: 3, err: repository.ErrNotFound}
	r := historyRouter(store)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/scans/not-a-uuid", nil))
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/scans/00000000-0000-0000-0000-000000000000", nil))
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
	store.err = nil
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/scans/00000000-0000-0000-0000-000000000001", nil))
	if w.Code != 204 || store.owner != "owner" || store.deleted == "" {
		t.Fatal(w.Code, store)
	}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/scans", nil))
	if w.Code != 200 || store.deletedAll != 3 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/stats", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"total_scans":2`) {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestCSVExportAndFormulaInjection(t *testing.T) {
	store := &fakeHistoryStore{rows: []models.ScanResult{{ScanID: "00000000-0000-0000-0000-000000000001", ScanType: "message", RiskScore: 55, FinalScore: 55, RiskLevel: "high", Category: "=HYPERLINK(\"x\")", AnalysisMode: "rules", AIStatus: "not_requested"}}}
	r := historyRouter(store)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/scans/export?risk_level=high", nil))
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Disposition"), "scamguard-scans.csv") {
		t.Fatal(w.Code, w.Header())
	}
	data, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if err != nil || len(data) != 2 || data[1][4] != "'=HYPERLINK(\"x\")" {
		t.Fatalf("unsafe CSV: %#v %v", data, err)
	}
	if csvSafe(" \t=1+1") != "' \t=1+1" {
		t.Fatal("leading whitespace bypasses spreadsheet formula guard")
	}
	store.err = errors.New("db unavailable")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/scans/export", nil))
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
}

func TestCSVExportRowLimit(t *testing.T) {
	store := &fakeHistoryStore{rows: make([]models.ScanResult, 10001)}
	w := httptest.NewRecorder()
	historyRouter(store).ServeHTTP(w, httptest.NewRequest("GET", "/scans/export", nil))
	if w.Code != 413 {
		t.Fatal("oversized export accepted", w.Code)
	}
}
