package handlers

import (
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/models"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/repository"
	"github.com/gin-gonic/gin"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReportOwnershipAndFailures(t *testing.T) {
	for _, tc := range []struct {
		name, owner, id string
		missing         bool
		want            int
	}{{"owner", "owner", "00000000-0000-0000-0000-000000000001", false, 200}, {"cross-user", "other", "00000000-0000-0000-0000-000000000001", false, 404}, {"missing", "owner", "00000000-0000-0000-0000-000000000001", true, 404}, {"invalid", "owner", "invalid", false, 400}} {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeHistoryStore{}
			if tc.missing {
				store.err = repository.ErrNotFound
			}
			r := gin.New()
			r.Use(func(c *gin.Context) { c.Set(models.IdentityKey, models.Identity{ID: tc.owner}); c.Next() })
			r.GET("/scans/:id/report", (&ScanHistory{Store: store}).Report)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest("GET", "/scans/"+tc.id+"/report", nil))
			if w.Code != tc.want {
				t.Fatalf("status %d body %s", w.Code, w.Body.String())
			}
			if tc.want == 200 {
				if !strings.HasPrefix(w.Body.String(), "%PDF-") || w.Header().Get("Content-Type") != "application/pdf" || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Header().Get("Content-Disposition"), "attachment;") {
					t.Fatal("unsafe or invalid PDF response")
				}
			}
		})
	}
}
