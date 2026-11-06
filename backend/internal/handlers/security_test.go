package handlers

import (
	"github.com/gin-gonic/gin"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestDecoderRejectsDuplicateAndUnexpectedFields(t *testing.T) {
	for _, body := range []string{`{"content":"benign","content":"malicious"}`, `{"Content":"one","content":"two"}`, `{"cont\u0065nt":"one","content":"two"}`, `{"content":"one","role":"admin"}`, `null`, `[]`, `{} {}`, `{"content":"` + strings.Repeat("x", 17000) + `"}`} {
		r := gin.New()
		r.POST("/", func(c *gin.Context) {
			var value struct {
				Content string `json:"content"`
			}
			if decode(c, &value) {
				c.Status(204)
			}
		})
		req := httptest.NewRequest("POST", "/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != 400 {
			t.Fatalf("ambiguous body accepted: %d", w.Code)
		}
	}
}
func TestCSVFormulaPrefixesAndUnicode(t *testing.T) {
	for _, value := range []string{"=1+1", "+CMD", "-CMD", "@SUM(A1)", " \t\r\n=HYPERLINK(\"x\")"} {
		if got := csvSafe(value); !strings.HasPrefix(got, "'") {
			t.Fatal("formula not neutralized")
		}
	}
	for _, value := range []string{"ScamGuard", "Ẹ káàárọ̀", "https://example.invalid"} {
		if csvSafe(value) != value {
			t.Fatal("safe text changed")
		}
	}
}
