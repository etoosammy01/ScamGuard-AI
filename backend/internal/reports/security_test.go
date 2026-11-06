package reports

import (
	"context"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/models"
	"strings"
	"testing"
	"time"
)

func TestUnicodeAndRenderingInjectionAreInert(t *testing.T) {
	scan := models.ScanResult{ScanID: "synthetic", Explanation: "Ẹ káàárọ̀ — 中文 — مرحبا — <script>alert(1)</script> (\\) /JavaScript /OpenAction", Recommendations: []string{strings.Repeat("Long explanation with no executable actions. ", 100)}}
	data, err := Generate(context.Background(), scan, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "%PDF-") || len(data) > 2<<20 {
		t.Fatal("invalid or oversized PDF")
	}
	for _, action := range []string{"/OpenAction ", "/S /JavaScript", "/URI ("} {
		if strings.Contains(string(data), action) {
			t.Fatal("stored text became active PDF action")
		}
	}
}
