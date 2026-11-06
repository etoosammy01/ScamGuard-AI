package reports

import (
	"context"
	"errors"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/models"
	"strings"
	"testing"
	"time"
)

func TestGenerateLimitsAndPDF(t *testing.T) {
	scan := models.ScanResult{ScanID: "fixture", Explanation: "Untrusted text (\\) <script>alert(1)</script>\n", Recommendations: []string{strings.Repeat("long", 900)}}
	data, err := Generate(context.Background(), scan, time.Now())
	if err != nil || !strings.HasPrefix(string(data), "%PDF-") || !strings.Contains(string(data), "%%EOF") {
		t.Fatalf("invalid PDF: %v", err)
	}
	scan.Explanation = strings.Repeat("x", 33000)
	if _, err = Generate(context.Background(), scan, time.Now()); !errors.Is(err, ErrLimit) {
		t.Fatal("size limit not enforced", err)
	}
	scan.Explanation = ""
	scan.Indicators = make([]models.Indicator, 101)
	if _, err = Generate(context.Background(), scan, time.Now()); !errors.Is(err, ErrLimit) {
		t.Fatal("indicator limit not enforced")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = Generate(ctx, models.ScanResult{}, time.Now()); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored", err)
	}
}
