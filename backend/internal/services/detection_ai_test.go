package services

import (
	"context"
	"testing"
	"time"

	"github.com/etoosammy01/ScamGuard-AI/backend/internal/ai"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/models"
)

type fakeAnalyzer struct {
	result ai.Assessment
	err    error
	calls  int
}

func (f *fakeAnalyzer) Analyze(context.Context, string, string, []models.Indicator) (ai.Assessment, ai.Usage, error) {
	f.calls++
	return f.result, ai.Usage{}, f.err
}

func TestHybridScoringPreservesRulesAndMapsResponse(t *testing.T) {
	f := &fakeAnalyzer{result: ai.Assessment{Category: ai.CategoryCredentialTheft, RiskScore: 96, Confidence: ai.ConfidenceHigh, Indicators: []ai.Indicator{{Type: "credential_request", Reason: "The text asks for a password."}}, Explanation: "Requests credentials.", Recommendations: []string{"Never share passwords."}}}
	d := NewDetection(f, NewAIUserRateLimiter(5, time.Hour))
	result := d.AnalyzeMessage(context.Background(), "user-1", "URGENT: your account is suspended, send your password now", AIAnalysisModeHybrid)
	if result.AnalysisMode != "hybrid" || result.AIStatus != "completed" || result.FinalScore != result.RiskScore || result.RiskScore < result.RuleScore || result.Category != "credential_theft" || result.AIAssessment == nil {
		t.Fatalf("unexpected hybrid result: %+v", result)
	}
	if result.FinalScore != result.RiskScore {
		t.Fatal("final score not aligned")
	}
	if FuseRiskScore(80, 20, ai.ConfidenceHigh, ai.CategoryPhishing) != 80 {
		t.Fatal("AI downgraded high-risk rules")
	}
	if FuseRiskScore(0, 100, ai.ConfidenceLow, ai.CategoryPhishing) != 15 {
		t.Fatal("unexpected conservative low-confidence lift")
	}
	if FuseRiskScore(0, 100, ai.ConfidenceHigh, ai.CategoryUnknown) != 0 {
		t.Fatal("unknown classification changed rules score")
	}
}

func TestHybridFallbackModes(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		analyzer ai.Analyzer
		status   string
		limiter  *AIUserRateLimiter
	}{
		{"disabled", nil, "disabled", nil},
		{"unavailable", &fakeAnalyzer{err: ai.ErrUnavailable}, "unavailable", nil},
		{"invalid output", &fakeAnalyzer{err: ai.ErrInvalidOutput}, "validation_failed", nil},
		{"rate limited", &fakeAnalyzer{}, "rate_limited", NewAIUserRateLimiter(0, time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := NewDetection(tc.analyzer, tc.limiter).AnalyzeMessage(ctx, "user", "hello", AIAnalysisModeHybrid)
			if result.AIStatus != tc.status || result.AnalysisMode != "rules" || result.AIAssessment != nil || result.RiskScore != result.RuleScore {
				t.Fatalf("unexpected fallback: %+v", result)
			}
		})
	}
	if got := NewDetection(nil, nil).AnalyzeMessage(ctx, "user", "hello", "rules"); got.AIStatus != "not_requested" {
		t.Fatalf("rules mode status %s", got.AIStatus)
	}
}

func TestAILimiter(t *testing.T) {
	l := NewAIUserRateLimiter(1, time.Hour)
	if !l.Allow("a") || l.Allow("a") || !l.Allow("b") {
		t.Fatal("per-user limit failed")
	}
}
