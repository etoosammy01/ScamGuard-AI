package services

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/etoosammy01/ScamGuard-AI/backend/internal/ai"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/detection"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/models"
)

const AIAnalysisModeHybrid = "hybrid"

type Detection struct {
	AI        ai.Analyzer
	AILimiter *AIUserRateLimiter
	stats     *detectionCounters
}

type detectionCounters struct {
	requested atomic.Uint64
	completed atomic.Uint64
	fallback  atomic.Uint64
}

type DetectionMetrics struct {
	Requested uint64 `json:"requested"`
	Completed uint64 `json:"completed"`
	Fallbacks uint64 `json:"fallbacks"`
}

func NewDetection(analyzer ai.Analyzer, limiter *AIUserRateLimiter) *Detection {
	return &Detection{AI: analyzer, AILimiter: limiter, stats: &detectionCounters{}}
}

func (d Detection) Message(content string) models.ScanResult {
	return detection.AnalyzeMessage(content)
}
func (d Detection) URL(raw string) (models.ScanResult, error) { return detection.AnalyzeURL(raw) }

func (d Detection) AnalyzeMessage(ctx context.Context, userID, content, mode string) models.ScanResult {
	base := detection.AnalyzeMessage(content)
	return d.applyAI(ctx, userID, mode, "message", content, base)
}

func (d Detection) AnalyzeURL(ctx context.Context, userID, rawURL, mode string) (models.ScanResult, error) {
	base, err := detection.AnalyzeURL(rawURL)
	if err != nil {
		return models.ScanResult{}, err
	}
	return d.applyAI(ctx, userID, mode, "url", rawURL, base), nil
}

func (d Detection) applyAI(ctx context.Context, userID, mode, kind, content string, result models.ScanResult) models.ScanResult {
	result.AnalysisMode = "rules"
	result.AIStatus = "not_requested"
	result.RuleScore = result.RiskScore
	result.FinalScore = result.RiskScore
	if mode != AIAnalysisModeHybrid {
		return result
	}
	if d.AI == nil {
		result.AIStatus = "disabled"
		d.recordFallback()
		slog.Info("scan used rules-only fallback", "ai_status", result.AIStatus)
		return result
	}
	if d.AILimiter != nil && !d.AILimiter.Allow(userID) {
		result.AIStatus = "rate_limited"
		d.recordFallback()
		slog.Info("scan used rules-only fallback", "ai_status", result.AIStatus)
		return result
	}
	if d.stats != nil {
		d.stats.requested.Add(1)
	}
	assessment, _, err := d.AI.Analyze(ctx, kind, content, result.Indicators)
	if err != nil {
		if errors.Is(err, ai.ErrInvalidOutput) {
			result.AIStatus = "validation_failed"
		} else {
			result.AIStatus = "unavailable"
		}
		d.recordFallback()
		slog.Warn("scan used rules-only fallback", "ai_status", result.AIStatus)
		return result
	}
	result.AIStatus = "completed"
	result.AnalysisMode = "hybrid"
	result.AIAssessment = &models.AIAssessment{
		Category: string(assessment.Category), RiskScore: assessment.RiskScore, Confidence: string(assessment.Confidence),
		Explanation: assessment.Explanation, Recommendations: assessment.Recommendations,
		Indicators: make([]models.AIAssessmentIndicator, 0, len(assessment.Indicators)),
	}
	for _, indicator := range assessment.Indicators {
		result.AIAssessment.Indicators = append(result.AIAssessment.Indicators, models.AIAssessmentIndicator{Type: indicator.Type, Reason: indicator.Reason})
	}
	if result.Category == "unknown" {
		result.Category = mapAICategory(assessment.Category)
	}
	result.RiskScore = FuseRiskScore(result.RuleScore, assessment.RiskScore, assessment.Confidence, assessment.Category)
	result.FinalScore = result.RiskScore
	result.RiskLevel = detection.RiskLevel(result.FinalScore)
	result.Recommendations = mergeRecommendations(result.Recommendations, assessment.Recommendations)
	if d.stats != nil {
		d.stats.completed.Add(1)
	}
	return result
}

// FuseRiskScore lets AI raise a rule score by only a confidence-weighted share
// of the remaining gap. AI never lowers objective rule evidence and its
// indicators are not added to the separately scored rule indicators.
func FuseRiskScore(ruleScore, aiScore int, confidence ai.Confidence, category ai.Category) int {
	if ruleScore < 0 {
		ruleScore = 0
	}
	if ruleScore > 100 {
		ruleScore = 100
	}
	if aiScore < 0 {
		aiScore = 0
	}
	if aiScore > 100 {
		aiScore = 100
	}
	if category == ai.CategoryUnknown || aiScore <= ruleScore {
		return ruleScore
	}
	factor := 15
	switch confidence {
	case ai.ConfidenceMedium:
		factor = 25
	case ai.ConfidenceHigh:
		factor = 40
	}
	lift := (aiScore - ruleScore) * factor
	if lift%100 != 0 {
		lift = lift/100 + 1
	} else {
		lift /= 100
	}
	if ruleScore+lift > 100 {
		return 100
	}
	return ruleScore + lift
}

func mapAICategory(category ai.Category) string {
	switch category {
	case ai.CategoryPhishing:
		return "phishing"
	case ai.CategoryBankImpersonation:
		return "bank_impersonation"
	case ai.CategoryCredentialTheft:
		return "credential_theft"
	case ai.CategoryFakePaymentNotification:
		return "fake_payment_notification"
	case ai.CategoryInvestmentScam:
		return "investment_scam"
	case ai.CategoryJobRecruitmentScam:
		return "job_scam"
	case ai.CategoryPrizeGiveawayScam:
		return "fake_prize"
	case ai.CategoryRomanceScam:
		return "romance_scam"
	case ai.CategoryDeliveryScam:
		return "delivery_scam"
	case ai.CategoryAccountTakeoverAttempt:
		return "account_takeover"
	case ai.CategorySocialEngineering:
		return "general_social_engineering"
	default:
		return "unknown"
	}
}

func mergeRecommendations(rules, aiRecommendations []string) []string {
	seen := make(map[string]bool, len(rules)+len(aiRecommendations))
	result := make([]string, 0, len(rules)+len(aiRecommendations))
	for _, list := range [][]string{rules, aiRecommendations} {
		for _, item := range list {
			if !seen[item] {
				seen[item] = true
				result = append(result, item)
			}
		}
	}
	return result
}

func (d Detection) recordFallback() {
	if d.stats != nil {
		d.stats.fallback.Add(1)
	}
}

func (d Detection) Metrics() DetectionMetrics {
	if d.stats == nil {
		return DetectionMetrics{}
	}
	return DetectionMetrics{Requested: d.stats.requested.Load(), Completed: d.stats.completed.Load(), Fallbacks: d.stats.fallback.Load()}
}

type aiRateEntry struct {
	count int
	until time.Time
}
type AIUserRateLimiter struct {
	mu              sync.Mutex
	entries         map[string]aiRateEntry
	limit, capacity int
	window          time.Duration
	now             func() time.Time
}

func NewAIUserRateLimiter(limit int, window time.Duration) *AIUserRateLimiter {
	return &AIUserRateLimiter{entries: make(map[string]aiRateEntry), limit: limit, capacity: 10000, window: window, now: time.Now}
}

func (l *AIUserRateLimiter) Allow(userID string) bool {
	if l == nil || userID == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	entry, exists := l.entries[userID]
	if !exists || !now.Before(entry.until) {
		if len(l.entries) >= l.capacity {
			for key, current := range l.entries {
				if !now.Before(current.until) {
					delete(l.entries, key)
				}
			}
			if len(l.entries) >= l.capacity {
				return false
			}
		}
		entry = aiRateEntry{until: now.Add(l.window)}
	}
	if entry.count >= l.limit {
		return false
	}
	entry.count++
	l.entries[userID] = entry
	return true
}
