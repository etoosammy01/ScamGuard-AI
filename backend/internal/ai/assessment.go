package ai

import (
	"encoding/json"
	"errors"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/strictjson"
	"strings"
	"unicode/utf8"
)

const MaxContentBytes = 10000

var ErrInvalidOutput = errors.New("AI provider returned an invalid assessment")
var ErrUnavailable = errors.New("AI provider unavailable")

type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

type Category string

const (
	CategoryPhishing                Category = "phishing"
	CategoryBankImpersonation       Category = "bank_impersonation"
	CategoryCredentialTheft         Category = "credential_theft"
	CategoryFakePaymentNotification Category = "fake_payment_notification"
	CategoryInvestmentScam          Category = "investment_scam"
	CategoryJobRecruitmentScam      Category = "job_recruitment_scam"
	CategoryPrizeGiveawayScam       Category = "prize_giveaway_scam"
	CategoryRomanceScam             Category = "romance_scam"
	CategoryDeliveryScam            Category = "delivery_scam"
	CategoryAccountTakeoverAttempt  Category = "account_takeover_attempt"
	CategorySocialEngineering       Category = "social_engineering"
	CategoryUnknown                 Category = "unknown_or_insufficient_evidence"
)

type Indicator struct {
	Type   string `json:"type"`
	Reason string `json:"reason"`
}

type Assessment struct {
	Category        Category    `json:"category"`
	RiskScore       int         `json:"risk_score"`
	Confidence      Confidence  `json:"confidence"`
	Indicators      []Indicator `json:"indicators"`
	Explanation     string      `json:"explanation"`
	Recommendations []string    `json:"recommendations"`
}

func DecodeAssessment(raw string) (Assessment, error) {
	var a Assessment
	if len(raw) > 16000 || strictjson.Decode([]byte(raw), &a) != nil {
		return Assessment{}, ErrInvalidOutput
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &fields) != nil {
		return Assessment{}, ErrInvalidOutput
	}
	for _, key := range []string{"category", "risk_score", "confidence", "indicators", "explanation", "recommendations"} {
		v, ok := fields[key]
		if !ok || string(v) == "null" {
			return Assessment{}, ErrInvalidOutput
		}
	}
	if !a.Category.Valid() || a.RiskScore < 0 || a.RiskScore > 100 || !a.Confidence.Valid() ||
		len(a.Indicators) > 8 || len(a.Recommendations) > 6 ||
		!validText(a.Explanation, 500) || len(a.Indicators) == 0 && a.Category != CategoryUnknown && a.RiskScore > 0 {
		return Assessment{}, ErrInvalidOutput
	}
	for _, item := range a.Indicators {
		if !validText(item.Type, 40) || !validText(item.Reason, 240) {
			return Assessment{}, ErrInvalidOutput
		}
	}
	for _, recommendation := range a.Recommendations {
		if !validText(recommendation, 200) {
			return Assessment{}, ErrInvalidOutput
		}
	}
	return a, nil
}

func (c Category) Valid() bool {
	switch c {
	case CategoryPhishing, CategoryBankImpersonation, CategoryCredentialTheft, CategoryFakePaymentNotification,
		CategoryInvestmentScam, CategoryJobRecruitmentScam, CategoryPrizeGiveawayScam, CategoryRomanceScam,
		CategoryDeliveryScam, CategoryAccountTakeoverAttempt, CategorySocialEngineering, CategoryUnknown:
		return true
	default:
		return false
	}
}

func (c Confidence) Valid() bool {
	return c == ConfidenceLow || c == ConfidenceMedium || c == ConfidenceHigh
}

func validText(value string, max int) bool {
	return strings.TrimSpace(value) != "" && utf8.ValidString(value) && utf8.RuneCountInString(value) <= max
}
