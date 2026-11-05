package detection

import (
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/models"
	"sort"
)

const maxScore = 100

type Finding struct {
	ID           string
	Category     string
	Description  string
	Weight       int
	Group        string
	ScamCategory string
	Priority     int
}

func score(findings []Finding) (int, []models.Indicator) {
	// Keep only the strongest signal in each correlated group.
	grouped := map[string]Finding{}
	for _, f := range findings {
		old, ok := grouped[f.Group]
		if !ok || f.Weight > old.Weight {
			grouped[f.Group] = f
		}
	}
	selected := make([]Finding, 0, len(grouped))
	for _, f := range grouped {
		selected = append(selected, f)
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].ID < selected[j].ID })
	score := 0
	indicators := make([]models.Indicator, 0, len(selected))
	for _, f := range selected {
		score += f.Weight
		indicators = append(indicators, models.Indicator{RuleID: f.ID, Category: f.Category, Description: f.Description, ScoreContribution: f.Weight})
	}
	if score > maxScore {
		score = maxScore
	}
	return score, indicators
}
func RiskLevel(score int) string {
	switch {
	case score < 0:
		return "low"
	case score < 25:
		return "low"
	case score < 50:
		return "moderate"
	case score < 75:
		return "high"
	default:
		return "critical"
	}
}
func Categories(findings []Finding) []string {
	seen := map[string]bool{}
	for _, f := range findings {
		if f.ScamCategory != "" {
			seen[f.ScamCategory] = true
		}
	}
	result := make([]string, 0, len(seen))
	for category := range seen {
		result = append(result, category)
	}
	sort.Strings(result)
	if len(result) == 0 {
		return []string{"unknown"}
	}
	return result
}
func recommendations(findings []Finding) []string {
	seen := map[int]string{}
	for _, f := range findings {
		if f.ScamCategory == "credential_theft" || f.ScamCategory == "account_takeover" {
			seen[1] = "Do not share your password or OTP."
		}
		if f.ScamCategory == "advance_fee" || f.ScamCategory == "fake_prize" {
			seen[2] = "Do not pay an unexpected fee to claim money or a prize."
		}
		if f.ScamCategory == "phishing" || f.ScamCategory == "bank_impersonation" {
			seen[3] = "Verify the request through an official channel you find independently."
		}
		if f.ScamCategory == "investment_scam" {
			seen[4] = "Research the provider independently and be wary of guaranteed returns."
		}
		if f.ScamCategory == "job_scam" {
			seen[5] = "Verify the employer and never pay to receive a job."
		}
		if f.ScamCategory == "delivery_scam" {
			seen[6] = "Check delivery notices in the carrier’s official app or website."
		}
		if f.ScamCategory == "general_social_engineering" {
			seen[7] = "Pause and confirm unexpected requests using a separate trusted channel."
		}
		if f.Category == "suspicious_link" {
			seen[8] = "Do not open the embedded link; navigate to the official site yourself."
		}
	}
	if len(Categories(findings)) == 1 && Categories(findings)[0] == "unknown" {
		seen[9] = "A low score cannot guarantee safety. Stay cautious with unexpected requests."
		if len(findings) > 0 {
			seen[11] = "Structural URL patterns alone do not establish maliciousness; verify the destination independently."
		}
	}
	seen[10] = "A rule-based assessment can miss threats or flag benign content."
	keys := make([]int, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	result := make([]string, 0, len(keys))
	for _, k := range keys {
		result = append(result, seen[k])
	}
	return result
}
func buildResult(scanType string, findings []Finding) models.ScanResult {
	score, indicators := score(findings)
	return models.ScanResult{ScanType: scanType, RiskScore: score, RiskLevel: RiskLevel(score), Category: primaryCategory(findings), Indicators: indicators, Recommendations: recommendations(findings), AnalysisMode: "rules"}
}
func primaryCategory(findings []Finding) string {
	categories := Categories(findings)
	if len(categories) == 0 {
		return "unknown"
	}
	priority := map[string]int{"credential_theft": 1, "account_takeover": 2, "bank_impersonation": 3, "phishing": 4, "advance_fee": 5, "fake_prize": 6, "investment_scam": 7, "job_scam": 8, "delivery_scam": 9, "general_social_engineering": 10, "unknown": 99}
	best := categories[0]
	for _, c := range categories[1:] {
		if priority[c] < priority[best] {
			best = c
		}
	}
	return best
}
