package models

import "time"

type Indicator struct {
	RuleID            string `json:"rule_id"`
	Category          string `json:"category"`
	Description       string `json:"description"`
	ScoreContribution int    `json:"score_contribution"`
}
type ScanResult struct {
	ScanID          string      `json:"scan_id"`
	ScanType        string      `json:"scan_type"`
	RiskScore       int         `json:"risk_score"`
	RiskLevel       string      `json:"risk_level"`
	Category        string      `json:"category"`
	Indicators      []Indicator `json:"indicators"`
	Recommendations []string    `json:"recommendations"`
	AnalysisMode    string      `json:"analysis_mode"`
	CreatedAt       time.Time   `json:"created_at"`
}
