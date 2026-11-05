package models

import "time"

type Indicator struct {
	RuleID            string `json:"rule_id"`
	Category          string `json:"category"`
	Description       string `json:"description"`
	ScoreContribution int    `json:"score_contribution"`
}

type AIAssessmentIndicator struct {
	Type   string `json:"type"`
	Reason string `json:"reason"`
}

type AIAssessment struct {
	Category        string                  `json:"category"`
	RiskScore       int                     `json:"risk_score"`
	Confidence      string                  `json:"confidence"`
	Indicators      []AIAssessmentIndicator `json:"indicators"`
	Explanation     string                  `json:"explanation"`
	Recommendations []string                `json:"recommendations"`
}

type ScanResult struct {
	ScanID          string        `json:"scan_id"`
	ScanType        string        `json:"scan_type"`
	RiskScore       int           `json:"risk_score"`
	RiskLevel       string        `json:"risk_level"`
	Category        string        `json:"category"`
	Indicators      []Indicator   `json:"indicators"`
	Recommendations []string      `json:"recommendations"`
	AnalysisMode    string        `json:"analysis_mode"`
	AIStatus        string        `json:"ai_status"`
	RuleScore       int           `json:"rule_score"`
	FinalScore      int           `json:"final_score"`
	AIAssessment    *AIAssessment `json:"ai_assessment,omitempty"`
	CreatedAt       time.Time     `json:"created_at"`
}
