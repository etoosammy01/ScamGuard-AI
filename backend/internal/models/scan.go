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
	ScanID                   string        `json:"scan_id"`
	ScanType                 string        `json:"scan_type"`
	RiskScore                int           `json:"risk_score"`
	RiskLevel                string        `json:"risk_level"`
	Category                 string        `json:"category"`
	Indicators               []Indicator   `json:"indicators"`
	Recommendations          []string      `json:"recommendations"`
	AnalysisMode             string        `json:"analysis_mode"`
	AIStatus                 string        `json:"ai_status"`
	RuleScore                int           `json:"rule_score"`
	FinalScore               int           `json:"final_score"`
	AIAssessment             *AIAssessment `json:"ai_assessment,omitempty"`
	Explanation              string        `json:"explanation"`
	OriginalContentAvailable bool          `json:"original_content_available"`
	CreatedAt                time.Time     `json:"created_at"`
}

type ScanFilter struct {
	RiskLevel string
	ScanType  string
	Category  string
	From      *time.Time
	To        *time.Time
	Search    string
	Page      int
	PageSize  int
}

type ScanPage struct {
	Items    []ScanResult `json:"items"`
	Page     int          `json:"page"`
	PageSize int          `json:"page_size"`
	Total    int64        `json:"total"`
}

type CountByCategory struct {
	Category string `json:"category"`
	Count    int64  `json:"count"`
}
type ScanActivity struct {
	Date  string `json:"date"`
	Count int64  `json:"count"`
}
type DashboardStats struct {
	TotalScans        int64             `json:"total_scans"`
	MessageScans      int64             `json:"message_scans"`
	URLScans          int64             `json:"url_scans"`
	LowRiskScans      int64             `json:"low_risk_scans"`
	ModerateRiskScans int64             `json:"moderate_risk_scans"`
	HighRiskScans     int64             `json:"high_risk_scans"`
	CriticalRiskScans int64             `json:"critical_risk_scans"`
	ScansLast7Days    int64             `json:"scans_last_7_days"`
	ScansLast30Days   int64             `json:"scans_last_30_days"`
	AIAssistedScans   int64             `json:"ai_assisted_scans"`
	RulesOnlyScans    int64             `json:"rules_only_scans"`
	Categories        []CountByCategory `json:"categories"`
	Activity          []ScanActivity    `json:"activity"`
}
