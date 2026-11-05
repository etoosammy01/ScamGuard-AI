export type Indicator = { rule_id: string; category: string; description: string; score_contribution: number };
export type AIAssessment = { category: string; risk_score: number; confidence: 'low'|'medium'|'high'; indicators: { type: string; reason: string }[]; explanation: string; recommendations: string[] };
export type ScanResult = {
 scan_id: string; scan_type: 'message'|'url'; risk_score: number; risk_level: 'low'|'moderate'|'high'|'critical'; category: string;
 indicators: Indicator[]; recommendations: string[]; analysis_mode: 'rules'|'hybrid'; ai_status: 'not_requested'|'disabled'|'completed'|'unavailable'|'validation_failed'|'rate_limited';
 rule_score: number; final_score: number; ai_assessment?: AIAssessment; created_at: string;
};
