export type Indicator = { rule_id: string; category: string; description: string; score_contribution: number };
export type ScanResult = { scan_id: string; scan_type: 'message'|'url'; risk_score: number; risk_level: 'low'|'moderate'|'high'|'critical'; category: string; indicators: Indicator[]; recommendations: string[]; analysis_mode: 'rules'; created_at: string };
