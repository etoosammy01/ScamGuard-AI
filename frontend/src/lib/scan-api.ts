import { authRequest } from '@/lib/auth-api';
import type { AIAssessment, ScanResult } from '@/types/scan';

export function validateScanInput(type: 'message'|'url', input: string): string | null {
 if (!input.trim()) return type === 'message' ? 'Enter a message to analyze.' : 'Enter a URL to analyze.';
 const maximum = type === 'message' ? 10000 : 2048;
 if (new TextEncoder().encode(input).length > maximum) return `Keep the input under ${maximum.toLocaleString()} bytes.`;
 if (type === 'url') {
  try { const parsed = new URL(input.trim()); if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) throw new Error(); }
  catch { return 'Enter a complete HTTP or HTTPS URL.'; }
 }
 return null;
}

export async function submitScan(type: 'message'|'url', input: string, mode: 'rules'|'hybrid' = 'rules'): Promise<ScanResult> {
 const body = type === 'message' ? { content: input, analysis_mode: mode } : { url: input, analysis_mode: mode };
 const path = type === 'message' ? '/api/v1/scans/message' : '/api/v1/scans/url';
 const data = await authRequest(path, { method: 'POST', body: JSON.stringify(body) });
 if (!isRecord(data) || !isRecord(data.result) || !validResult(data.result, type)) throw new Error('The scan service returned an invalid result.');
 return data.result as unknown as ScanResult;
}

function validResult(value: Record<string, unknown>, type: 'message'|'url'): boolean {
 const score=value.risk_score, mode=value.analysis_mode, status=value.ai_status;
 const expectedLevel = typeof score === 'number' && score < 25 ? 'low' : typeof score === 'number' && score < 50 ? 'moderate' : typeof score === 'number' && score < 75 ? 'high' : 'critical';
 const assessment = value.ai_assessment;
 return value.scan_type===type && typeof value.scan_id==='string' && !!value.scan_id && typeof value.category==='string' &&
  Number.isInteger(score) && Number(score)>=0 && Number(score)<=100 && value.risk_level===expectedLevel &&
  Array.isArray(value.indicators) && value.indicators.every(validRuleIndicator) &&
  Array.isArray(value.recommendations) && value.recommendations.every(item=>typeof item==='string') &&
  typeof value.created_at==='string' && (mode==='rules'||mode==='hybrid') &&
  ['not_requested','disabled','completed','unavailable','validation_failed','rate_limited'].includes(String(status)) &&
  Number.isInteger(value.rule_score) && Number(value.rule_score)>=0 && Number(value.rule_score)<=100 &&
  value.final_score===score &&
  (mode!=='hybrid'||status==='completed'&&validAssessment(assessment)) &&
  (status!=='completed'||mode==='hybrid'&&validAssessment(assessment)) &&
  (assessment===undefined||validAssessment(assessment));
}
function isRecord(value: unknown): value is Record<string, unknown> { return !!value && typeof value==='object' && !Array.isArray(value); }
function validRuleIndicator(value: unknown): boolean {
 if (!isRecord(value)) return false;
 return typeof value.rule_id==='string' && !!value.rule_id && typeof value.category==='string' && typeof value.description==='string' && Number.isInteger(value.score_contribution) && Number(value.score_contribution)>=0 && Number(value.score_contribution)<=100;
}
function validAssessment(value: unknown): value is AIAssessment {
 if (!isRecord(value)) return false;
 return typeof value.category==='string' && Number.isInteger(value.risk_score) && Number(value.risk_score)>=0 && Number(value.risk_score)<=100 &&
  ['low','medium','high'].includes(String(value.confidence)) && typeof value.explanation==='string' &&
  Array.isArray(value.indicators) && value.indicators.every(item=>isRecord(item)&&typeof item.type==='string'&&typeof item.reason==='string') &&
  Array.isArray(value.recommendations) && value.recommendations.every(item=>typeof item==='string');
}
