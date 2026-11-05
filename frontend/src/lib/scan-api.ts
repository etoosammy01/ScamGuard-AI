import { authRequest } from '@/lib/auth-api';
import type { ScanResult } from '@/types/scan';
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
export async function submitScan(type: 'message'|'url', input: string): Promise<ScanResult> {
 const body = type === 'message' ? { content: input } : { url: input };
 const path = type === 'message' ? '/api/v1/scans/message' : '/api/v1/scans/url';
 const data = await authRequest(path, { method: 'POST', body: JSON.stringify(body) });
 if (!data || typeof data !== 'object' || !('result' in data)) throw new Error('The scan service returned an invalid result.');
 const result=data.result as ScanResult;
 const expectedLevel = result?.risk_score < 25 ? 'low' : result?.risk_score < 50 ? 'moderate' : result?.risk_score < 75 ? 'high' : 'critical';
 if (!result || result.scan_type!==type || typeof result.scan_id!=='string' || !result.scan_id || typeof result.category!=='string' || !Number.isInteger(result.risk_score) || result.risk_score<0 || result.risk_score>100 || result.risk_level!==expectedLevel || !Array.isArray(result.indicators) || result.indicators.some(item => !item || typeof item.rule_id!=='string' || !item.rule_id || typeof item.category!=='string' || typeof item.description!=='string' || !Number.isInteger(item.score_contribution) || item.score_contribution<0 || item.score_contribution>100) || !Array.isArray(result.recommendations) || result.recommendations.some(item => typeof item!=='string') || typeof result.created_at!=='string' || result.analysis_mode!=='rules') throw new Error('The scan service returned an invalid result.');
 return result;
}
