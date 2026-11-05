-- Remove legacy raw submissions while preserving existing result and ownership records.
ALTER TABLE scans DROP COLUMN input_text;
ALTER TABLE scans DROP COLUMN explanation;
ALTER TABLE scans ADD COLUMN category text NOT NULL DEFAULT 'unknown';
ALTER TABLE scans ADD COLUMN indicators jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(indicators)='array');
ALTER TABLE scans ADD CONSTRAINT scans_category_valid CHECK (category IN ('phishing','bank_impersonation','credential_theft','fake_prize','advance_fee','investment_scam','job_scam','delivery_scam','account_takeover','general_social_engineering','unknown'));
ALTER TABLE scans DROP CONSTRAINT scans_scan_type_check;
ALTER TABLE scans ADD CONSTRAINT scans_scan_type_check CHECK (scan_type IN ('message','url'));
ALTER TABLE scans DROP CONSTRAINT scans_risk_consistency;
ALTER TABLE scans DROP CONSTRAINT scans_risk_level_check;
UPDATE scans SET risk_level = CASE WHEN risk_score < 25 THEN 'low' WHEN risk_score < 50 THEN 'moderate' WHEN risk_score < 75 THEN 'high' ELSE 'critical' END;
ALTER TABLE scans ADD CONSTRAINT scans_risk_level_check CHECK (risk_level IN ('low','moderate','high','critical'));
ALTER TABLE scans ADD CONSTRAINT scans_risk_consistency CHECK ((risk_score < 25 AND risk_level='low') OR (risk_score BETWEEN 25 AND 49 AND risk_level='moderate') OR (risk_score BETWEEN 50 AND 74 AND risk_level='high') OR (risk_score >= 75 AND risk_level='critical'));
