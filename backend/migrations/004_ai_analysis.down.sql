UPDATE scans SET category='unknown' WHERE category IN ('fake_payment_notification','romance_scam');
ALTER TABLE scans DROP CONSTRAINT scans_category_valid;
ALTER TABLE scans ADD CONSTRAINT scans_category_valid CHECK (category IN ('phishing','bank_impersonation','credential_theft','fake_prize','advance_fee','investment_scam','job_scam','delivery_scam','account_takeover','general_social_engineering','unknown'));
ALTER TABLE scans DROP COLUMN rule_score;
ALTER TABLE scans DROP COLUMN ai_status;
ALTER TABLE scans DROP COLUMN analysis_mode;
