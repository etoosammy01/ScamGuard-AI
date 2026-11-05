-- Keep provider metadata only; submitted content and free-form AI output are never persisted.
ALTER TABLE scans ADD COLUMN analysis_mode text NOT NULL DEFAULT 'rules' CHECK (analysis_mode IN ('rules','hybrid'));
ALTER TABLE scans ADD COLUMN ai_status text NOT NULL DEFAULT 'not_requested' CHECK (ai_status IN ('not_requested','disabled','completed','unavailable','validation_failed','rate_limited'));
ALTER TABLE scans ADD COLUMN rule_score smallint NOT NULL DEFAULT 0 CHECK (rule_score BETWEEN 0 AND 100);
UPDATE scans SET rule_score = risk_score;
ALTER TABLE scans DROP CONSTRAINT scans_category_valid;
ALTER TABLE scans ADD CONSTRAINT scans_category_valid CHECK (category IN ('phishing','bank_impersonation','credential_theft','fake_payment_notification','fake_prize','advance_fee','investment_scam','job_scam','romance_scam','delivery_scam','account_takeover','general_social_engineering','unknown'));
