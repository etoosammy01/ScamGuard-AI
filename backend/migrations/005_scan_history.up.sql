-- Retain only safe result metadata. No raw message, URL, or provider prose is restored.
ALTER TABLE scans ADD COLUMN recommendations jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(recommendations)='array');
ALTER TABLE scans ADD COLUMN explanation text NOT NULL DEFAULT 'Explanation unavailable for this earlier scan.' CHECK (length(explanation) <= 500);
CREATE INDEX scans_user_risk_created ON scans(user_id,risk_level,created_at DESC,id DESC);
CREATE INDEX scans_user_type_created ON scans(user_id,scan_type,created_at DESC,id DESC);
CREATE INDEX scans_user_category_created ON scans(user_id,category,created_at DESC,id DESC);
