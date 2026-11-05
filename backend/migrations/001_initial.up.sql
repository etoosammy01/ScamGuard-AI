CREATE TABLE users (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 full_name text NOT NULL CHECK (length(full_name) BETWEEN 1 AND 200),
 email text NOT NULL CHECK (length(email) BETWEEN 3 AND 320),
 password_hash text NOT NULL CHECK (length(password_hash) > 0),
 role text NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email_unique ON users (lower(email));
CREATE TABLE scans (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 user_id uuid REFERENCES users(id) ON DELETE SET NULL,
 scan_type text NOT NULL CHECK (scan_type IN ('message', 'url', 'email')),
 input_text text NOT NULL CHECK (length(input_text) BETWEEN 1 AND 10000),
 risk_score smallint NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
 risk_level text NOT NULL CHECK (risk_level IN ('low', 'medium', 'high')),
 explanation text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 CONSTRAINT scans_risk_consistency CHECK (
 (risk_score < 30 AND risk_level = 'low') OR
 (risk_score BETWEEN 30 AND 69 AND risk_level = 'medium') OR
 (risk_score >= 70 AND risk_level = 'high'))
);
CREATE INDEX scans_user_created ON scans(user_id, created_at DESC);
CREATE INDEX scans_created ON scans(created_at);
CREATE FUNCTION set_updated_at() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END; $$;
CREATE TRIGGER users_updated BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION set_updated_at();
