-- Preserve the original index and rows; enforce the service normalization at the database boundary.
CREATE UNIQUE INDEX users_normalized_email_unique ON users (lower(btrim(email)));
ALTER TABLE users ADD COLUMN bio text NOT NULL DEFAULT '' CHECK (char_length(bio) <= 500);
CREATE TABLE sessions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash)=32),
 created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL,
 revoked_at timestamptz,
 CHECK (expires_at > created_at),
 CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);
CREATE INDEX sessions_user_created ON sessions(user_id, created_at DESC);
CREATE INDEX sessions_expiry ON sessions(expires_at);
