ALTER TABLE users ADD COLUMN status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','suspended'));
CREATE TABLE audit_logs (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), actor_user_id uuid, action text NOT NULL,
 target_type text NOT NULL, target_id text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now(),
 outcome text NOT NULL CHECK(outcome IN ('success','denied')), metadata jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_logs_created ON audit_logs(created_at DESC,id DESC);
CREATE INDEX scans_platform_created ON scans(created_at);
CREATE INDEX users_created ON users(created_at);
-- Apply equivalent grants to the dedicated runtime role; table owners can bypass ACLs.
REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM PUBLIC;
CREATE FUNCTION prevent_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'audit logs are append-only'; END;
$$;
CREATE TRIGGER audit_logs_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_logs
FOR EACH STATEMENT EXECUTE FUNCTION prevent_audit_mutation();
