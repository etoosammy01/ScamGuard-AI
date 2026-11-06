DROP TABLE audit_logs;
DROP FUNCTION prevent_audit_mutation();
DROP INDEX scans_platform_created;
DROP INDEX users_created;
ALTER TABLE users DROP COLUMN status;
