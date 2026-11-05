DROP INDEX scans_user_category_created;
DROP INDEX scans_user_type_created;
DROP INDEX scans_user_risk_created;
ALTER TABLE scans DROP COLUMN explanation;
ALTER TABLE scans DROP COLUMN recommendations;
