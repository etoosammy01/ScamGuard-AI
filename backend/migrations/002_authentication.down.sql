DROP TABLE sessions;
ALTER TABLE users DROP COLUMN bio;
DROP INDEX users_normalized_email_unique;
