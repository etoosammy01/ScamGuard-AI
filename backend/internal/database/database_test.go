package database

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestSchemaIntegration(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set TEST_DATABASE_URL for PostgreSQL integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var id string
	if err = tx.QueryRow(ctx, "INSERT INTO users(full_name,email,password_hash) VALUES($1,$2,$3) RETURNING id", "Test User", "schema-test@example.invalid", "test-fixture-not-a-password").Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, "INSERT INTO scans(user_id,scan_type,input_text,risk_score,risk_level,explanation) VALUES($1,$2,$3,$4,$5,$6)", id, "message", "synthetic test input", 90, "high", "test fixture"); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, "DELETE FROM users WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
	var orphan bool
	if err = tx.QueryRow(ctx, "SELECT user_id IS NULL FROM scans WHERE input_text=$1", "synthetic test input").Scan(&orphan); err != nil || !orphan {
		t.Fatalf("foreign key: %v %v", orphan, err)
	}
	// A savepoint isolates the expected constraint failure from other checks.
	for _, sql := range []string{
		"INSERT INTO scans(scan_type,input_text,risk_score,risk_level,explanation) VALUES('message','synthetic',101,'high','test')",
		"INSERT INTO scans(scan_type,input_text,risk_score,risk_level,explanation) VALUES('message','synthetic',10,'high','test')",
		"INSERT INTO users(full_name,email,password_hash,role) VALUES('Test','invalid@example.invalid','fixture','superuser')",
	} {
		if _, err = tx.Exec(ctx, "SAVEPOINT constraint_check"); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, sql); err == nil {
			t.Fatal("invalid row accepted")
		}
		if _, err = tx.Exec(ctx, "ROLLBACK TO SAVEPOINT constraint_check"); err != nil {
			t.Fatal(err)
		}
	}
}
