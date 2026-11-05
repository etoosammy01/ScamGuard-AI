package database

import (
	"context"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/models"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/repository"
	"github.com/etoosammy01/ScamGuard-AI/backend/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"testing"
	"time"
)

func TestPrivateScanPersistenceAndOwnership(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set TEST_DATABASE_URL for PostgreSQL integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	schema := "scan_test_" + time.Now().Format("150405000000")
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, direction := range []string{"up", "up", "up"} {
		if err = migrations.Apply(ctx, conn.Conn(), direction); err != nil {
			t.Fatal(err)
		}
	}
	conn.Release()
	var userID string
	if err = pool.QueryRow(ctx, "INSERT INTO users(full_name,email,password_hash) VALUES('Fixture','scan@example.invalid','not-a-password') RETURNING id").Scan(&userID); err != nil {
		t.Fatal(err)
	}
	store := &repository.Scans{DB: pool}
	result := models.ScanResult{ScanType: "message", RiskScore: 30, RiskLevel: "moderate", Category: "phishing", Indicators: []models.Indicator{{RuleID: "fixture", Category: "url", Description: "synthetic fixture", ScoreContribution: 30}}, AnalysisMode: "rules"}
	created, err := store.Create(ctx, userID, result)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Get(ctx, userID, created.ScanID)
	if err != nil || len(loaded.Indicators) != 1 || loaded.RiskScore != 30 {
		t.Fatal(loaded, err)
	}
	if _, err = store.Get(ctx, "another-user", created.ScanID); err == nil {
		t.Fatal("cross-user scan access accepted")
	}
	var columns []string
	rows, err := pool.Query(ctx, "SELECT column_name FROM information_schema.columns WHERE table_schema=$1 AND table_name='scans'", schema)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var c string
		if err = rows.Scan(&c); err != nil {
			t.Fatal(err)
		}
		columns = append(columns, c)
	}
	rows.Close()
	for _, c := range columns {
		if c == "input_text" || c == "explanation" {
			t.Fatalf("raw content column persists: %s", c)
		}
	}
	if err = pool.QueryRow(ctx, "SELECT count(*) FROM scans WHERE input_text::text LIKE '%synthetic fixture%'").Scan(new(int)); err == nil {
		t.Fatal("legacy raw input column remains")
	}
}
