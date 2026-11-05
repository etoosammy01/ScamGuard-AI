package database

import (
	"context"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/models"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/repository"
	"github.com/etoosammy01/ScamGuard-AI/backend/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"strings"
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
	for _, direction := range []string{"up", "up", "up", "up", "up"} {
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
	result := models.ScanResult{ScanType: "message", RiskScore: 30, RiskLevel: "moderate", Category: "phishing", Indicators: []models.Indicator{{RuleID: "fixture", Category: "url", Description: "synthetic fixture", ScoreContribution: 30}}, Recommendations: []string{"Verify independently."}, AnalysisMode: "rules", AIStatus: "not_requested", RuleScore: 30, FinalScore: 30}
	created, err := store.Create(ctx, userID, result)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Get(ctx, userID, created.ScanID)
	if err != nil || len(loaded.Indicators) != 1 || len(loaded.Recommendations) != 1 || loaded.Explanation == "" || loaded.OriginalContentAvailable || loaded.RiskScore != 30 || loaded.RuleScore != 30 || loaded.AIStatus != "not_requested" {
		t.Fatal(loaded, err)
	}
	if _, err = store.Get(ctx, userID, created.ScanID); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Get(ctx, "00000000-0000-0000-0000-000000000000", created.ScanID); err == nil {
		t.Fatal("cross-user scan access accepted")
	}
	page, err := store.List(ctx, userID, models.ScanFilter{Page: 1, PageSize: 20})
	if err != nil || page.Total != 1 || len(page.Items) != 1 {
		t.Fatal(page, err)
	}
	page, err = store.List(ctx, "00000000-0000-0000-0000-000000000000", models.ScanFilter{Page: 1, PageSize: 20})
	if err != nil || page.Total != 0 || len(page.Items) != 0 {
		t.Fatal("cross-user list leak", page, err)
	}
	stats, err := store.Stats(ctx, userID)
	if err != nil || stats.TotalScans != 1 || stats.MessageScans != 1 || len(stats.Activity) != 30 {
		t.Fatal("stats mismatch", stats, err)
	}
	deleted, err := store.DeleteAll(ctx, "00000000-0000-0000-0000-000000000000")
	if err != nil || deleted != 0 {
		t.Fatal("cross-user deletion", deleted, err)
	}
	if err = store.Delete(ctx, "00000000-0000-0000-0000-000000000000", created.ScanID); err == nil {
		t.Fatal("cross-user single deletion accepted")
	}
	if _, err = store.Get(ctx, userID, created.ScanID); err != nil {
		t.Fatal(err)
	}
	if err = store.Delete(ctx, userID, created.ScanID); err != nil {
		t.Fatal(err)
	}
	stats, err = store.Stats(ctx, userID)
	if err != nil || stats.TotalScans != 0 {
		t.Fatal("deleted scan still counted", stats, err)
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
		if c == "input_text" {
			t.Fatalf("raw content column persists: %s", c)
		}
	}
	if strings.Contains(loaded.Explanation, "synthetic fixture") {
		t.Fatal("raw scan content leaked into persisted explanation")
	}
}
