package router_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/config"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/models"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/repository"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/router"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/services"
	"github.com/etoosammy01/ScamGuard-AI/backend/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPhase6Integration(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set TEST_DATABASE_URL for Phase 6 integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close(ctx)
	random := make([]byte, 8)
	if _, err = rand.Read(random); err != nil {
		t.Fatal(err)
	}
	schema := "phase6_" + hex.EncodeToString(random)
	ident := pgx.Identifier{schema}.Sanitize()
	if _, err = root.Exec(ctx, "CREATE SCHEMA "+ident); err != nil {
		t.Fatal(err)
	}
	defer root.Exec(context.Background(), "DROP SCHEMA "+ident+" CASCADE")
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
	err = migrations.Apply(ctx, conn.Conn(), "up")
	conn.Release()
	if err != nil {
		t.Fatal(err)
	}
	accounts := &repository.Accounts{DB: pool}
	admin := &repository.Admin{DB: pool}
	scans := &repository.Scans{DB: pool}
	var operator, user, other string
	for i, dest := range []*string{&operator, &user, &other} {
		email := []string{"admin@example.invalid", "user@example.invalid", "other@example.invalid"}[i]
		if err = pool.QueryRow(ctx, `INSERT INTO users(full_name,email,password_hash) VALUES('Fixture',$1,'fixture') RETURNING id`, email).Scan(dest); err != nil {
			t.Fatal(err)
		}
	}
	if err = admin.Provision(ctx, "admin@example.invalid", "test-operator-ticket"); err != nil {
		t.Fatal(err)
	}
	cookie := func(id string) *http.Cookie {
		t.Helper()
		b := make([]byte, 32)
		if _, e := rand.Read(b); e != nil {
			t.Fatal(e)
		}
		token := base64.RawURLEncoding.EncodeToString(b)
		hash := sha256.Sum256([]byte(token))
		if e := accounts.CreateSession(ctx, id, hash[:], nil, time.Now().Add(time.Hour)); e != nil {
			t.Fatal(e)
		}
		return &http.Cookie{Name: "scamguard_session", Value: token}
	}
	ac, uc, oc := cookie(operator), cookie(user), cookie(other)
	app := router.New(pool, []string{origin}, router.AuthOptions{Service: &services.Auth{Store: accounts}, Config: config.Config{}, ScanStore: scans})
	request := func(method, path, body string, cookie *http.Cookie, trusted bool) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if cookie != nil {
			req.AddCookie(cookie)
		}
		if trusted {
			req.Header.Set("Origin", origin)
		}
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		app.ServeHTTP(w, req)
		return w
	}
	expect := func(w *httptest.ResponseRecorder, status int) {
		t.Helper()
		if w.Code != status {
			t.Fatalf("want %d got %d: %s", status, w.Code, w.Body.String())
		}
	}
	scan, err := scans.Create(ctx, user, models.ScanResult{ScanType: "message", RiskScore: 85, RiskLevel: "critical", Category: "phishing", AnalysisMode: "rules", AIStatus: "unavailable", RuleScore: 85})
	if err != nil {
		t.Fatal(err)
	}
	reportPath := "/api/v1/scans/" + scan.ScanID + "/report"
	expect(request("GET", reportPath, "", nil, false), 401)
	expect(request("GET", reportPath, "", oc, false), 404)
	w := request("GET", reportPath, "", uc, false)
	expect(w, 200)
	if !strings.HasPrefix(w.Body.String(), "%PDF-") {
		t.Fatal("invalid PDF")
	}
	expect(request("GET", "/api/v1/scans/00000000-0000-0000-0000-000000000001/report", "", uc, false), 404)
	for _, path := range []string{"/overview", "/users", "/users/" + user, "/analytics", "/audit-logs", "/settings"} {
		expect(request("GET", "/api/v1/admin"+path, "", nil, false), 401)
		expect(request("GET", "/api/v1/admin"+path, "", uc, false), 403)
		expect(request("GET", "/api/v1/admin"+path, "", ac, false), 200)
	}
	w = request("GET", "/api/v1/admin/overview", "", ac, false)
	var overview struct {
		Metrics struct {
			Users    int `json:"total_users"`
			Scans    int `json:"total_scans"`
			Critical int `json:"critical_risk"`
		}
	}
	if json.Unmarshal(w.Body.Bytes(), &overview) != nil || overview.Metrics.Users != 3 || overview.Metrics.Scans != 1 || overview.Metrics.Critical != 1 {
		t.Fatal("incorrect aggregates", w.Body.String())
	}
	w = request("GET", "/api/v1/admin/analytics?days=7", "", ac, false)
	var analytics map[string]json.RawMessage
	if json.Unmarshal(w.Body.Bytes(), &analytics) != nil {
		t.Fatal("invalid analytics")
	}
	for _, key := range []string{"daily_scans", "weekly_scans", "risk_levels", "categories", "scan_types", "analysis_modes", "ai_statuses"} {
		var buckets []struct{ Count int }
		if json.Unmarshal(analytics[key], &buckets) != nil || len(buckets) != 1 || buckets[0].Count != 1 {
			t.Fatal("incorrect aggregate", key, w.Body.String())
		}
	}
	path := "/api/v1/admin/users/" + user + "/status"
	expect(request("PATCH", path, `{"status":"suspended"}`, ac, false), 403)
	expect(request("PATCH", path, `{"status":"suspended","role":"admin"}`, ac, true), 400)
	expect(request("PATCH", path, `{"status":"admin"}`, ac, true), 400)
	expect(request("PATCH", path, `{"status":"suspended"}`, uc, true), 403)
	expect(request("PATCH", "/api/v1/admin/users/"+operator+"/status", `{"status":"suspended"}`, ac, true), 409)
	expect(request("PATCH", path, `{"status":"suspended"}`, ac, true), 200)
	expect(request("GET", "/api/v1/auth/me", "", uc, false), 401)
	if _, _, e := accounts.Credentials(ctx, "user@example.invalid"); !errors.Is(e, repository.ErrNotFound) {
		t.Fatal("suspended credentials accepted", e)
	}
	if e := accounts.CreateSession(ctx, user, make([]byte, 32), nil, time.Now().Add(time.Hour)); !errors.Is(e, repository.ErrNotFound) {
		t.Fatal("suspended account session accepted", e)
	}
	expect(request("PATCH", path, `{"status":"active"}`, ac, true), 200)
	expect(request("GET", "/api/v1/auth/me", "", uc, false), 401)
	expect(request("GET", "/api/v1/auth/me", "", cookie(user), false), 200)
	var count int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action IN ('admin_provisioned','user_suspended','user_reactivated')`).Scan(&count); err != nil || count != 3 {
		t.Fatal("audit missing", count, err)
	}
	if e := admin.SetStatus(ctx, other, operator, "suspended"); !errors.Is(e, repository.ErrConflict) {
		t.Fatal("non-admin status mutation accepted", e)
	}
	expect(request("GET", "/api/v1/admin/analytics?days=91", "", ac, false), 400)
	expect(request("GET", "/api/v1/admin/users?page=0", "", ac, false), 400)
	expect(request("PATCH", "/api/v1/admin/settings", `{"scan_requests_per_hour":99999}`, ac, true), 404)
	// Database trigger protects append-only events even from accidental owner DML.
	if _, err = pool.Exec(ctx, `UPDATE audit_logs SET outcome='denied'`); err == nil {
		t.Fatal("audit update accepted")
	}
	if _, err = pool.Exec(ctx, `DELETE FROM audit_logs`); err == nil {
		t.Fatal("audit delete accepted")
	}
	if _, err = pool.Exec(ctx, `TRUNCATE audit_logs`); err == nil {
		t.Fatal("audit truncate accepted")
	}
	if err = admin.Provision(ctx, "other@example.invalid", "concurrency-test"); err != nil {
		t.Fatal(err)
	}
	// Two active admins concurrently trying to suspend each other must leave one active.
	outcomes := make(chan error, 2)
	go func() { outcomes <- admin.SetStatus(ctx, operator, other, "suspended") }()
	go func() { outcomes <- admin.SetStatus(ctx, other, operator, "suspended") }()
	succeeded := 0
	for i := 0; i < 2; i++ {
		e := <-outcomes
		if e == nil {
			succeeded++
		} else if !errors.Is(e, repository.ErrConflict) {
			t.Fatal(e)
		}
	}
	if succeeded != 1 {
		t.Fatal("concurrent lifecycle changes did not serialize", succeeded)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE role='admin' AND status='active'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("last-admin protection failed", count, err)
	}

}
