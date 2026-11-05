package router_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/etoosammy01/ScamGuard-AI/backend/internal/config"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/models"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/repository"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/router"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/services"
	"github.com/etoosammy01/ScamGuard-AI/backend/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const origin = "http://localhost:3000"
const testPassword = "synthetic long passphrase 123"

func TestAuthenticationIntegration(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set TEST_DATABASE_URL for authentication integration tests")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	random := make([]byte, 8)
	if _, err = rand.Read(random); err != nil {
		t.Fatal(err)
	}
	schema := "auth_test_" + hex.EncodeToString(random)
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE")
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
	passwords, err := services.NewPasswords()
	if err != nil {
		t.Fatal(err)
	}
	service := &services.Auth{Store: &repository.Accounts{DB: pool}, Passwords: passwords, Lifetime: 12 * time.Hour}
	configuration := config.Config{SessionLifetime: 12 * time.Hour}
	newApp := func() http.Handler {
		return router.New(pool, []string{origin}, router.AuthOptions{Service: service, Config: configuration, ScanStore: &repository.Scans{DB: pool}, ScanService: services.Detection{}})
	}
	app := newApp()
	request := func(handler http.Handler, method, path, body, requestOrigin string, cookie *http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.RemoteAddr = "192.0.2.1:1234"
		if requestOrigin != "" {
			req.Header.Set("Origin", requestOrigin)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		handler.ServeHTTP(w, req)
		return w
	}
	payload := func(email string) string {
		return fmt.Sprintf(`{"full_name":"Test User","email":%q,"password":%q,"confirm_password":%q}`, email, testPassword, testPassword)
	}
	login := func(handler http.Handler, email, password string, old *http.Cookie) *httptest.ResponseRecorder {
		return request(handler, "POST", "/api/v1/auth/login", fmt.Sprintf(`{"email":%q,"password":%q}`, email, password), origin, old)
	}
	requireCode := func(w *httptest.ResponseRecorder, code int) {
		t.Helper()
		if w.Code != code {
			t.Fatalf("HTTP %d want %d: %s", w.Code, code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "password_hash") || strings.Contains(w.Body.String(), "$argon2id$") || strings.Contains(w.Body.String(), "token_hash") {
			t.Fatal("secret leaked")
		}
	}
	var cookie *http.Cookie
	var user models.User
	t.Run("register normalized standard user and generic duplicate", func(t *testing.T) {
		first := request(app, "POST", "/api/v1/auth/register", payload(" Test@Example.COM "), origin, nil)
		requireCode(first, 202)
		duplicate := request(app, "POST", "/api/v1/auth/register", payload("test@example.com"), origin, nil)
		requireCode(duplicate, 202)
		if first.Body.String() != duplicate.Body.String() || len(first.Result().Cookies()) != 0 {
			t.Fatal("registration enumerates accounts or creates a session")
		}
		var count int
		var role, email, hash string
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM users").Scan(&count); err != nil || count != 1 {
			t.Fatal(count, err)
		}
		if err := pool.QueryRow(ctx, "SELECT role,email,password_hash FROM users").Scan(&role, &email, &hash); err != nil {
			t.Fatal(err)
		}
		if role != "user" || email != "test@example.com" || hash == testPassword {
			t.Fatal("unsafe account storage")
		}
		if _, err := pool.Exec(ctx, "INSERT INTO users(full_name,email,password_hash) VALUES($1,$2,$3)", "Another Test", "  TEST@EXAMPLE.COM  ", hash); err == nil {
			t.Fatal("normalized email uniqueness was not enforced by PostgreSQL")
		}

	})
	t.Run("invalid registration and role escalation", func(t *testing.T) {
		for _, body := range []string{
			`{}`, `{"full_name":" ","email":"bad","password":"short","confirm_password":"different"}`,
			strings.TrimSuffix(payload("role@example.com"), "}") + `,"role":"admin"}`,
			strings.Replace(payload("mismatch@example.com"), `"confirm_password":"`+testPassword+`"`, `"confirm_password":"different"`, 1),
			strings.Replace(payload("large@example.com"), "Test User", strings.Repeat("x", 17000), 1),
			payload("valid@example.com") + `{}`,
		} {
			requireCode(request(newApp(), "POST", "/api/v1/auth/register", body, origin, nil), 400)
		}
	})
	t.Run("csrf protects login register logout and profile", func(t *testing.T) {
		for _, path := range []string{"/auth/register", "/auth/login", "/auth/logout", "/users/me"} {
			method := "POST"
			if path == "/users/me" {
				method = "PATCH"
			}
			for _, badOrigin := range []string{"", "null", "https://evil.example"} {
				requireCode(request(app, method, "/api/v1"+path, `{}`, badOrigin, nil), 403)
			}
		}
	})
	t.Run("login generic failures", func(t *testing.T) {
		bad := login(app, "test@example.com", "incorrect long password", nil)
		requireCode(bad, 401)
		unknown := login(app, "unknown@example.com", "incorrect long password", nil)
		requireCode(unknown, 401)
		if bad.Body.String() != unknown.Body.String() {
			t.Fatal("login enumerates email")
		}
		requireCode(login(app, `' OR 1=1 --`, testPassword, nil), 401)
	})
	t.Run("login creates opaque hashed session", func(t *testing.T) {
		w := login(app, "TEST@example.com", testPassword, nil)
		requireCode(w, 200)
		cookies := w.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatal("missing session cookie")
		}
		cookie = cookies[0]
		if !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Secure || cookie.Path != "/" || cookie.MaxAge != 43200 || len(cookie.Value) != 43 {
			t.Fatal("unsafe development cookie")
		}
		var body struct {
			User models.User `json:"user"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		user = body.User
		var hash []byte
		if err := pool.QueryRow(ctx, "SELECT token_hash FROM sessions WHERE user_id=$1", user.ID).Scan(&hash); err != nil {
			t.Fatal(err)
		}
		expected := sha256.Sum256([]byte(cookie.Value))
		if hex.EncodeToString(hash) != hex.EncodeToString(expected[:]) {
			t.Fatal("token was not hashed")
		}
	})
	t.Run("profile requires session and permits only own safe fields", func(t *testing.T) {
		for _, path := range []string{"/api/v1/auth/me", "/api/v1/users/me"} {
			requireCode(request(app, "GET", path, "", "", nil), 401)
			requireCode(request(app, "GET", path, "", "", cookie), 200)
		}
		for _, body := range []string{`{"role":"admin"}`, `{"email":"change@example.com"}`, `{"id":"someone-else"}`, `{"password_hash":"malicious"}`, `{"created_at":"yesterday"}`, `{"bio":"` + strings.Repeat("x", 501) + `"}`} {
			requireCode(request(app, "PATCH", "/api/v1/users/me", body, origin, cookie), 400)
		}
		updated := request(app, "PATCH", "/api/v1/users/me", `{"full_name":"Updated Name","bio":"Synthetic bio"}`, origin, cookie)
		requireCode(updated, 200)
		if !strings.Contains(updated.Body.String(), "Updated Name") {
			t.Fatal("profile not updated")
		}
		var role string
		if err := pool.QueryRow(ctx, "SELECT role FROM users WHERE id=$1", user.ID).Scan(&role); err != nil || role != "user" {
			t.Fatal("role escalated")
		}
	})
	t.Run("scan endpoints authenticate, verify origin, persist only owner's results, and rate limit", func(t *testing.T) {
		const path = "/api/v1/scans/message"
		body := `{"content":"URGENT: Your bank account has been suspended. Verify your password at https://secure-login.invalid/verify"}`
		requireCode(request(app, "POST", path, body, origin, nil), 401)
		requireCode(request(app, "POST", path, body, "https://evil.example", cookie), 403)
		created := request(app, "POST", path, body, origin, cookie)
		requireCode(created, 201)
		if !strings.Contains(created.Body.String(), `"analysis_mode":"rules"`) || !strings.Contains(created.Body.String(), `"risk_level":"critical"`) {
			t.Fatalf("unexpected scan result: %s", created.Body.String())
		}
		var ownerCount int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM scans WHERE user_id=$1", user.ID).Scan(&ownerCount); err != nil || ownerCount != 1 {
			t.Fatal("scan result was not stored for authenticated owner", ownerCount, err)
		}
		urlScan := request(app, "POST", "/api/v1/scans/url", `{"url":"https://paypal-example.com/login"}`, origin, cookie)
		requireCode(urlScan, 201)
		if !strings.Contains(urlScan.Body.String(), `"rule_id":"brand_domain_mimic"`) {
			t.Fatalf("URL rule was not returned: %s", urlScan.Body.String())
		}
		for i := 0; i < 20; i++ {
			status := request(app, "POST", path, `{"content":"A routine message."}`, origin, cookie)
			want := 201
			if i >= 18 {
				want = 429
			}
			requireCode(status, want)
		}
	})
	t.Run("history, dashboard, export, and deletion remain owner-scoped", func(t *testing.T) {
		requireCode(request(app, "GET", "/api/v1/scans", "", "", nil), 401)
		requireCode(request(app, "GET", "/api/v1/dashboard/stats", "", "", nil), 401)
		listed := request(app, "GET", "/api/v1/scans?page=1&page_size=1", "", "", cookie)
		requireCode(listed, 200)
		var page struct {
			Items []struct {
				ScanID string `json:"scan_id"`
			} `json:"items"`
			Total int `json:"total"`
		}
		if err := json.Unmarshal(listed.Body.Bytes(), &page); err != nil || len(page.Items) != 1 || page.Total != 20 {
			t.Fatalf("pagination returned unexpected history: %+v %v", page, err)
		}
		id := page.Items[0].ScanID
		stats := request(app, "GET", "/api/v1/dashboard/stats", "", "", cookie)
		requireCode(stats, 200)
		if !strings.Contains(stats.Body.String(), `"total_scans":20`) || !strings.Contains(stats.Body.String(), `"activity":[`) {
			t.Fatalf("unexpected real dashboard stats: %s", stats.Body.String())
		}
		requireCode(request(app, "GET", "/api/v1/scans/"+id, "", "", cookie), 200)
		requireCode(request(app, "GET", "/api/v1/scans/00000000-0000-0000-0000-000000000000", "", "", cookie), 404)
		exported := request(app, "GET", "/api/v1/scans/export", "", "", cookie)
		requireCode(exported, 200)
		rows, err := csv.NewReader(strings.NewReader(exported.Body.String())).ReadAll()
		if err != nil || len(rows) != 21 || rows[0][0] != "Scan ID" {
			t.Fatalf("invalid metadata export: rows=%d err=%v", len(rows), err)
		}
		requireCode(request(app, "DELETE", "/api/v1/scans/"+id, "", "https://evil.example", cookie), 403)
		requireCode(request(app, "DELETE", "/api/v1/scans/"+id, "", origin, cookie), 204)
		stats = request(app, "GET", "/api/v1/dashboard/stats", "", "", cookie)
		if !strings.Contains(stats.Body.String(), `"total_scans":19`) {
			t.Fatalf("deleted scan remained in dashboard: %s", stats.Body.String())
		}
		bulk := request(app, "DELETE", "/api/v1/scans", "", origin, cookie)
		requireCode(bulk, 200)
		var count struct {
			Deleted int `json:"deleted"`
		}
		if err := json.Unmarshal(bulk.Body.Bytes(), &count); err != nil || count.Deleted != 19 {
			t.Fatalf("bulk delete count=%+v err=%v", count, err)
		}
		stats = request(app, "GET", "/api/v1/dashboard/stats", "", "", cookie)
		if !strings.Contains(stats.Body.String(), `"total_scans":0`) {
			t.Fatalf("bulk-deleted scans remained in dashboard: %s", stats.Body.String())
		}
	})
	t.Run("fresh login rotates current session", func(t *testing.T) {
		w := login(app, "test@example.com", testPassword, cookie)
		requireCode(w, 200)
		requireCode(request(app, "GET", "/api/v1/auth/me", "", "", cookie), 401)
		newCookie := w.Result().Cookies()[0]
		if newCookie.Value == cookie.Value {
			t.Fatal("session fixation")
		}
		cookie = newCookie
	})
	t.Run("logout revokes and clears cookie", func(t *testing.T) {
		w := request(app, "POST", "/api/v1/auth/logout", "", origin, cookie)
		requireCode(w, 204)
		if w.Result().Cookies()[0].MaxAge != -1 {
			t.Fatal("cookie not cleared")
		}
		requireCode(request(app, "GET", "/api/v1/auth/me", "", "", cookie), 401)
		requireCode(request(app, "POST", "/api/v1/auth/logout", "", origin, nil), 204)
		var revoked bool
		hash, _ := services.TokenHash(cookie.Value)
		if err := pool.QueryRow(ctx, "SELECT revoked_at IS NOT NULL FROM sessions WHERE token_hash=$1", hash).Scan(&revoked); err != nil || !revoked {
			t.Fatal("session not revoked")
		}
	})
	t.Run("expired and forged sessions rejected", func(t *testing.T) {
		raw := make([]byte, 32)
		_, _ = rand.Read(raw)
		token := base64.RawURLEncoding.EncodeToString(raw)
		hash, _ := services.TokenHash(token)
		if _, err := pool.Exec(ctx, "INSERT INTO sessions(user_id,token_hash,created_at,expires_at) VALUES($1,$2,now()-interval '2 hours',now()-interval '1 hour')", user.ID, hash); err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{token, "not-a-token", base64.RawURLEncoding.EncodeToString(make([]byte, 32))} {
			requireCode(request(app, "GET", "/api/v1/auth/me", "", "", &http.Cookie{Name: cookie.Name, Value: value}), 401)
		}
	})
	t.Run("rate limit ignores spoofed forwarded ip", func(t *testing.T) {
		limited := newApp()
		for i := 0; i < 11; i++ {
			req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{}`))
			req.Header.Set("Origin", origin)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", i))
			req.RemoteAddr = "192.0.2.2:1234"
			w := httptest.NewRecorder()
			limited.ServeHTTP(w, req)
			want := 401
			if i == 10 {
				want = 429
				if w.Header().Get("Retry-After") == "" {
					t.Fatal("missing retry")
				}
			}
			requireCode(w, want)
		}
	})
	t.Run("credentialed cors preflight", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/api/v1/users/me", nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "PATCH")
		w := httptest.NewRecorder()
		app.ServeHTTP(w, req)
		requireCode(w, 204)
		if w.Header().Get("Access-Control-Allow-Credentials") != "true" || w.Header().Get("Access-Control-Allow-Origin") != origin {
			t.Fatal("invalid credentialed CORS")
		}
	})
	t.Run("production host cookie and session cap", func(t *testing.T) {
		production := configuration
		production.SecureCookies = true
		secureApp := router.New(pool, []string{origin}, router.AuthOptions{Service: service, Config: production})
		for i := 0; i < 6; i++ {
			w := login(secureApp, "test@example.com", testPassword, nil)
			requireCode(w, 200)
			c := w.Result().Cookies()[0]
			if !c.Secure || c.Name != "__Host-scamguard_session" || c.Domain != "" {
				t.Fatal("unsafe production cookie")
			}
		}
		var count int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM sessions WHERE user_id=$1 AND revoked_at IS NULL AND expires_at>now()", user.ID).Scan(&count); err != nil || count != 5 {
			t.Fatal("missing session cap", count, err)
		}
	})
	t.Run("migration rollback preserves accounts", func(t *testing.T) {
		conn, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Release()
		if err = migrations.Apply(ctx, conn.Conn(), "down"); err != nil {
			t.Fatal(err)
		}
		var count int
		if err = pool.QueryRow(ctx, "SELECT count(*) FROM users WHERE id=$1", user.ID).Scan(&count); err != nil || count != 1 {
			t.Fatal("rollback deleted account")
		}
		if err = migrations.Apply(ctx, conn.Conn(), "up"); err != nil {
			t.Fatal(err)
		}
	})
}
