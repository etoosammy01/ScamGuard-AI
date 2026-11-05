package config

import "testing"

func TestParse(t *testing.T) {
	valid := map[string]string{"DATABASE_URL": "postgres://app:example@localhost/app?sslmode=disable", "CORS_ALLOWED_ORIGINS": "http://localhost:3000"}
	tests := []struct {
		name, key, value string
		bad              bool
	}{
		{"session lifetime", "SESSION_TTL_HOURS", "25", true}, {"session lifetime invalid", "SESSION_TTL_HOURS", "invalid", true}, {name: "defaults"}, {"port", "PORT", "99999", true}, {"missing database", "DATABASE_URL", "", true}, {"bad database", "DATABASE_URL", "https://example.com", true}, {"wildcard", "CORS_ALLOWED_ORIGINS", "*", true}, {"wildcard hostname", "CORS_ALLOWED_ORIGINS", "https://*.example.com", true},
		{"origin path", "CORS_ALLOWED_ORIGINS", "https://example.com/path", true}, {"missing origins", "CORS_ALLOWED_ORIGINS", "", true}, {"environment", "APP_ENV", "unknown", true}, {"production TLS", "APP_ENV", "production", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := map[string]string{}
			for k, v := range valid {
				m[k] = v
			}
			if tt.key != "" {
				m[tt.key] = tt.value
			}
			_, err := Parse(func(k string) string { return m[k] })
			if (err != nil) != tt.bad {
				t.Fatalf("unexpected validation result: %v", err)
			}
		})
	}
	t.Run("production", func(t *testing.T) {
		m := map[string]string{"APP_ENV": "production", "DATABASE_URL": "postgres://app@example.com/app?sslmode=verify-full", "CORS_ALLOWED_ORIGINS": "https://app.example.com"}
		c, err := Parse(func(k string) string { return m[k] })
		if err != nil {
			t.Fatal(err)
		}
		if !c.SecureCookies || c.CookieName() != "__Host-scamguard_session" {
			t.Fatal("unsafe production cookie configuration")
		}
	})
}
