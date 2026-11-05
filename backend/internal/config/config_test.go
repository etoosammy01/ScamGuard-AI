package config

import "testing"

func TestParse(t *testing.T) {
	valid := map[string]string{"DATABASE_URL": "postgres://app:example@localhost/app?sslmode=disable", "CORS_ALLOWED_ORIGINS": "http://localhost:3000"}
	tests := []struct {
		name, key, value string
		bad              bool
	}{
		{"session lifetime", "SESSION_TTL_HOURS", "25", true}, {"session lifetime invalid", "SESSION_TTL_HOURS", "invalid", true}, {name: "defaults"}, {"port", "PORT", "99999", true}, {"missing database", "DATABASE_URL", "", true}, {"bad database", "DATABASE_URL", "https://example.com", true}, {"wildcard", "CORS_ALLOWED_ORIGINS", "*", true}, {"wildcard hostname", "CORS_ALLOWED_ORIGINS", "https://*.example.com", true},
		{"bad AI boolean", "AI_ENABLED", "yes", true}, {"bad AI timeout", "AI_TIMEOUT_SECONDS", "31", true}, {"bad AI token limit", "AI_MAX_OUTPUT_TOKENS", "99", true},
		{"origin path", "CORS_ALLOWED_ORIGINS", "https://example.com/path", true}, {"missing origins", "CORS_ALLOWED_ORIGINS", "", true}, {"environment", "APP_ENV", "unknown", true}, {"production TLS", "APP_ENV", "production", true},
	}
	t.Run("AI disabled needs no credentials", func(t *testing.T) {
		c, err := Parse(func(k string) string { return valid[k] })
		if err != nil || c.AIEnabled || c.AITimeout.Seconds() != 15 || c.AIMaxOutputTokens != 700 {
			t.Fatalf("unexpected defaults: %+v %v", c, err)
		}
	})
	for _, key := range []string{"OPENAI_API_KEY", "OPENAI_MODEL"} {
		t.Run("AI enabled requires "+key, func(t *testing.T) {
			m := map[string]string{}
			for k, v := range valid {
				m[k] = v
			}
			m["AI_ENABLED"] = "true"
			m["OPENAI_API_KEY"] = "key"
			m["OPENAI_MODEL"] = "model"
			delete(m, key)
			if _, err := Parse(func(k string) string { return m[k] }); err == nil {
				t.Fatalf("missing %s accepted", key)
			}
		})
	}
	t.Run("AI configured", func(t *testing.T) {
		m := map[string]string{}
		for k, v := range valid {
			m[k] = v
		}
		m["AI_ENABLED"] = "true"
		m["OPENAI_API_KEY"] = "backend-only"
		m["OPENAI_MODEL"] = "configured-model"
		c, err := Parse(func(k string) string { return m[k] })
		if err != nil || !c.AIEnabled || c.OpenAIModel != "configured-model" {
			t.Fatalf("unexpected config: %+v %v", c, err)
		}
	})
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
