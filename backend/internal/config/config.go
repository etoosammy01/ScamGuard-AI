package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Environment, Port, DatabaseURL string
	Origins                        []string
	SessionLifetime                time.Duration
	SecureCookies                  bool
}

func Load() (Config, error) { return Parse(os.Getenv) }
func Parse(get func(string) string) (Config, error) {
	c := Config{Environment: get("APP_ENV"), Port: get("PORT"), DatabaseURL: get("DATABASE_URL")}
	if c.Environment == "" {
		c.Environment = "development"
	}
	if c.Port == "" {
		c.Port = "8080"
	}
	if c.Environment != "development" && c.Environment != "test" && c.Environment != "production" {
		return c, fmt.Errorf("invalid APP_ENV")
	}
	p, e := strconv.Atoi(c.Port)
	if e != nil || p < 1 || p > 65535 {
		return c, fmt.Errorf("invalid PORT")
	}
	u, e := url.Parse(c.DatabaseURL)
	if e != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Hostname() == "" || u.Path == "" {
		return c, fmt.Errorf("invalid DATABASE_URL")
	}
	if c.Environment == "production" && u.Query().Get("sslmode") != "verify-full" {
		return c, fmt.Errorf("production DATABASE_URL requires sslmode=verify-full")
	}
	for _, raw := range strings.Split(get("CORS_ALLOWED_ORIGINS"), ",") {
		origin := strings.TrimSpace(raw)
		u, e := url.Parse(origin)
		if e != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || strings.Contains(origin, "*") || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return c, fmt.Errorf("invalid CORS_ALLOWED_ORIGINS")
		}
		if c.Environment == "production" && u.Scheme != "https" {
			return c, fmt.Errorf("production origins require HTTPS")
		}
		c.Origins = append(c.Origins, origin)
	}
	hours := 12
	if raw := get("SESSION_TTL_HOURS"); raw != "" {
		hours, e = strconv.Atoi(raw)
		if e != nil || hours < 1 || hours > 24 {
			return c, fmt.Errorf("invalid SESSION_TTL_HOURS (1-24)")
		}
	}
	c.SessionLifetime = time.Duration(hours) * time.Hour
	c.SecureCookies = c.Environment == "production"
	return c, nil
}
func (c Config) CookieName() string {
	if c.SecureCookies {
		return "__Host-scamguard_session"
	}
	return "scamguard_session"
}
