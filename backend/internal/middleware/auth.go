package middleware

import (
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/etoosammy01/ScamGuard-AI/backend/internal/handlers"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/models"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/services"
	"github.com/gin-gonic/gin"
)

func RequireAuth(auth *services.Auth, cookie string) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := c.Cookie(cookie)
		if err != nil {
			handlers.Error(c, 401, "unauthenticated", "Sign in to continue")
			return
		}
		user, err := auth.Authenticate(c.Request.Context(), token)
		if err != nil {
			if errors.Is(err, services.ErrUnauthenticated) {
				handlers.Error(c, 401, "unauthenticated", "Sign in to continue")
			} else {
				handlers.Error(c, 503, "service_unavailable", "Service temporarily unavailable")
			}
			return
		}
		c.Set(models.IdentityKey, user)
		c.Next()
	}
}

// AdminOnly is separate from session authentication. No public Phase 2 route grants admin access.
func AdminOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		value, ok := c.Get(models.IdentityKey)
		if !ok {
			handlers.Error(c, 401, "unauthenticated", "Sign in to continue")
			return
		}
		user, ok := value.(models.Identity)
		if !ok || user.Role != "admin" {
			handlers.Error(c, 403, "forbidden", "Access denied")
			return
		}
		c.Next()
	}
}

// CSRF requires an exact trusted Origin on every mutation, including login and logout.
// Missing/null/duplicate Origins are rejected; Referer is not a fallback.
func CSRF(origins []string) gin.HandlerFunc {
	allowed := map[string]bool{}
	for _, origin := range origins {
		allowed[origin] = true
	}
	return func(c *gin.Context) {
		switch c.Request.Method {
		case "GET", "HEAD", "OPTIONS":
			c.Next()
			return
		}
		values := c.Request.Header.Values("Origin")
		if len(values) != 1 || !allowed[values[0]] {
			handlers.Error(c, 403, "csrf_rejected", "A trusted request origin is required")
			return
		}
		c.Next()
	}
}

type rateEntry struct {
	count int
	until time.Time
}
type RateLimiter struct {
	mu              sync.Mutex
	entries         map[string]rateEntry
	limit, capacity int
	window          time.Duration
	now             func() time.Time
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{entries: make(map[string]rateEntry), limit: limit, capacity: 10000, window: window, now: time.Now}
}
func (l *RateLimiter) allow(key string) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	entry, exists := l.entries[key]
	if !exists || !now.Before(entry.until) {
		for k, v := range l.entries {
			if !now.Before(v.until) {
				delete(l.entries, k)
			}
		}
		if len(l.entries) >= l.capacity {
			return false, int(l.window.Seconds())
		}
		entry = rateEntry{until: now.Add(l.window)}
	}
	retry := int(entry.until.Sub(now).Seconds()) + 1
	if entry.count >= l.limit {
		return false, retry
	}
	entry.count++
	l.entries[key] = entry
	return true, retry
}
func (l *RateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ok, retry := l.allow(c.ClientIP())
		if !ok {
			c.Header("Retry-After", strconv.Itoa(retry))
			handlers.Error(c, 429, "rate_limited", "Too many attempts. Try again later")
			return
		}
		c.Next()
	}
}
