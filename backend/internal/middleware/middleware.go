package middleware

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/etoosammy01/ScamGuard-AI/backend/internal/handlers"
	"github.com/gin-gonic/gin"
)

func Security() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "no-referrer")
		c.Header("Cache-Control", "no-store")
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16*1024)
		c.Next()
	}
}
func Logging() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		slog.Info("request", "method", c.Request.Method, "route", c.FullPath(), "status", c.Writer.Status(), "duration_ms", time.Since(start).Milliseconds())
	}
}
func Recovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if recover() != nil {
				slog.Error("request panic recovered")
				handlers.Error(c, 500, "internal_error", "An internal error occurred")
			}
		}()
		c.Next()
	}
}
func CORS(origins []string) gin.HandlerFunc {
	allowed := map[string]bool{}
	for _, o := range origins {
		allowed[o] = true
	}
	return func(c *gin.Context) {
		c.Header("Vary", "Origin")
		origin := c.GetHeader("Origin")
		if origin != "" {
			if !allowed[origin] {
				handlers.Error(c, 403, "origin_denied", "Origin is not allowed")
				return
			}
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Credentials", "true")
		}
		if c.Request.Method == http.MethodOptions {
			method := c.GetHeader("Access-Control-Request-Method")
			if method != "GET" && method != "POST" && method != "PATCH" && method != "DELETE" {
				handlers.Error(c, 405, "method_not_allowed", "Method is not allowed")
				return
			}
			c.Header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Content-Type")
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}
