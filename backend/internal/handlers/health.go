package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type Pinger interface{ Ping(context.Context) error }

func Error(c *gin.Context, status int, code, message string) {
	c.AbortWithStatusJSON(status, gin.H{"error": gin.H{"code": code, "message": message}})
}
func Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "scamguard-api", "version": "1.0.0"})
}
func Ready(db Pinger) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()
		if db == nil {
			Error(c, 503, "database_unavailable", "Service is not ready")
			return
		}
		if err := db.Ping(ctx); err != nil {
			Error(c, 503, "database_unavailable", "Service is not ready")
			return
		}
		c.JSON(200, gin.H{"status": "ready"})
	}
}
