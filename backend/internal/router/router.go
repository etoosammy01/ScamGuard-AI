package router

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/etoosammy01/ScamGuard-AI/backend/internal/config"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/handlers"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/middleware"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/repository"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/services"
	"github.com/gin-gonic/gin"
)

type AuthOptions struct {
	ScanStore   *repository.Scans
	ScanService handlers.ScanService
	Service     *services.Auth
	Config      config.Config
}

func New(db handlers.Pinger, origins []string, options ...AuthOptions) http.Handler {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	_ = r.SetTrustedProxies(nil)
	r.Use(middleware.Logging(), middleware.Recovery(), middleware.Security(), middleware.CORS(origins), middleware.CSRF(origins))
	r.GET("/api/v1/health", handlers.Health)
	r.GET("/api/v1/health/ready", handlers.Ready(db))
	if len(options) > 0 && options[0].Service != nil {
		option := options[0]
		if option.ScanStore != nil {
			auditStore := &repository.Admin{DB: option.ScanStore.DB}
			r.Use(func(c *gin.Context) {
				c.Next()
				if strings.HasPrefix(c.Request.URL.Path, "/api/v1/admin/") && c.Writer.Status() == http.StatusUnauthorized {
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					if err := auditStore.Audit(ctx, "", "admin_access_denied", "", "denied"); err != nil {
						slog.Warn("anonymous admin denial audit failed")
					}
				}
			})
		}
		auth := &handlers.Auth{Service: option.Service, Config: option.Config}
		limiter := middleware.NewRateLimiter(10, 15*time.Minute)
		r.POST("/api/v1/auth/register", limiter.Middleware(), auth.Register)
		r.POST("/api/v1/auth/login", limiter.Middleware(), auth.Login)
		r.POST("/api/v1/auth/logout", auth.Logout)
		protected := r.Group("/api/v1", middleware.RequireAuth(option.Service, option.Config.CookieName()))
		protected.GET("/auth/me", auth.Me)
		protected.GET("/users/me", auth.Me)
		protected.PATCH("/users/me", auth.UpdateProfile)
		if option.ScanStore != nil && option.ScanService != nil {
			scans := &handlers.ScanHandler{Store: option.ScanStore, Service: option.ScanService}
			limiter := middleware.NewUserRateLimiter(20, time.Hour)
			protected.POST("/scans/message", limiter.Middleware(), scans.Message)
			protected.POST("/scans/url", limiter.Middleware(), scans.URL)
		}
		if option.ScanStore != nil {
			history := &handlers.ScanHistory{Store: option.ScanStore}
			protected.GET("/dashboard/stats", history.Stats)
			protected.GET("/scans", history.List)
			protected.GET("/scans/export", middleware.NewUserRateLimiter(5, time.Hour).Middleware(), history.Export)
			protected.DELETE("/scans", history.DeleteAll)
			protected.GET("/scans/:id", history.Get)
			protected.GET("/scans/:id/report", middleware.NewUserRateLimiter(5, time.Hour).Middleware(), history.Report)
			admin := &handlers.AdminHandler{Store: &repository.Admin{DB: option.ScanStore.DB}, Started: time.Now(), AIEnabled: option.Config.AIEnabled}
			a := protected.Group("/admin", admin.Authorize)
			a.GET("/overview", admin.Overview)
			a.GET("/users", admin.Users)
			a.GET("/users/:id", admin.User)
			a.PATCH("/users/:id/status", admin.Status)
			a.GET("/analytics", admin.Analytics)
			a.GET("/audit-logs", admin.AuditLogs)
			a.GET("/settings", admin.Settings)
			protected.DELETE("/scans/:id", history.Delete)
		}
	}
	r.NoRoute(func(c *gin.Context) { handlers.Error(c, 404, "not_found", "Resource not found") })
	requestTimeout := 5 * time.Second
	if len(options) > 0 && options[0].Config.AITimeout > 0 {
		requestTimeout = options[0].Config.AITimeout + 3*time.Second
	}
	timed := http.TimeoutHandler(r, requestTimeout, `{"error":{"code":"request_timeout","message":"Request timed out"}}`)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		timed.ServeHTTP(w, req)
	})
}
