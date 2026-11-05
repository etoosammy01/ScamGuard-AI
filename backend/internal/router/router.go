package router

import (
	"net/http"
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
	}
	r.NoRoute(func(c *gin.Context) { handlers.Error(c, 404, "not_found", "Resource not found") })
	timed := http.TimeoutHandler(r, 5*time.Second, `{"error":{"code":"request_timeout","message":"Request timed out"}}`)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		timed.ServeHTTP(w, req)
	})
}
