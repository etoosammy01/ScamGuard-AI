package router

import (
	"net/http"
	"time"

	"github.com/etoosammy01/ScamGuard-AI/backend/internal/handlers"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/middleware"
	"github.com/gin-gonic/gin"
)

func New(db handlers.Pinger, origins []string) http.Handler {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	_ = r.SetTrustedProxies(nil)
	r.Use(middleware.Logging(), middleware.Recovery(), middleware.Security(), middleware.CORS(origins))
	r.GET("/api/v1/health", handlers.Health)
	r.GET("/api/v1/health/ready", handlers.Ready(db))
	r.NoRoute(func(c *gin.Context) { handlers.Error(c, 404, "not_found", "Resource not found") })
	timed := http.TimeoutHandler(r, 5*time.Second, `{"error":{"code":"request_timeout","message":"Request timed out"}}`)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		timed.ServeHTTP(w, req)
	})
}
