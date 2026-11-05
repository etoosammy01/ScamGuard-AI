package handlers

import (
	"context"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/models"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
	"time"
)

type ScanStore interface {
	Create(ctx context.Context, owner string, result models.ScanResult) (models.ScanResult, error)
}
type ScanService interface {
	Message(string) models.ScanResult
	URL(string) (models.ScanResult, error)
}
type ScanHandler struct {
	Store   ScanStore
	Service ScanService
}

func (h *ScanHandler) Message(c *gin.Context) {
	var body struct {
		Content string `json:"content"`
	}
	if !decode(c, &body) {
		return
	}
	if strings.TrimSpace(body.Content) == "" || len(body.Content) > 10000 {
		Error(c, 400, "invalid_input", "Message must contain 1 to 10,000 bytes")
		return
	}
	identity := c.MustGet(models.IdentityKey).(models.Identity)
	result := h.Service.Message(body.Content)
	h.persist(c, identity.ID, result)
}
func (h *ScanHandler) URL(c *gin.Context) {
	var body struct {
		URL string `json:"url"`
	}
	if !decode(c, &body) {
		return
	}
	if strings.TrimSpace(body.URL) == "" || len(body.URL) > 2048 {
		Error(c, 400, "invalid_input", "URL must contain 1 to 2,048 bytes")
		return
	}
	result, err := h.Service.URL(body.URL)
	if err != nil {
		Error(c, 400, "invalid_url", "Enter a valid HTTP or HTTPS URL")
		return
	}
	identity := c.MustGet(models.IdentityKey).(models.Identity)
	h.persist(c, identity.ID, result)
}
func (h *ScanHandler) persist(c *gin.Context, owner string, result models.ScanResult) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()
	stored, err := h.Store.Create(ctx, owner, result)
	if err != nil {
		Error(c, 503, "service_unavailable", "Scan could not be saved")
		return
	}
	c.JSON(http.StatusCreated, gin.H{"result": stored})
}
