package handlers

import (
	"context"
	"errors"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/models"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/reports"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/repository"
	"github.com/gin-gonic/gin"
	"time"
)

// A bounded global permit limits simultaneous in-memory PDF generation.
var reportSlots = make(chan struct{}, 2)

func (h *ScanHistory) Report(c *gin.Context) {
	if !adminQuery(c) {
		return
	}
	if !scanIDPattern.MatchString(c.Param("id")) {
		Error(c, 400, "invalid_scan_id", "Scan ID must be a UUID")
		return
	}
	select {
	case reportSlots <- struct{}{}:
		defer func() { <-reportSlots }()
	default:
		Error(c, 429, "report_busy", "Report generation is busy; retry shortly")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()
	scan, err := h.Store.Get(ctx, c.MustGet(models.IdentityKey).(models.Identity).ID, c.Param("id"))
	if errors.Is(err, repository.ErrNotFound) {
		Error(c, 404, "not_found", "Scan not found")
		return
	}
	if err != nil {
		Error(c, 503, "service_unavailable", "Report unavailable")
		return
	}
	data, err := reports.Generate(ctx, scan, time.Now())
	if errors.Is(err, reports.ErrLimit) {
		Error(c, 413, "report_too_large", "Saved analysis exceeds report limits")
		return
	}
	if err != nil {
		Error(c, 503, "report_failed", "Report could not be generated")
		return
	}
	c.Header("Content-Disposition", `attachment; filename="scamguard-security-report.pdf"`)
	c.Header("Cache-Control", "no-store")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Data(200, "application/pdf", data)
}
