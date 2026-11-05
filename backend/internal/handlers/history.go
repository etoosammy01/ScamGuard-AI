package handlers

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/etoosammy01/ScamGuard-AI/backend/internal/models"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/repository"
	"github.com/gin-gonic/gin"
)

type ScanHistoryStore interface {
	List(context.Context, string, models.ScanFilter) (models.ScanPage, error)
	Get(context.Context, string, string) (models.ScanResult, error)
	Delete(context.Context, string, string) error
	DeleteAll(context.Context, string) (int64, error)
	Stats(context.Context, string) (models.DashboardStats, error)
	Export(context.Context, string, models.ScanFilter, int) ([]models.ScanResult, error)
}

type ScanHistory struct{ Store ScanHistoryStore }

var scanIDPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (h *ScanHistory) List(c *gin.Context) {
	identity := c.MustGet(models.IdentityKey).(models.Identity)
	f, ok := parseScanFilter(c, false)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	page, err := h.Store.List(ctx, identity.ID, f)
	if err != nil {
		Error(c, 503, "service_unavailable", "Scan history is temporarily unavailable")
		return
	}
	c.JSON(http.StatusOK, page)
}

func (h *ScanHistory) Get(c *gin.Context) {
	identity := c.MustGet(models.IdentityKey).(models.Identity)
	id := c.Param("id")
	if !scanIDPattern.MatchString(id) {
		Error(c, 400, "invalid_scan_id", "Scan ID must be a UUID")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()
	result, err := h.Store.Get(ctx, identity.ID, id)
	if errors.Is(err, repository.ErrNotFound) {
		Error(c, 404, "not_found", "Scan not found")
		return
	}
	if err != nil {
		Error(c, 503, "service_unavailable", "Scan is temporarily unavailable")
		return
	}
	c.JSON(http.StatusOK, gin.H{"scan": result})
}

func (h *ScanHistory) Delete(c *gin.Context) {
	identity := c.MustGet(models.IdentityKey).(models.Identity)
	id := c.Param("id")
	if !scanIDPattern.MatchString(id) {
		Error(c, 400, "invalid_scan_id", "Scan ID must be a UUID")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()
	err := h.Store.Delete(ctx, identity.ID, id)
	if errors.Is(err, repository.ErrNotFound) {
		Error(c, 404, "not_found", "Scan not found")
		return
	}
	if err != nil {
		Error(c, 503, "service_unavailable", "Scan could not be deleted")
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *ScanHistory) DeleteAll(c *gin.Context) {
	identity := c.MustGet(models.IdentityKey).(models.Identity)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	deleted, err := h.Store.DeleteAll(ctx, identity.ID)
	if err != nil {
		Error(c, 503, "service_unavailable", "Scan history could not be deleted")
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": deleted})
}

func (h *ScanHistory) Stats(c *gin.Context) {
	identity := c.MustGet(models.IdentityKey).(models.Identity)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	stats, err := h.Store.Stats(ctx, identity.ID)
	if err != nil {
		Error(c, 503, "service_unavailable", "Dashboard statistics are temporarily unavailable")
		return
	}
	c.JSON(http.StatusOK, stats)
}

func (h *ScanHistory) Export(c *gin.Context) {
	identity := c.MustGet(models.IdentityKey).(models.Identity)
	f, ok := parseScanFilter(c, true)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	rows, err := h.Store.Export(ctx, identity.ID, f, 10001)
	if err != nil {
		Error(c, 503, "service_unavailable", "Export is temporarily unavailable")
		return
	}
	if len(rows) > 10000 {
		Error(c, 413, "export_too_large", "Narrow your filters to export at most 10,000 scans")
		return
	}
	var body bytes.Buffer
	writer := csv.NewWriter(&body)
	_ = writer.Write([]string{"Scan ID", "Scan type", "Risk score", "Risk level", "Category", "Analysis mode", "AI status", "Timestamp UTC"})
	for _, r := range rows {
		_ = writer.Write([]string{csvSafe(r.ScanID), csvSafe(r.ScanType), strconv.Itoa(r.FinalScore), csvSafe(r.RiskLevel), csvSafe(r.Category), csvSafe(r.AnalysisMode), csvSafe(r.AIStatus), r.CreatedAt.UTC().Format(time.RFC3339Nano)})
	}
	writer.Flush()
	if writer.Error() != nil {
		Error(c, 500, "export_failed", "Export could not be generated")
		return
	}
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", `attachment; filename="scamguard-scans.csv"`)
	c.Header("Cache-Control", "no-store")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Data(http.StatusOK, "text/csv; charset=utf-8", body.Bytes())
}

func csvSafe(value string) string {
	trimmed := strings.TrimLeft(value, " \t\r\n")
	if trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return "'" + value
	}
	return value
}

func parseScanFilter(c *gin.Context, export bool) (models.ScanFilter, bool) {
	q := c.Request.URL.Query()
	allowed := map[string]bool{"risk_level": true, "scan_type": true, "category": true, "from": true, "to": true, "search": true}
	if !export {
		allowed["page"] = true
		allowed["page_size"] = true
	}
	for key, values := range q {
		if !allowed[key] || len(values) != 1 {
			Error(c, 400, "invalid_filter", "Unsupported or repeated scan history filter")
			return models.ScanFilter{}, false
		}
	}
	f := models.ScanFilter{Page: 1, PageSize: 20, RiskLevel: q.Get("risk_level"), ScanType: q.Get("scan_type"), Category: q.Get("category"), Search: strings.TrimSpace(q.Get("search"))}
	if export {
		f.PageSize = 10000
	}
	if f.RiskLevel != "" && !oneOf(f.RiskLevel, "low", "moderate", "high", "critical") {
		Error(c, 400, "invalid_filter", "Invalid risk_level filter")
		return f, false
	}
	if f.ScanType != "" && !oneOf(f.ScanType, "message", "url") {
		Error(c, 400, "invalid_filter", "Invalid scan_type filter")
		return f, false
	}
	if f.Category != "" && !oneOf(f.Category, "phishing", "bank_impersonation", "credential_theft", "fake_payment_notification", "fake_prize", "advance_fee", "investment_scam", "job_scam", "romance_scam", "delivery_scam", "account_takeover", "general_social_engineering", "unknown") {
		Error(c, 400, "invalid_filter", "Invalid category filter")
		return f, false
	}
	if len(f.Search) > 100 {
		Error(c, 400, "invalid_filter", "Search must be 100 bytes or fewer")
		return f, false
	}
	if !export {
		for key, target := range map[string]*int{"page": &f.Page, "page_size": &f.PageSize} {
			raw := q.Get(key)
			if raw == "" {
				continue
			}
			value, err := strconv.Atoi(raw)
			if err != nil || value < 1 {
				Error(c, 400, "invalid_pagination", "Page values must be positive integers")
				return f, false
			}
			*target = value
		}
		if f.Page > 10000 {
			Error(c, 400, "invalid_pagination", "Page is too large")
			return f, false
		}
		if f.PageSize > 100 {
			Error(c, 400, "invalid_pagination", "page_size cannot exceed 100")
			return f, false
		}
	}
	if raw := q.Get("from"); raw != "" {
		parsed, err := parseDate(raw, false)
		if err != nil {
			Error(c, 400, "invalid_filter", "from must be an ISO date or RFC3339 timestamp")
			return f, false
		}
		f.From = &parsed
	}
	if raw := q.Get("to"); raw != "" {
		parsed, err := parseDate(raw, true)
		if err != nil {
			Error(c, 400, "invalid_filter", "to must be an ISO date or RFC3339 timestamp")
			return f, false
		}
		f.To = &parsed
	}
	if f.From != nil && f.To != nil && f.To.Before(*f.From) {
		Error(c, 400, "invalid_filter", "to must not be earlier than from")
		return f, false
	}
	return f, true
}

func parseDate(raw string, end bool) (time.Time, error) {
	if len(raw) == 10 {
		d, err := time.Parse("2006-01-02", raw)
		if err != nil {
			return time.Time{}, err
		}
		if end {
			d = d.Add(24*time.Hour - time.Nanosecond)
		}
		return d.UTC(), nil
	}
	d, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, err
	}
	return d.UTC(), nil
}
func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
