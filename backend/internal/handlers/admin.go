package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/models"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/repository"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"io"
	"mime"
	"net/http"
	"strconv"
	"time"
)

type AdminHandler struct {
	Store     *repository.Admin
	Started   time.Time
	AIEnabled bool
}

func (h *AdminHandler) Authorize(c *gin.Context) {
	u := c.MustGet(models.IdentityKey).(models.Identity)
	if u.Role != "admin" {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()
		if err := h.Store.Audit(ctx, u.ID, "admin_access_denied", "", "denied"); err != nil {
			Error(c, 503, "audit_unavailable", "Administrative access unavailable")
			return
		}
		Error(c, 403, "forbidden", "Access denied")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Next()
}
func adminQuery(c *gin.Context, allowed ...string) bool {
	for k, v := range c.Request.URL.Query() {
		if len(v) != 1 || !oneOf(k, allowed...) {
			Error(c, 400, "invalid_query", "Unsupported or repeated query parameter")
			return false
		}
	}
	return true
}
func adminPage(c *gin.Context) (int, bool) {
	page := 1
	if v := c.Query("page"); v != "" {
		n, e := strconv.Atoi(v)
		if e != nil || n < 1 || n > 10000 {
			Error(c, 400, "invalid_pagination", "Invalid page")
			return 0, false
		}
		page = n
	}
	return page, true
}
func (h *AdminHandler) Users(c *gin.Context) {
	if !adminQuery(c, "page", "search") {
		return
	}
	page, ok := adminPage(c)
	if !ok {
		return
	}
	search := c.Query("search")
	if len(search) > 100 {
		Error(c, 400, "invalid_query", "Search too long")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()
	var total int
	if err := h.Store.DB.QueryRow(ctx, `SELECT count(*) FROM users WHERE $1='' OR position(lower($1) in lower(full_name||' '||email))>0`, search).Scan(&total); err != nil {
		adminFailure(c)
		return
	}
	rows, err := h.Store.DB.Query(ctx, `SELECT jsonb_build_object('id',id,'full_name',full_name,'email',email,'role',role,'status',status,'created_at',created_at) FROM users WHERE $1='' OR position(lower($1) in lower(full_name||' '||email))>0 ORDER BY created_at DESC,id DESC LIMIT 20 OFFSET $2`, search, (page-1)*20)
	if err != nil {
		adminFailure(c)
		return
	}
	defer rows.Close()
	items := []json.RawMessage{}
	for rows.Next() {
		var raw json.RawMessage
		if rows.Scan(&raw) != nil {
			adminFailure(c)
			return
		}
		items = append(items, raw)
	}
	if rows.Err() != nil {
		adminFailure(c)
		return
	}
	c.JSON(200, gin.H{"items": items, "page": page, "page_size": 20, "total": total})
}
func (h *AdminHandler) User(c *gin.Context) {
	if !scanIDPattern.MatchString(c.Param("id")) {
		Error(c, 400, "invalid_user_id", "Invalid user ID")
		return
	}
	if !adminQuery(c) {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()
	var raw json.RawMessage
	err := h.Store.DB.QueryRow(ctx, `SELECT jsonb_build_object('id',id,'full_name',full_name,'email',email,'role',role,'status',status,'created_at',created_at) FROM users WHERE id=$1`, c.Param("id")).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		Error(c, 404, "not_found", "User not found")
		return
	}
	if err != nil {
		adminFailure(c)
		return
	}
	c.JSON(200, gin.H{"user": raw})
}
func (h *AdminHandler) Status(c *gin.Context) {
	if !scanIDPattern.MatchString(c.Param("id")) {
		Error(c, 400, "invalid_user_id", "Invalid user ID")
		return
	}
	if !adminQuery(c) {
		return
	}
	media, _, mediaErr := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if mediaErr != nil || media != "application/json" {
		Error(c, 415, "unsupported_media_type", "Use application/json")
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1024)
	var body struct {
		Status string `json:"status"`
	}
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&body) != nil || decoder.Decode(&struct{}{}) != io.EOF || !oneOf(body.Status, "active", "suspended") {
		Error(c, 400, "invalid_status", "Only active or suspended status is accepted")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()
	err := h.Store.SetStatus(ctx, c.MustGet(models.IdentityKey).(models.Identity).ID, c.Param("id"), body.Status)
	if errors.Is(err, repository.ErrConflict) {
		Error(c, 409, "unsafe_status_change", "Cannot suspend yourself or the last active administrator")
		return
	}
	if errors.Is(err, repository.ErrNotFound) {
		Error(c, 404, "not_found", "User not found")
		return
	}
	if err != nil {
		adminFailure(c)
		return
	}
	c.JSON(200, gin.H{"status": body.Status})
}
func (h *AdminHandler) AuditLogs(c *gin.Context) {
	if !adminQuery(c, "page") {
		return
	}
	page, ok := adminPage(c)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()
	var total int
	if h.Store.DB.QueryRow(ctx, `SELECT count(*) FROM audit_logs`).Scan(&total) != nil {
		adminFailure(c)
		return
	}
	rows, err := h.Store.DB.Query(ctx, `SELECT jsonb_build_object('id',id,'actor_user_id',actor_user_id,'action',action,'target_type',target_type,'target_id',target_id,'created_at',created_at,'outcome',outcome) FROM audit_logs ORDER BY created_at DESC,id DESC LIMIT 20 OFFSET $1`, (page-1)*20)
	if err != nil {
		adminFailure(c)
		return
	}
	defer rows.Close()
	items := []json.RawMessage{}
	for rows.Next() {
		var raw json.RawMessage
		if rows.Scan(&raw) != nil {
			adminFailure(c)
			return
		}
		items = append(items, raw)
	}
	if rows.Err() != nil {
		adminFailure(c)
		return
	}
	c.JSON(200, gin.H{"items": items, "page": page, "page_size": 20, "total": total})
}
func adminFailure(c *gin.Context) {
	Error(c, 503, "service_unavailable", "Administration temporarily unavailable")
}
func (h *AdminHandler) Settings(c *gin.Context) {
	if !adminQuery(c) {
		return
	}
	c.JSON(200, gin.H{"editable": false, "scan_requests_per_hour": 20, "ai_requests_per_hour": 5, "report_requests_per_hour": 5, "max_message_bytes": 10000, "ai_enabled": h.AIEnabled, "scope": "Read-only deployment policy; rate limits are per process. Secrets are not exposed."})
}
func (h *AdminHandler) Overview(c *gin.Context) {
	if !adminQuery(c) {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 4*time.Second)
	defer cancel()
	var raw json.RawMessage
	err := h.Store.DB.QueryRow(ctx, `SELECT jsonb_build_object('total_users',(SELECT count(*) FROM users),'total_scans',count(*),'message_scans',count(*) FILTER(WHERE scan_type='message'),'url_scans',count(*) FILTER(WHERE scan_type='url'),'high_risk',count(*) FILTER(WHERE risk_level='high'),'critical_risk',count(*) FILTER(WHERE risk_level='critical'),'ai_assisted',count(*) FILTER(WHERE ai_status='completed'),'scans_last_7_days',count(*) FILTER(WHERE created_at>=now()-interval '7 days')) FROM scans`).Scan(&raw)
	if err != nil {
		adminFailure(c)
		return
	}
	c.JSON(200, gin.H{"metrics": raw, "monitoring": gin.H{"database_ready": h.Store.DB.Ping(ctx) == nil, "uptime_seconds": int(time.Since(h.Started).Seconds()), "ai_enabled": h.AIEnabled, "scope": "Uptime is for this process. Historical AI status is available in analytics. API latency and provider error counters are not instrumented."}})
}
func (h *AdminHandler) Analytics(c *gin.Context) {
	if !adminQuery(c, "days") {
		return
	}
	days := 30
	if s := c.Query("days"); s != "" {
		n, e := strconv.Atoi(s)
		if e != nil || n < 1 || n > 90 {
			Error(c, 400, "invalid_range", "days must be between 1 and 90")
			return
		}
		days = n
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 4*time.Second)
	defer cancel()
	tx, err := h.Store.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		adminFailure(c)
		return
	}
	defer tx.Rollback(ctx)
	// Date buckets use UTC; weekly buckets start on Monday. No account identifiers leave these queries.
	queries := map[string]string{
		"daily_scans":    `SELECT to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD') AS label,count(*) AS count FROM scans WHERE created_at >= $1 GROUP BY 1 ORDER BY 1`,
		"weekly_scans":   `SELECT to_char(date_trunc('week',created_at AT TIME ZONE 'UTC'),'YYYY-MM-DD') AS label,count(*) AS count FROM scans WHERE created_at >= $1 GROUP BY 1 ORDER BY 1`,
		"risk_levels":    `SELECT risk_level AS label,count(*) AS count FROM scans WHERE created_at >= $1 GROUP BY 1 ORDER BY 1`,
		"categories":     `SELECT category AS label,count(*) AS count FROM scans WHERE created_at >= $1 GROUP BY 1 ORDER BY count(*) DESC,category LIMIT 15`,
		"scan_types":     `SELECT scan_type AS label,count(*) AS count FROM scans WHERE created_at >= $1 GROUP BY 1 ORDER BY 1`,
		"analysis_modes": `SELECT analysis_mode AS label,count(*) AS count FROM scans WHERE created_at >= $1 GROUP BY 1 ORDER BY 1`,
		"ai_statuses":    `SELECT ai_status AS label,count(*) AS count FROM scans WHERE created_at >= $1 GROUP BY 1 ORDER BY 1`,
		"registrations":  `SELECT to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD') AS label,count(*) AS count FROM users WHERE created_at >= $1 GROUP BY 1 ORDER BY 1`,
	}
	result := gin.H{"days": days, "from": time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -days+1)}
	for key, query := range queries {
		var raw json.RawMessage
		err := tx.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(t),'[]'::jsonb) FROM (`+query+`) t`, result["from"]).Scan(&raw)
		if err != nil {
			adminFailure(c)
			return
		}
		result[key] = raw
	}
	if err := tx.Commit(ctx); err != nil {
		adminFailure(c)
		return
	}
	c.JSON(200, result)
}
