package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/etoosammy01/ScamGuard-AI/backend/internal/models"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const scanColumns = `id,scan_type,risk_score,risk_level,category,indicators,analysis_mode,ai_status,rule_score,recommendations,explanation,created_at`

type Scans struct{ DB *pgxpool.Pool }

func (s *Scans) Create(ctx context.Context, owner string, result models.ScanResult) (models.ScanResult, error) {
	if result.Indicators == nil {
		result.Indicators = []models.Indicator{}
	}
	if result.Recommendations == nil {
		result.Recommendations = []string{}
	}
	if result.Explanation == "" {
		result.Explanation = safeExplanation(result)
	}
	if explanation := []rune(result.Explanation); len(explanation) > 500 {
		result.Explanation = string(explanation[:500])
	}
	rawIndicators, err := json.Marshal(result.Indicators)
	if err != nil {
		return result, err
	}
	rawRecommendations, err := json.Marshal(result.Recommendations)
	if err != nil {
		return result, err
	}
	err = s.DB.QueryRow(ctx, `INSERT INTO scans(user_id,scan_type,risk_score,risk_level,category,indicators,analysis_mode,ai_status,rule_score,recommendations,explanation) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id,created_at`, owner, result.ScanType, result.RiskScore, result.RiskLevel, result.Category, rawIndicators, result.AnalysisMode, result.AIStatus, result.RuleScore, rawRecommendations, result.Explanation).Scan(&result.ScanID, &result.CreatedAt)
	result.OriginalContentAvailable = false
	return result, err
}

func (s *Scans) Get(ctx context.Context, owner, id string) (models.ScanResult, error) {
	r, err := scanResult(s.DB.QueryRow(ctx, `SELECT `+scanColumns+` FROM scans WHERE user_id=$1 AND id=$2`, owner, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrNotFound
	}
	return r, err
}

func (s *Scans) List(ctx context.Context, owner string, filter models.ScanFilter) (models.ScanPage, error) {
	page := models.ScanPage{Page: filter.Page, PageSize: filter.PageSize, Items: []models.ScanResult{}}
	args := filterArgs(owner, filter)
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM scans WHERE `+whereFilters, args...).Scan(&page.Total); err != nil {
		return page, err
	}
	args = append(args, filter.PageSize, (filter.Page-1)*filter.PageSize)
	rows, err := s.DB.Query(ctx, `SELECT `+scanColumns+` FROM scans WHERE `+whereFilters+` ORDER BY created_at DESC,id DESC LIMIT $8 OFFSET $9`, args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		result, scanErr := scanResult(rows)
		if scanErr != nil {
			return page, scanErr
		}
		page.Items = append(page.Items, result)
	}
	return page, rows.Err()
}

func (s *Scans) Delete(ctx context.Context, owner, id string) error {
	tag, err := s.DB.Exec(ctx, `DELETE FROM scans WHERE user_id=$1 AND id=$2`, owner, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Scans) DeleteAll(ctx context.Context, owner string) (int64, error) {
	tag, err := s.DB.Exec(ctx, `DELETE FROM scans WHERE user_id=$1`, owner)
	return tag.RowsAffected(), err
}

func (s *Scans) Stats(ctx context.Context, owner string) (models.DashboardStats, error) {
	var result models.DashboardStats
	err := s.DB.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE scan_type='message'),count(*) FILTER(WHERE scan_type='url'),count(*) FILTER(WHERE risk_level='low'),count(*) FILTER(WHERE risk_level='moderate'),count(*) FILTER(WHERE risk_level='high'),count(*) FILTER(WHERE risk_level='critical'),count(*) FILTER(WHERE created_at >= statement_timestamp()-interval '7 days'),count(*) FILTER(WHERE created_at >= statement_timestamp()-interval '30 days'),count(*) FILTER(WHERE ai_status='completed'),count(*) FILTER(WHERE analysis_mode='rules') FROM scans WHERE user_id=$1`, owner).Scan(&result.TotalScans, &result.MessageScans, &result.URLScans, &result.LowRiskScans, &result.ModerateRiskScans, &result.HighRiskScans, &result.CriticalRiskScans, &result.ScansLast7Days, &result.ScansLast30Days, &result.AIAssistedScans, &result.RulesOnlyScans)
	if err != nil {
		return result, err
	}
	result.Categories = []models.CountByCategory{}
	rows, err := s.DB.Query(ctx, `SELECT category,count(*) FROM scans WHERE user_id=$1 AND category<>'unknown' GROUP BY category ORDER BY count(*) DESC,category ASC LIMIT 8`, owner)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var item models.CountByCategory
		if err = rows.Scan(&item.Category, &item.Count); err != nil {
			rows.Close()
			return result, err
		}
		result.Categories = append(result.Categories, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return result, err
	}
	rows.Close()
	result.Activity = []models.ScanActivity{}
	rows, err = s.DB.Query(ctx, `WITH days AS (SELECT generate_series(((statement_timestamp() AT TIME ZONE 'UTC')::date-29)::timestamp, (statement_timestamp() AT TIME ZONE 'UTC')::date::timestamp, interval '1 day') AS day) SELECT to_char(days.day,'YYYY-MM-DD'),count(scans.id) FROM days LEFT JOIN scans ON scans.user_id=$1 AND scans.created_at >= (days.day AT TIME ZONE 'UTC') AND scans.created_at < ((days.day+interval '1 day') AT TIME ZONE 'UTC') GROUP BY days.day ORDER BY days.day`, owner)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var item models.ScanActivity
		if err = rows.Scan(&item.Date, &item.Count); err != nil {
			rows.Close()
			return result, err
		}
		result.Activity = append(result.Activity, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return result, err
	}
	rows.Close()
	return result, nil
}

// Export is deliberately bounded; CSV export never loads unbounded user history.
func (s *Scans) Export(ctx context.Context, owner string, filter models.ScanFilter, limit int) ([]models.ScanResult, error) {
	args := filterArgs(owner, filter)
	args = append(args, limit)
	rows, err := s.DB.Query(ctx, `SELECT `+scanColumns+` FROM scans WHERE `+whereFilters+` ORDER BY created_at DESC,id DESC LIMIT $8`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	results := make([]models.ScanResult, 0)
	for rows.Next() {
		r, e := scanResult(rows)
		if e != nil {
			return nil, e
		}
		results = append(results, r)
	}
	return results, rows.Err()
}

const whereFilters = `user_id=$1 AND ($2='' OR risk_level=$2) AND ($3='' OR scan_type=$3) AND ($4='' OR category=$4) AND ($5::timestamptz IS NULL OR created_at >= $5) AND ($6::timestamptz IS NULL OR created_at <= $6) AND ($7='' OR position(lower($7) in lower(scan_type||' '||risk_level||' '||category||' '||analysis_mode||' '||indicators::text))>0)`

func filterArgs(owner string, f models.ScanFilter) []any {
	return []any{owner, f.RiskLevel, f.ScanType, f.Category, f.From, f.To, f.Search}
}

type rowScanner interface{ Scan(...any) error }

func scanResult(row rowScanner) (models.ScanResult, error) {
	var result models.ScanResult
	var indicators, recommendations []byte
	err := row.Scan(&result.ScanID, &result.ScanType, &result.RiskScore, &result.RiskLevel, &result.Category, &indicators, &result.AnalysisMode, &result.AIStatus, &result.RuleScore, &recommendations, &result.Explanation, &result.CreatedAt)
	if err != nil {
		return result, err
	}
	if err = json.Unmarshal(indicators, &result.Indicators); err != nil {
		return result, err
	}
	if err = json.Unmarshal(recommendations, &result.Recommendations); err != nil {
		return result, err
	}
	if result.Indicators == nil {
		result.Indicators = []models.Indicator{}
	}
	if result.Recommendations == nil {
		result.Recommendations = []string{}
	}
	result.FinalScore = result.RiskScore
	result.OriginalContentAvailable = false
	return result, nil
}

func safeExplanation(result models.ScanResult) string {
	if len(result.Indicators) == 0 {
		return "No configured risk indicators were found. This result does not guarantee safety."
	}
	risk := result.RiskLevel
	if risk == "" {
		risk = "unknown"
	} else {
		risk = strings.ToUpper(risk[:1]) + risk[1:]
	}
	return fmt.Sprintf("This %s scan triggered %d documented indicator(s) and received a %s risk assessment. Original submitted content is not retained.", strings.ToLower(result.ScanType), len(result.Indicators), risk)
}
