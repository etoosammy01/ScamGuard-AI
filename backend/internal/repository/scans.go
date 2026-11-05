package repository

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/models"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Scans struct{ DB *pgxpool.Pool }

func (s *Scans) Create(ctx context.Context, owner string, result models.ScanResult) (models.ScanResult, error) {
	raw, err := json.Marshal(result.Indicators)
	if err != nil {
		return result, err
	}
	err = s.DB.QueryRow(ctx, `INSERT INTO scans(user_id,scan_type,risk_score,risk_level,category,indicators,analysis_mode,ai_status,rule_score) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id,created_at`, owner, result.ScanType, result.RiskScore, result.RiskLevel, result.Category, raw, result.AnalysisMode, result.AIStatus, result.RuleScore).Scan(&result.ScanID, &result.CreatedAt)
	return result, err
}
func (s *Scans) Get(ctx context.Context, owner, id string) (models.ScanResult, error) {
	var r models.ScanResult
	var raw []byte
	err := s.DB.QueryRow(ctx, `SELECT id,scan_type,risk_score,risk_level,category,indicators,analysis_mode,ai_status,rule_score,created_at FROM scans WHERE user_id=$1 AND id=$2`, owner, id).Scan(&r.ScanID, &r.ScanType, &r.RiskScore, &r.RiskLevel, &r.Category, &raw, &r.AnalysisMode, &r.AIStatus, &r.RuleScore, &r.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, err
	}
	if err = json.Unmarshal(raw, &r.Indicators); err != nil {
		return r, err
	}
	r.FinalScore = r.RiskScore
	return r, nil
}
