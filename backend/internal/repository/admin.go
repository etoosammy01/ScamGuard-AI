package repository

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Admin struct{ DB *pgxpool.Pool }

var ErrConflict = errors.New("unsafe account status change")

func (a *Admin) Audit(ctx context.Context, actor, action, target, outcome string) error {
	_, err := a.DB.Exec(ctx, `INSERT INTO audit_logs(actor_user_id,action,target_type,target_id,outcome) VALUES(NULLIF($1,'')::uuid,$2,'user',$3,$4)`, actor, action, target, outcome)
	return err
}

// All administrator lifecycle operations share this transaction lock, including provisioning.
func (a *Admin) SetStatus(ctx context.Context, actor, target, status string) error {
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(734130)`); err != nil {
		return err
	}
	var authorized bool
	if err = tx.QueryRow(ctx, `SELECT role='admin' AND status='active' FROM users WHERE id=$1 FOR UPDATE`, actor).Scan(&authorized); err != nil {
		return err
	}
	if !authorized || actor == target {
		return ErrConflict
	}
	var role, old string
	if err = tx.QueryRow(ctx, `SELECT role,status FROM users WHERE id=$1 FOR UPDATE`, target).Scan(&role, &old); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if status == "suspended" && role == "admin" && old == "active" {
		var count int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM users WHERE role='admin' AND status='active'`).Scan(&count); err != nil {
			return err
		}
		if count <= 1 {
			return ErrConflict
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE users SET status=$2 WHERE id=$1`, target, status); err != nil {
		return err
	}
	if status == "suspended" {
		if _, err = tx.Exec(ctx, `UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, target); err != nil {
			return err
		}
	}
	action := "user_reactivated"
	if status == "suspended" {
		action = "user_suspended"
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_logs(actor_user_id,action,target_type,target_id,outcome) VALUES($1,$2,'user',$3,'success')`, actor, action, target); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (a *Admin) Provision(ctx context.Context, email, operator string) error {
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(734130)`); err != nil {
		return err
	}
	var id string
	if err = tx.QueryRow(ctx, `UPDATE users SET role='admin' WHERE lower(btrim(email))=lower(btrim($1)) AND status='active' RETURNING id`, email).Scan(&id); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_logs(action,target_type,target_id,outcome,metadata) VALUES('admin_provisioned','user',$1,'success',jsonb_build_object('operator',$2::text,'database_identity',session_user))`, id, operator); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
