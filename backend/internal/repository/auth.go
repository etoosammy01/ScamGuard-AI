package repository

import (
	"context"
	"errors"
	"time"

	"github.com/etoosammy01/ScamGuard-AI/backend/internal/models"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("record not found")
var ErrDuplicate = errors.New("duplicate account")

type Accounts struct{ DB *pgxpool.Pool }

const userColumns = "id, full_name, email, bio, role, created_at"

func scanUser(row pgx.Row) (models.User, error) {
	var u models.User
	err := row.Scan(&u.ID, &u.FullName, &u.Email, &u.Bio, &u.Role, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return u, ErrNotFound
	}
	return u, err
}
func (a *Accounts) CreateUser(ctx context.Context, name, email, hash string) error {
	_, err := a.DB.Exec(ctx, "INSERT INTO users(full_name,email,password_hash,role) VALUES($1,$2,$3,'user')", name, email, hash)
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		return ErrDuplicate
	}
	return err
}
func (a *Accounts) Credentials(ctx context.Context, email string) (models.User, string, error) {
	var u models.User
	var hash string
	err := a.DB.QueryRow(ctx, "SELECT "+userColumns+", password_hash FROM users WHERE lower(btrim(email))=$1", email).Scan(&u.ID, &u.FullName, &u.Email, &u.Bio, &u.Role, &u.CreatedAt, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return u, "", ErrNotFound
	}
	return u, hash, err
}
func (a *Accounts) CreateSession(ctx context.Context, userID string, hash, previous []byte, expires time.Time) error {
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Serialize account logins so the concurrent-session limit remains deterministic.
	if _, err = tx.Exec(ctx, "SELECT id FROM users WHERE id=$1 FOR UPDATE", userID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "DELETE FROM sessions WHERE user_id=$1 AND (expires_at<=now() OR revoked_at IS NOT NULL)", userID); err != nil {
		return err
	}
	if len(previous) > 0 {
		if _, err = tx.Exec(ctx, "UPDATE sessions SET revoked_at=now() WHERE token_hash=$1 AND revoked_at IS NULL", previous); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, "INSERT INTO sessions(user_id,token_hash,expires_at) VALUES($1,$2,$3)", userID, hash, expires); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE sessions SET revoked_at=now() WHERE id IN (
 SELECT id FROM sessions WHERE user_id=$1 AND revoked_at IS NULL AND expires_at>now()
 ORDER BY created_at DESC, id DESC OFFSET 5)`, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (a *Accounts) SessionIdentity(ctx context.Context, hash []byte) (models.Identity, error) {
	var identity models.Identity
	err := a.DB.QueryRow(ctx, `SELECT u.id,u.role FROM sessions s
 JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>now()`, hash).Scan(&identity.ID, &identity.Role)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity, ErrNotFound
	}
	return identity, err
}

func (a *Accounts) Revoke(ctx context.Context, hash []byte) error {
	_, err := a.DB.Exec(ctx, "UPDATE sessions SET revoked_at=now() WHERE token_hash=$1 AND revoked_at IS NULL", hash)
	return err
}
func (a *Accounts) Profile(ctx context.Context, id string) (models.User, error) {
	return scanUser(a.DB.QueryRow(ctx, "SELECT "+userColumns+" FROM users WHERE id=$1", id))
}
func (a *Accounts) UpdateProfile(ctx context.Context, id string, name, bio *string) (models.User, error) {
	return scanUser(a.DB.QueryRow(ctx, "UPDATE users SET full_name=COALESCE($2,full_name),bio=COALESCE($3,bio) WHERE id=$1 RETURNING "+userColumns, id, name, bio))
}
