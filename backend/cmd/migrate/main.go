package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/etoosammy01/ScamGuard-AI/backend/internal/config"
	"github.com/etoosammy01/ScamGuard-AI/backend/migrations"
	"github.com/jackc/pgx/v5"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Migration failed; verify configuration and database availability.")
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) != 2 || (os.Args[1] != "up" && os.Args[1] != "down") {
		return errors.New("usage: migrate up|down")
	}
	c, err := config.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, c.DatabaseURL)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(734129)"); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "CREATE TABLE IF NOT EXISTS schema_migrations(version integer PRIMARY KEY)"); err != nil {
		return err
	}
	var exists bool
	if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)", 1).Scan(&exists); err != nil {
		return err
	}
	direction := os.Args[1]
	if (direction == "up" && !exists) || (direction == "down" && exists) {
		sql, err := migrations.Files.ReadFile("001_initial." + direction + ".sql")
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, string(sql)); err != nil {
			return err
		}
		if direction == "up" {
			_, err = tx.Exec(ctx, "INSERT INTO schema_migrations(version) VALUES($1)", 1)
		} else {
			_, err = tx.Exec(ctx, "DELETE FROM schema_migrations WHERE version=$1", 1)
		}
		if err != nil {
			return err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	fmt.Println("Migration", direction, "complete")
	return nil
}
