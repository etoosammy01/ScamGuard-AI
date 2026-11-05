package migrations

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Apply migrates up to the latest embedded version or rolls back one version.
// Existing version-1 bookkeeping remains compatible with Phase 1 installations.
func Apply(ctx context.Context, conn *pgx.Conn, direction string) error {
	if direction != "up" && direction != "down" {
		return fmt.Errorf("invalid migration direction")
	}
	files, err := Files.ReadDir(".")
	if err != nil {
		return err
	}
	names := map[int]string{}
	var versions []int
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".up.sql") {
			continue
		}
		prefix, _, ok := strings.Cut(file.Name(), "_")
		version, e := strconv.Atoi(prefix)
		if !ok || e != nil {
			return fmt.Errorf("invalid migration name")
		}
		if _, ok := names[version]; ok {
			return fmt.Errorf("duplicate migration version")
		}
		names[version] = strings.TrimSuffix(file.Name(), ".up.sql")
		versions = append(versions, version)
	}
	sort.Ints(versions)
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(734129)"); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "CREATE TABLE IF NOT EXISTS schema_migrations(version integer PRIMARY KEY)"); err != nil {
		return err
	}
	var current int
	if err = tx.QueryRow(ctx, "SELECT COALESCE(max(version),0) FROM schema_migrations").Scan(&current); err != nil {
		return err
	}
	if current != 0 && names[current] == "" {
		return fmt.Errorf("unknown database migration version")
	}
	for _, version := range versions {
		apply := direction == "up" && version > current || direction == "down" && version == current
		if !apply {
			continue
		}
		sql, err := Files.ReadFile(names[version] + "." + direction + ".sql")
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, string(sql)); err != nil {
			return err
		}
		if direction == "up" {
			_, err = tx.Exec(ctx, "INSERT INTO schema_migrations(version) VALUES($1)", version)
		} else {
			_, err = tx.Exec(ctx, "DELETE FROM schema_migrations WHERE version=$1", version)
		}
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
