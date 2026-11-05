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
	direction := os.Args[1]
	if err = migrations.Apply(ctx, conn, direction); err != nil {
		return err
	}
	fmt.Println("Migration", direction, "complete")
	return nil
}
