// The operator is authenticated by OS access and PostgreSQL credentials, never an HTTP role claim.
package main

import (
	"context"
	"fmt"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) != 3 || len(os.Args[1]) > 254 || len(os.Args[2]) > 100 || strings.TrimSpace(os.Args[2]) == "" {
		fmt.Fprintln(os.Stderr, "usage: admin <existing-account-email> <operator-ticket-reference>")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err == nil {
		defer db.Close()
		err = (&repository.Admin{DB: db}).Provision(ctx, os.Args[1], os.Args[2])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Provisioning failed; verify active account and operator database access.")
		os.Exit(1)
	}
	fmt.Println("Administrator provisioned and audited.")
}
