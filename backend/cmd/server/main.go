package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/etoosammy01/ScamGuard-AI/backend/internal/config"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/database"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/repository"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/router"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/services"
)

func main() {
	if err := run(); err != nil {
		slog.Error("server stopped", "reason", err.Error())
		os.Exit(1)
	}
}
func run() error {
	c, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	db, err := database.Open(ctx, c.DatabaseURL)
	if err != nil {
		return errors.New("database configuration failed")
	}
	defer db.Close()
	passwords, err := services.NewPasswords()
	if err != nil {
		return errors.New("password service initialization failed")
	}
	auth := &services.Auth{Store: &repository.Accounts{DB: db}, Passwords: passwords, Lifetime: c.SessionLifetime}
	s := &http.Server{Addr: ":" + c.Port, Handler: router.New(db, c.Origins, router.AuthOptions{Service: auth, Config: c}), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	done := make(chan error, 1)
	go func() { slog.Info("server listening", "port", c.Port); done <- s.ListenAndServe() }()
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			return errors.New("HTTP server failed")
		}
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.Shutdown(shutdown)
}
