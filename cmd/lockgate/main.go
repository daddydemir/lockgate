package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/daddydemir/lockgate/internal/server"
	"github.com/daddydemir/lockgate/internal/store"
)

func main() {
	if err := run(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}
func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
func run() error {
	command := "serve"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	if command == "help" || command == "--help" {
		fmt.Println("LockGate\n\n  serve                 Start HTTP server (applies migrations and initializes the DB key)\n  migrate               Apply PostgreSQL migrations\n  key-import FILE       One-time import of the previous file-backed master key\n  keygen FILE           Generate a legacy master key file (never overwrites)\n  admin-create USER      Create admin; password read from LOCKGATE_ADMIN_PASSWORD_FILE\n\nRequired: POSTGRE_DSN (or DATABASE_URL). See README.md for deployment configuration.")
		return nil
	}
	if command == "keygen" {
		if len(os.Args) != 3 {
			return errors.New("usage: lockgate keygen FILE")
		}
		b := make([]byte, 32)
		if _, e := rand.Read(b); e != nil {
			return errors.New("key generation failed")
		}
		defer clear(b)
		f, e := os.OpenFile(os.Args[2], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return errors.New("cannot create key file; it must not already exist")
		}
		_, e = f.WriteString(base64.StdEncoding.EncodeToString(b) + "\n")
		ce := f.Close()
		if e != nil || ce != nil {
			return errors.New("cannot write key file")
		}
		fmt.Println("Master key file created. Back it up separately from the database.")
		return nil
	}
	if command != "serve" && command != "migrate" && command != "admin-create" && command != "key-import" {
		return errors.New("unknown command; use lockgate help")
	}
	if command == "key-import" && len(os.Args) != 3 {
		return errors.New("usage: lockgate key-import FILE")
	}
	url := env("POSTGRE_DSN", os.Getenv("DATABASE_URL"))
	if url == "" {
		return errors.New("POSTGRE_DSN or DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, e := store.New(ctx, url, nil)
	if e != nil {
		cancel()
		return errors.New("cannot connect to PostgreSQL; check POSTGRE_DSN / DATABASE_URL and database availability")
	}
	defer s.DB.Close()
	if e = s.Migrate(ctx); e != nil {
		cancel()
		return errors.New("database migration failed; check database permissions and schema")
	}
	if command == "migrate" {
		fmt.Println("Migrations applied.")
		return nil
	}
	if command == "key-import" {
		if _, e = s.InitializeMasterKey(ctx, os.Args[2]); e != nil {
			return e
		}
		fmt.Println("Database master key is initialized. An existing database key was not overwritten.")
		return nil
	}
	if command == "admin-create" {
		if len(os.Args) != 3 {
			return errors.New("usage: lockgate admin-create USER")
		}
		file := os.Getenv("LOCKGATE_ADMIN_PASSWORD_FILE")
		if file == "" {
			return errors.New("LOCKGATE_ADMIN_PASSWORD_FILE is required")
		}
		b, e := os.ReadFile(file)
		if e != nil {
			return errors.New("cannot read admin password file")
		}
		defer clear(b)
		password := strings.TrimRight(string(b), "\r\n")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if e = s.CreateAdmin(ctx, os.Args[2], password); e != nil {
			return errors.New("cannot create admin; username must be unique and password must be 12–1024 characters")
		}
		fmt.Println("Admin created.")
		return nil
	}
	keys, e := s.InitializeMasterKey(ctx, "")
	if e != nil {
		return e
	}
	s.Keys = keys
	cancel()
	handler, e := server.New(s, server.Config{Origin: env("LOCKGATE_ORIGIN", "https://localhost:8080"), SecureCookies: os.Getenv("LOCKGATE_INSECURE_DEV_COOKIES") != "true"})
	if e != nil {
		return e
	}
	httpServer := &http.Server{Addr: env("LOCKGATE_ADDR", "127.0.0.1:8080"), Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	stop, done := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer done()
	errs := make(chan error, 1)
	go func() {
		slog.Info("LockGate listening", "address", httpServer.Addr)
		errs <- httpServer.ListenAndServe()
	}()
	select {
	case e = <-errs:
		if !errors.Is(e, http.ErrServerClosed) {
			return errors.New("HTTP server stopped unexpectedly")
		}
	case <-stop.Done():
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if e = httpServer.Shutdown(ctx); e != nil {
			_ = httpServer.Close()
		}
	}
	return nil
}
