// Package testutil creates isolated PostgreSQL schemas for integration tests.
package testutil

import (
	"context"
	"encoding/base64"
	"github.com/daddydemir/lockgate/internal/secure"
	"github.com/daddydemir/lockgate/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func Store(t *testing.T) *store.Store {
	t.Helper()
	dsn := os.Getenv("LOCKGATE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set LOCKGATE_TEST_DATABASE_URL for PostgreSQL integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	schema := "lgtest_" + time.Now().Format("20060102150405") + stringID()
	if _, e = db.Exec(ctx, `CREATE SCHEMA `+schema); e != nil {
		db.Close()
		t.Fatal(e)
	}
	config, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	file := filepath.Join(t.TempDir(), "master.key")
	if e = os.WriteFile(file, []byte(base64.StdEncoding.EncodeToString(make([]byte, 32))), 0600); e != nil {
		t.Fatal(e)
	}
	keys, e := secure.LoadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	schemaDB, e := pgxpool.NewWithConfig(ctx, config)
	if e != nil {
		t.Fatal(e)
	}
	s := &store.Store{DB: schemaDB, Keys: keys}
	t.Cleanup(func() {
		s.DB.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, e := db.Exec(ctx, `DROP SCHEMA `+schema+` CASCADE`)
		db.Close()
		if e != nil {
			t.Error(e)
		}
	})
	if e = s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	if e = s.Migrate(ctx); e != nil {
		t.Fatal("migration is not idempotent", e)
	}
	if e = s.CreateAdmin(ctx, "admin", "test-password-at-least-12"); e != nil {
		t.Fatal(e)
	}
	return s
}
func stringID() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz"
	b := []byte(secure.Random(12))
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}
