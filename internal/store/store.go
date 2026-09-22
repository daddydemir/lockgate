package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"lockgate/internal/secure"
	"lockgate/migrations"
)

var (
	ErrUnauthorized = errors.New("invalid token or disabled application")
	ErrForbidden    = errors.New("requested secret path is not allowed")
	ErrNotFound     = errors.New("record not found")
	ErrInvalid      = errors.New("invalid input")
	ErrConflict     = errors.New("record already exists or has changed")
)

type Store struct {
	DB   *pgxpool.Pool
	Keys secure.KeyProvider
}

func New(ctx context.Context, url string, keys secure.KeyProvider) (*Store, error) {
	db, e := pgxpool.New(ctx, url)
	if e != nil {
		return nil, e
	}
	if e = db.Ping(ctx); e != nil {
		db.Close()
		return nil, e
	}
	return &Store{db, keys}, nil
}
func (s *Store) Migrate(ctx context.Context) error {
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(732198421)`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations(version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); e != nil {
		return e
	}
	files, e := migrations.FS.ReadDir(".")
	if e != nil {
		return e
	}
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".sql") {
			continue
		}
		var exists bool
		if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, file.Name()).Scan(&exists); e != nil {
			return e
		}
		if exists {
			continue
		}
		b, e := migrations.FS.ReadFile(file.Name())
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, string(b)); e != nil {
			return fmt.Errorf("migration %s: %w", file.Name(), e)
		}
		if _, e = tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES($1)`, file.Name()); e != nil {
			return e
		}
	}
	return tx.Commit(ctx)
}
func audit(ctx context.Context, tx pgx.Tx, event, actor string, app *int64, path, ip string) error {
	_, e := tx.Exec(ctx, `INSERT INTO audit_events(event_type,actor,application_id,secret_path,client_ip) VALUES($1,$2,$3,NULLIF($4,''),$5)`, event, actor, app, path, ip)
	return e
}
func (s *Store) Audit(ctx context.Context, event, actor, ip string) error {
	_, e := s.DB.Exec(ctx, `INSERT INTO audit_events(event_type,actor,client_ip,result) VALUES($1,$2,$3,$4)`, event, actor, ip, map[bool]string{true: "failure", false: "success"}[event == "LOGIN_FAILED"])
	return e
}
func AdminActor(id int64) string { return fmt.Sprintf("admin:%d", id) }
func AppActor(id int64) string   { return fmt.Sprintf("application:%d", id) }

type Application struct {
	ID                      int64
	Name, Environment       string
	Enabled                 bool
	Paths                   []string
	CreatedAt, UpdatedAt    time.Time
	LastAccess              *time.Time
	GrantStatus, ApprovedBy string
	ApprovedAt              *time.Time
}

func (s *Store) Applications(ctx context.Context) ([]Application, error) {
	rows, e := s.DB.Query(ctx, `SELECT a.id,a.name,a.environment,a.enabled,a.allowed_paths,a.created_at,a.updated_at,a.last_access,COALESCE(g.status,''),COALESCE(ad.username,''),g.created_at FROM applications a LEFT JOIN grants g ON g.application_id=a.id AND g.status='active' LEFT JOIN admins ad ON ad.id=g.approved_by ORDER BY a.name,a.environment`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Application{}
	for rows.Next() {
		var a Application
		if e = rows.Scan(&a.ID, &a.Name, &a.Environment, &a.Enabled, &a.Paths, &a.CreatedAt, &a.UpdatedAt, &a.LastAccess, &a.GrantStatus, &a.ApprovedBy, &a.ApprovedAt); e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func validateApp(name, env string, paths []string) error {
	if len(name) < 1 || len(name) > 100 || len(env) < 1 || len(env) > 100 || len(paths) < 1 || len(paths) > 100 {
		return ErrInvalid
	}
	for _, p := range paths {
		if !secure.ValidPattern(p) {
			return ErrInvalid
		}
	}
	return nil
}
func (s *Store) CreateApplication(ctx context.Context, name, env string, paths []string, admin int64, ip string) (int64, string, error) {
	if e := validateApp(name, env, paths); e != nil {
		return 0, "", e
	}
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return 0, "", e
	}
	defer tx.Rollback(ctx)
	var id int64
	if e = tx.QueryRow(ctx, `INSERT INTO applications(name,environment,allowed_paths) VALUES($1,$2,$3) RETURNING id`, name, env, paths).Scan(&id); e != nil {
		return 0, "", e
	}
	token := secure.Token()
	if _, e = tx.Exec(ctx, `INSERT INTO application_tokens(application_id,token_hash) VALUES($1,$2)`, id, secure.Hash(token)); e != nil {
		return 0, "", e
	}
	if e = audit(ctx, tx, "APPLICATION_CREATED", AdminActor(admin), &id, "", ip); e != nil {
		return 0, "", e
	}
	e = tx.Commit(ctx)
	return id, token, e
}
func revoke(ctx context.Context, tx pgx.Tx, id int64) error {
	if _, e := tx.Exec(ctx, `UPDATE grants SET status='revoked',revoked_at=now() WHERE application_id=$1 AND status='active'`, id); e != nil {
		return e
	}
	_, e := tx.Exec(ctx, `UPDATE access_requests SET status='revoked',resolved_at=now(),updated_at=now() WHERE application_id=$1 AND status IN ('approved','pending')`, id)
	return e
}
func (s *Store) ChangeApplication(ctx context.Context, id, admin int64, action string, paths []string, ip string) (string, error) {
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return "", e
	}
	defer tx.Rollback(ctx)
	var exists int64
	if e = tx.QueryRow(ctx, `SELECT id FROM applications WHERE id=$1 FOR UPDATE`, id).Scan(&exists); e != nil {
		return "", ErrNotFound
	}
	token := ""
	event := ""
	switch action {
	case "rotate":
		token = secure.Token()
		if _, e = tx.Exec(ctx, `UPDATE application_tokens SET revoked_at=now() WHERE application_id=$1 AND revoked_at IS NULL`, id); e != nil {
			return "", e
		}
		_, e = tx.Exec(ctx, `INSERT INTO application_tokens(application_id,token_hash) VALUES($1,$2)`, id, secure.Hash(token))
		event = "APPLICATION_TOKEN_ROTATED"
	case "disable":
		_, e = tx.Exec(ctx, `UPDATE applications SET enabled=false,updated_at=now() WHERE id=$1`, id)
		event = "APPLICATION_DISABLED"
	case "enable":
		_, e = tx.Exec(ctx, `UPDATE applications SET enabled=true,updated_at=now() WHERE id=$1`, id)
		event = "APPLICATION_ENABLED"
	case "paths":
		if e = validateApp("x", "x", paths); e != nil {
			return "", e
		}
		_, e = tx.Exec(ctx, `UPDATE applications SET allowed_paths=$2,updated_at=now() WHERE id=$1`, id, paths)
		event = "APPLICATION_PATHS_UPDATED"
	case "revoke":
		event = "ACCESS_REVOKED"
	default:
		return "", ErrInvalid
	}
	if e != nil {
		return "", e
	}
	// Identity and boundary changes always require fresh approval.
	if action != "enable" {
		if e = revoke(ctx, tx, id); e != nil {
			return "", e
		}
	}
	if e = audit(ctx, tx, event, AdminActor(admin), &id, "", ip); e != nil {
		return "", e
	}
	return token, tx.Commit(ctx)
}
func normalizePaths(paths []string) ([]string, error) {
	if len(paths) == 0 || len(paths) > 100 {
		return nil, ErrInvalid
	}
	m := map[string]bool{}
	out := []string{}
	for _, p := range paths {
		if !secure.ValidPath(p) {
			return nil, ErrInvalid
		}
		if !m[p] {
			m[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}
