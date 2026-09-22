package store

import (
	"context"
	"github.com/jackc/pgx/v5"
	"lockgate/internal/secure"
	"time"
)

type Session struct {
	AdminID        int64
	Username, CSRF string
	ExpiresAt      time.Time
}

func (s *Store) CreateAdmin(ctx context.Context, username, password string) error {
	if len(username) < 1 || len(username) > 100 || len(password) < 12 || len(password) > 1024 {
		return ErrInvalid
	}
	hash := secure.Password(password)
	_, e := s.DB.Exec(ctx, `INSERT INTO admins(username,password_hash) VALUES($1,$2)`, username, hash)
	return e
}
func (s *Store) Login(ctx context.Context, username, password, ip string) (string, error) {
	var id int64
	var hash string
	e := s.DB.QueryRow(ctx, `SELECT id,password_hash FROM admins WHERE username=$1`, username).Scan(&id, &hash)
	if e != nil && e != pgx.ErrNoRows {
		return "", e
	}
	// Use a real Argon2id calculation even for unknown usernames.
	if e == pgx.ErrNoRows {
		hash = "$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	}
	valid := secure.VerifyPassword(password, hash)
	if !valid || id == 0 {
		if e = s.Audit(ctx, "LOGIN_FAILED", "anonymous", ip); e != nil {
			return "", e
		}
		return "", ErrUnauthorized
	}
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return "", e
	}
	defer tx.Rollback(ctx)
	token := secure.Random(32)
	if _, e = tx.Exec(ctx, `DELETE FROM sessions WHERE expires_at<=now()`); e != nil {
		return "", e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO sessions(token_hash,admin_id,csrf,expires_at) VALUES($1,$2,$3,now()+interval '12 hours')`, secure.Hash(token), id, secure.Random(32)); e != nil {
		return "", e
	}
	if e = audit(ctx, tx, "LOGIN_SUCCESS", AdminActor(id), nil, "", ip); e != nil {
		return "", e
	}
	return token, tx.Commit(ctx)
}
func (s *Store) Session(ctx context.Context, token string) (Session, error) {
	var a Session
	e := s.DB.QueryRow(ctx, `SELECT a.id,a.username,s.csrf,s.expires_at FROM sessions s JOIN admins a ON a.id=s.admin_id WHERE s.token_hash=$1 AND s.expires_at>now()`, secure.Hash(token)).Scan(&a.AdminID, &a.Username, &a.CSRF, &a.ExpiresAt)
	if e == pgx.ErrNoRows {
		return a, ErrUnauthorized
	}
	return a, e
}
func (s *Store) Logout(ctx context.Context, token string) error {
	_, e := s.DB.Exec(ctx, `DELETE FROM sessions WHERE token_hash=$1`, secure.Hash(token))
	return e
}

type Event struct {
	ID                                                      int64
	Type, Actor, Application, Environment, Path, IP, Result string
	At                                                      time.Time
}

func (s *Store) Events(ctx context.Context) ([]Event, error) {
	rows, e := s.DB.Query(ctx, `SELECT e.id,e.event_type,e.actor,COALESCE(a.name,''),COALESCE(a.environment,''),COALESCE(e.secret_path,''),e.client_ip,e.result,e.created_at FROM audit_events e LEFT JOIN applications a ON a.id=e.application_id ORDER BY e.id DESC LIMIT 200`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var v Event
		if e = rows.Scan(&v.ID, &v.Type, &v.Actor, &v.Application, &v.Environment, &v.Path, &v.IP, &v.Result, &v.At); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Store) Counts(ctx context.Context) (map[string]int, error) {
	out := map[string]int{}
	for _, v := range []struct{ k, q string }{{"Pending approvals", `SELECT count(*) FROM access_requests WHERE status='pending'`}, {"Applications", `SELECT count(*) FROM applications`}, {"Active grants", `SELECT count(*) FROM grants WHERE status='active' AND (expires_at IS NULL OR expires_at>now())`}, {"Secrets", `SELECT count(*) FROM secrets WHERE archived_at IS NULL`}} {
		var n int
		if e := s.DB.QueryRow(ctx, v.q).Scan(&n); e != nil {
			return nil, e
		}
		out[v.k] = n
	}
	return out, nil
}
