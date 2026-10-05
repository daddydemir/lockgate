package store

import (
	"context"
	"fmt"
	"github.com/daddydemir/lockgate/internal/secure"
	"github.com/jackc/pgx/v5"
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
func (s *Store) Login(ctx context.Context, username, password, otp, ip string) (string, error) {
	var id int64
	var hash string
	var enabled bool
	var env secure.Envelope
	e := s.DB.QueryRow(ctx, `SELECT id,password_hash,totp_enabled,COALESCE(totp_ciphertext,''::bytea),COALESCE(totp_nonce,''::bytea),COALESCE(totp_encrypted_dek,''::bytea),COALESCE(totp_algorithm,''),COALESCE(totp_key_version,'') FROM admins WHERE username=$1`, username).Scan(&id, &hash, &enabled, &env.Ciphertext, &env.Nonce, &env.EncryptedDEK, &env.Algorithm, &env.KeyVersion)
	if e != nil && e != pgx.ErrNoRows {
		return "", e
	}
	// Use a real Argon2id calculation even for unknown usernames.
	if e == pgx.ErrNoRows {
		hash = "$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	}
	valid := secure.VerifyPassword(password, hash)
	if valid && id != 0 && enabled {
		secret, openErr := secure.Open(s.Keys, env, fmt.Sprintf("admin-totp:%d", id), 1)
		valid = openErr == nil && secure.VerifyTOTP(string(secret), otp, time.Now())
		clear(secret)
	}
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

type MFASettings struct {
	Enabled bool
	Secret  string
}

func (s *Store) MFA(ctx context.Context, admin int64) (MFASettings, error) {
	var out MFASettings
	var env secure.Envelope
	e := s.DB.QueryRow(ctx, `SELECT totp_enabled,COALESCE(totp_ciphertext,''::bytea),COALESCE(totp_nonce,''::bytea),COALESCE(totp_encrypted_dek,''::bytea),COALESCE(totp_algorithm,''),COALESCE(totp_key_version,'') FROM admins WHERE id=$1`, admin).Scan(&out.Enabled, &env.Ciphertext, &env.Nonce, &env.EncryptedDEK, &env.Algorithm, &env.KeyVersion)
	if e != nil {
		return out, e
	}
	if !out.Enabled && len(env.Ciphertext) > 0 {
		plain, err := secure.Open(s.Keys, env, fmt.Sprintf("admin-totp:%d", admin), 1)
		if err != nil {
			return out, err
		}
		out.Secret = string(plain)
		clear(plain)
	}
	return out, nil
}

func (s *Store) BeginMFA(ctx context.Context, admin int64, ip string) error {
	secret := secure.TOTPSecret()
	defer func() { secret = "" }()
	env, e := secure.Seal(s.Keys, []byte(secret), fmt.Sprintf("admin-totp:%d", admin), 1)
	if e != nil {
		return e
	}
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	result, e := tx.Exec(ctx, `UPDATE admins SET totp_enabled=false,totp_ciphertext=$2,totp_nonce=$3,totp_encrypted_dek=$4,totp_algorithm=$5,totp_key_version=$6 WHERE id=$1 AND NOT totp_enabled`, admin, env.Ciphertext, env.Nonce, env.EncryptedDEK, env.Algorithm, env.KeyVersion)
	if e != nil {
		return e
	}
	if result.RowsAffected() != 1 {
		return ErrConflict
	}
	if e = audit(ctx, tx, "MFA_SETUP_STARTED", AdminActor(admin), nil, "", ip); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

func (s *Store) SetMFA(ctx context.Context, admin int64, code string, enable bool, ip string) error {
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var current bool
	var env secure.Envelope
	e = tx.QueryRow(ctx, `SELECT totp_enabled,COALESCE(totp_ciphertext,''::bytea),COALESCE(totp_nonce,''::bytea),COALESCE(totp_encrypted_dek,''::bytea),COALESCE(totp_algorithm,''),COALESCE(totp_key_version,'') FROM admins WHERE id=$1 FOR UPDATE`, admin).Scan(&current, &env.Ciphertext, &env.Nonce, &env.EncryptedDEK, &env.Algorithm, &env.KeyVersion)
	if e != nil {
		return e
	}
	if current == enable || len(env.Ciphertext) == 0 {
		return ErrConflict
	}
	plain, e := secure.Open(s.Keys, env, fmt.Sprintf("admin-totp:%d", admin), 1)
	if e != nil {
		return e
	}
	valid := secure.VerifyTOTP(string(plain), code, time.Now())
	clear(plain)
	if !valid {
		return ErrMFARequired
	}
	event := "MFA_ENABLED"
	if enable {
		_, e = tx.Exec(ctx, `UPDATE admins SET totp_enabled=true WHERE id=$1`, admin)
	} else {
		event = "MFA_DISABLED"
		_, e = tx.Exec(ctx, `UPDATE admins SET totp_enabled=false,totp_ciphertext=NULL,totp_nonce=NULL,totp_encrypted_dek=NULL,totp_algorithm=NULL,totp_key_version=NULL WHERE id=$1`, admin)
	}
	if e != nil {
		return e
	}
	if e = audit(ctx, tx, event, AdminActor(admin), nil, "", ip); e != nil {
		return e
	}
	return tx.Commit(ctx)
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
