package store

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"lockgate/internal/secure"
	"time"
)

type Secret struct {
	Archived  bool
	ID        int64
	Path      string
	Version   int
	UpdatedAt time.Time
}
type Version struct {
	Number    int
	CreatedAt time.Time
	CreatedBy string
}

func (s *Store) Secrets(ctx context.Context) ([]Secret, error) {
	rows, e := s.DB.Query(ctx, `SELECT s.id,s.path,max(v.version),s.updated_at,s.archived_at IS NOT NULL FROM secrets s JOIN secret_versions v ON v.secret_id=s.id GROUP BY s.id ORDER BY s.path`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Secret{}
	for rows.Next() {
		var v Secret
		if e = rows.Scan(&v.ID, &v.Path, &v.Version, &v.UpdatedAt, &v.Archived); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func validValues(values map[string]string) bool {
	if len(values) == 0 || len(values) > 500 {
		return false
	}
	for k, v := range values {
		if len(k) == 0 || len(k) > 256 || len(v) > 65536 {
			return false
		}
	}
	return true
}
func (s *Store) SaveSecret(ctx context.Context, path string, values map[string]string, admin int64, ip string) (int, error) {
	if !secure.ValidPath(path) || !validValues(values) {
		return 0, ErrInvalid
	}
	b, e := json.Marshal(values)
	if e != nil || len(b) > 1024*1024 {
		return 0, ErrInvalid
	}
	defer clear(b)
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return 0, e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `INSERT INTO secrets(path) VALUES($1) ON CONFLICT(path) DO NOTHING`, path); e != nil {
		return 0, e
	}
	var id int64
	if e = tx.QueryRow(ctx, `SELECT id FROM secrets WHERE path=$1 FOR UPDATE`, path).Scan(&id); e != nil {
		return 0, e
	}
	v, e := s.writeVersion(ctx, tx, id, path, b, admin, ip)
	if e != nil {
		return 0, e
	}
	return v, tx.Commit(ctx)
}
func (s *Store) writeVersion(ctx context.Context, tx pgx.Tx, id int64, path string, b []byte, admin int64, ip string) (int, error) {
	var v int
	if e := tx.QueryRow(ctx, `SELECT COALESCE(max(version),0)+1 FROM secret_versions WHERE secret_id=$1`, id).Scan(&v); e != nil {
		return 0, e
	}
	env, e := secure.Seal(s.Keys, b, path, v)
	if e != nil {
		return 0, e
	}
	_, e = tx.Exec(ctx, `INSERT INTO secret_versions(secret_id,version,ciphertext,nonce,encrypted_dek,algorithm,key_version,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, id, v, env.Ciphertext, env.Nonce, env.EncryptedDEK, env.Algorithm, env.KeyVersion, admin)
	if e != nil {
		return 0, e
	}
	if _, e = tx.Exec(ctx, `UPDATE secrets SET updated_at=now(),archived_at=NULL WHERE id=$1`, id); e != nil {
		return 0, e
	}
	event := "SECRET_UPDATED"
	if v == 1 {
		event = "SECRET_CREATED"
	}
	return v, audit(ctx, tx, event, AdminActor(admin), nil, path, ip)
}
func (s *Store) readSecret(ctx context.Context, tx pgx.Tx, path string, v int) (map[string]string, error) {
	var env secure.Envelope
	var version int
	e := tx.QueryRow(ctx, `SELECT v.version,v.ciphertext,v.nonce,v.encrypted_dek,v.algorithm,v.key_version FROM secret_versions v JOIN secrets s ON s.id=v.secret_id WHERE s.path=$1 AND ($2::int=0 OR v.version=$2) ORDER BY v.version DESC LIMIT 1`, path, v).Scan(&version, &env.Ciphertext, &env.Nonce, &env.EncryptedDEK, &env.Algorithm, &env.KeyVersion)
	if e == pgx.ErrNoRows {
		return nil, ErrNotFound
	}
	if e != nil {
		return nil, e
	}
	b, e := secure.Open(s.Keys, env, path, version)
	if e != nil {
		return nil, e
	}
	defer clear(b)
	values := map[string]string{}
	e = json.Unmarshal(b, &values)
	return values, e
}
func (s *Store) ReadSecret(ctx context.Context, path string, admin int64, ip string) (map[string]string, error) {
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	v, e := s.readSecret(ctx, tx, path, 0)
	if e != nil {
		return nil, e
	}
	if e = audit(ctx, tx, "SECRET_READ", AdminActor(admin), nil, path, ip); e != nil {
		return nil, e
	}
	return v, tx.Commit(ctx)
}
func (s *Store) Versions(ctx context.Context, path string) ([]Version, error) {
	rows, e := s.DB.Query(ctx, `SELECT v.version,v.created_at,a.username FROM secret_versions v JOIN secrets s ON s.id=v.secret_id JOIN admins a ON a.id=v.created_by WHERE s.path=$1 ORDER BY v.version DESC`, path)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Version{}
	for rows.Next() {
		var v Version
		if e = rows.Scan(&v.Number, &v.CreatedAt, &v.CreatedBy); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Store) Restore(ctx context.Context, path string, version int, admin int64, ip string) error {
	if version < 1 {
		return ErrInvalid
	}
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var id int64
	if e = tx.QueryRow(ctx, `SELECT id FROM secrets WHERE path=$1 FOR UPDATE`, path).Scan(&id); e != nil {
		return ErrNotFound
	}
	values, e := s.readSecret(ctx, tx, path, version)
	if e != nil {
		return e
	}
	b, e := json.Marshal(values)
	if e != nil {
		return e
	}
	defer clear(b)
	if _, e = s.writeVersion(ctx, tx, id, path, b, admin, ip); e != nil {
		return e
	}
	if e = audit(ctx, tx, "SECRET_RESTORED", AdminActor(admin), nil, path, ip); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

// Archive removes a path from machine access without deleting immutable history.
func (s *Store) Archive(ctx context.Context, path string, admin int64, ip string) error {
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	result, e := tx.Exec(ctx, `UPDATE secrets SET archived_at=now(),updated_at=now() WHERE path=$1 AND archived_at IS NULL`, path)
	if e != nil {
		return e
	}
	if result.RowsAffected() != 1 {
		return ErrNotFound
	}
	if e = audit(ctx, tx, "SECRET_ARCHIVED", AdminActor(admin), nil, path, ip); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (s *Store) IsArchived(ctx context.Context, path string) (bool, error) {
	var archived bool
	e := s.DB.QueryRow(ctx, `SELECT archived_at IS NOT NULL FROM secrets WHERE path=$1`, path).Scan(&archived)
	return archived, e
}
