package store

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"lockgate/internal/secure"
)

type Access struct {
	Status     string                       `json:"status"`
	RequestID  string                       `json:"request_id,omitempty"`
	ApprovalID string                       `json:"approval_id,omitempty"`
	RetryAfter int                          `json:"retry_after,omitempty"`
	Secrets    map[string]map[string]string `json:"secrets,omitempty"`
}

// Every access and application mutation locks the same application row. This
// serializes grant checks with revocation and token/permission changes.
func authenticate(ctx context.Context, tx pgx.Tx, token string) (Application, error) {
	var a Application
	if !strings.HasPrefix(token, "lg_app_") || len(token) > 128 {
		return a, ErrUnauthorized
	}
	e := tx.QueryRow(ctx, `SELECT a.id,a.name,a.environment,a.enabled,a.allowed_paths FROM applications a JOIN application_tokens t ON t.application_id=a.id WHERE t.token_hash=$1 FOR UPDATE OF a`, secure.Hash(token)).Scan(&a.ID, &a.Name, &a.Environment, &a.Enabled, &a.Paths)
	if e == pgx.ErrNoRows {
		return a, ErrUnauthorized
	}
	if e != nil {
		return a, e
	}
	var valid bool
	if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM application_tokens WHERE application_id=$1 AND token_hash=$2 AND revoked_at IS NULL)`, a.ID, secure.Hash(token)).Scan(&valid); e != nil {
		return a, e
	}
	if !valid || !a.Enabled {
		return a, ErrUnauthorized
	}
	return a, nil
}
func hasGrant(ctx context.Context, tx pgx.Tx, id int64) (bool, error) {
	if _, e := tx.Exec(ctx, `UPDATE grants SET status='expired' WHERE application_id=$1 AND status='active' AND expires_at<=now()`, id); e != nil {
		return false, e
	}
	var active bool
	e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM grants WHERE application_id=$1 AND status='active' AND (expires_at IS NULL OR expires_at>now()))`, id).Scan(&active)
	return active, e
}
func checkPaths(ctx context.Context, tx pgx.Tx, a Application, paths []string) error {
	for _, p := range paths {
		if !secure.Allowed(a.Paths, p) {
			return ErrForbidden
		}
	}
	for _, p := range paths {
		var exists bool
		if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM secrets WHERE path=$1 AND archived_at IS NULL)`, p).Scan(&exists); e != nil {
			return e
		}
		if !exists {
			return ErrNotFound
		}
	}
	return nil
}
func configuredPaths(ctx context.Context, tx pgx.Tx, a Application) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT path FROM secrets WHERE archived_at IS NULL ORDER BY path`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	paths := []string{}
	for rows.Next() {
		var path string
		if err = rows.Scan(&path); err != nil {
			return nil, err
		}
		if secure.Allowed(a.Paths, path) {
			paths = append(paths, path)
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, ErrNotFound
	}
	return paths, nil
}
func (s *Store) deliver(ctx context.Context, tx pgx.Tx, a Application, paths []string, ip string) (Access, error) {
	out := Access{Status: "approved", Secrets: map[string]map[string]string{}}
	for _, p := range paths {
		v, e := s.readSecret(ctx, tx, p, 0)
		if e != nil {
			return Access{}, e
		}
		out.Secrets[p] = v
		if e = audit(ctx, tx, "SECRET_READ", AppActor(a.ID), &a.ID, p, ip); e != nil {
			return Access{}, e
		}
	}
	if _, e := tx.Exec(ctx, `UPDATE applications SET last_access=now() WHERE id=$1`, a.ID); e != nil {
		return Access{}, e
	}
	return out, nil
}
func (s *Store) Access(ctx context.Context, token string, paths []string, instance, ip string) (Access, error) {
	var e error
	configured := len(paths) == 0
	if !configured {
		paths, e = normalizePaths(paths)
		if e != nil {
			return Access{}, e
		}
	}
	if len(instance) > 128 {
		return Access{}, ErrInvalid
	}
	if instance == "" {
		instance = secure.Random(24)
	}
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return Access{}, e
	}
	defer tx.Rollback(ctx)
	a, e := authenticate(ctx, tx, token)
	if e != nil {
		return Access{}, e
	}
	if configured {
		paths, e = configuredPaths(ctx, tx, a)
		if e != nil {
			return Access{}, e
		}
	}
	if e = checkPaths(ctx, tx, a, paths); e != nil {
		return Access{}, e
	}
	active, e := hasGrant(ctx, tx, a.ID)
	if e != nil {
		return Access{}, e
	}
	if active {
		out, e := s.deliver(ctx, tx, a, paths, ip)
		if e != nil {
			return Access{}, e
		}
		return out, tx.Commit(ctx)
	}
	id := secure.Random(24)
	var approval string
	// Partial unique index guarantees one logical pending request per application.
	e = tx.QueryRow(ctx, `INSERT INTO access_requests(id,application_id) VALUES($1,$2) ON CONFLICT(application_id) WHERE status='pending' DO UPDATE SET updated_at=now() RETURNING id`, id, a.ID).Scan(&approval)
	if e != nil {
		return Access{}, e
	}
	if id == approval {
		if e = audit(ctx, tx, "ACCESS_REQUESTED", AppActor(a.ID), &a.ID, "", ip); e != nil {
			return Access{}, e
		}
	}
	var request string
	e = tx.QueryRow(ctx, `INSERT INTO request_instances(id,request_id,instance_key,paths) VALUES($1,$2,$3,$4) ON CONFLICT(request_id,instance_key) DO UPDATE SET last_seen=now() RETURNING id`, secure.Random(24), approval, instance, paths).Scan(&request)
	if e != nil {
		return Access{}, e
	}
	// Idempotency keys cannot be reused with a different secret set.
	var stored []string
	if e = tx.QueryRow(ctx, `SELECT paths FROM request_instances WHERE id=$1`, request).Scan(&stored); e != nil {
		return Access{}, e
	}
	if strings.Join(stored, "\n") != strings.Join(paths, "\n") {
		return Access{}, ErrConflict
	}
	return Access{Status: "waiting_approval", RequestID: request, ApprovalID: approval, RetryAfter: 3}, tx.Commit(ctx)
}
func (s *Store) Poll(ctx context.Context, token, id, ip string) (Access, error) {
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return Access{}, e
	}
	defer tx.Rollback(ctx)
	a, e := authenticate(ctx, tx, token)
	if e != nil {
		return Access{}, e
	}
	var paths []string
	var status, approval string
	e = tx.QueryRow(ctx, `SELECT i.paths,r.status,r.id FROM request_instances i JOIN access_requests r ON r.id=i.request_id WHERE i.id=$1 AND r.application_id=$2`, id, a.ID).Scan(&paths, &status, &approval)
	if e == pgx.ErrNoRows {
		return Access{}, ErrNotFound
	}
	if e != nil {
		return Access{}, e
	}
	if e = checkPaths(ctx, tx, a, paths); e != nil {
		return Access{}, e
	}
	out := Access{Status: status, RequestID: id, ApprovalID: approval}
	switch status {
	case "pending":
		out.Status = "waiting_approval"
		out.RetryAfter = 3
		if _, e = tx.Exec(ctx, `UPDATE request_instances SET last_seen=now() WHERE id=$1`, id); e != nil {
			return Access{}, e
		}
		if _, e = tx.Exec(ctx, `UPDATE access_requests SET updated_at=now() WHERE id=$1`, approval); e != nil {
			return Access{}, e
		}
	case "approved":
		active, e := hasGrant(ctx, tx, a.ID)
		if e != nil {
			return Access{}, e
		}
		if active {
			out, e = s.deliver(ctx, tx, a, paths, ip)
			if e != nil {
				return Access{}, e
			}
		} else {
			out.Status = "revoked"
		}
	}
	return out, tx.Commit(ctx)
}

type Approval struct {
	ID, Name, Environment, Status string
	ApplicationID                 int64
	Paths                         []string
	Waiting                       int
	FirstSeen, LastSeen           time.Time
}

func (s *Store) Approvals(ctx context.Context) ([]Approval, error) {
	rows, e := s.DB.Query(ctx, `SELECT r.id,a.id,a.name,a.environment,r.status,r.created_at,r.updated_at,(SELECT count(*) FROM request_instances i WHERE i.request_id=r.id AND i.last_seen>now()-interval '30 seconds'),ARRAY(SELECT DISTINCT unnest(i.paths) FROM request_instances i WHERE i.request_id=r.id ORDER BY 1) FROM access_requests r JOIN applications a ON a.id=r.application_id WHERE r.status='pending' ORDER BY r.created_at`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Approval{}
	for rows.Next() {
		var a Approval
		if e = rows.Scan(&a.ID, &a.ApplicationID, &a.Name, &a.Environment, &a.Status, &a.FirstSeen, &a.LastSeen, &a.Waiting, &a.Paths); e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func (s *Store) Resolve(ctx context.Context, id string, admin int64, approve bool, ip string) error {
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var app int64
	if e = tx.QueryRow(ctx, `SELECT application_id FROM access_requests WHERE id=$1`, id).Scan(&app); e != nil {
		return ErrNotFound
	}
	var enabled bool
	if e = tx.QueryRow(ctx, `SELECT enabled FROM applications WHERE id=$1 FOR UPDATE`, app).Scan(&enabled); e != nil {
		return e
	}
	if !enabled {
		return ErrConflict
	}
	status := "denied"
	event := "ACCESS_DENIED"
	if approve {
		status = "approved"
		event = "ACCESS_APPROVED"
	}
	result, e := tx.Exec(ctx, `UPDATE access_requests SET status=$2,resolved_at=now(),resolved_by=$3,updated_at=now() WHERE id=$1 AND status='pending'`, id, status, admin)
	if e != nil {
		return e
	}
	if result.RowsAffected() != 1 {
		return ErrConflict
	}
	if approve {
		if _, e = tx.Exec(ctx, `INSERT INTO grants(application_id,status,approved_by) VALUES($1,'active',$2)`, app, admin); e != nil {
			return e
		}
	}
	if e = audit(ctx, tx, event, AdminActor(admin), &app, "", ip); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
