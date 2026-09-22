package store_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"lockgate/internal/store"
	"lockgate/internal/testutil"
	"sync"
	"testing"
)

func TestTokenResolvesConfiguredSecrets(t *testing.T) {
	s := testutil.Store(t)
	ctx := context.Background()
	if _, err := s.SaveSecret(ctx, "apps/billing/production", map[string]string{"DB_USER": "postgres"}, 1, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveSecret(ctx, "apps/unrelated/production", map[string]string{"KEY": "hidden"}, 1, ""); err != nil {
		t.Fatal(err)
	}
	_, token, err := s.CreateApplication(ctx, "billing", "production", []string{"apps/billing/production"}, 1, "")
	if err != nil {
		t.Fatal(err)
	}
	request, err := s.Access(ctx, token, nil, "configured-instance", "")
	if err != nil || request.Status != "waiting_approval" {
		t.Fatal(request, err)
	}
	approvals, err := s.Approvals(ctx)
	if err != nil || len(approvals) != 1 || len(approvals[0].Paths) != 1 || approvals[0].Paths[0] != "apps/billing/production" {
		t.Fatalf("unexpected resolved paths: %#v %v", approvals, err)
	}
	if err = s.Resolve(ctx, request.ApprovalID, 1, true, ""); err != nil {
		t.Fatal(err)
	}
	result, err := s.Poll(ctx, token, request.RequestID, "")
	if err != nil || result.Secrets["apps/billing/production"]["DB_USER"] != "postgres" || len(result.Secrets) != 1 {
		t.Fatal(result, err)
	}
}

func TestLifecycleAndConcurrentStartup(t *testing.T) {
	s := testutil.Store(t)
	ctx := context.Background()
	const path = "projects/crypto/prod/database"
	if _, e := s.SaveSecret(ctx, path, map[string]string{"PASSWORD": "one"}, 1, ""); e != nil {
		t.Fatal(e)
	}
	if _, e := s.SaveSecret(ctx, "projects/crypto/prod/binance", map[string]string{"KEY": "two"}, 1, ""); e != nil {
		t.Fatal(e)
	}
	id, token, e := s.CreateApplication(ctx, "crypto", "production", []string{"projects/crypto/prod/*"}, 1, "")
	if e != nil {
		t.Fatal(e)
	}
	t.Run("unauthorized paths never queue", func(t *testing.T) {
		_, e := s.Access(ctx, token, []string{"projects/other/db"}, "", "")
		if !errors.Is(e, store.ErrForbidden) {
			t.Fatal(e)
		}
		a, e := s.Approvals(ctx)
		if e != nil || len(a) != 0 {
			t.Fatal("unauthorized approval queued", e)
		}
	})
	t.Run("invalid token", func(t *testing.T) {
		_, e := s.Access(ctx, "lg_app_wrong", []string{path}, "", "")
		if !errors.Is(e, store.ErrUnauthorized) {
			t.Fatal(e)
		}
	})
	const n = 24
	out := make([]store.Access, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := path
			if i%2 == 1 {
				p = "projects/crypto/prod/binance"
			}
			out[i], errs[i] = s.Access(ctx, token, []string{p}, fmt.Sprintf("instance-%d", i), "")
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Fatalf("instance %d: %v", i, e)
		}
		if out[i].Status != "waiting_approval" || out[i].ApprovalID != out[0].ApprovalID {
			t.Fatal("duplicate approval", out[i])
		}
	}
	a, e := s.Approvals(ctx)
	if e != nil || len(a) != 1 || a[0].Waiting != n || len(a[0].Paths) != 2 {
		t.Fatalf("bad aggregation: %+v %v", a, e)
	}
	retry, e := s.Access(ctx, token, []string{path}, "instance-0", "")
	if e != nil || retry.RequestID != out[0].RequestID {
		t.Fatal("not idempotent", e)
	}
	a, _ = s.Approvals(ctx)
	if a[0].Waiting != n {
		t.Fatal("retry inflated waiting count")
	}
	_, e = s.Access(ctx, token, []string{"projects/crypto/prod/binance"}, "instance-0", "")
	if !errors.Is(e, store.ErrConflict) {
		t.Fatal("idempotency payload mismatch allowed", e)
	}
	// The database constraint must protect the invariant independently of service locks.
	_, e = s.DB.Exec(ctx, `INSERT INTO access_requests(id,application_id) VALUES('duplicate',$1)`, id)
	if e == nil {
		t.Fatal("missing unique pending constraint")
	}
	if e = s.Resolve(ctx, out[0].ApprovalID, 1, true, ""); e != nil {
		t.Fatal(e)
	}
	for i, r := range out {
		got, e := s.Poll(ctx, token, r.RequestID, "")
		if e != nil || got.Status != "approved" || len(got.Secrets) != 1 {
			t.Fatal("approval failed or leaked other instance paths", i, e)
		}
	}
	got, e := s.Access(ctx, token, []string{path}, "restart", "")
	if e != nil || got.Status != "approved" {
		t.Fatal("restart should retain grant", e)
	}
	if _, e = s.ChangeApplication(ctx, id, 1, "revoke", nil, ""); e != nil {
		t.Fatal(e)
	}
	got, e = s.Poll(ctx, token, out[0].RequestID, "")
	if e != nil || got.Status != "revoked" || len(got.Secrets) != 0 {
		t.Fatal("revoked poll exposed secrets", e)
	}
	got, e = s.Access(ctx, token, []string{path}, "restart-2", "")
	if e != nil || got.Status != "waiting_approval" || got.ApprovalID == out[0].ApprovalID {
		t.Fatal("revocation did not require fresh approval", e)
	}
	if e = s.Resolve(ctx, got.ApprovalID, 1, false, ""); e != nil {
		t.Fatal(e)
	}
	denied, e := s.Poll(ctx, token, got.RequestID, "")
	if e != nil || denied.Status != "denied" {
		t.Fatal("denial failed", e)
	}
	newReq, e := s.Access(ctx, token, []string{path}, "new", "")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Resolve(ctx, newReq.ApprovalID, 1, true, ""); e != nil {
		t.Fatal(e)
	}
	denied, e = s.Poll(ctx, token, got.RequestID, "")
	if e != nil || denied.Status != "denied" {
		t.Fatal("denied request revived", e)
	}
	if _, e = s.ChangeApplication(ctx, id, 1, "disable", nil, ""); e != nil {
		t.Fatal(e)
	}
	_, e = s.Access(ctx, token, []string{path}, "disabled", "")
	if !errors.Is(e, store.ErrUnauthorized) {
		t.Fatal("disabled app accepted", e)
	}
	_, e = s.Poll(ctx, token, newReq.RequestID, "")
	if !errors.Is(e, store.ErrUnauthorized) {
		t.Fatal("disabled poll accepted", e)
	}
	if _, e = s.ChangeApplication(ctx, id, 1, "enable", nil, ""); e != nil {
		t.Fatal(e)
	}
	rotated, e := s.ChangeApplication(ctx, id, 1, "rotate", nil, "")
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.Access(ctx, token, []string{path}, "old-token", "")
	if !errors.Is(e, store.ErrUnauthorized) {
		t.Fatal("rotated token accepted", e)
	}
	got, e = s.Access(ctx, rotated, []string{path}, "rotated", "")
	if e != nil || got.Status != "waiting_approval" {
		t.Fatal("rotated identity inherited grant", e)
	}
	_, other, e := s.CreateApplication(ctx, "other", "production", []string{"projects/crypto/prod/*"}, 1, "")
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.Poll(ctx, other, got.RequestID, "")
	if !errors.Is(e, store.ErrNotFound) {
		t.Fatal("cross-application poll permitted", e)
	}
	if _, e = s.ChangeApplication(ctx, id, 1, "paths", []string{"projects/crypto/prod/binance"}, ""); e != nil {
		t.Fatal(e)
	}
	_, e = s.Poll(ctx, rotated, got.RequestID, "")
	if !errors.Is(e, store.ErrForbidden) {
		t.Fatal("old poll bypasses new path boundary", e)
	}
}
func TestVersioning(t *testing.T) {
	s := testutil.Store(t)
	ctx := context.Background()
	const p = "projects/example/db"
	for i := 1; i <= 2; i++ {
		v, e := s.SaveSecret(ctx, p, map[string]string{"PASSWORD": fmt.Sprintf("plaintext-%d", i)}, 1, "")
		if e != nil || v != i {
			t.Fatal(v, e)
		}
	}
	if e := s.Restore(ctx, p, 1, 1, ""); e != nil {
		t.Fatal(e)
	}
	values, e := s.ReadSecret(ctx, p, 1, "")
	if e != nil || values["PASSWORD"] != "plaintext-1" {
		t.Fatal("restore failed", e)
	}
	versions, e := s.Versions(ctx, p)
	if e != nil || len(versions) != 3 {
		t.Fatal("old versions overwritten", e)
	}
	_, e = s.DB.Exec(ctx, `UPDATE secret_versions SET ciphertext='changed' WHERE version=1`)
	if e == nil {
		t.Fatal("immutable version changed")
	}
	var ciphertext, dek []byte
	if e = s.DB.QueryRow(ctx, `SELECT ciphertext,encrypted_dek FROM secret_versions LIMIT 1`).Scan(&ciphertext, &dek); e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(ciphertext, []byte("plaintext-")) || len(dek) == 0 {
		t.Fatal("plaintext storage")
	}
	const n = 10
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, e := s.SaveSecret(ctx, p, map[string]string{"N": fmt.Sprint(i)}, 1, "")
			errs <- e
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	versions, e = s.Versions(ctx, p)
	if e != nil || len(versions) != 13 || versions[0].Number != 13 {
		t.Fatal("concurrent versions lost", e)
	}
}
func TestRevocationUnderLoad(t *testing.T) {
	s := testutil.Store(t)
	ctx := context.Background()
	p := "a/b"
	if _, e := s.SaveSecret(ctx, p, map[string]string{"K": "V"}, 1, ""); e != nil {
		t.Fatal(e)
	}
	id, token, e := s.CreateApplication(ctx, "load", "test", []string{"a/*"}, 1, "")
	if e != nil {
		t.Fatal(e)
	}
	r, e := s.Access(ctx, token, []string{p}, "first", "")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Resolve(ctx, r.ApprovalID, 1, true, ""); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = s.Access(ctx, token, []string{p}, "load", "") }()
	}
	if _, e = s.ChangeApplication(ctx, id, 1, "revoke", nil, ""); e != nil {
		t.Fatal(e)
	}
	wg.Wait()
	for i := 0; i < 12; i++ {
		got, e := s.Access(ctx, token, []string{p}, fmt.Sprint(i), "")
		if e != nil || got.Status != "waiting_approval" || len(got.Secrets) > 0 {
			t.Fatal("post-revocation access", e)
		}
	}
}

func TestArchiveAndRestore(t *testing.T) {
	s := testutil.Store(t)
	ctx := context.Background()
	p := "archive/db"
	if _, e := s.SaveSecret(ctx, p, map[string]string{"KEY": "value"}, 1, ""); e != nil {
		t.Fatal(e)
	}
	_, token, e := s.CreateApplication(ctx, "archive", "test", []string{"archive/*"}, 1, "")
	if e != nil {
		t.Fatal(e)
	}
	r, e := s.Access(ctx, token, []string{p}, "instance", "")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Resolve(ctx, r.ApprovalID, 1, true, ""); e != nil {
		t.Fatal(e)
	}
	if e = s.Archive(ctx, p, 1, ""); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Access(ctx, token, []string{p}, "new", ""); !errors.Is(e, store.ErrNotFound) {
		t.Fatal("archived secret exposed", e)
	}
	if _, e = s.Poll(ctx, token, r.RequestID, ""); !errors.Is(e, store.ErrNotFound) {
		t.Fatal("poll exposed archived secret", e)
	}
	if e = s.Restore(ctx, p, 1, 1, ""); e != nil {
		t.Fatal(e)
	}
	got, e := s.Access(ctx, token, []string{p}, "restored", "")
	if e != nil || got.Status != "approved" {
		t.Fatal("restored path unavailable", e)
	}
	versions, e := s.Versions(ctx, p)
	if e != nil || len(versions) != 2 {
		t.Fatal("history lost", e)
	}
}
