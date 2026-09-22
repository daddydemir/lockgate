package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestWaitAndRestart(t *testing.T) {
	var polls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer lg_app_test" {
			t.Error("missing token")
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "POST" {
			if r.Header.Get("Idempotency-Key") == "" {
				t.Error("missing instance identity")
			}
			fmt.Fprint(w, `{"status":"waiting_approval","request_id":"abc"}`)
		} else {
			polls.Add(1)
			fmt.Fprint(w, `{"status":"approved","secrets":{"a/b":{"KEY":"VALUE"}}}`)
		}
	}))
	defer ts.Close()
	c := New(Config{URL: ts.URL, Token: "lg_app_test", PollInterval: time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	v, e := c.Get(ctx, "a/b")
	if e != nil || v["a/b"]["KEY"] != "VALUE" || polls.Load() != 1 {
		t.Fatal(v, e)
	}
}
func TestGetSecretReturnsFlatBundle(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"approved","secrets":{"apps/payments/production":{"DB_USER":"postgres","DB_PASSWORD":"secret"}}}`)
	}))
	defer ts.Close()
	values, err := New(Config{URL: ts.URL, Token: "lg_app_test"}).GetSecret(context.Background(), "apps/payments/production")
	if err != nil || values["DB_USER"] != "postgres" || values["DB_PASSWORD"] != "secret" {
		t.Fatal(values, err)
	}
}
func TestGetSecretRequiresPath(t *testing.T) {
	if _, err := New(Config{}).GetSecret(context.Background(), ""); err == nil {
		t.Fatal("empty secret path succeeded")
	}
}
func TestGetConfigUsesTokenAssignedBundle(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) != 0 {
			t.Errorf("expected empty access body, got %#v: %v", body, err)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"approved","secrets":{"apps/payments/production":{"DB_USER":"postgres"}}}`)
	}))
	defer ts.Close()
	values, err := New(Config{URL: ts.URL, Token: "lg_app_test"}).GetConfig(context.Background())
	if err != nil || values["DB_USER"] != "postgres" {
		t.Fatal(values, err)
	}
}
func TestFailureModes(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		code       int
		expected   error
	}{{"denied", `{"status":"denied"}`, 200, ErrDenied}, {"unauthorized", "", 401, nil}, {"incomplete", `{"status":"approved","secrets":{}}`, 200, nil}, {"bad JSON", "not JSON", 200, nil}, {"unknown status", `{"status":"maybe"}`, 200, nil}} {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tt.code); fmt.Fprint(w, tt.body) }))
			defer ts.Close()
			_, e := New(Config{URL: ts.URL, Token: "token"}).Get(context.Background(), "a/b")
			if e == nil || tt.expected != nil && !errors.Is(e, tt.expected) {
				t.Fatal(e)
			}
		})
	}
}
func TestCancellation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"waiting_approval","request_id":"abc"}`)
	}))
	defer ts.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, e := New(Config{URL: ts.URL, Token: "token"}).Get(ctx, "a/b")
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
}
func TestRedirectDoesNotLeakToken(t *testing.T) {
	var leaked atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Store(true) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer source.Close()
	_, e := New(Config{URL: source.URL, Token: "secret"}).Get(context.Background(), "a/b")
	if e == nil || leaked.Load() {
		t.Fatal("redirect followed")
	}
}
func TestUnreachable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	u := ts.URL
	ts.Close()
	_, e := New(Config{URL: u, Token: "token"}).Get(context.Background(), "a/b")
	if e == nil {
		t.Fatal("unreachable server succeeded")
	}
}
