package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"lockgate/internal/store"
	"lockgate/internal/testutil"
	lockgate "lockgate/pkg/client"
)

func TestHTTPWorkflow(t *testing.T) {
	db := testutil.Store(t)
	ctx := context.Background()
	s, e := New(db, Config{Origin: "https://lockgate.test", SecureCookies: true})
	if e != nil {
		t.Fatal(e)
	}
	do := func(method, path string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "https://lockgate.test"+path, strings.NewReader(form.Encode()))
		r.Header.Set("Origin", "https://lockgate.test")
		if form != nil {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		for _, c := range cookies {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	login := do("GET", "/admin/login", nil)
	if login.Header().Get("Referrer-Policy") != "same-origin" {
		t.Fatal("browser forms require a same-origin referrer policy for origin-based CSRF checks")
	}
	if login.Code != 200 {
		t.Fatal(login.Body.String())
	}
	cookies := login.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("insecure login cookie")
	}
	fields := url.Values{"username": {"admin"}, "password": {"test-password-at-least-12"}, "csrf": {cookies[0].Value}}
	logged := do("POST", "/admin/login", fields, cookies[0])
	if logged.Code != 303 {
		t.Fatal(logged.Body.String())
	}
	var cookie *http.Cookie
	for _, c := range logged.Result().Cookies() {
		if c.Name == "lg_session" {
			cookie = c
		}
	}
	if cookie == nil || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("missing secure session cookie")
	}
	session, e := db.Session(ctx, cookie.Value)
	if e != nil {
		t.Fatal(e)
	}
	t.Run("CSRF and origin rejected", func(t *testing.T) {
		for _, origin := range []string{"https://evil.test", ""} {
			r := httptest.NewRequest("POST", "https://lockgate.test/admin/applications", strings.NewReader(url.Values{"csrf": {session.CSRF}}.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", origin)
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != 403 {
				t.Fatal("bad origin accepted", w.Code)
			}
		}
		w := do("POST", "/admin/applications", url.Values{"csrf": {"wrong"}}, cookie)
		if w.Code != 403 {
			t.Fatal("bad csrf accepted")
		}
	})
	created := do("POST", "/admin/applications", url.Values{"csrf": {session.CSRF}, "name": {"browser-app"}, "environment": {"test"}, "paths": {"projects/test/*"}}, cookie)
	if created.Code != 200 || !strings.Contains(created.Body.String(), "shown only once") {
		t.Fatal(created.Body.String())
	}
	secret := do("POST", "/admin/secrets", url.Values{"csrf": {session.CSRF}, "path": {"projects/test/db"}, "values": {"{\"PASSWORD\":\"sensitive-value\"}"}}, cookie)
	if secret.Code != 303 {
		t.Fatal(secret.Body.String())
	}
	id, token, e := db.CreateApplication(ctx, "machine", "test", []string{"projects/test/*"}, 1, "")
	if e != nil {
		t.Fatal(e)
	}
	post := func(token string, sessionCookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://lockgate.test/api/v1/access", strings.NewReader(`{"secrets":["projects/test/db"]}`))
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		if sessionCookie != nil {
			r.AddCookie(sessionCookie)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	if w := post("", cookie); w.Code != 401 {
		t.Fatal("browser session authorized machine endpoint", w.Code)
	}
	req := post(token, nil)
	if req.Code != 202 {
		t.Fatal(req.Body.String())
	}
	var access store.Access
	if e = json.Unmarshal(req.Body.Bytes(), &access); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{"/admin", "/admin/applications", "/admin/applications/" + jsonNumber(id), "/admin/secrets", "/admin/secret?path=projects/test/db", "/admin/approvals", "/admin/audit", "/admin/docs"} {
		w := do("GET", p, nil, cookie)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", p, w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("sensitive page cached")
		}
	}
	asset := do("GET", "/static/app.css", nil, nil)
	if asset.Code != 200 || asset.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Fatal("static assets are not cacheable", asset.Code, asset.Header().Get("Cache-Control"))
	}
	docs := do("GET", "/admin/docs", nil, cookie)
	if !strings.Contains(docs.Body.String(), "https://lockgate.test/api/v1/access") || !strings.Contains(docs.Body.String(), "No LockGate SDK or Go package is required") || !strings.Contains(docs.Body.String(), "There is no published") {
		t.Fatal("documentation is missing configured API or language-neutral guidance")
	}
	audit := do("GET", "/admin/audit", nil, cookie)
	if strings.Contains(audit.Body.String(), token) || strings.Contains(audit.Body.String(), "sensitive-value") {
		t.Fatal("audit leaks secrets")
	}
	approved := do("POST", "/admin/approvals/"+access.ApprovalID, url.Values{"csrf": {session.CSRF}, "action": {"approve"}}, cookie)
	if approved.Code != 303 {
		t.Fatal(approved.Body.String())
	}
	w := post(token, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "sensitive-value") {
		t.Fatal("approved API failed", w.Body.String())
	}
	// The embedded Go client must use the actual application API correctly.
	httpServer := httptest.NewServer(s)
	defer httpServer.Close()
	client := lockgate.New(lockgate.Config{URL: httpServer.URL, Token: token})
	got, e := client.Get(ctx, "projects/test/db")
	if e != nil || got["projects/test/db"]["PASSWORD"] != "sensitive-value" {
		t.Fatal("client integration", e)
	}
	if w = do("POST", "/admin/logout", url.Values{"csrf": {session.CSRF}}, cookie); w.Code != 303 {
		t.Fatal(w.Body.String())
	}
	if _, e = db.Session(ctx, cookie.Value); e == nil {
		t.Fatal("session survived logout")
	}
}
func jsonNumber(id int64) string { b, _ := json.Marshal(id); return string(b) }
func TestSSE(t *testing.T) {
	db := testutil.Store(t)
	s, e := New(db, Config{Origin: "http://lockgate.test"})
	if e != nil {
		t.Fatal(e)
	}
	token, e := db.Login(context.Background(), "admin", "test-password-at-least-12", "")
	if e != nil {
		t.Fatal(e)
	}
	ts := httptest.NewServer(s)
	defer ts.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", ts.URL+"/admin/events", nil)
	req.AddCookie(&http.Cookie{Name: "lg_session", Value: token})
	res, e := http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer res.Body.Close()
	if res.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatal("SSE not enabled")
	}
	b := make([]byte, 13)
	if _, e = io.ReadFull(res.Body, b); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(b), "heartbeat") {
		t.Fatal("missing heartbeat")
	}
}
func TestCookieConfig(t *testing.T) {
	if _, e := New(nil, Config{Origin: "http://localhost:8080", SecureCookies: true}); e == nil {
		t.Fatal("insecure default accepted")
	}
	if _, e := New(nil, Config{Origin: "http://localhost:8080"}); e != nil {
		t.Fatal(e)
	}
}
