package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"lockgate/internal/secure"
	"lockgate/internal/store"
	"lockgate/web"
)

type Config struct {
	Origin        string
	SecureCookies bool
}
type Server struct {
	Store      *store.Store
	config     Config
	templates  *template.Template
	mux        *http.ServeMux
	loginSlots chan struct{}
	mu         sync.Mutex
	attempts   map[string]attempt
}
type attempt struct {
	Count int
	Until time.Time
}
type sessionKey struct{}
type Page struct {
	Archived                                                           bool
	Title, Section, CSRF, Username, Error, Notice, Token, Path, Values string
	PublicURL                                                          string
	Application                                                        store.Application
	Applications                                                       []store.Application
	Secrets                                                            []store.Secret
	Versions                                                           []store.Version
	Approvals                                                          []store.Approval
	Events                                                             []store.Event
	Counts                                                             map[string]int
}

func New(s *store.Store, c Config) (*Server, error) {
	origin, e := url.Parse(c.Origin)
	if e != nil || origin.Host == "" || (origin.Scheme != "https" && origin.Scheme != "http") || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" || origin.User != nil {
		return nil, errors.New("LOCKGATE_ORIGIN must be an http(s) origin without a path")
	}
	if c.SecureCookies && origin.Scheme != "https" {
		return nil, errors.New("HTTPS origin required unless explicitly enabling insecure development cookies")
	}
	assets := map[string]string{}
	for _, name := range []string{"app.css", "app.js", "theme-init.js", "favicon.svg"} {
		body, err := web.FS.ReadFile("static/" + name)
		if err != nil {
			return nil, err
		}
		hash := sha256.Sum256(body)
		assets[name] = fmt.Sprintf("/static/%s?v=%x", name, hash[:8])
	}
	t, e := template.New("").Funcs(template.FuncMap{
		"join":  strings.Join,
		"asset": func(name string) string { return assets[name] },
		"time":  func(t time.Time) string { return t.UTC().Format("02 Jan 2006 · 15:04:05 UTC") },
	}).ParseFS(web.FS, "templates/*.html")
	if e != nil {
		return nil, e
	}
	a := &Server{Store: s, config: c, templates: t, mux: http.NewServeMux(), loginSlots: make(chan struct{}, 2), attempts: map[string]attempt{}}
	a.routes()
	return a, nil
}
func (s *Server) routes() {
	static, _ := fs.Sub(web.FS, "static")
	files := http.StripPrefix("/static/", http.FileServer(http.FS(static)))
	s.mux.Handle("GET /static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		files.ServeHTTP(w, r)
	}))
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if s.Store.DB.Ping(ctx) != nil {
			http.Error(w, "database unavailable", 503)
			return
		}
		w.Write([]byte("ok\n"))
	})
	s.mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/admin", http.StatusSeeOther) })
	s.mux.HandleFunc("GET /admin/login", s.loginPage)
	s.mux.HandleFunc("POST /admin/login", s.login)
	s.mux.HandleFunc("POST /api/v1/access", s.access)
	s.mux.HandleFunc("GET /api/v1/access/{id}", s.poll)
	s.admin("GET /admin", s.dashboard)
	s.admin("POST /admin/logout", s.logout)
	s.admin("GET /admin/applications", s.applications)
	s.admin("POST /admin/applications", s.createApplication)
	s.admin("GET /admin/applications/{id}", s.application)
	s.admin("POST /admin/applications/{id}", s.changeApplication)
	s.admin("GET /admin/secrets", s.secrets)
	s.admin("POST /admin/secrets", s.saveSecret)
	s.admin("GET /admin/secret", s.secret)
	s.admin("POST /admin/secret/restore", s.restore)
	s.admin("POST /admin/secret/archive", s.archive)
	s.admin("GET /admin/approvals", s.approvals)
	s.admin("POST /admin/approvals/{id}", s.resolve)
	s.admin("GET /admin/audit", s.audit)
	s.admin("GET /admin/docs", s.docs)
	s.admin("GET /admin/events", s.events)
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if s.config.SecureCookies {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1100000)
	s.mux.ServeHTTP(w, r)
}
func ip(r *http.Request) string {
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		return ""
	}
	return host
}
func (s *Server) cookie(w http.ResponseWriter, name, value string, age int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/admin", HttpOnly: true, Secure: s.config.SecureCookies, SameSite: http.SameSiteStrictMode, MaxAge: age})
}
func equal(a, b string) bool {
	return a != "" && b != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
func (s *Server) originOK(r *http.Request) bool {
	if origin := r.Header.Get("Origin"); origin != "" {
		return origin == s.config.Origin
	}
	if ref := r.Referer(); ref != "" {
		u, e := url.Parse(ref)
		return e == nil && u.Scheme+"://"+u.Host == s.config.Origin
	}
	return false
}
func (s *Server) admin(route string, h http.HandlerFunc) {
	s.mux.HandleFunc(route, func(w http.ResponseWriter, r *http.Request) {
		c, e := r.Cookie("lg_session")
		if e != nil {
			http.Redirect(w, r, "/admin/login", 303)
			return
		}
		a, e := s.Store.Session(r.Context(), c.Value)
		if e != nil {
			if !errors.Is(e, store.ErrUnauthorized) {
				s.fail(w, r, e)
				return
			}
			http.Redirect(w, r, "/admin/login", 303)
			return
		}
		if r.Method == http.MethodPost {
			if !s.originOK(r) || r.ParseForm() != nil || !equal(r.PostForm.Get("csrf"), a.CSRF) {
				http.Error(w, "Invalid CSRF token or origin. Reload the page and try again.", 403)
				return
			}
		}
		h(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, a)))
	})
}
func session(r *http.Request) store.Session { return r.Context().Value(sessionKey{}).(store.Session) }
func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, p Page) {
	if a, ok := r.Context().Value(sessionKey{}).(store.Session); ok {
		p.CSRF = a.CSRF
		p.Username = a.Username
	}
	p.Section = name
	var b bytes.Buffer
	if e := s.templates.ExecuteTemplate(&b, name, p); e != nil {
		s.fail(w, r, e)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(b.Bytes())
}
func status(err error) (int, string) {
	var dbError *pgconn.PgError
	if errors.As(err, &dbError) && dbError.Code == "23505" {
		return 409, "A record with that name already exists."
	}
	switch {
	case errors.Is(err, store.ErrUnauthorized):
		return 401, "Invalid token, credentials, or disabled application"
	case errors.Is(err, store.ErrForbidden):
		return 403, "Requested secret path is not allowed"
	case errors.Is(err, store.ErrNotFound):
		return 404, "Record not found"
	case errors.Is(err, store.ErrInvalid):
		return 400, "Invalid input. Check the fields and try again."
	case errors.Is(err, store.ErrConflict):
		return 409, "Record already exists or has changed. Reload and try again."
	}
	return 500, "The operation could not be completed"
}
func (s *Server) fail(w http.ResponseWriter, r *http.Request, e error) {
	code, msg := status(e)
	// PostgreSQL errors can contain secret/token input in Detail. Never log them.
	if code == 500 {
		slog.Error("request failed", "method", r.Method, "error_type", fmt.Sprintf("%T", e))
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeJSON(w, code, map[string]string{"error": msg})
		return
	}
	http.Error(w, msg, code)
}
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
func token(r *http.Request) string {
	v := r.Header.Get("Authorization")
	if !strings.HasPrefix(v, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(v, "Bearer ")
}
func (s *Server) access(w http.ResponseWriter, r *http.Request) {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		writeJSON(w, 415, map[string]string{"error": "Content-Type must be application/json"})
		return
	}
	var in struct {
		Secrets []string `json:"secrets"`
	}
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(&in); e != nil {
		s.fail(w, r, store.ErrInvalid)
		return
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		s.fail(w, r, store.ErrInvalid)
		return
	}
	out, e := s.Store.Access(r.Context(), token(r), in.Secrets, r.Header.Get("Idempotency-Key"), ip(r))
	if e != nil {
		s.fail(w, r, e)
		return
	}
	if out.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(out.RetryAfter))
	}
	code := 200
	if out.Status == "waiting_approval" {
		code = 202
	}
	writeJSON(w, code, out)
}
func (s *Server) poll(w http.ResponseWriter, r *http.Request) {
	out, e := s.Store.Poll(r.Context(), token(r), r.PathValue("id"), ip(r))
	if e != nil {
		s.fail(w, r, e)
		return
	}
	if out.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(out.RetryAfter))
	}
	writeJSON(w, 200, out)
}
func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	csrf := secure.Random(32)
	s.cookie(w, "lg_login", csrf, 600)
	s.render(w, r, "login", Page{Title: "Welcome back", CSRF: csrf})
}
func (s *Server) loginAllowed(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.attempts {
		if now.After(v.Until) {
			delete(s.attempts, k)
		}
	}
	v, ok := s.attempts[ip]
	if !ok {
		if len(s.attempts) >= 10000 {
			return false
		}
		v = attempt{Until: now.Add(10 * time.Minute)}
	}
	v.Count++
	s.attempts[ip] = v
	return v.Count <= 10
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	c, e := r.Cookie("lg_login")
	if e != nil || !s.originOK(r) || r.ParseForm() != nil || !equal(c.Value, r.PostForm.Get("csrf")) {
		http.Error(w, "Invalid login CSRF token or origin. Reload the login page.", 403)
		return
	}
	if !s.loginAllowed(ip(r)) {
		http.Error(w, "Too many login attempts. Try again in 10 minutes.", 429)
		return
	}
	select {
	case s.loginSlots <- struct{}{}:
		defer func() { <-s.loginSlots }()
	default:
		http.Error(w, "Login busy. Try again shortly.", 429)
		return
	}
	username, password := r.PostForm.Get("username"), r.PostForm.Get("password")
	if len(username) > 100 || len(password) > 1024 {
		s.fail(w, r, store.ErrInvalid)
		return
	}
	t, e := s.Store.Login(r.Context(), username, password, ip(r))
	if e != nil {
		if errors.Is(e, store.ErrUnauthorized) {
			s.render(w, r, "login", Page{Title: "Welcome back", CSRF: c.Value, Error: "Username or password is incorrect."})
			return
		}
		s.fail(w, r, e)
		return
	}
	s.cookie(w, "lg_login", "", -1)
	s.cookie(w, "lg_session", t, 43200)
	http.Redirect(w, r, "/admin", 303)
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie("lg_session")
	if e := s.Store.Logout(r.Context(), c.Value); e != nil {
		s.fail(w, r, e)
		return
	}
	s.cookie(w, "lg_session", "", -1)
	http.Redirect(w, r, "/admin/login", 303)
}
