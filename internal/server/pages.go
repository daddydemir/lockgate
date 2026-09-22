package server

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"lockgate/internal/store"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	counts, e := s.Store.Counts(r.Context())
	if e != nil {
		s.fail(w, r, e)
		return
	}
	events, e := s.Store.Events(r.Context())
	if e != nil {
		s.fail(w, r, e)
		return
	}
	if len(events) > 8 {
		events = events[:8]
	}
	s.render(w, r, "dashboard", Page{Title: "Overview", Counts: counts, Events: events})
}
func (s *Server) applications(w http.ResponseWriter, r *http.Request) {
	a, e := s.Store.Applications(r.Context())
	if e != nil {
		s.fail(w, r, e)
		return
	}
	s.render(w, r, "applications", Page{Title: "Applications", Applications: a})
}
func paths(raw string) []string { return strings.Fields(strings.ReplaceAll(raw, ",", " ")) }
func (s *Server) createApplication(w http.ResponseWriter, r *http.Request) {
	id, t, e := s.Store.CreateApplication(r.Context(), strings.TrimSpace(r.PostForm.Get("name")), strings.TrimSpace(r.PostForm.Get("environment")), paths(r.PostForm.Get("paths")), session(r).AdminID, ip(r))
	if e != nil {
		s.fail(w, r, e)
		return
	}
	s.render(w, r, "token", Page{Title: "Application created", Token: t, Application: store.Application{ID: id}})
}
func appID(r *http.Request) int64 { id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64); return id }
func (s *Server) application(w http.ResponseWriter, r *http.Request) {
	all, e := s.Store.Applications(r.Context())
	if e != nil {
		s.fail(w, r, e)
		return
	}
	for _, a := range all {
		if a.ID == appID(r) {
			s.render(w, r, "application", Page{Title: a.Name, Application: a})
			return
		}
	}
	s.fail(w, r, store.ErrNotFound)
}
func (s *Server) changeApplication(w http.ResponseWriter, r *http.Request) {
	t, e := s.Store.ChangeApplication(r.Context(), appID(r), session(r).AdminID, r.PostForm.Get("action"), paths(r.PostForm.Get("paths")), ip(r))
	if e != nil {
		s.fail(w, r, e)
		return
	}
	if t != "" {
		s.render(w, r, "token", Page{Title: "Token rotated", Token: t, Application: store.Application{ID: appID(r)}})
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/applications/%d", appID(r)), 303)
}
func (s *Server) secrets(w http.ResponseWriter, r *http.Request) {
	all, e := s.Store.Secrets(r.Context())
	if e != nil {
		s.fail(w, r, e)
		return
	}
	s.render(w, r, "secrets", Page{Title: "Secrets", Secrets: all})
}
func (s *Server) saveSecret(w http.ResponseWriter, r *http.Request) {
	var values map[string]string
	if e := json.Unmarshal([]byte(r.PostForm.Get("values")), &values); e != nil {
		s.fail(w, r, store.ErrInvalid)
		return
	}
	path := strings.TrimSpace(r.PostForm.Get("path"))
	_, e := s.Store.SaveSecret(r.Context(), path, values, session(r).AdminID, ip(r))
	if e != nil {
		s.fail(w, r, e)
		return
	}
	http.Redirect(w, r, "/admin/secret?path="+path, 303)
}
func (s *Server) secret(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	versions, e := s.Store.Versions(r.Context(), path)
	if e != nil {
		s.fail(w, r, e)
		return
	}
	if len(versions) == 0 {
		s.fail(w, r, store.ErrNotFound)
		return
	}
	values, e := s.Store.ReadSecret(r.Context(), path, session(r).AdminID, ip(r))
	if e != nil {
		s.fail(w, r, e)
		return
	}
	b, e := json.MarshalIndent(values, "", "  ")
	if e != nil {
		s.fail(w, r, e)
		return
	}
	archived, e := s.Store.IsArchived(r.Context(), path)
	if e != nil {
		s.fail(w, r, e)
		return
	}
	s.render(w, r, "secret", Page{Archived: archived, Title: "Secret details", Path: path, Values: string(b), Versions: versions})
}
func (s *Server) restore(w http.ResponseWriter, r *http.Request) {
	v, _ := strconv.Atoi(r.PostForm.Get("version"))
	p := r.PostForm.Get("path")
	if e := s.Store.Restore(r.Context(), p, v, session(r).AdminID, ip(r)); e != nil {
		s.fail(w, r, e)
		return
	}
	http.Redirect(w, r, "/admin/secret?path="+p, 303)
}
func (s *Server) approvals(w http.ResponseWriter, r *http.Request) {
	all, e := s.Store.Approvals(r.Context())
	if e != nil {
		s.fail(w, r, e)
		return
	}
	s.render(w, r, "approvals", Page{Title: "Approvals", Approvals: all})
}
func (s *Server) resolve(w http.ResponseWriter, r *http.Request) {
	action := r.PostForm.Get("action")
	if action != "approve" && action != "deny" {
		s.fail(w, r, store.ErrInvalid)
		return
	}
	if e := s.Store.Resolve(r.Context(), r.PathValue("id"), session(r).AdminID, action == "approve", ip(r)); e != nil {
		s.fail(w, r, e)
		return
	}
	http.Redirect(w, r, "/admin/approvals", 303)
}
func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	all, e := s.Store.Events(r.Context())
	if e != nil {
		s.fail(w, r, e)
		return
	}
	s.render(w, r, "audit", Page{Title: "Audit log", Events: all})
}
func (s *Server) docs(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "docs", Page{Title: "Documentation", PublicURL: s.config.Origin})
}
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	f, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unavailable", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	var previous [32]byte
	first := true
	for {
		c, e := r.Cookie("lg_session")
		if e != nil {
			return
		}
		if _, e = s.Store.Session(r.Context(), c.Value); e != nil {
			return
		}
		// Only approval identity and live instance counts affect the stream, never secrets.
		all, e := s.Store.Approvals(r.Context())
		if e != nil {
			return
		}
		var snapshot strings.Builder
		for _, a := range all {
			fmt.Fprintf(&snapshot, "%s:%d:%v;", a.ID, a.Waiting, a.Paths)
		}
		hash := sha256.Sum256([]byte(snapshot.String()))
		if !first && hash != previous {
			if _, e = fmt.Fprint(w, "event: approvals\ndata: changed\n\n"); e != nil {
				return
			}
		} else {
			if _, e = fmt.Fprint(w, ": heartbeat\n\n"); e != nil {
				return
			}
		}
		f.Flush()
		previous = hash
		first = false
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) archive(w http.ResponseWriter, r *http.Request) {
	if e := s.Store.Archive(r.Context(), r.PostForm.Get("path"), session(r).AdminID, ip(r)); e != nil {
		s.fail(w, r, e)
		return
	}
	http.Redirect(w, r, "/admin/secrets", 303)
}
