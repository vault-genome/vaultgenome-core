// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/console"
)

//go:embed ui/index.html
var indexHTML []byte

const sessionCookie = "vgconsole"

// web is the page on loopback. Only the browser holding the token reaches
// it: a page from anywhere else has neither the cookie nor, because the Host
// header is checked, a way in through a name that resolves here.
type web struct {
	app   *App
	token string
	addr  string
}

func newWeb(app *App, token, addr string) *web { return &web{app: app, token: token, addr: addr} }

func (w *web) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", w.page)
	mux.HandleFunc("GET /api/servers", w.api(w.servers))
	mux.HandleFunc("GET /api/overview", w.api(w.overviewAPI))
	mux.HandleFunc("POST /api/join", w.api(w.join))
	mux.HandleFunc("POST /api/check", w.api(w.check))
	mux.HandleFunc("POST /api/restore", w.api(w.restore))
	mux.HandleFunc("GET /api/job", w.api(w.jobAPI))
	mux.HandleFunc("POST /api/stop", w.api(w.stop))
	mux.HandleFunc("POST /api/invite", w.api(w.invite))
	mux.HandleFunc("POST /api/remove", w.api(w.remove))
	return w.guard(mux)
}

func (w *web) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if !w.hostAllowed(r.Host) {
			http.Error(rw, "wrong host", http.StatusForbidden)
			return
		}
		rw.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		rw.Header().Set("X-Content-Type-Options", "nosniff")
		rw.Header().Set("Referrer-Policy", "no-referrer")
		rw.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(rw, r)
	})
}

// hostAllowed admits only this listener's own address, by number or as
// localhost: a site that points its own name here is refused.
func (w *web) hostAllowed(host string) bool {
	if host == w.addr {
		return true
	}
	_, port, err := net.SplitHostPort(w.addr)
	return err == nil && host == net.JoinHostPort("localhost", port)
}

func (w *web) authorized(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	return err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(w.token)) == 1
}

// page takes the token from the address once, moves it to a cookie and sends
// the browser to a clean address.
func (w *web) page(rw http.ResponseWriter, r *http.Request) {
	if t := r.URL.Query().Get("t"); t != "" {
		if subtle.ConstantTimeCompare([]byte(t), []byte(w.token)) != 1 {
			http.Error(rw, "wrong token", http.StatusForbidden)
			return
		}
		http.SetCookie(rw, &http.Cookie{Name: sessionCookie, Value: w.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
		http.Redirect(rw, r, "/", http.StatusSeeOther)
		return
	}
	if !w.authorized(r) {
		http.Error(rw, "open the address vgconsole printed", http.StatusForbidden)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = rw.Write(indexHTML)
}

type apiFunc func(ctx context.Context, r *http.Request, lang string) (any, error)

func (w *web) api(f apiFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		if !w.authorized(r) {
			http.Error(rw, "forbidden", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-VG-Console") != "1" {
			http.Error(rw, "forbidden", http.StatusForbidden)
			return
		}
		lang := r.URL.Query().Get("lang")
		if lang != "ru" {
			lang = "en"
		}
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		out, err := f(ctx, r, lang)
		rw.Header().Set("Content-Type", "application/json")
		if err != nil {
			rw.WriteHeader(http.StatusUnprocessableEntity)
			_ = json.NewEncoder(rw).Encode(map[string]string{"error": plainError(lang, err)})
			return
		}
		_ = json.NewEncoder(rw).Encode(out)
	}
}

func (w *web) servers(context.Context, *http.Request, string) (any, error) {
	type row struct {
		ID    string `json:"id"`
		Label string `json:"label"`
	}
	out := []row{}
	for _, s := range w.app.Servers() {
		out = append(out, row{s.id, s.pass.ServerLabel})
	}
	return out, nil
}

// refresh asks the chip and reads the journal; what fails stays on the server
// object and the overview says so.
func refresh(ctx context.Context, s *server) {
	if _, err := s.check(ctx); err == nil {
		_ = s.refreshJournal(ctx)
	}
}

func (w *web) overviewAPI(ctx context.Context, r *http.Request, lang string) (any, error) {
	s, err := w.app.Server(r.URL.Query().Get("server"))
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	never := s.last == nil && s.lastErr == nil && s.unproven == nil
	s.mu.Unlock()
	if never {
		refresh(ctx, s)
	}
	return w.app.overview(s, lang), nil
}

func (w *web) join(_ context.Context, r *http.Request, lang string) (any, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	s, err := w.app.Join(raw)
	if err != nil {
		return nil, err
	}
	return w.app.overview(s, lang), nil
}

func (w *web) check(ctx context.Context, r *http.Request, lang string) (any, error) {
	s, err := w.app.Server(r.URL.Query().Get("server"))
	if err != nil {
		return nil, err
	}
	refresh(ctx, s)
	return w.app.overview(s, lang), nil
}

func (w *web) restore(ctx context.Context, r *http.Request, _ string) (any, error) {
	s, err := w.app.Server(r.URL.Query().Get("server"))
	if err != nil {
		return nil, err
	}
	return s.restoreCheck(ctx)
}

func (w *web) jobAPI(ctx context.Context, r *http.Request, lang string) (any, error) {
	s, err := w.app.Server(r.URL.Query().Get("server"))
	if err != nil {
		return nil, err
	}
	j, err := s.job(ctx, r.URL.Query().Get("id"))
	if err != nil {
		return nil, err
	}
	text, step := stageText(lang, j.State)
	out := map[string]any{"status": j.Status, "stage": text, "step": step, "steps": 5, "level": j.GateLevel, "fixtures": j.Fixtures}
	if j.CompletedAt != nil {
		out["seconds"] = j.CompletedAt.Sub(j.SubmittedAt).Seconds()
	}
	switch {
	case j.Status == "succeeded":
		out["done"] = tr(lang, "Модель вернулась точно такой же", "The model came back exactly the same")
		if j.GateLevel == "EQUIVALENT" {
			out["done"] = tr(lang, "Модель вернулась в пределах допуска", "The model came back within tolerance")
		}
	case j.Status == "failed":
		out["failed"] = refusalText(lang, j)
	}
	return out, nil
}

func refusalText(lang string, j console.JobSummary) string {
	if j.ErrorCode == "trust.operator_stop" || containsStop(j.ErrorCode) || containsStop(j.ErrorMessage) {
		return tr(lang, "Отказано: включена аварийная остановка", "Refused: the emergency stop is on")
	}
	return tr(lang, "Модель не вернулась. Подробности в журнале.", "The model did not come back. See the journal.")
}

func (w *web) stop(ctx context.Context, r *http.Request, lang string) (any, error) {
	s, err := w.app.Server(r.URL.Query().Get("server"))
	if err != nil {
		return nil, err
	}
	var req struct {
		Stop   bool   `json:"stop"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		return nil, err
	}
	res, err := s.check(ctx)
	if err != nil {
		return nil, err
	}
	if err := w.app.setStop(ctx, s, res.State.Stop, req.Stop, req.Reason); err != nil {
		return nil, err
	}
	refresh(ctx, s)
	return w.app.overview(s, lang), nil
}

func (w *web) invite(ctx context.Context, r *http.Request, _ string) (any, error) {
	s, err := w.app.Server(r.URL.Query().Get("server"))
	if err != nil {
		return nil, err
	}
	var req struct {
		Name string       `json:"name"`
		Role console.Role `json:"role"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		return nil, err
	}
	raw, err := w.app.Invite(ctx, s, req.Name, req.Role)
	if err != nil {
		return nil, err
	}
	return map[string]any{"pass": string(raw)}, nil
}

func (w *web) remove(ctx context.Context, r *http.Request, lang string) (any, error) {
	s, err := w.app.Server(r.URL.Query().Get("server"))
	if err != nil {
		return nil, err
	}
	var req console.RemoveRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		return nil, err
	}
	if err := s.callJSON(ctx, http.MethodPost, "/v1/console/people/remove", req, nil); err != nil {
		return nil, err
	}
	refresh(ctx, s)
	return w.app.overview(s, lang), nil
}
