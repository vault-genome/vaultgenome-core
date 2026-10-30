// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/console"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
)

// The buttons against the real daemon: the real sagvd, provisioned by the real
// acpctl, under the simulated TEE, with no worker. What a worker adds is on
// hardware, in scripts/hardware-test/console.

var (
	buildOnce sync.Once
	binDir    string
	errBuild  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if binDir != "" {
		_ = os.RemoveAll(binDir)
	}
	os.Exit(code)
}

func binaries(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		binDir, errBuild = os.MkdirTemp("", "vgconsole-e2e-*")
		if errBuild != nil {
			return
		}
		for _, name := range []string{"sagvd", "acp-compute", "acpctl", "acp-keygen"} {
			out, err := exec.CommandContext(context.Background(), "go", "build", "-o", filepath.Join(binDir, name), "github.com/vault-genome/vaultgenome-core/cmd/"+name).CombinedOutput()
			if err != nil {
				errBuild = fmt.Errorf("go build %s: %w: %s", name, err, out)
				return
			}
		}
	})
	require.NoError(t, errBuild)
	return binDir
}

func freePorts(t *testing.T, n int) []string {
	t.Helper()
	out := make([]string, n)
	var ls []net.Listener
	for i := range out {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		ls = append(ls, l)
		out[i] = l.Addr().String()
	}
	for _, l := range ls {
		_ = l.Close()
	}
	return out
}

type deployment struct {
	dir     string
	address string
	cmd     *exec.Cmd
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.CommandContext(context.Background(), name, args...).CombinedOutput()
	require.NoError(t, err, "%s %v: %s", name, args, out)
	return string(out)
}

// startDeployment provisions a deployment with the console on and starts sagvd;
// with a model, one sealed genome is in its genome directory.
func startDeployment(t *testing.T, withModel bool) *deployment {
	t.Helper()
	bins := binaries(t)
	dir, err := os.MkdirTemp("", "vgc")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ports := freePorts(t, 5)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "base"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "worker"), 0o700))
	run(t, filepath.Join(bins, "acpctl"), "provision", "--out", filepath.Join(dir, "d"), "--bin-dir", bins, "--provider", "simulated", "--insecure-simulation",
		"--console-listen", ports[0], "--vault-listen", ports[1], "--api-listen", ports[2], "--vault-health", ports[3], "--worker-health", ports[4],
		"--door-python", "/bin/sh", "--base-model", filepath.Join(dir, "base"), "--worker-package", filepath.Join(dir, "worker"))
	if withModel {
		content := filepath.Join(dir, "content")
		require.NoError(t, os.MkdirAll(content, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(content, "weights.bin"), []byte("a model, for the test"), 0o600))
		run(t, filepath.Join(bins, "acpctl"), "genome", "seal", "--content-dir", content,
			"--output", filepath.Join(dir, "d", "genomes", "gen-0.genome"), "--key-out", filepath.Join(dir, "d", "genomes", "gen-0.key"))
	}
	cmd := exec.CommandContext(context.Background(), filepath.Join(bins, "sagvd"), "-config", filepath.Join(dir, "d", "sagvd.json"))
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	deadline := time.Now().Add(30 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", ports[0], time.Second)
		if err == nil {
			_ = c.Close()
			break
		}
		require.True(t, time.Now().Before(deadline), "the listener did not come up")
		time.Sleep(50 * time.Millisecond)
	}
	return &deployment{dir: dir, address: ports[0], cmd: cmd}
}

func (d *deployment) pass(t *testing.T, name string, role console.Role) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), "p.vgpass")
	run(t, filepath.Join(binaries(t), "acpctl"), "console", "invite", "--sagvd-config", filepath.Join(d.dir, "d", "sagvd.json"), "--worker-config", filepath.Join(d.dir, "d", "acp-compute.json"),
		"--address", d.address, "--label", name+"'s server", "--name", name, "--role", string(role), "--out", out)
	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	return raw
}

// page is the application's page handler for one person, as their browser
// reaches it.
type page struct {
	t    *testing.T
	app  *App
	h    http.Handler
	host string
}

func newPage(t *testing.T) *page {
	t.Helper()
	a, err := newApp(t.TempDir())
	require.NoError(t, err)
	const addr = "127.0.0.1:7000"
	return &page{t: t, app: a, host: addr, h: newWeb(a, "tk", addr).handler()}
}

func (p *page) do(method, target, body string, out any) (int, string) {
	p.t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Host = p.host
	req.Header.Set(tokenHeader, "tk")
	rec := httptest.NewRecorder()
	p.h.ServeHTTP(rec, req)
	if out != nil && rec.Code == http.StatusOK {
		require.NoError(p.t, json.Unmarshal(rec.Body.Bytes(), out), rec.Body.String())
	}
	return rec.Code, rec.Body.String()
}

func (p *page) overview(server string) Overview {
	p.t.Helper()
	var o Overview
	code, body := p.do(http.MethodPost, "/api/check?lang=ru&server="+server, "", &o)
	require.Equal(p.t, http.StatusOK, code, body)
	return o
}

func lineTitled(o Overview, title string) *CheckLine {
	for i := range o.Lines {
		if strings.Contains(o.Lines[i].Title, title) {
			return &o.Lines[i]
		}
	}
	return nil
}

func journalHas(o Overview, text string) bool {
	for _, j := range o.Journal {
		if strings.Contains(j.Text, text) {
			return true
		}
	}
	return false
}

// A person's whole path through the page, against the real daemon: a pass, what
// is shown, the stop and its lifting, inviting and closing, each on the record.
func TestThePageAgainstTheDaemon(t *testing.T) {
	d := startDeployment(t, false)
	p := newPage(t)

	var empty []map[string]string
	code, _ := p.do(http.MethodGet, "/api/servers", "", &empty)
	require.Equal(t, http.StatusOK, code)
	require.Empty(t, empty)
	code, body := p.do(http.MethodPost, "/api/join?lang=ru", "this is a photo", nil)
	require.Equal(t, http.StatusUnprocessableEntity, code)
	require.Contains(t, body, "vgpass")

	pass := d.pass(t, "Anna", console.RoleOwner)
	var o Overview
	code, body = p.do(http.MethodPost, "/api/join?lang=ru", string(pass), &o)
	require.Equal(t, http.StatusOK, code, body)
	require.Equal(t, "Anna", o.You)
	require.True(t, o.CanStop && o.CanRestore && o.CanInvite, "the first owner holds the stop")
	require.Equal(t, "attention", o.Verdict)
	require.Contains(t, o.Where, "Учебный")
	require.NotNil(t, lineTitled(o, "Второго сервера нет"))
	require.True(t, journalHas(o, "Anna получает доступ"))
	require.True(t, journalHas(o, "Аварийная остановка готова"))

	// The pass is kept without its code.
	stored, err := os.ReadFile(filepath.Join(p.app.dir, "servers", o.ServerID+".json"))
	require.NoError(t, err)
	require.NotContains(t, string(stored), "invite_code", string(stored))

	code, _ = p.do(http.MethodGet, "/api/overview?lang=en", "", &o)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, "Working. Items to review: 2", o.Headline)

	// With no model there is nothing to bring back, in plain words.
	code, body = p.do(http.MethodPost, "/api/restore?lang=ru", "", nil)
	require.Equal(t, http.StatusUnprocessableEntity, code)
	require.Contains(t, body, "запечатанной модели")
	code, body = p.do(http.MethodGet, "/api/job?id=none&lang=ru", "", nil)
	require.Equal(t, http.StatusUnprocessableEntity, code, body)
	code, body = p.do(http.MethodGet, "/api/job?id=..%2F..%2Fescape&lang=ru", "", nil)
	require.Equal(t, http.StatusUnprocessableEntity, code, body)

	// The stop.
	code, body = p.do(http.MethodPost, "/api/stop?lang=ru", `{"stop":true,"reason":"test"}`, &o)
	require.Equal(t, http.StatusOK, code, body)
	require.True(t, o.Stopped)
	require.Equal(t, "stopped", o.Verdict)
	require.True(t, journalHas(o, "АВАРИЙНАЯ ОСТАНОВКА ВКЛЮЧЕНА. Кто: Anna. Причина: test"))
	require.False(t, o.CanMove, "a server under a stop hands nothing over")
	code, _ = p.do(http.MethodPost, "/api/stop?lang=ru", "not json", nil)
	require.Equal(t, http.StatusUnprocessableEntity, code)
	code, body = p.do(http.MethodPost, "/api/stop?lang=ru", `{"stop":false}`, &o)
	require.Equal(t, http.StatusOK, code, body)
	require.False(t, o.Stopped)
	require.True(t, journalHas(o, "Аварийная остановка снята. Кто: Anna"))

	// An invited person sees and cannot act; closed, they are out.
	var inv map[string]string
	code, body = p.do(http.MethodPost, "/api/invite", `{"name":"Oleg K.","role":"viewer"}`, &inv)
	require.Equal(t, http.StatusOK, code, body)
	code, _ = p.do(http.MethodPost, "/api/invite", `{"name":"<script>","role":"viewer"}`, nil)
	require.Equal(t, http.StatusUnprocessableEntity, code)
	code, _ = p.do(http.MethodPost, "/api/invite", "not json", nil)
	require.Equal(t, http.StatusUnprocessableEntity, code)

	oleg := newPage(t)
	var ov Overview
	code, body = oleg.do(http.MethodPost, "/api/join?lang=ru", inv["pass"], &ov)
	require.Equal(t, http.StatusOK, code, body)
	require.Equal(t, "Oleg K.", ov.You)
	require.False(t, ov.CanRestore || ov.CanStop || ov.CanInvite || ov.CanMove)
	code, body = oleg.do(http.MethodPost, "/api/restore?lang=ru", "", nil)
	require.Equal(t, http.StatusUnprocessableEntity, code)
	require.Contains(t, body, "не позволяет")

	o = p.overview("")
	require.Len(t, o.People, 2)
	var olegKey string
	for _, person := range o.People {
		if person.Name == "Oleg K." {
			olegKey = person.PublicKeyHex
			require.False(t, person.HoldsStop)
		} else {
			require.True(t, person.HoldsStop && person.You)
		}
	}
	code, _ = p.do(http.MethodPost, "/api/remove", "not json", nil)
	require.Equal(t, http.StatusUnprocessableEntity, code)
	code, body = p.do(http.MethodPost, "/api/remove?lang=ru", `{"public_key_hex":"`+olegKey+`"}`, &o)
	require.Equal(t, http.StatusOK, code, body)
	require.Len(t, o.People, 1)
	ov = oleg.overview("")
	require.Equal(t, "offline", ov.Verdict, "shut out, the page says so")
	require.Contains(t, ov.Lines[0].Text, "больше нет доступа")

	// A pass opened again on the same computer is not an error; used elsewhere it is.
	code, _ = p.do(http.MethodPost, "/api/join?lang=ru", string(pass), &o)
	require.Equal(t, http.StatusOK, code)
	other := newPage(t)
	code, body = other.do(http.MethodPost, "/api/join?lang=ru", string(pass), nil)
	require.Equal(t, http.StatusUnprocessableEntity, code)
	require.Contains(t, body, "уже использован")
	code, _ = other.do(http.MethodPost, "/api/check", "", nil)
	require.Equal(t, http.StatusUnprocessableEntity, code, "no server yet")

	// The application comes back to its servers.
	again, err := newApp(p.app.dir)
	require.NoError(t, err)
	require.Len(t, again.Servers(), 1)
	require.Equal(t, "Anna", again.Servers()[0].you.Name)
	s, err := again.Server("")
	require.NoError(t, err)
	_, err = s.check(context.Background())
	require.NoError(t, err)
	require.NoError(t, s.refreshJournal(context.Background()))
	_, err = again.Server("no such id")
	require.Error(t, err)

	// A journal the walk finds broken is said so, with its record's number.
	s.mu.Lock()
	evt := s.events[0]
	evt.Payload = []byte(`{"changed":true}`)
	s.events = append([]audit_event.AuditEvent{evt}, s.events[1:]...)
	s.first = 0
	s.mu.Unlock()
	_, err = console.VerifyEvents(s.events, 0, nil, s.resolver)
	var broken *console.BrokenJournalError
	require.True(t, errors.As(err, &broken))
	s.mu.Lock()
	s.journalErr = err
	s.mu.Unlock()
	o2 := again.overview(s, "ru")
	require.Contains(t, lineTitled(o2, "Журнал повреждён").Text, "номер 1")
	s.mu.Lock()
	s.journalErr = errors.New("connection reset")
	s.mu.Unlock()
	require.NotNil(t, lineTitled(again.overview(s, "en"), "could not be read"))
}

// A daemon that is gone is not a server that failed its proof, and a chip that
// answers wrongly outranks everything remembered.
func TestThePageWhenThingsGoWrong(t *testing.T) {
	d := startDeployment(t, false)
	p := newPage(t)
	var o Overview
	code, body := p.do(http.MethodPost, "/api/join?lang=ru", string(d.pass(t, "Anna", console.RoleOwner)), &o)
	require.Equal(t, http.StatusOK, code, body)
	require.Equal(t, "attention", o.Verdict)

	s, err := p.app.Server("")
	require.NoError(t, err)

	// The same listener, another pin: the page refuses what it hears.
	honest := s.verifier
	wrong := s.pass.Pin
	wrong.MeasurementHex = strings.Repeat("ab", 32)
	_, s.verifier, err = wrong.Verifier(s.cacheDir)
	require.NoError(t, err)
	o = p.overview("")
	require.Equal(t, "unproven", o.Verdict)
	require.Len(t, o.Lines, 1, "nothing remembered is shown beside a failed proof")
	s.verifier = honest
	require.Equal(t, "attention", p.overview("").Verdict, "a check that passes clears it")

	require.NoError(t, d.cmd.Process.Kill())
	_ = d.cmd.Wait()
	o = p.overview("")
	require.Equal(t, "offline", o.Verdict)
	require.Contains(t, o.Lines[0].Text, "не отвечает")
}

// The move button against two real daemons, with a sealed model: the bundle
// arrives byte for byte and the envelope with it, and the source's and the
// target's journals say so. The restore on hardware is the kit's.
func TestTheMoveAgainstTwoDaemons(t *testing.T) {
	first := startDeployment(t, true)
	second := startDeployment(t, false)
	p := newPage(t)

	var o Overview
	code, body := p.do(http.MethodPost, "/api/join?lang=ru", string(first.pass(t, "Anna", console.RoleOwner)), &o)
	require.Equal(t, http.StatusOK, code, body)
	firstID := o.ServerID
	require.True(t, o.CanMove)
	require.Empty(t, o.Targets)

	code, body = p.do(http.MethodPost, "/api/join?lang=ru", string(second.pass(t, "Anna", console.RoleOwner)), &o)
	require.Equal(t, http.StatusOK, code, body)
	secondID := o.ServerID
	require.Len(t, o.AllServers, 2)
	require.Equal(t, firstID, o.AllServers[0].ID, "in the order a person got them")

	o = p.overview(firstID)
	require.NotNil(t, lineTitled(o, "Есть куда перенести"))
	require.Len(t, o.Targets, 1)

	// With a stop on the second server the first sends nothing.
	code, body = p.do(http.MethodPost, "/api/stop?lang=ru&server="+secondID, `{"stop":true}`, nil)
	require.Equal(t, http.StatusOK, code, body)
	code, body = p.do(http.MethodPost, "/api/move?lang=ru&server="+firstID+"&to="+secondID, "", nil)
	require.Equal(t, http.StatusUnprocessableEntity, code)
	require.Contains(t, body, "На новом сервере включена")
	code, body = p.do(http.MethodPost, "/api/stop?lang=ru&server="+secondID, `{"stop":false}`, nil)
	require.Equal(t, http.StatusOK, code, body)

	code, body = p.do(http.MethodPost, "/api/move?server="+firstID+"&to="+firstID, "", nil)
	require.Equal(t, http.StatusUnprocessableEntity, code, body)
	code, _ = p.do(http.MethodPost, "/api/move?server="+firstID+"&to=nobody", "", nil)
	require.Equal(t, http.StatusUnprocessableEntity, code)
	code, _ = p.do(http.MethodPost, "/api/move?server=nobody&to="+firstID, "", nil)
	require.Equal(t, http.StatusUnprocessableEntity, code)

	var moved console.MoveResponse
	code, body = p.do(http.MethodPost, "/api/move?lang=ru&server="+firstID+"&to="+secondID, "", &moved)
	require.Equal(t, http.StatusOK, code, body)
	require.Equal(t, "gen-0.genome", moved.Bundle)
	require.NotEmpty(t, moved.BundleSHA256)

	want, err := os.ReadFile(filepath.Join(first.dir, "d", "genomes", "gen-0.genome"))
	require.NoError(t, err)
	got, err := os.ReadFile(filepath.Join(second.dir, "d", "genomes", "gen-0.genome"))
	require.NoError(t, err)
	require.Equal(t, want, got)
	require.FileExists(t, filepath.Join(second.dir, "d", "genomes", "gen-0.genome.escrow"))
	require.NoFileExists(t, filepath.Join(second.dir, "d", "genomes", "gen-0.key"), "the key does not travel in the clear")

	o = p.overview(firstID)
	require.True(t, journalHas(o, "Приказ о переносе"))
	require.True(t, journalHas(o, "Модель передана на сервер"))
	o = p.overview(secondID)
	require.True(t, journalHas(o, "Получена модель от сервера"))
	require.Len(t, o.People, 2, "the source's listener is on the list for the move")

	var after Overview
	code, body = p.do(http.MethodPost, "/api/forget-peers?lang=ru&server="+secondID, "", &after)
	require.Equal(t, http.StatusOK, code, body)
	require.Len(t, after.People, 1)
	code, _ = p.do(http.MethodPost, "/api/forget-peers?server=nobody", "", nil)
	require.Equal(t, http.StatusUnprocessableEntity, code)

	// The same model cannot be sent over it, and the target is left as it was.
	code, body = p.do(http.MethodPost, "/api/move?lang=ru&server="+firstID+"&to="+secondID, "", nil)
	require.Equal(t, http.StatusUnprocessableEntity, code)
	require.Contains(t, body, "уже есть на новом сервере")
	after = p.overview(secondID)
	require.Len(t, after.People, 1, "a move that did not happen leaves no server on the list")
}

// The progress of a restore reads in plain words at each stage, and its end.
func TestJobProgress(t *testing.T) {
	cases := []struct {
		job  console.JobSummary
		want string
		key  string
	}{
		{console.JobSummary{Status: "running", State: "disclosure"}, "частями", "stage"},
		{console.JobSummary{Status: "succeeded", State: "release_authorized", GateLevel: "EXACT", Fixtures: 6}, "точно такой же", "done"},
		{console.JobSummary{Status: "succeeded", State: "release_authorized", GateLevel: "EQUIVALENT", Fixtures: 6}, "в пределах допуска", "done"},
		{console.JobSummary{Status: "failed", State: "incident_terminated", ErrorCode: "trust_denied", ErrorMessage: "operator stop in force"}, "аварийная остановка", "failed"},
		{console.JobSummary{Status: "failed", State: "validation", ErrorCode: "gate_failed"}, "не вернулась", "failed"},
	}
	for _, c := range cases {
		now := time.Now()
		c.job.SubmittedAt = now.Add(-5 * time.Second)
		if c.job.Status != "running" {
			c.job.CompletedAt = &now
		}
		text, ok := jobView("ru", c.job)[c.key].(string)
		require.True(t, ok, c.key)
		require.Contains(t, text, c.want)
	}
}

// checkCmd tells a script whether every server proved itself.
func TestCheckCommand(t *testing.T) {
	d := startDeployment(t, false)
	dir := t.TempDir()
	a, err := newApp(dir)
	require.NoError(t, err)
	_, err = a.Join(d.pass(t, "Anna", console.RoleOwner))
	require.NoError(t, err)
	require.Equal(t, 0, checkCmd([]string{"--data-dir", dir, "--lang", "ru"}))
	require.NoError(t, d.cmd.Process.Kill())
	_ = d.cmd.Wait()
	require.Equal(t, 1, checkCmd([]string{"--data-dir", dir}))
	require.Equal(t, 2, checkCmd([]string{"--no-such-flag"}))
}

// run opens the page once, finds a console already running, and goes when idle.
func TestRunFindsTheOneAlreadyRunning(t *testing.T) {
	dir := t.TempDir()
	a, err := newApp(dir)
	require.NoError(t, err)
	srv := httptest.NewServer(nil)
	defer srv.Close()
	srv.Config.Handler = newWeb(a, "tk", strings.TrimPrefix(srv.URL, "http://")).handler()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "running.url"), []byte(srv.URL+"/#t=tk"), 0o600))
	require.NoError(t, runConsole([]string{"--data-dir", dir, "--no-open"}), "it says where the page is and leaves")
	require.Error(t, runConsole([]string{"--no-such-flag"}))
	require.Error(t, runConsole([]string{"--data-dir", dir, "--no-open", filepath.Join(dir, "no-such-pass")}))
}

// The idle clock runs from the last thing the page asked.
func TestIdleClock(t *testing.T) {
	a, err := newApp(t.TempDir())
	require.NoError(t, err)
	w := newWeb(a, "tk", "127.0.0.1:1")
	w.last.Store(time.Now().Add(-time.Hour).Unix())
	require.Greater(t, w.idleFor(), 59*time.Minute)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "127.0.0.1:1"
	w.handler().ServeHTTP(httptest.NewRecorder(), req)
	require.Less(t, w.idleFor(), time.Minute)
	require.True(t, w.hostAllowed("localhost:1"))
	require.False(t, w.hostAllowed("localhost:2"))
	require.False(t, w.hostAllowed("evil.example:1"))
}
