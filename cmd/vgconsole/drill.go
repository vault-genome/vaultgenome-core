// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build drill

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/console"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	"github.com/vault-genome/vaultgenome-core/internal/vault/revocation"
)

func init() { drillMain = drillCmd }

// drillRecord is one line of what the drill did to a real server and what
// came back.
type drillRecord struct {
	Step   string  `json:"step"`
	OK     bool    `json:"ok"`
	Detail string  `json:"detail,omitempty"`
	Secs   float64 `json:"seconds,omitempty"`
}

// drill runs what the buttons run, against a real server, and holds the
// answers to what they must be, including every refusal. It takes a fresh
// pass; each person it plays has a key of their own, as they would.
type drill struct {
	out     string
	records []drillRecord
	failed  bool
}

func (d *drill) record(step string, ok bool, detail string, start time.Time) {
	r := drillRecord{Step: step, OK: ok, Detail: detail}
	if !start.IsZero() {
		r.Secs = time.Since(start).Seconds()
	}
	d.records = append(d.records, r)
	word := "ok   "
	if !ok {
		word = "FAIL "
		d.failed = true
	}
	fmt.Printf("%s %s", word, step)
	if detail != "" {
		fmt.Printf(": %s", detail)
	}
	fmt.Println()
}

func (d *drill) keep(name string, data []byte) {
	_ = os.WriteFile(filepath.Join(d.out, name), data, 0o644)
}

func drillCmd(args []string) int {
	fs := flag.NewFlagSet("vgconsole drill", flag.ContinueOnError)
	passPath := fs.String("pass", "", "An unused owner's pass for a server this drill may stop and restart (required)")
	secondPath := fs.String("second", "", "An unused owner's pass for a second server, with no model of its own: the drill moves the model there")
	out := fs.String("out", "", "Where the record goes (required)")
	work := fs.String("work", "", "Scratch directory for the people's keys (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *passPath == "" || *out == "" || *work == "" {
		fmt.Fprintln(os.Stderr, "usage: vgconsole drill --pass FILE --out DIR --work DIR")
		return 2
	}
	raw, err := os.ReadFile(*passPath)
	if err == nil {
		err = os.MkdirAll(*out, 0o755)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "vgconsole drill:", err)
		return 1
	}
	d := &drill{out: *out}
	var second []byte
	if *secondPath != "" {
		if second, err = os.ReadFile(*secondPath); err != nil {
			fmt.Fprintln(os.Stderr, "vgconsole drill:", err)
			return 1
		}
	}
	d.run(raw, second, *work)
	rec, _ := json.MarshalIndent(d.records, "", "  ")
	d.keep("drill.json", append(rec, '\n'))
	if d.failed {
		fmt.Println("DRILL: FAIL")
		return 1
	}
	fmt.Println("DRILL: PASS")
	return 0
}

func (d *drill) run(passRaw, secondRaw []byte, work string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	owner, err := newApp(filepath.Join(work, "owner"))
	if err != nil {
		d.record("the owner's console opens", false, err.Error(), time.Time{})
		return
	}
	stranger, err := newApp(filepath.Join(work, "stranger"))
	if err != nil {
		d.record("a stranger's console opens", false, err.Error(), time.Time{})
		return
	}

	// A key nobody invited is refused at everything but the door.
	pass, err := console.ParsePass(passRaw)
	if err != nil {
		d.record("the pass reads", false, err.Error(), time.Time{})
		return
	}
	strangerConn, err := stranger.newServer(pass)
	if err != nil {
		d.record("a stranger connects", false, err.Error(), time.Time{})
		return
	}
	_, err = strangerConn.check(ctx)
	d.refusal("a key on nobody's list is refused a check", err, "not_listed")
	err = strangerConn.callJSON(ctx, http.MethodPost, "/v1/console/join", console.JoinRequest{Code: "0000"}, nil)
	d.refusal("a made-up pass code is refused", err, "invite_unknown")

	// The pass opens once.
	start := time.Now()
	srv, err := owner.Join(passRaw)
	if err != nil {
		d.record("the owner opens the pass", false, err.Error(), start)
		return
	}
	d.record("the owner opens the pass, gets the emergency stop and signs its first list", srv.you.Role == console.RoleOwner, srv.you.Name, start)
	err = strangerConn.callJSON(ctx, http.MethodPost, "/v1/console/join", console.JoinRequest{Code: pass.InviteCode}, nil)
	d.refusal("the same pass is dead for anyone else", err, "invite_unknown")

	// The check: fresh, on this computer, bound to the listener and the state.
	start = time.Now()
	challenge := make([]byte, console.NonceBytes)
	_, _ = rand.Read(challenge)
	var resp console.CheckResponse
	err = srv.callJSON(ctx, http.MethodPost, "/v1/console/check", console.CheckRequest{NonceHex: hex.EncodeToString(challenge)}, &resp)
	if err != nil {
		d.record("the chip answers a check", false, err.Error(), start)
		return
	}
	verdict, err := console.VerifyCheck(srv.verifier, challenge, srv.certDER, resp)
	if err != nil {
		d.record("the chip's answer verifies on this computer", false, err.Error(), start)
		return
	}
	d.record("the chip's answer verifies on this computer", true, fmt.Sprintf("%s, measurement %x", verdict.State.Provider, []byte(verdict.Measurement)), start)
	d.keep("check-state.json", resp.State)
	d.keep("check-evidence.bin", resp.Evidence)
	d.keep("check-challenge.hex", []byte(hex.EncodeToString(challenge)+"\n"))
	if verdict.Detail != nil {
		detail, _ := json.MarshalIndent(verdict.Detail, "", "  ")
		d.keep("check-detail.json", append(detail, '\n'))
	}

	// The same answer does not pass for anything else.
	other := make([]byte, console.NonceBytes)
	_, _ = rand.Read(other)
	_, err = console.VerifyCheck(srv.verifier, other, srv.certDER, resp)
	d.record("an old answer does not pass for a new question", err != nil, "", time.Time{})
	forged := append([]byte(nil), resp.State...)
	forged[len(forged)/2] ^= 1
	_, err = console.VerifyCheck(srv.verifier, challenge, srv.certDER, console.CheckResponse{State: forged, Evidence: resp.Evidence})
	d.record("one bit changed in the server's state is caught", err != nil, "", time.Time{})
	_, err = console.VerifyCheck(srv.verifier, challenge, append([]byte{0}, srv.certDER...), resp)
	d.record("an answer made for another listener is refused", err != nil, "", time.Time{})
	wrongPin := pass.Pin
	measurement, _ := hex.DecodeString(wrongPin.MeasurementHex)
	if len(measurement) > 0 {
		measurement[0] ^= 1
	}
	wrongPin.MeasurementHex = hex.EncodeToString(measurement)
	if _, v, err := wrongPin.Verifier(srv.cacheDir); err != nil {
		d.record("a pin one bit away builds", false, err.Error(), time.Time{})
	} else {
		_, err = console.VerifyCheck(v, challenge, srv.certDER, resp)
		d.record("the real chip does not pass for a pin one bit away", err != nil, "", time.Time{})
	}

	// The journal: verified here, read while both services run.
	start = time.Now()
	res, err := srv.check(ctx)
	if err == nil {
		err = srv.refreshJournal(ctx)
	}
	if err != nil {
		d.record("the journal verifies on this computer", false, err.Error(), start)
		return
	}
	srv.mu.Lock()
	events := append([]audit_event.AuditEvent(nil), srv.events...)
	first := srv.first
	srv.mu.Unlock()
	d.record("the journal verifies on this computer, with both services running", len(events) == res.State.Audit.Events-first,
		fmt.Sprintf("%d records, tip %s", len(events), res.State.Audit.TipHex), start)
	if len(events) > 0 {
		tampered := append([]audit_event.AuditEvent(nil), events...)
		mid := len(tampered) / 2
		e := tampered[mid]
		e.Payload = append(append([]byte(nil), e.Payload...), ' ')
		tampered[mid] = e
		_, err = console.VerifyEvents(tampered, first, nil, srv.resolver)
		var broken *console.BrokenJournalError
		d.record("a changed record is caught and named", errors.As(err, &broken) && broken.Index == first+mid, fmt.Sprintf("record %d of %d", first+mid, len(tampered)), time.Time{})
		if mid+1 < len(events) {
			shorter := append(append([]audit_event.AuditEvent(nil), events[:mid]...), events[mid+1:]...)
			_, err = console.VerifyEvents(shorter, first, nil, srv.resolver)
			d.record("a removed record is caught", errors.As(err, &broken), fmt.Sprintf("record %d of %d", first+mid, len(events)), time.Time{})
		}
	}

	// A person with a smaller role.
	viewerPass, err := owner.Invite(ctx, srv, "Viewer Drill", console.RoleViewer)
	if err != nil {
		d.record("the owner invites a viewer", false, err.Error(), time.Time{})
		return
	}
	viewer, err := newApp(filepath.Join(work, "viewer"))
	if err != nil {
		d.record("the viewer's console opens", false, err.Error(), time.Time{})
		return
	}
	viewerSrv, err := viewer.Join(viewerPass)
	if err != nil {
		d.record("the viewer opens their pass", false, err.Error(), time.Time{})
		return
	}
	vres, err := viewerSrv.check(ctx)
	d.record("the viewer's own computer verifies the same chip", err == nil, "", time.Time{})
	_, err = viewerSrv.restoreCheck(ctx, "")
	d.refusal("the viewer cannot start a restore", err, "role_refused")
	if vres != nil {
		err = viewer.setStop(ctx, viewerSrv, vres.State.Stop, true, "not mine")
		d.refusal("the viewer cannot press stop", err, "role_refused")
	}

	// A restore while nothing is stopped.
	level, secs := d.restore(ctx, srv, "", "the restore check, stop off")
	d.record("the model comes back", level == "EXACT" || level == "EQUIVALENT", fmt.Sprintf("%s in %.1f s", level, secs), time.Time{})

	// Stop: signed here, verified there, and the next job is refused.
	res, err = srv.check(ctx)
	if err != nil {
		d.record("a check before the stop", false, err.Error(), time.Time{})
		return
	}
	before := res.State.Stop
	strangerKey, _ := crypto.GenerateSigningKey(crypto.SuiteEd25519, nil)
	if strangerKey != nil {
		forgedList, _ := revocation.Sign(revocation.List{Serial: before.Serial + 1, IssuedAt: time.Now().UTC().Truncate(time.Second), StopAll: false, SigningKeyID: before.KeyID}, strangerKey)
		rawForged, _ := json.Marshal(forgedList)
		d.refusal("a stop list signed by another key is refused", srv.call(ctx, http.MethodPut, "/v1/console/stop", rawForged, nil), "list_refused")
		strangerKey.Zeroize()
	}
	start = time.Now()
	if err := owner.setStop(ctx, srv, before, true, "drill"); err != nil {
		d.record("the owner presses stop", false, err.Error(), start)
		return
	}
	res, err = srv.check(ctx)
	d.record("the chip's next answer says the stop is on", err == nil && res.State.Stop.StopAll, "", start)
	_, jobErr := d.restoreRefused(ctx, srv)
	d.record("with the stop on, a restore is refused on the record", jobErr == nil, "", time.Time{})

	// The old list cannot be brought back.
	key, err := crypto.LoadSigningKey(crypto.SuiteEd25519, owner.seed)
	if err == nil {
		defer key.Zeroize()
		old, _ := revocation.Sign(revocation.List{Serial: before.Serial, IssuedAt: time.Now().UTC().Truncate(time.Second), StopAll: false, SigningKeyID: before.KeyID}, key)
		rawOld, _ := json.Marshal(old)
		d.refusal("an older list cannot lift the stop", srv.call(ctx, http.MethodPut, "/v1/console/stop", rawOld, nil), "list_old")
	}

	// Lift, and the model comes back again.
	res, err = srv.check(ctx)
	if err == nil {
		err = owner.setStop(ctx, srv, res.State.Stop, false, "")
	}
	d.record("the owner lifts the stop", err == nil, "", time.Time{})
	level, secs = d.restore(ctx, srv, "", "the restore check, stop lifted")
	d.record("the model comes back after the stop is lifted", level == "EXACT" || level == "EQUIVALENT", fmt.Sprintf("%s in %.1f s", level, secs), time.Time{})

	if secondRaw != nil {
		d.move(ctx, owner, srv, secondRaw)
	}

	// Taking a person off the list ends their access at once.
	if err := srv.callJSON(ctx, http.MethodPost, "/v1/console/people/remove", console.RemoveRequest{PublicKeyHex: viewer.publicKeyHex()}, nil); err != nil {
		d.record("the owner removes the viewer", false, err.Error(), time.Time{})
	} else {
		_, err = viewerSrv.check(ctx)
		d.refusal("a removed person is refused at once", err, "not_listed")
	}

	// The journal says all of it, in a person's words, verified again.
	res, err = srv.check(ctx)
	if err == nil {
		err = srv.refreshJournal(ctx)
	}
	if err != nil {
		d.record("the journal after everything", false, err.Error(), time.Time{})
		return
	}
	srv.mu.Lock()
	events = append([]audit_event.AuditEvent(nil), srv.events...)
	first = srv.first
	srv.mu.Unlock()
	counts := map[string]int{}
	var lines []JournalLine
	for i := range events {
		if events[i].Kind == audit_event.KindConsoleAction {
			counts[str(payloadOf(events[i]), "action")]++
		}
		if line, ok := describe(events[i], first+i, "ru"); ok {
			lines = append(lines, line)
		}
	}
	// The stop goes on and off once, and twice more around the move.
	moves, stops := 0, 1
	if secondRaw != nil {
		moves, stops = 1, 3
	}
	d.record("the journal names every person's action", counts[console.ActionPersonJoined] == 2 && counts[console.ActionStopReady] == 1 && counts[console.ActionStopSet] == stops && counts[console.ActionStopLifted] == stops && counts[console.ActionPersonRemoved] == 1 && counts[console.ActionInviteMade] == 1 && counts[console.ActionModelSent] == moves && counts[console.ActionModelReleased] == moves, fmt.Sprintf("%v", counts), time.Time{})
	rawLines, _ := json.MarshalIndent(lines, "", "  ")
	d.keep("journal-plain.json", append(rawLines, '\n'))
	overview, _ := json.MarshalIndent(owner.overview(srv, "ru"), "", "  ")
	d.keep("overview-ru.json", append(overview, '\n'))
	overviewEN, _ := json.MarshalIndent(owner.overview(srv, "en"), "", "  ")
	d.keep("overview-en.json", append(overviewEN, '\n'))
	d.record("the provider is a real one", tee.Provider(res.State.Provider) != tee.ProviderSimulated, res.State.Provider, time.Time{})
}

// move plays the move button against two real servers, each refusal first.
func (d *drill) move(ctx context.Context, owner *App, from *server, secondRaw []byte) {
	to, err := owner.Join(secondRaw)
	if err != nil {
		d.record("the owner opens the second server's pass", false, err.Error(), time.Time{})
		return
	}
	d.record("the owner opens the second server's pass and holds its stop too", to.you.Role == console.RoleOwner, to.pass.ServerLabel, time.Time{})
	res, err := to.check(ctx)
	if err != nil {
		d.record("the second server's chip verifies on this computer", false, err.Error(), time.Time{})
		return
	}
	d.record("the second server's chip verifies on this computer", true, fmt.Sprintf("%s, measurement %x", res.State.Provider, []byte(res.Measurement)), time.Time{})
	d.record("the second server names its key for receiving, under its chip", res.State.EscrowPublicKeyPEM != "", "", time.Time{})
	src, err := from.check(ctx)
	if err != nil {
		d.record("a check of the first server", false, err.Error(), time.Time{})
		return
	}
	if len(src.State.Genomes) == 0 {
		d.record("the first server has a sealed model", false, "", time.Time{})
		return
	}
	bundle := src.State.Genomes[0]
	target := func(pin console.Pin) console.MoveTarget {
		var code console.InviteResponse
		if err := to.callJSON(ctx, http.MethodPost, "/v1/console/invites", console.InviteRequest{Name: "Drill Source (server)", Role: console.RolePeer, Hours: 1}, &code); err != nil {
			d.record("the second server makes a code", false, err.Error(), time.Time{})
		}
		return console.MoveTarget{Label: to.pass.ServerLabel, Address: to.pass.Address, ServerCertPEM: to.pass.ServerCertPEM, Pin: pin, JoinCode: code.Code}
	}
	order := func(key *crypto.SigningKey, certSum, id string, issued time.Time, ttl time.Duration, pin console.Pin) []byte {
		signed, err := console.SignMoveOrder(console.MoveOrder{OrderID: id, IssuedAt: issued, ExpiresAt: issued.Add(ttl), FromCertSHA256: certSum, Bundle: bundle, To: target(pin), SigningKeyID: src.State.Stop.KeyID}, key)
		if err != nil {
			d.record("an order signs", false, err.Error(), time.Time{})
			return nil
		}
		raw, _ := json.Marshal(signed)
		return raw
	}
	mine, err := crypto.LoadSigningKey(crypto.SuiteEd25519, owner.seed)
	if err != nil {
		d.record("the owner's key loads", false, err.Error(), time.Time{})
		return
	}
	defer mine.Zeroize()
	other, _ := crypto.GenerateSigningKey(crypto.SuiteEd25519, nil)
	now := time.Now().UTC().Truncate(time.Second)
	sum := console.CertSHA256(from.certDER)
	d.refusal("an order signed by another key is refused", from.longCall(ctx, http.MethodPost, "/v1/console/move", order(other, sum, "drill-forged", now, 10*time.Minute, to.pass.Pin), nil), "order_refused")
	other.Zeroize()
	d.refusal("an order addressed to another server is refused", from.longCall(ctx, http.MethodPost, "/v1/console/move", order(mine, console.CertSHA256(to.certDER), "drill-elsewhere", now, 10*time.Minute, to.pass.Pin), nil), "order_refused")
	d.refusal("an order out of its time is refused", from.longCall(ctx, http.MethodPost, "/v1/console/move", order(mine, sum, "drill-old", now.Add(-time.Hour), 10*time.Minute, to.pass.Pin), nil), "order_refused")
	wrong := to.pass.Pin
	measurement, _ := hex.DecodeString(wrong.MeasurementHex)
	if len(measurement) > 0 {
		measurement[0] ^= 1
	}
	wrong.MeasurementHex = hex.EncodeToString(measurement)
	d.refusal("the first server itself refuses a target that does not show the pin, and sends nothing", from.longCall(ctx, http.MethodPost, "/v1/console/move", order(mine, sum, "drill-pin", now, 10*time.Minute, wrong), nil), "target_unproven")
	if res, err := to.check(ctx); err == nil {
		d.record("nothing arrived at the second server", !slicesContains(res.State.Genomes, bundle), fmt.Sprintf("%v", res.State.Genomes), time.Time{})
	}

	// With the stop on, the first server hands over nothing.
	src, err = from.check(ctx)
	if err == nil {
		err = owner.setStop(ctx, from, src.State.Stop, true, "drill: before a move")
	}
	if err != nil {
		d.record("the stop goes on for the move's refusal", false, err.Error(), time.Time{})
		return
	}
	_, err = owner.Move(ctx, from, to)
	d.refusal("with the stop on, the first server hands over nothing", err, "stopped")
	src, err = from.check(ctx)
	if err == nil {
		err = owner.setStop(ctx, from, src.State.Stop, false, "")
	}
	if err != nil {
		d.record("the stop comes off", false, err.Error(), time.Time{})
		return
	}

	// The move.
	start := time.Now()
	resp, err := owner.Move(ctx, from, to)
	if err != nil {
		d.record("the model moves", false, err.Error(), start)
		return
	}
	d.record("the model is handed over, after the first server verified the second's chip", resp.TargetMeasurement == to.pass.Pin.MeasurementHex, fmt.Sprintf("%s, %d bytes, sha256 %s, key %s", resp.Bundle, resp.Bytes, resp.BundleSHA256, resp.EscrowKey), start)
	raw, _ := json.MarshalIndent(resp, "", "  ")
	d.keep("move.json", append(raw, '\n'))
	level, secs := d.restore(ctx, to, resp.Bundle, "the second server's restore check of the moved model")
	d.record("the moved model comes back on the second server, by its own worker, under its own gate", level == "EXACT" || level == "EQUIVALENT", fmt.Sprintf("%s in %.1f s", level, secs), time.Time{})
	_, err = owner.Move(ctx, from, to)
	d.refusal("the same model cannot be sent over it", err, "already_here")

	// The second server's own journal says it, verified here.
	if err := to.forgetPeers(ctx); err != nil {
		d.record("the second server forgets the first", false, err.Error(), time.Time{})
	}
	final, err := to.check(ctx)
	if err == nil {
		err = to.refreshJournal(ctx)
	}
	if err != nil {
		d.record("the second server's journal verifies on this computer", false, err.Error(), time.Time{})
		return
	}
	to.mu.Lock()
	events := append([]audit_event.AuditEvent(nil), to.events...)
	first := to.first
	to.mu.Unlock()
	received, released := 0, false
	var lines []JournalLine
	for i := range events {
		if events[i].Kind == audit_event.KindConsoleAction && str(payloadOf(events[i]), "action") == console.ActionModelReceived {
			received++
		}
		if events[i].Kind == audit_event.KindReleaseDecided {
			if rel, _ := payloadOf(events[i])["release"].(bool); rel {
				released = true
			}
		}
		if line, ok := describe(events[i], first+i, "ru"); ok {
			lines = append(lines, line)
		}
	}
	d.record("the second server's journal verifies here and says the model arrived and came back", received == 2 && released, fmt.Sprintf("%d records, tip %s", len(events), final.State.Audit.TipHex), time.Time{})
	rawLines, _ := json.MarshalIndent(lines, "", "  ")
	d.keep("second-journal-plain.json", append(rawLines, '\n'))
	second, _ := json.MarshalIndent(owner.overview(to, "ru"), "", "  ")
	d.keep("second-overview-ru.json", append(second, '\n'))
	stillThere := 0
	for _, p := range final.State.People {
		if p.Role == console.RolePeer {
			stillThere++
		}
	}
	d.record("the first server is off the second's list after the move", stillThere == 0, "", time.Time{})

	// Stopping the old server, the last step a person takes.
	src, err = from.check(ctx)
	if err == nil {
		err = owner.setStop(ctx, from, src.State.Stop, true, "the model moved")
	}
	d.record("the owner stops the old server", err == nil, "", time.Time{})
	_, jobErr := d.restoreRefused(ctx, from)
	d.record("the old server now refuses the model, on its record", jobErr == nil, "", time.Time{})
	src, err = from.check(ctx)
	if err == nil {
		err = owner.setStop(ctx, from, src.State.Stop, false, "")
	}
	d.record("the stop on the old server is lifted for the rest of the drill", err == nil, "", time.Time{})
}

func slicesContains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// refusal holds err to the listener's word for it.
func (d *drill) refusal(step string, err error, code string) {
	var api *apiError
	ok := errors.As(err, &api) && api.Code == code
	detail := ""
	if !ok {
		detail = fmt.Sprintf("want %s, got %v", code, err)
	}
	d.record(step, ok, detail, time.Time{})
}

// restore starts a restore check and waits for its end.
func (d *drill) restore(ctx context.Context, srv *server, bundle, step string) (string, float64) {
	start := time.Now()
	r, err := srv.restoreCheck(ctx, bundle)
	if err != nil {
		d.record(step, false, err.Error(), start)
		return "", 0
	}
	for {
		select {
		case <-ctx.Done():
			d.record(step, false, "no end", start)
			return "", 0
		case <-time.After(time.Second):
		}
		j, err := srv.job(ctx, r.JobID)
		if err != nil {
			d.record(step, false, err.Error(), start)
			return "", 0
		}
		if j.Status == "succeeded" || j.Status == "failed" {
			raw, _ := json.MarshalIndent(j, "", "  ")
			d.keep("job-"+r.JobID+".json", append(raw, '\n'))
			d.record(step, j.Status == "succeeded", fmt.Sprintf("%s, %s", j.Status, j.GateLevel), start)
			return j.GateLevel, time.Since(start).Seconds()
		}
	}
}

// restoreRefused starts a restore check that must end refused by the stop.
func (d *drill) restoreRefused(ctx context.Context, srv *server) (console.JobSummary, error) {
	r, err := srv.restoreCheck(ctx, "")
	if err != nil {
		var api *apiError
		if errors.As(err, &api) && containsStop(api.Code+api.Message) {
			return console.JobSummary{}, nil
		}
		return console.JobSummary{}, err
	}
	for {
		select {
		case <-ctx.Done():
			return console.JobSummary{}, ctx.Err()
		case <-time.After(time.Second):
		}
		j, err := srv.job(ctx, r.JobID)
		if err != nil {
			return j, err
		}
		if j.Status == "succeeded" {
			return j, errors.New("the job succeeded with the stop on")
		}
		if j.Status == "failed" {
			raw, _ := json.MarshalIndent(j, "", "  ")
			d.keep("job-refused-"+r.JobID+".json", append(raw, '\n'))
			if containsStop(j.ErrorCode + j.ErrorMessage) {
				return j, nil
			}
			return j, fmt.Errorf("failed for another reason: %s %s", j.ErrorCode, j.ErrorMessage)
		}
	}
}
