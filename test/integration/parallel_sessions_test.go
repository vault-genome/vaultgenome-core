// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build integration

package integration

import (
	"bufio"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// gauge reads one gauge from sagvd's Prometheus exposition; absent reads as zero.
func (v *vault) gauge(t *testing.T, series string) float64 {
	t.Helper()
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(v.healthURL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), series+" "); ok {
			f, err := strconv.ParseFloat(strings.TrimSpace(rest), 64)
			if err != nil {
				t.Fatalf("parse %s: %v", series, err)
			}
			return f
		}
	}
	return 0
}

// runtime.max_sessions = 2: two workers attest, each is handed one of
// two queued jobs, both jobs gate EXACT, and the one audit chain carries
// both flows and verifies. With the limit at one (the default) a second
// worker waits for the first session to end; here it does not.
func TestLiveDaemons_TwoWorkersServedInParallel(t *testing.T) {
	secrets := keygen(t)
	v := startVaultWith(t, secrets, func(cfg map[string]any) {
		cfg["runtime"].(map[string]any)["max_sessions"] = 2
	})
	w1, h1 := v.startWorker(t, "acp-compute-1", workerIdentity{tlsFrom: secrets, teeFrom: secrets})
	w2, h2 := v.startWorker(t, "acp-compute-2", workerIdentity{tlsFrom: secrets, teeFrom: secrets})
	waitReady(t, w1, h1+"/healthz")
	waitReady(t, w2, h2+"/healthz")
	// Both workers are attested and waiting for work before any job exists: two sessions open at once.
	waitFor(t, 20*time.Second, "two sessions opened", func() bool { return v.counter(t, `sagvd_sessions_opened_total`) >= 2 })
	if got := v.gauge(t, `sagvd_sessions_active`); got < 2 {
		t.Fatalf("sagvd_sessions_active = %v while two attested workers wait for work; the limit is two", got)
	}
	if got := v.gauge(t, `sagvd_sessions_limit`); got != 2 {
		t.Fatalf("sagvd_sessions_limit = %v, want 2", got)
	}
	a := v.sealGenome(t, "gen-a", true)
	b := v.sealGenome(t, "gen-b", true)
	idA, _ := v.submitGenome(t, a)
	idB, _ := v.submitGenome(t, b)
	jobA := v.waitJob(t, idA, "succeeded", jobTimeout)
	jobB := v.waitJob(t, idB, "succeeded", jobTimeout)
	for _, j := range []jobView{jobA, jobB} {
		if j.Gate == nil || j.Gate.Level != "EXACT" {
			t.Fatalf("gate verdict: %+v", j.Gate)
		}
	}
	if got := v.counter(t, `sagvd_jobs_completed_total{outcome="success"}`); got != 2 {
		t.Fatalf("jobs completed = %d, want 2", got)
	}
	if took, killed := w1.stop(); killed {
		t.Fatalf("worker 1 had to be killed after %s", took)
	}
	if took, killed := w2.stop(); killed {
		t.Fatalf("worker 2 had to be killed after %s", took)
	}
	kinds, _ := v.auditLogAfterStop(t)
	var decided int
	for _, k := range kinds {
		if k == "RELEASE_DECIDED" {
			decided++
		}
	}
	if decided != 2 {
		t.Fatalf("release decisions on the one chain: %d, want 2 (%s)", decided, strings.Join(kinds, ","))
	}
}
