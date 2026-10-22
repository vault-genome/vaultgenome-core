// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build integration

package integration

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	shared_crypto "github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee/ratstest"
)

// benchVerifier is the bench's RATS Verifier for the simulated family: a
// Veraison-shaped challenge-response API (ratstest) whose appraisal reads
// the simulated TEE's statement — magic, nonce, measurement, signature —
// and affirms it when the signature verifies under one of the attestation
// keys it was provisioned with and the nonce is the session's; anything
// else is contraindicated. What a bank's Verifier does for a chip, this
// does for the simulated TEE, so the daemons' delegated path runs end to
// end with no hardware.
type benchVerifier struct {
	double *ratstest.Server
	srv    *httptest.Server
	keyDir string
}

func startBenchVerifier(t *testing.T, attesterKeys ...string) *benchVerifier {
	t.Helper()
	var keys []shared_crypto.PublicKey
	for _, p := range attesterKeys {
		raw, err := os.ReadFile(p)
		if err != nil || len(raw) != shared_crypto.Ed25519PublicKeySize {
			t.Fatalf("attester key %s: %v (%d bytes)", p, err, len(raw))
		}
		keys = append(keys, shared_crypto.PublicKey(raw))
	}
	double := &ratstest.Server{Submod: "SIM", PolicyID: "policy:bench-sim", Developer: "vault-genome bench", Build: "ratstest",
		Accept: []string{tee.MediaTypeSimulatedEvidence}}
	double.Appraise = func(mediaType string, value, nonce []byte) (string, map[string]any) {
		const magic = "SAGV-TEE-SIM-V1"
		if mediaType != tee.MediaTypeSimulatedEvidence || len(value) < len(magic)+4 || string(value[:len(magic)]) != magic {
			return "", nil
		}
		off := len(magic)
		nlen := int(binary.BigEndian.Uint32(value[off : off+4]))
		off += 4
		if nlen == 0 || len(value)-off < nlen+shared_crypto.HashSize+shared_crypto.Ed25519SignatureSize {
			return "", nil
		}
		gotNonce := value[off : off+nlen]
		off += nlen
		measurement := value[off : off+shared_crypto.HashSize]
		off += shared_crypto.HashSize
		sig := value[off : off+shared_crypto.Ed25519SignatureSize]
		ann := map[string]any{"measurement": hex.EncodeToString(measurement)}
		if !bytes.Equal(gotNonce, nonce) {
			ann["reason"] = "nonce is not the session's"
			return "contraindicated", ann
		}
		signed := append(append([]byte(nil), measurement...), gotNonce...)
		for _, k := range keys {
			if shared_crypto.Verify(k, signed, sig) == nil {
				ann["attester"] = hex.EncodeToString(k)[:16]
				return "affirming", ann
			}
		}
		ann["reason"] = "signed by no attestation key this Verifier knows"
		return "contraindicated", ann
	}
	srv := httptest.NewServer(double.Handler())
	t.Cleanup(srv.Close)
	keyDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(keyDir, "verifier-ear.jwk"), double.PublicJWK(), 0o600); err != nil {
		t.Fatal(err)
	}
	return &benchVerifier{double: double, srv: srv, keyDir: keyDir}
}

// delegate points a daemon's tee.peer.verifier at the bench Verifier.
func (b *benchVerifier) delegate(cfg map[string]any, url string) {
	peer := cfg["tee"].(map[string]any)["peer"].(map[string]any)
	peer["verifier"] = map[string]any{"mode": "rats", "url": url, "ear_public_key_path": filepath.Join(b.keyDir, "verifier-ear.jwk"),
		"policy_id": "policy:bench-sim", "submod": "SIM", "timeout_seconds": 5}
}

type trustEvaluatedPayload struct {
	Outcome    string `json:"outcome"`
	Phase      string `json:"phase"`
	Reason     string `json:"reason"`
	Code       string `json:"code"`
	PeerDetail *struct {
		Provider string              `json:"provider"`
		Verifier *tee.VerifierResult `json:"verifier"`
	} `json:"peer_detail"`
}

// Both daemons delegate appraisal to the bench Verifier (ADR 0025, step
// 2b): the vault's verdict on the worker and the worker's on the vault
// come from EARs the Verifier signed for each session's nonce; the pins
// stay the daemons' own; the job runs to EXACT; the admission on the
// record carries the EAR, which verifies again under the Verifier's key.
func TestLiveDaemons_DelegatedVerifierAppraisesBothPeers(t *testing.T) {
	secrets := keygen(t)
	ver := startBenchVerifier(t, filepath.Join(secrets, "sagvd", "peer_worker_pubkey"), filepath.Join(secrets, "acp-compute", "peer_vault_pubkey"))
	v := startVaultWith(t, secrets, func(cfg map[string]any) { ver.delegate(cfg, ver.srv.URL) })
	w, health := v.startWorkerWith(t, "acp-compute", workerIdentity{tlsFrom: secrets, teeFrom: secrets}, func(cfg map[string]any) { ver.delegate(cfg, ver.srv.URL) })
	waitReady(t, w, health+"/healthz")
	sealed := v.sealGenome(t, "gen-delegated", true)
	id, _ := v.submitGenome(t, sealed)
	job := v.waitJob(t, id, "succeeded", jobTimeout)
	if job.Gate == nil || job.Gate.Level != "EXACT" {
		t.Fatalf("gate verdict with a delegated verifier: %+v", job.Gate)
	}
	if got := v.counter(t, `sagvd_sessions_opened_total`); got < 1 {
		t.Fatalf("no session opened (%d)", got)
	}
	if n := ver.double.Requests(); n < 6 {
		t.Fatalf("the Verifier served %d requests; two sessions (newSession, evidence, delete) were expected", n)
	}
	if took, killed := w.stop(); killed {
		t.Fatalf("worker had to be killed after %s", took)
	}
	_, events := v.auditLogAfterStop(t)
	var allowed int
	for _, e := range events {
		if e.Kind != "TRUST_EVALUATED" {
			continue
		}
		var p trustEvaluatedPayload
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			t.Fatalf("TRUST_EVALUATED payload: %v: %s", err, e.Payload)
		}
		if p.Outcome != "allow" {
			t.Fatalf("a refusal with both peers delegated: %s", e.Payload)
		}
		allowed++
		if p.PeerDetail == nil || p.PeerDetail.Verifier == nil {
			t.Fatalf("the admission does not carry the Verifier's result: %s", e.Payload)
		}
		vr := p.PeerDetail.Verifier
		if vr.URL != ver.srv.URL || vr.Status != "affirming" || vr.Submod != "SIM" || vr.PolicyID != "policy:bench-sim" || vr.VerifierDeveloper != "vault-genome bench" {
			t.Fatalf("verifier result on the record: %+v", vr)
		}
		ear, err := tee.VerifyEAR(vr.EAR, ver.double.PublicKey())
		if err != nil {
			t.Fatalf("the EAR on the record does not verify under the Verifier's key: %v", err)
		}
		if sub := ear.Submods["SIM"]; sub.Status != "affirming" || len(ear.Nonce) < tee.NonceMinBytes {
			t.Fatalf("the EAR on the record: %+v", ear)
		}
	}
	if allowed == 0 {
		t.Fatal("no admission on the record")
	}
}

// A worker that is not one of the Verifier's attesters is contraindicated
// by the Verifier and refused at the handshake, on the record with the
// Verifier's word; the pinned worker is admitted after it. A Verifier
// that cannot be reached refuses the peer too — nothing is admitted on a
// missing verdict.
func TestLiveDaemons_DelegatedVerifierRefusesWhatItContraindicatesOrCannotJudge(t *testing.T) {
	secrets := keygen(t)
	rogueTEE := keygen(t)
	ver := startBenchVerifier(t, filepath.Join(secrets, "sagvd", "peer_worker_pubkey"))
	v := startVaultWith(t, secrets, func(cfg map[string]any) { ver.delegate(cfg, ver.srv.URL) })
	rogue, rogueHealth := v.startWorker(t, "rogue-worker", workerIdentity{tlsFrom: secrets, teeFrom: rogueTEE})
	waitReady(t, rogue, rogueHealth+"/healthz")
	before := v.counter(t, `sagvd_handshake_failures_total{phase="handshake"}`)
	id, _ := v.submitGenome(t, v.sealGenome(t, "gen-held", true))
	waitFor(t, 20*time.Second, "the rogue worker contraindicated by the Verifier and refused", func() bool {
		return v.counter(t, `sagvd_handshake_failures_total{phase="handshake"}`) > before
	})
	if job := v.job(t, id); job.Status != "queued" {
		t.Fatalf("job reached %q while only a contraindicated worker was connected", job.Status)
	}
	if got := v.counter(t, `sagvd_sessions_opened_total`); got != 0 {
		t.Fatalf("a session opened for the contraindicated worker (%d)", got)
	}
	w, health := v.startWorker(t, "acp-compute", workerIdentity{tlsFrom: secrets, teeFrom: secrets})
	waitReady(t, w, health+"/healthz")
	job := v.waitJob(t, id, "succeeded", jobTimeout)
	if job.Result == nil || job.Result.WorkerSigningKeyID != workerSigningKID {
		t.Fatalf("held job not delivered by the pinned worker: %+v", job)
	}
	if took, killed := rogue.stop(); killed {
		t.Fatalf("rogue worker had to be killed after %s", took)
	}
	if took, killed := w.stop(); killed {
		t.Fatalf("worker had to be killed after %s", took)
	}
	_, events := v.auditLogAfterStop(t)
	var denied, allowed int
	for _, e := range events {
		if e.Kind != "TRUST_EVALUATED" {
			continue
		}
		var p trustEvaluatedPayload
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			t.Fatal(err)
		}
		switch p.Outcome {
		case "deny":
			if p.Code == "peer_disconnected" {
				// The rogue worker hung up mid-handshake (its dial loop, or its
				// stop): a disconnect on the record, not a trust decision —
				// nothing was evaluated, and the record says so by its code.
				continue
			}
			denied++
			if p.Phase != "handshake" || !strings.Contains(p.Reason, "says SIM: contraindicated") || !strings.Contains(p.Reason, ver.srv.URL) || p.Code != "handshake_failure" {
				t.Fatalf("the refusal on the record does not carry the Verifier's word: %s", e.Payload)
			}
		case "allow":
			allowed++
			if denied == 0 {
				t.Fatalf("admission before any refusal: %s", e.Payload)
			}
			if p.PeerDetail == nil || p.PeerDetail.Verifier == nil || p.PeerDetail.Verifier.Status != "affirming" {
				t.Fatalf("the admission without the Verifier's result: %s", e.Payload)
			}
		}
	}
	if denied == 0 || allowed != 1 {
		t.Fatalf("trust decisions on record: %d denied, %d allowed", denied, allowed)
	}

	// The Verifier gone: the pinned worker is refused, the reason names the Verifier, no session opens.
	down := httptest.NewServer(ver.double.Handler())
	downURL := down.URL
	down.Close()
	v2 := startVaultWith(t, secrets, func(cfg map[string]any) { ver.delegate(cfg, downURL) })
	w2, health2 := v2.startWorker(t, "acp-compute", workerIdentity{tlsFrom: secrets, teeFrom: secrets})
	waitReady(t, w2, health2+"/healthz")
	before = v2.counter(t, `sagvd_handshake_failures_total{phase="handshake"}`)
	id2, _ := v2.submitGenome(t, v2.sealGenome(t, "gen-waiting", true))
	waitFor(t, 20*time.Second, "the worker refused while the Verifier is unreachable", func() bool {
		return v2.counter(t, `sagvd_handshake_failures_total{phase="handshake"}`) > before
	})
	if job := v2.job(t, id2); job.Status != "queued" {
		t.Fatalf("job reached %q with no Verifier to ask", job.Status)
	}
	if got := v2.counter(t, `sagvd_sessions_opened_total`); got != 0 {
		t.Fatalf("a session opened with no verdict (%d)", got)
	}
	if took, killed := w2.stop(); killed {
		t.Fatalf("worker had to be killed after %s", took)
	}
	_, events = v2.auditLogAfterStop(t)
	var unavailable int
	for _, e := range events {
		if e.Kind != "TRUST_EVALUATED" {
			continue
		}
		var p trustEvaluatedPayload
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			t.Fatal(err)
		}
		if p.Outcome == "deny" && strings.Contains(p.Reason, "verifier_unavailable") && strings.Contains(p.Reason, downURL) {
			unavailable++
		}
	}
	if unavailable == 0 {
		t.Fatal("no refusal naming the unreachable Verifier on the record")
	}
}
