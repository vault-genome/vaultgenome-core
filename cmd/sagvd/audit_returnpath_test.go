// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ai-continuity-platform/core/internal/audit/store"
	"github.com/ai-continuity-platform/core/internal/compute/returnpath"
	"github.com/ai-continuity-platform/core/internal/compute/returnpath/transport"
	"github.com/ai-continuity-platform/core/internal/contracts/audit_event"
	"github.com/ai-continuity-platform/core/internal/observability/metrics"
	"github.com/ai-continuity-platform/core/internal/shared/crypto"
	shared_errors "github.com/ai-continuity-platform/core/internal/shared/errors"
	"github.com/ai-continuity-platform/core/internal/shared/tee"
	shared_time "github.com/ai-continuity-platform/core/internal/shared/time"
	"github.com/ai-continuity-platform/core/internal/vault/keys"
	"github.com/stretchr/testify/require"
)

// newTestAudit opens a Return Path audit log in a temp dir under a fresh
// audit key and returns it with the config that names it.
func newTestAudit(t *testing.T) (*returnPathAudit, Config) {
	t.Helper()
	dir := t.TempDir()
	seed := bytes.Repeat([]byte{0x42}, crypto.Ed25519SeedSize)
	seedPath := filepath.Join(dir, "audit.seed")
	require.NoError(t, os.WriteFile(seedPath, seed, 0o600))
	cfg := DefaultConfig()
	cfg.Audit.LogPath = filepath.Join(dir, "returnpath.db")
	cfg.Keys.AuditSigning = SigningKeyConfig{KeyID: "audit-test-1", SeedPath: seedPath}
	a, err := openReturnPathAudit(cfg, shared_time.NewSystemClock(), metrics.NewRegistry())
	require.NoError(t, err)
	require.NotNil(t, a)
	t.Cleanup(func() { _ = a.Close() })
	return a, cfg
}

func testReq() transport.JobRequest {
	return transport.JobRequest{ManifestID: "rjm-audit", SessionID: "ses-audit"}
}

func TestReturnPathAudit_RecordsEveryDecisionInOrderAndVerifies(t *testing.T) {
	a, cfg := newTestAudit(t)
	req := testReq()

	// A job, accepted.
	job := builtJob{Req: req, Genome: GenomeView{KeyID: "genome-0123456789ab-g0-0123456789ab", Bundle: "g.genome", Fixtures: 3, Critical: 2, Files: 4, Bytes: 100}}
	job.Req.ExpectedOutputMaxBytes = 666
	job.Req.Deadline = time.Now().Add(time.Minute)
	require.NoError(t, a.JobAccepted("job-1", job))

	// A worker refused, then one admitted.
	require.NoError(t, a.TrustRefused("handshake", "127.0.0.1:5", tee.ProviderSimulated,
		shared_errors.Authority("handshake_failure", "client TEE evidence verification failed", nil)))
	require.NoError(t, a.TrustAdmitted("job-1", req, "127.0.0.1:6", tee.ProviderGCPSEVSNP, bytes.Repeat([]byte{0xab}, 48)))

	// A candidate, judged EXACT.
	out := returnpath.CandidateOutput{ManifestID: "rjm-audit", SessionID: "ses-audit", OutputKind: "bytes/fixed-length", Bytes: []byte(`{"schema":"x"}`), ProducedAt: time.Now()}
	require.NoError(t, a.CandidateReceived("job-1", req, out, "worker-1"))
	dir := t.TempDir()
	sealed := sealTestGenome(t, dir, genomeOptions{})
	g, _ := newTestGenomeJobs(t, dir, "")
	built, err := g.build(genomeRef{Bundle: sealed.Bundle, KeyFile: sealed.KeyFile}, time.Minute)
	require.NoError(t, err)
	pass, err := evaluateGate(built.Gate, candidate(sealed.KeyID, sealed.rightOutput(t, nil)))
	require.NoError(t, err)
	pass.SignerKeyID = "authority-1"
	require.NoError(t, a.Judged("job-1", req, built.Gate, pass, nil))

	// A second job whose model misses its references, and one that ended
	// without a candidate.
	fail, gateErr := evaluateGate(built.Gate, candidate(sealed.KeyID, sealed.rightOutput(t, map[[2]int]float32{{0, 0}: 5})))
	require.Error(t, gateErr)
	require.NoError(t, a.Judged("job-2", req, built.Gate, fail, gateErr))
	require.NoError(t, a.JobEnded("job-3", req, "serve", "worker-1", shared_errors.Authority("worker_rejected_job", "JobReject", nil)))
	require.NoError(t, a.JobEnded("job-4", req, "serve", "worker-1", shared_errors.Integrity("worker_signature_invalid", "bad signature", nil)))

	// On record, in order.
	events := a.chain.Events()
	var kinds []audit_event.Kind
	for _, e := range events {
		kinds = append(kinds, e.Kind)
	}
	require.Equal(t, []audit_event.Kind{
		audit_event.KindManifestIssued,
		audit_event.KindTrustEvaluated, audit_event.KindTrustEvaluated,
		audit_event.KindCandidateReceived,
		audit_event.KindValidationStarted, audit_event.KindValidationDimension, audit_event.KindValidationCompleted,
		audit_event.KindValidationStarted, audit_event.KindValidationDimension,
		audit_event.KindValidationFinding, audit_event.KindValidationFinding, audit_event.KindValidationFinding, // two doors failed + no door opened
		audit_event.KindValidationCompleted,
		audit_event.KindSessionInvalidated,
		audit_event.KindIncidentDetected,
	}, kinds)
	require.Equal(t, 15, a.Len())
	require.Len(t, a.Tip(), 64)

	// Payloads say what happened.
	var accepted jobAcceptedPayload
	require.NoError(t, json.Unmarshal(events[0].Payload, &accepted))
	require.Equal(t, auditPayloadSchema, accepted.Schema)
	require.Equal(t, "job-1", accepted.JobID)
	require.Equal(t, uint64(666), accepted.OutputBudget)
	require.Equal(t, "ses-audit", string(events[0].SessionID))
	require.Equal(t, "rjm-audit", string(events[0].ManifestID))
	var refused, admitted trustPayload
	require.NoError(t, json.Unmarshal(events[1].Payload, &refused))
	require.Equal(t, "deny", refused.Outcome)
	require.Equal(t, "handshake_failure", refused.Code)
	require.Empty(t, string(events[1].SessionID), "a refused peer has no job")
	require.NoError(t, json.Unmarshal(events[2].Payload, &admitted))
	require.Equal(t, "allow", admitted.Outcome)
	require.Equal(t, "gcp-sev-snp", admitted.PeerProvider)
	require.Len(t, admitted.PeerMeasurementHex, 96)
	var dim validationDimensionPayload
	require.NoError(t, json.Unmarshal(events[5].Payload, &dim))
	require.Equal(t, "behavioral", dim.Dimension)
	require.Equal(t, "pass", dim.Verdict)
	require.Equal(t, "EXACT", dim.Level)
	var done validationCompletedPayload
	require.NoError(t, json.Unmarshal(events[6].Payload, &done))
	require.Equal(t, "pass", done.Overall)
	require.Equal(t, 3, done.NExact)
	require.Len(t, done.VerdictSHA256, 64)
	require.Equal(t, "authority-1", done.SignerKeyID)
	var failed validationCompletedPayload
	require.NoError(t, json.Unmarshal(events[12].Payload, &failed))
	require.Equal(t, "fail", failed.Overall)
	require.Equal(t, CodeGateFailed, failed.Code)
	require.Equal(t, "FAIL", failed.Level)
	var ended sessionEndedPayload
	require.NoError(t, json.Unmarshal(events[14].Payload, &ended))
	require.Equal(t, "integrity", ended.Category)

	// The log verifies under the published audit key, as acpctl does,
	// after the daemon let go of it.
	require.NoError(t, a.Close())
	pub, _, err := crypto.Ed25519FromSeed(bytes.Repeat([]byte{0x42}, crypto.Ed25519SeedSize))
	require.NoError(t, err)
	logStore, err := store.Open(cfg.Audit.LogPath)
	require.NoError(t, err)
	stored, err := logStore.Load()
	require.NoError(t, err)
	require.NoError(t, logStore.Close())
	require.Len(t, stored, 15)
	resolver := keys.NewInMemoryStore(shared_time.NewSystemClock())
	_, err = resolver.RegisterSigningFromSeed("audit-test-1", keys.PurposeSigningAudit, bytes.Repeat([]byte{0x42}, crypto.Ed25519SeedSize))
	require.NoError(t, err)
	for i, e := range stored {
		require.NoError(t, e.VerifySignature(resolver), "event %d", i)
		if i > 0 {
			require.Equal(t, stored[i-1].Hash, e.PrevHash, "event %d links to its predecessor", i)
		}
	}
	_ = pub

	// Reopened, the log continues where it stopped.
	again, err := openReturnPathAudit(cfg, shared_time.NewSystemClock(), nil)
	require.NoError(t, err)
	defer func() { _ = again.Close() }()
	require.Equal(t, 15, again.Len())
	require.NoError(t, again.JobEnded("job-5", req, "dispatch", "", shared_errors.Operational("x", "y", nil)))
	require.Equal(t, 16, again.Len())
}

func TestReturnPathAudit_ClosedLogStopsTheDecision(t *testing.T) {
	a, _ := newTestAudit(t)
	require.NoError(t, a.Close())
	err := a.JobAccepted("job-1", builtJob{Req: testReq()})
	require.Error(t, err)
	require.Equal(t, CodeAuditUnavailable, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))

	// No log configured: nothing is recorded, nothing fails.
	var none *returnPathAudit
	require.NoError(t, none.JobAccepted("job-1", builtJob{}))
	require.NoError(t, none.TrustRefused("tls", "", tee.ProviderSimulated, shared_errors.Operational("x", "y", nil)))
	require.NoError(t, none.Close())
	require.Equal(t, 0, none.Len())
	require.Equal(t, "", none.Tip())
}

func TestReturnPathAudit_RefusesAnEditedLogAndNeedsItsKey(t *testing.T) {
	a, cfg := newTestAudit(t)
	require.NoError(t, a.JobEnded("job-1", testReq(), "serve", "", shared_errors.Operational("x", "y", nil)))
	require.NoError(t, a.Close())

	// Another key: the stored events do not verify, the log is refused.
	other := filepath.Join(t.TempDir(), "other.seed")
	require.NoError(t, os.WriteFile(other, bytes.Repeat([]byte{0x43}, crypto.Ed25519SeedSize), 0o600))
	wrong := cfg
	wrong.Keys.AuditSigning.SeedPath = other
	_, err := openReturnPathAudit(wrong, shared_time.NewSystemClock(), nil)
	require.ErrorContains(t, err, "does not verify")

	// No key configured with a log path.
	nokey := cfg
	nokey.Keys.AuditSigning = SigningKeyConfig{}
	_, err = openReturnPathAudit(nokey, shared_time.NewSystemClock(), nil)
	require.ErrorContains(t, err, "keys.audit_signing")

	// No log path: no audit, no error.
	none := cfg
	none.Audit.LogPath = ""
	got, err := openReturnPathAudit(none, shared_time.NewSystemClock(), nil)
	require.NoError(t, err)
	require.Nil(t, got)
}
