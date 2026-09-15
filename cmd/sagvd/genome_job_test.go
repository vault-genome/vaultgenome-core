// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ai-continuity-platform/core/internal/compute/returnpath"
	"github.com/ai-continuity-platform/core/internal/compute/returnpath/transport"
	rjm "github.com/ai-continuity-platform/core/internal/contracts/reconstruction_job_manifest"
	"github.com/ai-continuity-platform/core/internal/genome/gatejob"
	"github.com/ai-continuity-platform/core/internal/shared/crypto"
	shared_errors "github.com/ai-continuity-platform/core/internal/shared/errors"
	"github.com/ai-continuity-platform/core/internal/shared/ids"
	shared_time "github.com/ai-continuity-platform/core/internal/shared/time"
	"github.com/ai-continuity-platform/core/internal/validation/equivalence"
	"github.com/ai-continuity-platform/core/internal/vault/keys"
	"github.com/stretchr/testify/require"
)

// newGenomeJobs wires a builder over a temp bundle dir with a fresh
// sealing key; the store is returned so a test can open what was sealed.
func newTestGenomeJobs(t *testing.T, bundleDir, escrowKey string) (*genomeJobs, *keys.InMemoryStore) {
	t.Helper()
	clock := shared_time.NewSystemClock()
	store := keys.NewInMemoryStore(clock)
	sealKID := testRegisterSealing(t, store)
	cfg := DefaultConfig()
	cfg.Genome.BundleDir = bundleDir
	cfg.Genome.KeyEscrowPath = escrowKey
	cfg.Runtime.MaxPayloadBytes = 1 << 20
	g := newGenomeJobs(cfg, store, sealKID, clock)
	require.NotNil(t, g)
	return g, store
}

func TestGenomeJobs_BuildSealsTheModelSideAndKeepsTheReferences(t *testing.T) {
	dir := t.TempDir()
	sealed := sealTestGenome(t, dir, genomeOptions{})
	g, store := newTestGenomeJobs(t, dir, "")

	job, err := g.build(genomeRef{Bundle: sealed.Bundle, KeyFile: sealed.KeyFile}, 90*time.Second)
	require.NoError(t, err)
	req := job.Req
	require.NoError(t, req.Validate())
	require.True(t, strings.HasPrefix(req.ManifestID, "rjm-"))
	require.True(t, strings.HasPrefix(req.SessionID, "ses-"))
	require.Equal(t, string(rjm.OutputKindBytesFixedLength), req.ExpectedOutputKind)
	require.Equal(t, req.IssuedAt.Add(90*time.Second), req.Deadline)

	// The genome view is public and complete.
	require.Equal(t, sealed.Bundle, job.Genome.Bundle)
	require.Equal(t, sealed.KeyID, job.Genome.KeyID)
	require.Equal(t, "key_file", job.Genome.KeySource)
	require.Equal(t, "tiny-llama", job.Genome.Base)
	require.Equal(t, 3, job.Genome.Fixtures)
	require.Equal(t, 2, job.Genome.Critical)
	require.Equal(t, 4, job.Genome.Files, "genome.json, two adapter files, prompts.json")
	require.Len(t, job.Genome.BundleSHA256, 64)

	// What is kept to judge: the references, under the operator's tolerance.
	require.Equal(t, sealed.KeyID, job.Gate.GenomeID)
	require.Equal(t, sealed.Fixtures, job.Gate.Fixtures)
	require.Equal(t, equivalence.Tolerance{Atol: 1e-2, Rtol: 1e-3}, job.Gate.Tol)

	// The budget is the exact size of a right answer.
	require.Equal(t, uint64(len(sealed.rightOutput(t, nil))), req.ExpectedOutputMaxBytes)

	// Open every component as the worker does and check the job shape:
	// component 0 describes the rest; the fixtures' references and the
	// training data are not shipped.
	require.Len(t, req.SealedMaterial, 5)
	var files [][]byte
	for i, m := range req.SealedMaterial {
		require.Equal(t, buildComponentAAD(req.ManifestID, req.SessionID, req.ExpectedOutputKind, uint32(i)), m.AAD)
		pt, err := store.Open(ids.KeyID(m.RecipientKeyID), m.Nonce, m.Ciphertext, m.AAD)
		require.NoError(t, err)
		files = append(files, pt)
	}
	desc, err := gatejob.DecodeDescriptor(files[0])
	require.NoError(t, err)
	require.Equal(t, sealed.KeyID, desc.GenomeID)
	var paths []string
	for _, f := range desc.Files {
		paths = append(paths, f.Path)
		sum := sha256.Sum256(files[f.Component])
		require.Equal(t, hex.EncodeToString(sum[:]), f.SHA256)
		require.Equal(t, int64(len(files[f.Component])), f.Bytes)
	}
	require.Equal(t, []string{"adapter/adapter_config.json", "adapter/adapter_model.safetensors", "genome.json", "prompts.json"}, paths)
	require.Equal(t, sealed.Files["adapter/adapter_model.safetensors"], files[2])
	prompts, err := gatejob.DecodePrompts(files[4])
	require.NoError(t, err)
	require.Equal(t, sealed.Prompts, prompts)
	for _, f := range files {
		require.NotContains(t, string(f), "raw_b64", "no reference output leaves the authority")
		require.NotContains(t, string(f), `"completion"`, "the training data stays sealed")
	}

	// A component cannot be replayed at another index: the AAD differs.
	_, err = store.Open(ids.KeyID(req.SealedMaterial[1].RecipientKeyID), req.SealedMaterial[1].Nonce, req.SealedMaterial[1].Ciphertext,
		buildComponentAAD(req.ManifestID, req.SessionID, req.ExpectedOutputKind, 2))
	require.Error(t, err)

	// Two jobs for the same genome have their own identities.
	again, err := g.build(genomeRef{Bundle: sealed.Bundle, KeyFile: sealed.KeyFile}, 90*time.Second)
	require.NoError(t, err)
	require.NotEqual(t, req.ManifestID, again.Req.ManifestID)
}

func TestGenomeJobs_OpensAnEscrowedGenome(t *testing.T) {
	dir := t.TempDir()
	privPath, pubPath := escrowKeyPair(t, t.TempDir())
	sealed := sealTestGenome(t, dir, genomeOptions{name: "esc", escrowPub: pubPath})
	g, _ := newTestGenomeJobs(t, dir, privPath)

	job, err := g.build(genomeRef{Bundle: sealed.Bundle}, time.Minute)
	require.NoError(t, err)
	require.Equal(t, "escrow", job.Genome.KeySource)
	require.Equal(t, sealed.KeyID, job.Genome.KeyID)

	// Without the escrow key configured there is nothing to open it with.
	noEscrow, _ := newTestGenomeJobs(t, dir, "")
	_, err = noEscrow.build(genomeRef{Bundle: sealed.Bundle}, time.Minute)
	require.Equal(t, CodeGenomeNotFound, shared_errors.CodeOf(err))

	// An envelope for another genome is refused before it is opened.
	other := sealTestGenome(t, dir, genomeOptions{name: "other", escrowPub: pubPath})
	require.NoError(t, os.Rename(filepath.Join(dir, other.Bundle+".escrow"), filepath.Join(dir, sealed.Bundle+".escrow")))
	_, err = g.build(genomeRef{Bundle: sealed.Bundle}, time.Minute)
	require.Equal(t, CodeGenomeKeyInvalid, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err))
}

func TestGenomeJobs_RefusesWhatItShould(t *testing.T) {
	dir := t.TempDir()
	sealed := sealTestGenome(t, dir, genomeOptions{})
	g, _ := newTestGenomeJobs(t, dir, "")
	otherDir := t.TempDir()
	foreign := sealTestGenome(t, otherDir, genomeOptions{name: "foreign"})
	require.NoError(t, os.Rename(filepath.Join(otherDir, foreign.KeyFile), filepath.Join(dir, "foreign.key")))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "open.key"), bytes.Repeat([]byte{1}, 32), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "short.key"), []byte("nope"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "not-a-bundle.genome"), []byte("hello"), 0o644))

	for name, tc := range map[string]struct {
		ref  genomeRef
		code string
		cat  shared_errors.Category
	}{
		"no bundle":          {genomeRef{}, shared_errors.CodeRequiredFieldMissing, shared_errors.CategoryStructural},
		"path, not a name":   {genomeRef{Bundle: "../" + sealed.Bundle, KeyFile: sealed.KeyFile}, shared_errors.CodeFieldValueInvalid, shared_errors.CategoryStructural},
		"key path":           {genomeRef{Bundle: sealed.Bundle, KeyFile: "/etc/passwd"}, shared_errors.CodeFieldValueInvalid, shared_errors.CategoryStructural},
		"missing bundle":     {genomeRef{Bundle: "absent.genome", KeyFile: sealed.KeyFile}, CodeGenomeNotFound, shared_errors.CategoryStructural},
		"missing key":        {genomeRef{Bundle: sealed.Bundle, KeyFile: "absent.key"}, CodeGenomeNotFound, shared_errors.CategoryStructural},
		"not a bundle":       {genomeRef{Bundle: "not-a-bundle.genome", KeyFile: sealed.KeyFile}, CodeGenomeInvalid, shared_errors.CategoryStructural},
		"wrong key":          {genomeRef{Bundle: sealed.Bundle, KeyFile: "foreign.key"}, CodeGenomeKeyInvalid, shared_errors.CategoryAuthority},
		"key open to others": {genomeRef{Bundle: sealed.Bundle, KeyFile: "open.key"}, CodeGenomeKeyInvalid, shared_errors.CategoryAuthority},
		"key too short":      {genomeRef{Bundle: sealed.Bundle, KeyFile: "short.key"}, CodeGenomeKeyInvalid, shared_errors.CategoryAuthority},
		"no key, no escrow":  {genomeRef{Bundle: sealed.Bundle}, CodeGenomeNotFound, shared_errors.CategoryStructural},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := g.build(tc.ref, time.Minute)
			require.Error(t, err)
			require.Equal(t, tc.code, shared_errors.CodeOf(err), err.Error())
			require.Equal(t, tc.cat, shared_errors.CategoryOf(err), err.Error())
		})
	}

	// Genomes that open but cannot be gated.
	for name, opts := range map[string]genomeOptions{
		"fixtures without prompts":  {name: "noprompts", noPrompts: true},
		"adapter not the one named": {name: "wrongw", wrongWeigh: true},
		"no genome.json":            {name: "nogenome", mutate: func(f map[string][]byte) { delete(f, "genome.json") }},
		"no adapter config":         {name: "nocfg", mutate: func(f map[string][]byte) { delete(f, "adapter/adapter_config.json") }},
		"fixtures edited":           {name: "edited", mutate: func(f map[string][]byte) { f["fixtures.json"] = append(f["fixtures.json"], ' ') }},
	} {
		t.Run(name, func(t *testing.T) {
			s := sealTestGenome(t, dir, opts)
			_, err := g.build(genomeRef{Bundle: s.Bundle, KeyFile: s.KeyFile}, time.Minute)
			require.Error(t, err)
			require.Equal(t, CodeGenomeInvalid, shared_errors.CodeOf(err), err.Error())
		})
	}

	// A genome the Return Path cannot carry.
	small := g
	small.maxPayload = 4096
	_, err := small.build(genomeRef{Bundle: sealed.Bundle, KeyFile: sealed.KeyFile}, time.Minute)
	require.Equal(t, CodeGenomeTooLarge, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))
	tiny := g
	tiny.maxPayload = 1
	_, err = tiny.build(genomeRef{Bundle: sealed.Bundle, KeyFile: sealed.KeyFile}, time.Minute)
	require.Equal(t, CodeGenomeTooLarge, shared_errors.CodeOf(err), "refused before the bundle is read")

	// Not configured at all.
	require.Nil(t, newGenomeJobs(DefaultConfig(), nil, "", nil))
}

func candidate(genomeID string, out []byte) returnpath.CandidateOutput {
	return returnpath.CandidateOutput{ManifestID: "rjm-1", SessionID: "ses-1", OutputKind: rjm.OutputKindBytesFixedLength, Bytes: out, ProducedAt: time.Now()}
}

func TestEvaluateGate_LadderAndVerdicts(t *testing.T) {
	dir := t.TempDir()
	sealed := sealTestGenome(t, dir, genomeOptions{})
	g, _ := newTestGenomeJobs(t, dir, "")
	job, err := g.build(genomeRef{Bundle: sealed.Bundle, KeyFile: sealed.KeyFile}, time.Minute)
	require.NoError(t, err)
	spec := job.Gate

	t.Run("byte-exact answer opens door 0", func(t *testing.T) {
		view, err := evaluateGate(spec, candidate(sealed.KeyID, sealed.rightOutput(t, nil)))
		require.NoError(t, err)
		require.Equal(t, "EXACT", view.Level)
		require.Equal(t, doorPinnedReplay, view.Door)
		require.Equal(t, 0, view.Rung)
		require.Equal(t, "pinned-replay", view.Kind)
		require.Equal(t, 3, view.Fixtures)
		require.Len(t, view.Attempts, 1)
		require.NotNil(t, view.SignedVerdict)
		require.Equal(t, equivalence.LevelExact, view.SignedVerdict.Verdict.Level)
		require.Equal(t, 3, view.SignedVerdict.Verdict.NExact)
		require.Equal(t, sealed.KeyID, view.SignedVerdict.Verdict.GenomeID)
	})
	t.Run("within tolerance opens door 1 as EQUIVALENT", func(t *testing.T) {
		out := sealed.rightOutput(t, map[[2]int]float32{{0, 1}: 2e-3, {2, 0}: -1e-3})
		view, err := evaluateGate(spec, candidate(sealed.KeyID, out))
		require.NoError(t, err)
		require.Equal(t, "EQUIVALENT", view.Level)
		require.Equal(t, doorNativeFloat, view.Door)
		require.Equal(t, 1, view.Rung)
		require.Len(t, view.Attempts, 2)
		require.Equal(t, equivalence.LevelFail, view.Attempts[0].Level, "door 0 refused it first, on the record")
		require.InDelta(t, 2e-3, view.SignedVerdict.Verdict.MaxAbsErr, 1e-6)
	})
	t.Run("outside tolerance fails every door", func(t *testing.T) {
		out := sealed.rightOutput(t, map[[2]int]float32{{1, 2}: 0.5})
		view, err := evaluateGate(spec, candidate(sealed.KeyID, out))
		require.Error(t, err)
		require.Equal(t, CodeGateFailed, shared_errors.CodeOf(err))
		require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))
		require.Equal(t, "FAIL", view.Level)
		require.Nil(t, view.SignedVerdict)
		require.Len(t, view.Attempts, 2)
		require.Contains(t, err.Error(), "missed its references")
	})
	t.Run("a non-critical outlier within policy still passes", func(t *testing.T) {
		lenient := *spec
		lenient.Pol = equivalence.Policy{MaxNonCriticalOutliers: 1}
		out := sealed.rightOutput(t, map[[2]int]float32{{2, 0}: 0.5}) // fx-002 is not critical
		view, err := evaluateGate(&lenient, candidate(sealed.KeyID, out))
		require.NoError(t, err)
		require.Equal(t, "EQUIVALENT", view.Level)
		require.Equal(t, 1, view.SignedVerdict.Verdict.NMismatch)
		critical := sealed.rightOutput(t, map[[2]int]float32{{0, 0}: 0.5}) // fx-000 is critical
		_, err = evaluateGate(&lenient, candidate(sealed.KeyID, critical))
		require.Equal(t, CodeGateFailed, shared_errors.CodeOf(err))
	})
	t.Run("an answer that is not an answer is an integrity failure", func(t *testing.T) {
		for name, out := range map[string][]byte{
			"garbage": []byte("not an output"),
			"other genome": func() []byte {
				o := sealed
				o.KeyID = "genome-000000000000-g0-000000000000"
				return o.rightOutput(t, nil)
			}(),
			"missing fixture": []byte(`{"schema":"vault-genome/gate-output/v1","genome_id":"` + sealed.KeyID + `","outputs":{"fx-000":{"dtype":"f32","shape":[3],"raw_b64":"AAAAAAAAAAAAAAAA"}}}`),
		} {
			t.Run(name, func(t *testing.T) {
				view, err := evaluateGate(spec, candidate(sealed.KeyID, out))
				require.Error(t, err)
				require.Equal(t, CodeGateOutputInvalid, shared_errors.CodeOf(err), err.Error())
				require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
				require.Equal(t, "ERROR", view.Level)
			})
		}
	})
}

func TestSignVerdict_VerifiesUnderTheAuthorityKey(t *testing.T) {
	dir := t.TempDir()
	sealed := sealTestGenome(t, dir, genomeOptions{})
	g, store := newTestGenomeJobs(t, dir, "")
	job, err := g.build(genomeRef{Bundle: sealed.Bundle, KeyFile: sealed.KeyFile}, time.Minute)
	require.NoError(t, err)
	view, err := evaluateGate(job.Gate, candidate(sealed.KeyID, sealed.rightOutput(t, nil)))
	require.NoError(t, err)

	vk, err := store.RegisterSigningFromSeed("authority-1", keys.PurposeSigningAuthority, bytes.Repeat([]byte{7}, crypto.Ed25519SeedSize))
	require.NoError(t, err)
	require.NoError(t, signVerdict(&view, store, "authority-1", vk.PublicKey))
	require.Equal(t, "authority-1", view.SignerKeyID)
	require.NoError(t, equivalence.VerifySigned(*view.SignedVerdict))
	tampered := *view.SignedVerdict
	tampered.Verdict.MaxAbsErr = 1
	require.Error(t, equivalence.VerifySigned(tampered))

	// Nothing to sign when no door opened.
	none := GateView{Level: "FAIL"}
	require.NoError(t, signVerdict(&none, store, "authority-1", vk.PublicKey))
	require.Nil(t, none.SignedVerdict)
}

func TestUntarFiles_ReadsRegularFilesAndRefusesEscapes(t *testing.T) {
	pack := func(entries ...tar.Header) []byte {
		var b bytes.Buffer
		tw := tar.NewWriter(&b)
		for _, h := range entries {
			h.Format = tar.FormatPAX
			if h.Typeflag == 0 {
				h.Typeflag = tar.TypeReg
			}
			require.NoError(t, tw.WriteHeader(&h))
			if h.Typeflag == tar.TypeReg {
				_, err := tw.Write(bytes.Repeat([]byte{'x'}, int(h.Size)))
				require.NoError(t, err)
			}
		}
		require.NoError(t, tw.Close())
		return b.Bytes()
	}
	files, err := untarFiles(pack(tar.Header{Name: "a/b.txt", Size: 3}, tar.Header{Name: "dir/", Typeflag: tar.TypeDir}, tar.Header{Name: "c", Size: 0}))
	require.NoError(t, err)
	require.Equal(t, map[string][]byte{"a/b.txt": []byte("xxx"), "c": {}}, files)
	for name, raw := range map[string][]byte{
		"escape":    pack(tar.Header{Name: "../x", Size: 1}),
		"absolute":  pack(tar.Header{Name: "/x", Size: 1}),
		"duplicate": pack(tar.Header{Name: "x", Size: 1}, tar.Header{Name: "x", Size: 1}),
		"empty":     pack(),
		"not tar":   []byte("nope"),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := untarFiles(raw)
			require.Error(t, err)
		})
	}
}

func TestBundleFileName(t *testing.T) {
	for _, ok := range []string{"gen-0.genome", "a.key", "x"} {
		got, err := bundleFileName(ok)
		require.NoError(t, err)
		require.Equal(t, ok, got)
	}
	for _, bad := range []string{"", ".", "..", "a/b", "/abs", `a\b`, "../x"} {
		_, err := bundleFileName(bad)
		require.Error(t, err, bad)
	}
}

func TestBuildComponentAAD_BindsJobAndIndex(t *testing.T) {
	a := buildComponentAAD("m", "s", string(rjm.OutputKindBytesFixedLength), 0)
	require.Equal(t, "sagvd/v1|m=m|s=s|k=bytes/fixed-length|c=0", string(a))
	require.NotEqual(t, a, buildComponentAAD("m", "s", string(rjm.OutputKindBytesFixedLength), 1))
	var _ transport.JobRequest // the AAD travels in the JobRequest's SealedMaterial
}
