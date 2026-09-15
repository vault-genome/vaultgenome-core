// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ai-continuity-platform/core/internal/compute/returnpath"
	"github.com/ai-continuity-platform/core/internal/compute/returnpath/transport"
	rjm "github.com/ai-continuity-platform/core/internal/contracts/reconstruction_job_manifest"
	"github.com/ai-continuity-platform/core/internal/genome/bundle"
	"github.com/ai-continuity-platform/core/internal/genome/escrow"
	"github.com/ai-continuity-platform/core/internal/genome/gatejob"
	"github.com/ai-continuity-platform/core/internal/genome/lora"
	"github.com/ai-continuity-platform/core/internal/shared/crypto"
	shared_errors "github.com/ai-continuity-platform/core/internal/shared/errors"
	"github.com/ai-continuity-platform/core/internal/shared/ids"
	shared_time "github.com/ai-continuity-platform/core/internal/shared/time"
	"github.com/ai-continuity-platform/core/internal/validation/equivalence"
	"github.com/ai-continuity-platform/core/internal/validation/reconstruction"
	"github.com/ai-continuity-platform/core/internal/vault/keys"
)

// A gate job (ADR 0013). The operator seals a model genome — the
// vg_genome worker's genome.json, LoRA adapter, fixtures and recipe — into
// a v3 bundle and drops it in genome.bundle_dir with its key file or escrow
// envelope. POST /v1/jobs names the bundle. This file is the authority's
// side of the job:
//
//   - build: open the bundle in memory, keep the fixtures' references,
//     seal the model side — genome.json, the adapter, the fixtures'
//     prompts — as one component each under the session key, behind a
//     gatejob.Descriptor in component 0; set the job's output budget to the
//     exact size of the answer (gatejob.OutputBudget).
//   - judge: decode the worker's signed candidate output, hold it to the
//     references with the determinism ladder — the byte-exact door first,
//     then the native-float door within the operator's tolerance — and
//     record the verdict on the job. No door opened: the job fails.
//
// The authority holds the genome's plaintext only for the time it takes
// to seal the components, in memory, and never writes any of it: it is a
// sealer here, as it is for every JobRequest.

// Error codes of the gate-job path.
const (
	// CodeGateJobsDisabled (Structural): genome.bundle_dir is not
	// configured, so there is nothing a job could name.
	CodeGateJobsDisabled = "gate_jobs_disabled"

	// CodeGenomeNotFound (Structural): the named bundle, key file or
	// escrow envelope is not in genome.bundle_dir.
	CodeGenomeNotFound = "genome_not_found"

	// CodeBundleDirUnavailable (Operational): genome.bundle_dir cannot be
	// opened on the vault.
	CodeBundleDirUnavailable = "bundle_dir_unavailable"

	// CodeGenomeKeyInvalid (Authority): the key file or envelope does not
	// open the named bundle.
	CodeGenomeKeyInvalid = "genome_key_invalid"

	// CodeGenomeInvalid (Structural): the bundle opened but does not hold
	// a model genome a gate job can carry.
	CodeGenomeInvalid = "genome_invalid"

	// CodeGenomeTooLarge (Operational): the model side of the genome does
	// not fit one Return Path job.
	CodeGenomeTooLarge = "genome_too_large"

	// CodeGateFailed (Operational): the worker's outputs missed the
	// sealed references at every door.
	CodeGateFailed = "gate_failed"

	// CodeGateOutputInvalid (Integrity): the worker's signed output is not
	// an answer to the job it was given.
	CodeGateOutputInvalid = "gate_output_invalid"
)

// Names of the two ladder doors a gate job tries, recorded in verdicts.
const (
	doorPinnedReplay = "pinned replay"
	doorNativeFloat  = "native float"
)

// genomeRef is how POST /v1/jobs names a genome.
type genomeRef struct {
	// Bundle is the .genome file's name in genome.bundle_dir.
	Bundle string `json:"bundle"`
	// KeyFile is the key file's name in genome.bundle_dir (acpctl genome
	// seal --key-out). Empty: the envelope <bundle>.escrow is opened with
	// the authority's escrow key.
	KeyFile string `json:"key_file,omitempty"`
}

// GenomeView is the genome side of a job, as GET /v1/jobs/{id} shows it.
// Nothing in it is secret.
type GenomeView struct {
	Bundle        string `json:"bundle"`
	KeyID         string `json:"key_id"`
	KeySource     string `json:"key_source"` // key_file | escrow
	BundleSHA256  string `json:"bundle_sha256"`
	PayloadSHA256 string `json:"payload_sha256"`
	Generation    uint64 `json:"generation"`
	Base          string `json:"base"`
	BaseDigest    string `json:"base_digest"`
	Files         int    `json:"files"` // files shipped to the worker
	Bytes         int64  `json:"bytes"` // their plaintext bytes
	Fixtures      int    `json:"fixtures"`
	Critical      int    `json:"critical"`
}

// gateSpec is what the authority keeps, in memory, to judge the answer.
type gateSpec struct {
	GenomeID string
	Fixtures []equivalence.Fixture
	Tol      equivalence.Tolerance
	Pol      equivalence.Policy
}

// GateView is a gate job's verdict, as GET /v1/jobs/{id} shows it.
type GateView struct {
	// Level is EXACT or EQUIVALENT when a door opened, FAIL when every
	// door judged the outputs and refused them, ERROR when no door could
	// judge (the output could not be read).
	Level    string                   `json:"level"`
	Door     string                   `json:"door,omitempty"`
	Rung     int                      `json:"rung"`
	Kind     string                   `json:"kind,omitempty"`
	Fixtures int                      `json:"fixtures"`
	Attempts []reconstruction.Attempt `json:"attempts"`
	// SignedVerdict is the passing verdict, signed by the authority's
	// signing key (equivalence.VerifySigned checks it); absent when no
	// door opened.
	SignedVerdict *equivalence.SignedVerdict `json:"signed_verdict,omitempty"`
	SignerKeyID   string                     `json:"signer_key_id,omitempty"`
}

// genomeJobs builds gate jobs from the genomes in genome.bundle_dir.
type genomeJobs struct {
	cfg        GenomeConfig
	escrowPath string
	sealer     keys.Sealer
	sealKID    ids.KeyID
	maxPayload uint64
	clock      shared_time.Clock
}

// newGenomeJobs wires a builder; nil when gate jobs are not configured.
func newGenomeJobs(cfg Config, sealer keys.Sealer, sealKID ids.KeyID, clock shared_time.Clock) *genomeJobs {
	if !cfg.Genome.Enabled() {
		return nil
	}
	return &genomeJobs{
		cfg:        cfg.Genome,
		escrowPath: cfg.EscrowKeyPath(),
		sealer:     sealer,
		sealKID:    sealKID,
		maxPayload: cfg.Runtime.MaxPayloadBytes,
		clock:      clock,
	}
}

// builtJob is one gate job ready to queue.
type builtJob struct {
	Req    transport.JobRequest
	Genome GenomeView
	Gate   *gateSpec
}

// build opens the named genome and seals a gate job for it. deadline is
// how long the worker has from now.
func (g *genomeJobs) build(ref genomeRef, deadline time.Duration) (builtJob, error) {
	var zero builtJob
	name, err := bundleFileName(ref.Bundle)
	if err != nil {
		return zero, err
	}
	// Every file a job names is opened relative to genome.bundle_dir
	// through an os.Root: a name that still pointed outside it — a
	// symlink, say — is refused by the kernel, not by string checks.
	root, err := os.OpenRoot(g.cfg.BundleDir)
	if err != nil {
		return zero, shared_errors.Operational(CodeBundleDirUnavailable, "genome.bundle_dir cannot be opened", err)
	}
	defer func() { _ = root.Close() }()

	// A bundle the Return Path could not carry is refused before it is
	// read into memory.
	blob, size, err := readInRoot(root, name, int64(g.maxPayload)+bundle.MaxHeaderBytes+1<<20)
	switch {
	case errors.Is(err, errFileTooLarge):
		return zero, shared_errors.Operational(CodeGenomeTooLarge,
			fmt.Sprintf("genome %s is %d bytes; a gate job carries at most runtime.max_payload_bytes (%d)", name, size, g.maxPayload), nil)
	case err != nil:
		return zero, shared_errors.Structural(CodeGenomeNotFound, fmt.Sprintf("genome %s is not in genome.bundle_dir", name), nil)
	}
	rd, err := bundle.NewReader(bytes.NewReader(blob))
	if err != nil {
		return zero, shared_errors.Structural(CodeGenomeInvalid, fmt.Sprintf("genome %s: %v", name, err), nil)
	}
	if rd.Header.ContentKind != bundle.ContentDir {
		return zero, shared_errors.Structural(CodeGenomeInvalid,
			fmt.Sprintf("genome %s holds a %s snapshot, not a model genome directory", name, rd.Header.ContentKind), nil)
	}
	bundleSum := sha256.Sum256(blob)

	dek, keySource, err := g.openKey(root, ref, name, rd.Header.KeyID)
	if err != nil {
		return zero, err
	}
	defer clear(dek)
	payload, err := rd.PayloadWithKey(dek)
	if err != nil {
		return zero, shared_errors.Authority(CodeGenomeKeyInvalid, fmt.Sprintf("genome %s: %v", name, err), nil)
	}
	plain, err := io.ReadAll(payload)
	if err != nil {
		return zero, shared_errors.Authority(CodeGenomeKeyInvalid, fmt.Sprintf("genome %s does not open: %v", name, err), nil)
	}
	defer clear(plain)

	files, err := untarFiles(plain)
	if err != nil {
		return zero, shared_errors.Structural(CodeGenomeInvalid, fmt.Sprintf("genome %s: %v", name, err), nil)
	}
	defer func() {
		for _, b := range files {
			clear(b)
		}
	}()

	model, err := modelSide(files)
	if err != nil {
		return zero, shared_errors.Structural(CodeGenomeInvalid, fmt.Sprintf("genome %s: %v", name, err), nil)
	}

	genomeID := rd.Header.KeyID
	promptsJSON, err := gatejob.EncodePrompts(model.prompts)
	if err != nil {
		return zero, shared_errors.Structural(CodeGenomeInvalid, fmt.Sprintf("genome %s: %v", name, err), nil)
	}
	shipped := map[string][]byte{gatejob.GenomePath: files[gatejob.GenomePath], gatejob.PromptsPath: promptsJSON}
	for _, p := range model.adapterFiles {
		shipped[p] = files[p]
	}
	budget, err := gatejob.OutputBudget(genomeID, model.fixtures)
	if err != nil {
		return zero, shared_errors.Structural(CodeGenomeInvalid, fmt.Sprintf("genome %s: %v", name, err), nil)
	}

	manifestID, sessionID, err := newJobIdentity()
	if err != nil {
		return zero, shared_errors.Operational(shared_errors.CodeResourceExhausted, "sagvd: allocate job identity", err)
	}
	now := g.clock.Now().UTC()
	req := transport.JobRequest{
		Type:                   transport.FrameTypeJobRequest,
		SchemaVersion:          1,
		ManifestID:             manifestID,
		SessionID:              sessionID,
		ExpectedOutputKind:     string(rjm.OutputKindBytesFixedLength),
		ExpectedOutputMaxBytes: budget,
		Deadline:               now.Add(deadline),
		IssuedAt:               now,
	}

	// Component order: the descriptor, then every file in path order.
	paths := make([]string, 0, len(shipped))
	for p := range shipped {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	desc := gatejob.Descriptor{Schema: gatejob.DescriptorSchema, GenomeID: genomeID}
	var shippedBytes int64
	for i, p := range paths {
		sum := sha256.Sum256(shipped[p])
		desc.Files = append(desc.Files, gatejob.File{Path: p, SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(shipped[p])), Component: uint32(i + 1)})
		shippedBytes += int64(len(shipped[p]))
	}
	if uint64(shippedBytes) > g.maxPayload {
		return zero, shared_errors.Operational(CodeGenomeTooLarge,
			fmt.Sprintf("genome %s ships %d bytes to the worker; runtime.max_payload_bytes is %d", name, shippedBytes, g.maxPayload), nil)
	}
	descRaw, err := gatejob.EncodeDescriptor(desc)
	if err != nil {
		return zero, shared_errors.Structural(CodeGenomeInvalid, fmt.Sprintf("genome %s: %v", name, err), nil)
	}
	components := make([][]byte, 0, len(paths)+1)
	components = append(components, descRaw)
	for _, p := range paths {
		components = append(components, shipped[p])
	}
	for i, plaintext := range components {
		aad := buildComponentAAD(req.ManifestID, req.SessionID, req.ExpectedOutputKind, uint32(i))
		nonce, ct, err := g.sealer.Seal(g.sealKID, plaintext, aad)
		if err != nil {
			return zero, shared_errors.Authority("seal_failed", "seal gate-job component", err)
		}
		req.SealedMaterial = append(req.SealedMaterial, transport.SealedMaterialRef{
			RecipientKeyID: string(g.sealKID), Nonce: nonce, Ciphertext: ct, AAD: aad,
		})
	}
	if err := req.Validate(); err != nil {
		return zero, err
	}
	frame, err := transport.EncodeBody(req)
	if err != nil {
		return zero, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "encode JobRequest", err)
	}
	if uint64(len(frame)) > uint64(transport.MaxFrameSize) {
		return zero, shared_errors.Operational(CodeGenomeTooLarge,
			fmt.Sprintf("genome %s makes a %d-byte JobRequest; the Return Path carries frames of at most %d bytes", name, len(frame), transport.MaxFrameSize), nil)
	}

	return builtJob{
		Req: req,
		Genome: GenomeView{
			Bundle:        name,
			KeyID:         rd.Header.KeyID,
			KeySource:     keySource,
			BundleSHA256:  hex.EncodeToString(bundleSum[:]),
			PayloadSHA256: rd.Header.PayloadSHA256,
			Generation:    rd.Header.Generation,
			Base:          model.genome.Base.Name,
			BaseDigest:    model.genome.Base.Manifest.Digest,
			Files:         len(paths),
			Bytes:         shippedBytes,
			Fixtures:      len(model.fixtures),
			Critical:      model.critical,
		},
		Gate: &gateSpec{
			GenomeID: genomeID,
			Fixtures: model.fixtures,
			Tol:      equivalence.Tolerance{Atol: g.cfg.Gate.Atol, Rtol: g.cfg.Gate.Rtol},
			Pol:      equivalence.Policy{MaxNonCriticalOutliers: g.cfg.Gate.MaxNonCriticalOutliers},
		},
	}, nil
}

// openKey finds the genome's key: the named key file, or the escrow
// envelope beside the bundle opened with the authority's escrow key. Both
// are read through root; the key is checked against the bundle's key ID
// before anything is opened.
func (g *genomeJobs) openKey(root *os.Root, ref genomeRef, bundleName, keyID string) ([]byte, string, error) {
	if ref.KeyFile != "" {
		name, err := bundleFileName(ref.KeyFile)
		if err != nil {
			return nil, "", err
		}
		f, err := root.Open(name)
		if err != nil {
			return nil, "", shared_errors.Structural(CodeGenomeNotFound, fmt.Sprintf("key file %s is not in genome.bundle_dir", name), nil)
		}
		defer func() { _ = f.Close() }()
		info, err := f.Stat()
		if err != nil {
			return nil, "", shared_errors.Structural(CodeGenomeNotFound, fmt.Sprintf("key file %s: %v", name, err), nil)
		}
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			return nil, "", shared_errors.Authority(CodeGenomeKeyInvalid,
				fmt.Sprintf("key file %s is open to other users (mode %04o); chmod 600 it", name, perm), nil)
		}
		dek, err := io.ReadAll(io.LimitReader(f, crypto.AES256KeySize+1))
		if err != nil {
			return nil, "", shared_errors.Structural(CodeGenomeNotFound, fmt.Sprintf("key file %s: %v", name, err), nil)
		}
		if err := bundle.CheckKey(keyID, dek); err != nil {
			clear(dek)
			return nil, "", shared_errors.Authority(CodeGenomeKeyInvalid, fmt.Sprintf("key file %s: %v", name, err), nil)
		}
		return dek, "key_file", nil
	}
	if g.escrowPath == "" {
		return nil, "", shared_errors.Structural(CodeGenomeNotFound,
			"no key_file named and no escrow key configured (genome.key_escrow_path)", nil)
	}
	raw, _, err := readInRoot(root, bundleName+".escrow", maxEnvelopeBytes)
	if err != nil {
		return nil, "", shared_errors.Structural(CodeGenomeNotFound,
			fmt.Sprintf("no key_file named and no envelope %s.escrow in genome.bundle_dir", bundleName), nil)
	}
	env, err := escrow.Parse(raw)
	if err != nil {
		return nil, "", shared_errors.Authority(CodeGenomeKeyInvalid, fmt.Sprintf("envelope %s.escrow: %v", bundleName, err), nil)
	}
	if env.KeyID != keyID {
		return nil, "", shared_errors.Authority(CodeGenomeKeyInvalid,
			fmt.Sprintf("envelope %s.escrow holds key %s, the bundle is sealed under %s", bundleName, env.KeyID, keyID), nil)
	}
	priv, err := escrow.ReadPrivate(g.escrowPath)
	if err != nil {
		return nil, "", shared_errors.Authority(CodeGenomeKeyInvalid, fmt.Sprintf("genome.key_escrow_path: %v", err), nil)
	}
	dek, err := escrow.Open(env, priv)
	if err != nil {
		return nil, "", shared_errors.Authority(CodeGenomeKeyInvalid, fmt.Sprintf("envelope %s.escrow: %v", bundleName, err), nil)
	}
	if err := bundle.CheckKey(keyID, dek); err != nil {
		clear(dek)
		return nil, "", shared_errors.Authority(CodeGenomeKeyInvalid, fmt.Sprintf("envelope %s.escrow: %v", bundleName, err), nil)
	}
	return dek, "escrow", nil
}

// maxEnvelopeBytes bounds an escrow envelope: a key ID, two tags and a
// wrapped 32-byte key.
const maxEnvelopeBytes = 16 << 10

var errFileTooLarge = errors.New("file too large")

// readInRoot reads the regular file name inside root, refusing one larger
// than limit before reading it. It returns the file's size with the error
// so a refusal can name it.
func readInRoot(root *os.Root, name string, limit int64) ([]byte, int64, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	if !info.Mode().IsRegular() {
		return nil, info.Size(), fmt.Errorf("%s is not a regular file", name)
	}
	if info.Size() > limit {
		return nil, info.Size(), errFileTooLarge
	}
	data := make([]byte, info.Size())
	if _, err := io.ReadFull(f, data); err != nil {
		return nil, info.Size(), err
	}
	return data, info.Size(), nil
}

// modelGenome is the model side of an opened genome.
type modelGenome struct {
	genome       lora.Genome
	fixtures     []equivalence.Fixture
	prompts      gatejob.Prompts
	adapterFiles []string
	critical     int
}

// modelSide reads the genome's description and fixtures from the opened
// files and checks the adapter is the one the genome names.
func modelSide(files map[string][]byte) (modelGenome, error) {
	raw, ok := files[gatejob.GenomePath]
	if !ok {
		return modelGenome{}, errors.New("no genome.json: not a model genome (workers/genome)")
	}
	g, err := lora.Parse(raw)
	if err != nil {
		return modelGenome{}, err
	}
	fxRaw, ok := files[g.Fixtures.File]
	if !ok {
		return modelGenome{}, fmt.Errorf("genome.json names fixtures %s, which the bundle does not hold", g.Fixtures.File)
	}
	fixtures, prompts, err := lora.ParseFixtures(g, fxRaw)
	if err != nil {
		return modelGenome{}, err
	}
	if len(prompts) != len(fixtures) {
		return modelGenome{}, fmt.Errorf("%d of %d fixtures carry no prompt (input_ids, topk_index); the genome was written by a worker older than the gate job", len(fixtures)-len(prompts), len(fixtures))
	}
	out := modelGenome{genome: g, fixtures: fixtures, prompts: gatejob.Prompts{Schema: gatejob.PromptsSchema}}
	for _, p := range prompts {
		out.prompts.Prompts = append(out.prompts.Prompts, gatejob.Prompt{ID: p.ID, InputIDs: p.InputIDs, TopKIndex: p.TopKIndex})
	}
	for _, f := range fixtures {
		if f.Critical {
			out.critical++
		}
	}
	prefix := path.Clean(g.Adapter.Dir) + "/"
	for p := range files {
		if strings.HasPrefix(p, prefix) {
			out.adapterFiles = append(out.adapterFiles, p)
		}
	}
	sort.Strings(out.adapterFiles)
	weights, ok := files[prefix+"adapter_model.safetensors"]
	if !ok {
		return modelGenome{}, fmt.Errorf("no %sadapter_model.safetensors in the bundle", prefix)
	}
	if _, ok := files[prefix+"adapter_config.json"]; !ok {
		return modelGenome{}, fmt.Errorf("no %sadapter_config.json in the bundle", prefix)
	}
	if got := "sha256:" + hex.EncodeToString(crypto.SHA256Slice(weights)); got != g.Adapter.WeightsSHA256 {
		return modelGenome{}, errors.New("the adapter weights are not the ones genome.json names")
	}
	return out, nil
}

// evaluateGate judges the worker's candidate output against the sealed
// references. It returns the verdict view and, when no door opened, a
// classified error; both are recorded on the job.
func evaluateGate(spec *gateSpec, out returnpath.CandidateOutput) (GateView, error) {
	view := GateView{Level: "ERROR", Fixtures: len(spec.Fixtures)}
	genomeID, outputs, err := gatejob.DecodeOutput(out.Bytes)
	if err != nil {
		return view, shared_errors.Integrity(CodeGateOutputInvalid, "the worker's output is not a gate output", err)
	}
	if genomeID != spec.GenomeID {
		return view, shared_errors.Integrity(CodeGateOutputInvalid,
			fmt.Sprintf("the worker answered for genome %s, the job was for %s", genomeID, spec.GenomeID), nil)
	}
	recompute := func(id string) (equivalence.Tensor, error) {
		t, ok := outputs[id]
		if !ok {
			return equivalence.Tensor{}, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing,
				fmt.Sprintf("the worker gave no output for fixture %q", id), nil)
		}
		return t, nil
	}
	res, err := reconstruction.Regenerate(spec.GenomeID, spec.Fixtures, []reconstruction.Strategy{
		reconstruction.PinnedReplayDoor(doorPinnedReplay, recompute),
		{Rung: 1, Kind: reconstruction.KindNativeFloat, Name: doorNativeFloat, Recompute: recompute, Tol: spec.Tol, Pol: spec.Pol},
	})
	if err != nil {
		return view, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "gate", err)
	}
	view.Attempts = res.Attempts
	if res.Opened {
		v := res.Verdict
		view.Level, view.Door, view.Rung, view.Kind = string(v.Level), res.Name, res.Rung, string(res.Kind)
		view.SignedVerdict = &equivalence.SignedVerdict{Verdict: v}
		return view, nil
	}
	last := res.Attempts[len(res.Attempts)-1]
	if last.Err != "" {
		return view, shared_errors.Integrity(CodeGateOutputInvalid, "no door could judge the worker's output: "+last.Err, nil)
	}
	view.Level = string(equivalence.LevelFail)
	return view, shared_errors.Operational(CodeGateFailed,
		fmt.Sprintf("the restored model missed its references at every door (max abs err %.3g at %q)", last.MaxAbsErr, last.Name), nil)
}

// signVerdict signs a passing verdict with the authority's signing key.
func signVerdict(view *GateView, signer keys.Signer, kid ids.KeyID, pub crypto.PublicKey) error {
	if view.SignedVerdict == nil {
		return nil
	}
	msg, err := view.SignedVerdict.Verdict.CanonicalBytes()
	if err != nil {
		return err
	}
	sig, err := signer.Sign(kid, keys.PurposeSigningAuthority, msg)
	if err != nil {
		return err
	}
	view.SignedVerdict.Signature = sig
	view.SignedVerdict.SignerPub = append([]byte(nil), pub...)
	view.SignerKeyID = string(kid)
	return nil
}

// untarFiles reads every regular file of a genome payload — the
// deterministic tar internal/contentdir writes — into memory.
func untarFiles(payload []byte) (map[string][]byte, error) {
	files := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(payload))
	var total int64
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("payload is not the tar a genome holds: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		name := h.Name
		if name == "" || strings.HasPrefix(name, "/") || path.Clean(name) != name || name == "." || name == ".." || strings.HasPrefix(name, "../") {
			return nil, fmt.Errorf("payload holds %q, which is not a local path", name)
		}
		if _, dup := files[name]; dup {
			return nil, fmt.Errorf("payload holds %s twice", name)
		}
		if h.Size < 0 || total+h.Size > int64(len(payload)) {
			return nil, errors.New("payload describes more bytes than it holds")
		}
		data := make([]byte, h.Size)
		if _, err := io.ReadFull(tr, data); err != nil {
			return nil, fmt.Errorf("payload: %s: %w", name, err)
		}
		files[name] = data
		total += h.Size
	}
	if len(files) == 0 {
		return nil, errors.New("payload holds no files")
	}
	return files, nil
}

// bundleFileNameRE is what a job may name: a file name of letters,
// digits, dots, dashes and underscores, starting with a letter or digit.
// No separators, no ".", no "..", no control characters.
var bundleFileNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`)

// bundleFileName accepts a bare file name inside genome.bundle_dir and
// refuses anything else, so the name can be joined, opened and logged.
func bundleFileName(name string) (string, error) {
	if name == "" {
		return "", shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "genome.bundle required", nil)
	}
	if !bundleFileNameRE.MatchString(name) {
		return "", shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("%q is not a file name in genome.bundle_dir (letters, digits, '.', '-', '_'; no paths)", name), nil)
	}
	return name, nil
}

// logSafe strips line breaks from a value before it goes into a log line,
// so a log entry is one line whatever the request carried.
func logSafe(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", " ")
}

// buildComponentAAD is the associated data the vault binds into every
// sealed component: the job's identity and the component's position, so
// a component cannot be replayed under another job or at another index.
// Human-inspectable so an Open() failure can be read.
func buildComponentAAD(manifestID, sessionID, kind string, index uint32) []byte {
	return []byte(fmt.Sprintf("sagvd/v1|m=%s|s=%s|k=%s|c=%d", manifestID, sessionID, kind, index))
}

// newJobIdentity mints the manifest and session ids of a job. The
// authority names its own jobs; a caller does not.
func newJobIdentity() (manifestID, sessionID string, err error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", err
	}
	return "rjm-" + hex.EncodeToString(b[:8]), "ses-" + hex.EncodeToString(b[8:]), nil
}
