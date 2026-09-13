// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ai-continuity-platform/core/internal/contentdir"
	"github.com/ai-continuity-platform/core/internal/ollama"
	"github.com/ai-continuity-platform/core/internal/shared/tee"
)

// genomeMagic distinguishes a Vault Genome model bundle from the older
// vault envelope used by `acpctl recover`. Same on-disk shape (magic ||
// metadata length || JSON metadata || sealed blob) so tooling stays
// uniform; the magic prevents an operator from accidentally feeding a
// model bundle into the vault recovery flow or vice versa.
const genomeMagic = "VG-GENOME-01\x00\x00\x00\x00"

// envelopeFormatV2 supersedes the v1 single-snapshot envelope. v2 adds
// Generation + ParentBundleSHA256 (continuous-cycle support) and
// ContentKind/ContentRef so the same bundle format can hold either an
// Ollama model snapshot or an arbitrary directory snapshot (LoRA
// adapter, fine-tune checkpoint, RAG corpus, anything else).
const envelopeFormatV2 = "vault-genome-v2"

// ContentKind discriminates which payload-source produced this bundle.
type ContentKind string

const (
	ContentKindOllama ContentKind = "ollama" // payload was an Ollama model
	ContentKindDir    ContentKind = "dir"    // payload was a generic directory
)

// GenomeEnvelope is the on-disk metadata for a sealed bundle. v2 adds
// chain-of-custody fields (Generation + ParentBundleSHA256) so a
// directory of .genome files can be walked as a continuity timeline.
type GenomeEnvelope struct {
	Format      string `json:"format"`       // envelopeFormatV2
	TEEProvider string `json:"tee_provider"` // tee.Provider value
	SealedAt    int64  `json:"sealed_at"`    // unix nano

	// --- Chain-of-custody ---
	// Generation is monotonically increasing. 0 = genesis (no parent).
	Generation uint64 `json:"generation"`
	// ParentBundleSHA256 is the sha256 of the parent .genome FILE on
	// disk. Zero-length string at genesis. This binds the chain even if
	// envelope contents are tampered with.
	ParentBundleSHA256 string `json:"parent_bundle_sha256,omitempty"`
	// ParentPayloadSHA256 cross-links to the parent's payload digest for
	// faster lineage walking without re-hashing parent files.
	ParentPayloadSHA256 string `json:"parent_payload_sha256,omitempty"`
	// ParentGeneration is the parent's generation. Redundant with the
	// parent's envelope but cheap to verify the chain is monotonic.
	ParentGeneration uint64 `json:"parent_generation,omitempty"`

	// --- Content payload ---
	ContentKind ContentKind `json:"content_kind"`
	ContentRef  string      `json:"content_ref"` // "llama3.2:3b" or "/path/to/dir"
	// ContentSnapshot holds the kind-specific structured metadata
	// (ollama.Snapshot for ContentKindOllama, contentdir.Snapshot for
	// ContentKindDir). We store as raw JSON so the envelope schema
	// doesn't have to grow a tagged-union shape.
	ContentSnapshot json.RawMessage `json:"content_snapshot"`

	// --- Crypto ---
	Measurement []byte `json:"measurement"`
	AAD         []byte `json:"aad"`

	// --- Simulated TEE recovery params ---
	SimulatedWorkloadDescriptor []byte `json:"simulated_workload_descriptor,omitempty"`
	SimulatedSeed               []byte `json:"simulated_seed,omitempty"`
}

// genomeCmd is the entry-point dispatcher for `acpctl genome <sub>`.
func genomeCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printGenomeUsage(stderr)
		return 2
	}
	switch args[0] {
	case "seal":
		return genomeSealCmd(args[1:], stdout, stderr)
	case "open", "rewind":
		// `rewind` is an alias for `open` — semantically clearer in chain context.
		return genomeOpenCmd(args[1:], stdout, stderr)
	case "verify":
		return genomeVerifyCmd(args[1:], stdout, stderr)
	case "inspect":
		return genomeInspectCmd(args[1:], stdout, stderr)
	case "chain":
		return genomeChainCmd(args[1:], stdout, stderr)
	case "lineage":
		return genomeLineageCmd(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		printGenomeUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "acpctl genome: unknown subcommand %q\n\n", args[0])
		printGenomeUsage(stderr)
		return 2
	}
}

func printGenomeUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: acpctl genome <subcommand> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Subcommands:")
	fmt.Fprintln(w, "  seal      Seal an Ollama model OR an arbitrary directory into a .genome bundle")
	fmt.Fprintln(w, "  open      Restore a sealed bundle (alias: rewind)")
	fmt.Fprintln(w, "  verify    Re-hash a bundle and confirm components match envelope")
	fmt.Fprintln(w, "  inspect   Print envelope metadata (incl. generation + parent linkage)")
	fmt.Fprintln(w, "  chain     Walk a directory of .genome bundles, validate the lineage chain")
	fmt.Fprintln(w, "  lineage   From any bundle, walk parent references back to genesis")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Continuity quickstart:")
	fmt.Fprintln(w, "  acpctl genome seal --model=llama3.2:3b --output=gen-0.genome")
	fmt.Fprintln(w, "  acpctl genome seal --content-dir=./adapters/1 --parent=gen-0.genome --output=gen-1.genome")
	fmt.Fprintln(w, "  acpctl genome seal --content-dir=./adapters/2 --parent=gen-1.genome --output=gen-2.genome")
	fmt.Fprintln(w, "  acpctl genome chain --dir=./generations")
	fmt.Fprintln(w, "  acpctl genome rewind --bundle=gen-3.genome --target=/tmp/restored")
}

// ---------------------------------------------------------------------------
// genome seal
// ---------------------------------------------------------------------------

func genomeSealCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("genome seal", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		modelRef     = fs.String("model", "", "Ollama model ref (mutually exclusive with --content-dir)")
		contentDir   = fs.String("content-dir", "", "Directory to seal as the payload (mutually exclusive with --model)")
		ollamaHome   = fs.String("ollama-home", defaultOllamaHome(), "Path to OLLAMA root")
		parentBundle = fs.String("parent", "", "Path to parent .genome bundle — links this seal as its successor")
		outputPath   = fs.String("output", "", "Path to write the sealed .genome bundle (required)")
		jsonOut      = fs.Bool("json", false, "Emit machine-readable JSON output")
		force        = fs.Bool("force", false, "Overwrite output file if it exists")
	)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: acpctl genome seal {--model REF | --content-dir PATH} --output PATH [--parent BUNDLE] [...]")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Seal a payload into a .genome bundle. Either --model (Ollama model) or")
		fmt.Fprintln(stderr, "--content-dir (any directory of files) selects the payload source.")
		fmt.Fprintln(stderr, "--parent attaches this seal as the next generation in a continuity chain.")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *outputPath == "" {
		fmt.Fprintln(stderr, "acpctl genome seal: --output is required")
		fs.Usage()
		return 2
	}
	if (*modelRef == "") == (*contentDir == "") {
		fmt.Fprintln(stderr, "acpctl genome seal: pass exactly one of --model or --content-dir")
		fs.Usage()
		return 2
	}
	if !*force {
		if _, err := os.Stat(*outputPath); err == nil {
			fmt.Fprintf(stderr, "acpctl genome seal: refusing to overwrite %s (pass --force)\n", *outputPath)
			return 2
		}
	}

	// --- Capture payload (Ollama model OR generic dir) ---
	var (
		payload         []byte
		contentKind     ContentKind
		contentRef      string
		contentSnapJSON json.RawMessage
		payloadDigest   string
	)
	if *modelRef != "" {
		snap, p, err := ollama.CapturePayload(*modelRef, *ollamaHome)
		if err != nil {
			fmt.Fprintf(stderr, "acpctl genome seal: %v\n", err)
			return 1
		}
		payload = p
		contentKind = ContentKindOllama
		contentRef = *modelRef
		payloadDigest = snap.PayloadSHA256
		contentSnapJSON, err = json.Marshal(snap)
		if err != nil {
			fmt.Fprintf(stderr, "acpctl genome seal: marshal ollama snap: %v\n", err)
			return 1
		}
	} else {
		snap, p, err := contentdir.CapturePayload(*contentDir)
		if err != nil {
			fmt.Fprintf(stderr, "acpctl genome seal: %v\n", err)
			return 1
		}
		payload = p
		contentKind = ContentKindDir
		contentRef = *contentDir
		payloadDigest = snap.PayloadSHA256
		contentSnapJSON, err = json.Marshal(snap)
		if err != nil {
			fmt.Fprintf(stderr, "acpctl genome seal: marshal dir snap: %v\n", err)
			return 1
		}
	}

	// --- Resolve parent linkage ---
	var (
		generation        uint64 = 0
		parentBundleHash  string
		parentPayloadHash string
		parentGeneration  uint64
	)
	if *parentBundle != "" {
		parentBlob, err := os.ReadFile(*parentBundle)
		if err != nil {
			fmt.Fprintf(stderr, "acpctl genome seal: read parent bundle: %v\n", err)
			return 1
		}
		parentEnv, _, err := decodeGenome(parentBlob)
		if err != nil {
			fmt.Fprintf(stderr, "acpctl genome seal: decode parent bundle: %v\n", err)
			return 1
		}
		generation = parentEnv.Generation + 1
		parentBundleHash = sha256Hex(parentBlob)
		parentPayloadHash = strings.TrimPrefix(parentEnv.payloadDigest(), "sha256:")
		parentGeneration = parentEnv.Generation
	}

	// --- Construct workload descriptor + Sealer ---
	wd := workloadDescriptorV2(contentKind, contentRef, payloadDigest, generation)
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		fmt.Fprintf(stderr, "acpctl genome seal: rand: %v\n", err)
		return 1
	}
	sealer, err := tee.NewSimulated(wd, seed)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl genome seal: NewSimulated: %v\n", err)
		return 1
	}
	measurement := sealer.Measurement()
	aad := []byte(payloadDigest)

	sealed, err := sealer.Seal(payload, aad)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl genome seal: Seal: %v\n", err)
		return 1
	}

	env := GenomeEnvelope{
		Format:                      envelopeFormatV2,
		TEEProvider:                 string(tee.ProviderSimulated),
		SealedAt:                    time.Now().UnixNano(),
		Generation:                  generation,
		ParentBundleSHA256:          parentBundleHash,
		ParentPayloadSHA256:         parentPayloadHash,
		ParentGeneration:            parentGeneration,
		ContentKind:                 contentKind,
		ContentRef:                  contentRef,
		ContentSnapshot:             contentSnapJSON,
		Measurement:                 append([]byte(nil), measurement[:]...),
		AAD:                         aad,
		SimulatedWorkloadDescriptor: wd,
		SimulatedSeed:               seed,
	}

	blob, err := encodeGenome(env, sealed)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl genome seal: encode: %v\n", err)
		return 1
	}
	if err := os.WriteFile(*outputPath, blob, 0o644); err != nil {
		fmt.Fprintf(stderr, "acpctl genome seal: write: %v\n", err)
		return 1
	}

	emitGenome(stdout, *jsonOut, sealResult{
		OK:                 true,
		Output:             *outputPath,
		ContentKind:        string(contentKind),
		ContentRef:         contentRef,
		Generation:         generation,
		ParentBundle:       *parentBundle,
		ParentBundleSHA256: parentBundleHash,
		PayloadBytes:       len(payload),
		SealedBytes:        len(sealed),
		BundleBytes:        len(blob),
		PayloadSHA256:      payloadDigest,
		MeasurementHex:     hex.EncodeToString(measurement[:]),
		ComponentCount:     countComponents(&env),
		SealedAt:           time.Unix(0, env.SealedAt).UTC().Format(time.RFC3339),
	})
	return 0
}

// ---------------------------------------------------------------------------
// genome open / rewind
// ---------------------------------------------------------------------------

func genomeOpenCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("genome open", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		bundlePath = fs.String("bundle", "", "Path to .genome bundle (required)")
		targetDir  = fs.String("target", "", "Target directory for restore (required)")
		jsonOut    = fs.Bool("json", false, "Emit machine-readable JSON output")
	)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: acpctl genome open --bundle PATH --target PATH [--json]")
		fmt.Fprintln(stderr, "       acpctl genome rewind --bundle PATH --target PATH [--json]   (alias)")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *bundlePath == "" || *targetDir == "" {
		fmt.Fprintln(stderr, "acpctl genome open: --bundle and --target are required")
		fs.Usage()
		return 2
	}

	blob, err := os.ReadFile(*bundlePath)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl genome open: read bundle: %v\n", err)
		return 1
	}
	env, sealed, err := decodeGenome(blob)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl genome open: %v\n", err)
		return 1
	}

	if env.TEEProvider != string(tee.ProviderSimulated) {
		fmt.Fprintf(stderr, "acpctl genome open: provider %q not supported by this build\n", env.TEEProvider)
		return 1
	}
	sealer, err := tee.NewSimulated(env.SimulatedWorkloadDescriptor, env.SimulatedSeed)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl genome open: NewSimulated: %v\n", err)
		return 1
	}
	live := sealer.Measurement()
	if !bytes.Equal(live[:], env.Measurement) {
		fmt.Fprintf(stderr, "acpctl genome open: measurement mismatch — refusing unseal\n")
		return 4
	}

	payload, err := sealer.Unseal(sealed, env.AAD)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl genome open: Unseal: %v\n", err)
		return 4
	}
	gotDigest := "sha256:" + hex.EncodeToString(sha256Sum(payload))
	if gotDigest != env.payloadDigest() {
		fmt.Fprintf(stderr, "acpctl genome open: payload digest mismatch (envelope=%s, computed=%s)\n", env.payloadDigest(), gotDigest)
		return 4
	}

	var (
		written int64
		kind    string
	)
	switch env.ContentKind {
	case ContentKindOllama:
		written, err = ollama.Restore(payload, *targetDir)
		kind = "ollama"
	case ContentKindDir:
		written, err = contentdir.Restore(payload, *targetDir)
		kind = "dir"
	default:
		fmt.Fprintf(stderr, "acpctl genome open: unknown content kind %q\n", env.ContentKind)
		return 1
	}
	if err != nil {
		fmt.Fprintf(stderr, "acpctl genome open: restore: %v\n", err)
		return 1
	}

	emitGenome(stdout, *jsonOut, openResult{
		OK:             true,
		Bundle:         *bundlePath,
		Target:         *targetDir,
		ContentKind:    kind,
		ContentRef:     env.ContentRef,
		Generation:     env.Generation,
		BytesWritten:   written,
		PayloadSHA256:  env.payloadDigest(),
		MeasurementHex: hex.EncodeToString(env.Measurement),
	})
	return 0
}

// ---------------------------------------------------------------------------
// genome verify
// ---------------------------------------------------------------------------

func genomeVerifyCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("genome verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		bundlePath = fs.String("bundle", "", "Path to .genome bundle (required)")
		restored   = fs.String("restored", "", "Optional: restored target dir to re-hash blobs against")
		jsonOut    = fs.Bool("json", false, "Emit machine-readable JSON output")
	)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: acpctl genome verify --bundle PATH [--restored PATH] [--json]")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *bundlePath == "" {
		fmt.Fprintln(stderr, "acpctl genome verify: --bundle is required")
		fs.Usage()
		return 2
	}
	blob, err := os.ReadFile(*bundlePath)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl genome verify: read: %v\n", err)
		return 1
	}
	env, sealed, err := decodeGenome(blob)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl genome verify: %v\n", err)
		return 1
	}
	res := verifyResult{
		OK:             true,
		Bundle:         *bundlePath,
		ContentKind:    string(env.ContentKind),
		ContentRef:     env.ContentRef,
		Generation:     env.Generation,
		EnvelopeFormat: env.Format,
		ComponentCount: countComponents(env),
		SealedBytes:    len(sealed),
		PayloadSHA256:  env.payloadDigest(),
		MeasurementHex: hex.EncodeToString(env.Measurement),
		SealedAt:       time.Unix(0, env.SealedAt).UTC().Format(time.RFC3339),
	}
	if *restored != "" {
		switch env.ContentKind {
		case ContentKindOllama:
			var snap ollama.Snapshot
			if err := json.Unmarshal(env.ContentSnapshot, &snap); err != nil {
				res.OK = false
				res.RestoredVerify = "fail: decode ollama snapshot: " + err.Error()
			} else if err := ollama.VerifyComponents(snap, *restored); err != nil {
				res.OK = false
				res.RestoredVerify = "fail: " + err.Error()
			} else {
				res.RestoredVerify = "ok: every component blob digest matches envelope"
			}
		case ContentKindDir:
			var snap contentdir.Snapshot
			if err := json.Unmarshal(env.ContentSnapshot, &snap); err != nil {
				res.OK = false
				res.RestoredVerify = "fail: decode dir snapshot: " + err.Error()
			} else if err := verifyDirComponents(snap, *restored); err != nil {
				res.OK = false
				res.RestoredVerify = "fail: " + err.Error()
			} else {
				res.RestoredVerify = "ok: every file digest matches envelope"
			}
		}
		if !res.OK {
			emitGenome(stdout, *jsonOut, res)
			return 5
		}
	}
	emitGenome(stdout, *jsonOut, res)
	return 0
}

func verifyDirComponents(snap contentdir.Snapshot, restoredDir string) error {
	for _, c := range snap.Components {
		path := filepath.Join(restoredDir, filepath.FromSlash(c.Path))
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		got := "sha256:" + hex.EncodeToString(sha256Sum(data))
		if got != c.Digest {
			return fmt.Errorf("file %s: digest mismatch (envelope %s, on-disk %s)", c.Path, c.Digest, got)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// genome inspect
// ---------------------------------------------------------------------------

func genomeInspectCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("genome inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		bundlePath = fs.String("bundle", "", "Path to .genome bundle (required)")
		jsonOut    = fs.Bool("json", false, "Emit machine-readable JSON output")
	)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: acpctl genome inspect --bundle PATH [--json]")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *bundlePath == "" {
		fmt.Fprintln(stderr, "acpctl genome inspect: --bundle is required")
		fs.Usage()
		return 2
	}
	blob, err := os.ReadFile(*bundlePath)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl genome inspect: read: %v\n", err)
		return 1
	}
	env, sealed, err := decodeGenome(blob)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl genome inspect: %v\n", err)
		return 1
	}
	if *jsonOut {
		out := map[string]any{
			"format":                env.Format,
			"tee_provider":          env.TEEProvider,
			"sealed_at":             time.Unix(0, env.SealedAt).UTC().Format(time.RFC3339),
			"generation":            env.Generation,
			"parent_bundle_sha256":  env.ParentBundleSHA256,
			"parent_payload_sha256": env.ParentPayloadSHA256,
			"parent_generation":     env.ParentGeneration,
			"content_kind":          env.ContentKind,
			"content_ref":           env.ContentRef,
			"measurement":           hex.EncodeToString(env.Measurement),
			"payload_sha256":        env.payloadDigest(),
			"sealed_bytes":          len(sealed),
			"bundle_bytes":          len(blob),
			"content_snapshot":      json.RawMessage(env.ContentSnapshot),
		}
		_ = json.NewEncoder(stdout).Encode(out)
		return 0
	}
	fmt.Fprintf(stdout, "bundle:           %s\n", *bundlePath)
	fmt.Fprintf(stdout, "format:           %s\n", env.Format)
	fmt.Fprintf(stdout, "tee provider:     %s\n", env.TEEProvider)
	fmt.Fprintf(stdout, "sealed at (UTC):  %s\n", time.Unix(0, env.SealedAt).UTC().Format(time.RFC3339))
	fmt.Fprintf(stdout, "generation:       %d\n", env.Generation)
	if env.ParentBundleSHA256 != "" {
		fmt.Fprintf(stdout, "parent bundle:    sha256:%s (gen %d)\n", env.ParentBundleSHA256, env.ParentGeneration)
		fmt.Fprintf(stdout, "parent payload:   sha256:%s\n", env.ParentPayloadSHA256)
	} else {
		fmt.Fprintln(stdout, "parent bundle:    (none — genesis)")
	}
	fmt.Fprintf(stdout, "content kind:     %s\n", env.ContentKind)
	fmt.Fprintf(stdout, "content ref:      %s\n", env.ContentRef)
	fmt.Fprintf(stdout, "bundle bytes:     %d (%s)\n", len(blob), humanBytes(int64(len(blob))))
	fmt.Fprintf(stdout, "sealed bytes:     %d (%s)\n", len(sealed), humanBytes(int64(len(sealed))))
	fmt.Fprintf(stdout, "payload sha256:   %s\n", env.payloadDigest())
	fmt.Fprintf(stdout, "measurement:      %s\n", hex.EncodeToString(env.Measurement))
	fmt.Fprintf(stdout, "components (%d):\n", countComponents(env))
	listComponents(stdout, env)
	return 0
}

func listComponents(w io.Writer, env *GenomeEnvelope) {
	switch env.ContentKind {
	case ContentKindOllama:
		var snap ollama.Snapshot
		if err := json.Unmarshal(env.ContentSnapshot, &snap); err != nil {
			fmt.Fprintf(w, "  <decode error: %v>\n", err)
			return
		}
		for _, c := range snap.Components {
			fmt.Fprintf(w, "  [%s] %-50s %12d  %s\n", c.Role, c.Digest, c.Size, c.MediaType)
		}
	case ContentKindDir:
		var snap contentdir.Snapshot
		if err := json.Unmarshal(env.ContentSnapshot, &snap); err != nil {
			fmt.Fprintf(w, "  <decode error: %v>\n", err)
			return
		}
		for _, c := range snap.Components {
			fmt.Fprintf(w, "  %-44s %12d  %s\n", c.Path, c.Size, c.Digest)
		}
	}
}

func countComponents(env *GenomeEnvelope) int {
	switch env.ContentKind {
	case ContentKindOllama:
		var snap ollama.Snapshot
		if err := json.Unmarshal(env.ContentSnapshot, &snap); err != nil {
			return -1
		}
		return len(snap.Components)
	case ContentKindDir:
		var snap contentdir.Snapshot
		if err := json.Unmarshal(env.ContentSnapshot, &snap); err != nil {
			return -1
		}
		return len(snap.Components)
	}
	return 0
}

// ---------------------------------------------------------------------------
// genome chain
// ---------------------------------------------------------------------------

type chainNode struct {
	Path             string
	Generation       uint64
	BundleSHA256     string
	ParentSHA256     string
	ParentGeneration uint64
	ContentKind      string
	ContentRef       string
	BundleBytes      int64
	SealedAt         time.Time
}

func genomeChainCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("genome chain", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		dir     = fs.String("dir", ".", "Directory containing .genome bundles")
		jsonOut = fs.Bool("json", false, "Emit machine-readable JSON output")
	)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: acpctl genome chain --dir PATH [--json]")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Walk every .genome file in PATH, sort by generation, and validate that")
		fmt.Fprintln(stderr, "every parent reference resolves to an existing bundle in the directory.")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	entries, err := os.ReadDir(*dir)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl genome chain: read dir: %v\n", err)
		return 1
	}
	var nodes []chainNode
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".genome") {
			continue
		}
		path := filepath.Join(*dir, e.Name())
		blob, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(stderr, "acpctl genome chain: read %s: %v\n", path, err)
			return 1
		}
		env, _, err := decodeGenome(blob)
		if err != nil {
			fmt.Fprintf(stderr, "acpctl genome chain: decode %s: %v\n", path, err)
			return 1
		}
		nodes = append(nodes, chainNode{
			Path:             path,
			Generation:       env.Generation,
			BundleSHA256:     sha256Hex(blob),
			ParentSHA256:     env.ParentBundleSHA256,
			ParentGeneration: env.ParentGeneration,
			ContentKind:      string(env.ContentKind),
			ContentRef:       env.ContentRef,
			BundleBytes:      int64(len(blob)),
			SealedAt:         time.Unix(0, env.SealedAt).UTC(),
		})
	}
	if len(nodes) == 0 {
		fmt.Fprintf(stderr, "acpctl genome chain: no .genome files in %s\n", *dir)
		return 1
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Generation < nodes[j].Generation })

	// Validate the chain: every non-genesis node's ParentSHA256 must point at an in-set bundle.
	bySHA := make(map[string]*chainNode, len(nodes))
	for i := range nodes {
		bySHA[nodes[i].BundleSHA256] = &nodes[i]
	}
	var brokenLinks []string
	for _, n := range nodes {
		if n.Generation == 0 {
			continue
		}
		if n.ParentSHA256 == "" {
			brokenLinks = append(brokenLinks, fmt.Sprintf("%s (gen %d): missing parent_bundle_sha256", n.Path, n.Generation))
			continue
		}
		if _, ok := bySHA[n.ParentSHA256]; !ok {
			brokenLinks = append(brokenLinks, fmt.Sprintf("%s (gen %d): parent sha256:%s not found in dir", n.Path, n.Generation, n.ParentSHA256))
		}
	}

	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(map[string]any{
			"ok":           len(brokenLinks) == 0,
			"dir":          *dir,
			"node_count":   len(nodes),
			"chain":        nodes,
			"broken_links": brokenLinks,
		})
		if len(brokenLinks) > 0 {
			return 5
		}
		return 0
	}

	fmt.Fprintf(stdout, "chain @ %s — %d generation(s)\n\n", *dir, len(nodes))
	for _, n := range nodes {
		marker := "├──"
		if n.Generation == 0 {
			marker = "●  "
		}
		fmt.Fprintf(stdout, "%s gen %3d  %s  %s  %s\n",
			marker, n.Generation, humanBytes(n.BundleBytes),
			n.SealedAt.Format("15:04:05"), filepath.Base(n.Path))
		fmt.Fprintf(stdout, "          bundle    sha256:%s\n", n.BundleSHA256[:16]+"…")
		if n.Generation > 0 {
			fmt.Fprintf(stdout, "          parent →  sha256:%s\n", n.ParentSHA256[:16]+"…")
		}
		fmt.Fprintf(stdout, "          content   %s · %s\n\n", n.ContentKind, n.ContentRef)
	}
	if len(brokenLinks) > 0 {
		fmt.Fprintln(stdout, "✗ chain has broken links:")
		for _, b := range brokenLinks {
			fmt.Fprintf(stdout, "  %s\n", b)
		}
		return 5
	}
	fmt.Fprintln(stdout, "✓ chain valid — every parent reference resolves to an in-dir bundle")
	return 0
}

// ---------------------------------------------------------------------------
// genome lineage
// ---------------------------------------------------------------------------

func genomeLineageCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("genome lineage", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		bundlePath = fs.String("bundle", "", "Path to .genome bundle (required)")
		dir        = fs.String("dir", "", "Directory containing the chain's bundles (required)")
		jsonOut    = fs.Bool("json", false, "Emit machine-readable JSON output")
	)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: acpctl genome lineage --bundle PATH --dir PATH [--json]")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Walk parent references back to the genesis bundle, printing every ancestor.")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *bundlePath == "" || *dir == "" {
		fmt.Fprintln(stderr, "acpctl genome lineage: --bundle and --dir are required")
		fs.Usage()
		return 2
	}

	// Index the directory by bundle SHA-256.
	entries, err := os.ReadDir(*dir)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl genome lineage: read dir: %v\n", err)
		return 1
	}
	bySHA := make(map[string]string)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".genome") {
			continue
		}
		p := filepath.Join(*dir, e.Name())
		blob, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		bySHA[sha256Hex(blob)] = p
	}

	// Walk parents from the starting bundle.
	current := *bundlePath
	var ancestors []chainNode
	for {
		blob, err := os.ReadFile(current)
		if err != nil {
			fmt.Fprintf(stderr, "acpctl genome lineage: read %s: %v\n", current, err)
			return 1
		}
		env, _, err := decodeGenome(blob)
		if err != nil {
			fmt.Fprintf(stderr, "acpctl genome lineage: decode %s: %v\n", current, err)
			return 1
		}
		ancestors = append(ancestors, chainNode{
			Path:             current,
			Generation:       env.Generation,
			BundleSHA256:     sha256Hex(blob),
			ParentSHA256:     env.ParentBundleSHA256,
			ParentGeneration: env.ParentGeneration,
			ContentKind:      string(env.ContentKind),
			ContentRef:       env.ContentRef,
			BundleBytes:      int64(len(blob)),
			SealedAt:         time.Unix(0, env.SealedAt).UTC(),
		})
		if env.Generation == 0 {
			break
		}
		next, ok := bySHA[env.ParentBundleSHA256]
		if !ok {
			fmt.Fprintf(stderr, "acpctl genome lineage: parent sha256:%s not found in %s\n", env.ParentBundleSHA256, *dir)
			return 1
		}
		current = next
	}

	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(map[string]any{
			"ok":        true,
			"bundle":    *bundlePath,
			"depth":     len(ancestors),
			"ancestors": ancestors,
		})
		return 0
	}
	fmt.Fprintf(stdout, "lineage of %s — depth %d\n\n", filepath.Base(*bundlePath), len(ancestors))
	for i, a := range ancestors {
		arrow := "├──"
		if i == len(ancestors)-1 {
			arrow = "●  "
		}
		fmt.Fprintf(stdout, "%s gen %3d  %s  %s  %s\n",
			arrow, a.Generation, humanBytes(a.BundleBytes),
			a.SealedAt.Format("15:04:05"), filepath.Base(a.Path))
	}
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "✓ lineage complete — every parent reference resolved to an existing bundle")
	return 0
}

// ---------------------------------------------------------------------------
// envelope encode / decode
// ---------------------------------------------------------------------------

func encodeGenome(env GenomeEnvelope, sealed []byte) ([]byte, error) {
	meta, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("encode metadata: %w", err)
	}
	if len(meta) > 4<<20 { // 4 MiB cap for envelope JSON
		return nil, fmt.Errorf("metadata > 4 MiB (%d bytes)", len(meta))
	}
	var buf bytes.Buffer
	buf.WriteString(genomeMagic)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(meta)))
	buf.Write(lenBuf[:])
	buf.Write(meta)
	buf.Write(sealed)
	return buf.Bytes(), nil
}

func decodeGenome(blob []byte) (*GenomeEnvelope, []byte, error) {
	if len(blob) < len(genomeMagic)+4 {
		return nil, nil, errors.New("decode: blob too short")
	}
	if string(blob[:len(genomeMagic)]) != genomeMagic {
		return nil, nil, errors.New("decode: magic mismatch (not a Vault Genome bundle)")
	}
	off := len(genomeMagic)
	metaLen := binary.BigEndian.Uint32(blob[off : off+4])
	off += 4
	if uint32(len(blob)-off) < metaLen {
		return nil, nil, errors.New("decode: truncated metadata")
	}
	var env GenomeEnvelope
	if err := json.Unmarshal(blob[off:off+int(metaLen)], &env); err != nil {
		return nil, nil, fmt.Errorf("decode: metadata json: %w", err)
	}
	if env.Format != envelopeFormatV2 {
		return nil, nil, fmt.Errorf("decode: unsupported format %q (this build expects %s)", env.Format, envelopeFormatV2)
	}
	return &env, blob[off+int(metaLen):], nil
}

// payloadDigest extracts the payload SHA-256 from the embedded snapshot.
// Both snapshot kinds expose a PayloadSHA256 field at the top level.
func (e *GenomeEnvelope) payloadDigest() string {
	var probe struct {
		PayloadSHA256 string `json:"payload_sha256"`
	}
	_ = json.Unmarshal(e.ContentSnapshot, &probe)
	return probe.PayloadSHA256
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func defaultOllamaHome() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/root/.ollama"
	}
	return filepath.Join(home, ".ollama")
}

// workloadDescriptorV2 binds the TEE measurement to the (kind + ref +
// payload digest + generation). Two seals of identical inputs at the
// same generation produce identical measurements; a different generation
// or a different content ref yields a different measurement, which is
// the property we want for chain integrity.
func workloadDescriptorV2(kind ContentKind, ref, payloadDigest string, generation uint64) []byte {
	h := sha256.New()
	h.Write([]byte("vault-genome.v2\n"))
	h.Write([]byte(string(kind) + "\n"))
	h.Write([]byte(ref + "\n"))
	h.Write([]byte(payloadDigest + "\n"))
	var genBuf [8]byte
	binary.BigEndian.PutUint64(genBuf[:], generation)
	h.Write(genBuf[:])
	return h.Sum(nil)
}

func sha256Sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// ---------------------------------------------------------------------------
// result types — separate from envelope so JSON output stays stable as the
// envelope evolves.
// ---------------------------------------------------------------------------

type sealResult struct {
	OK                 bool   `json:"ok"`
	Output             string `json:"output"`
	ContentKind        string `json:"content_kind"`
	ContentRef         string `json:"content_ref"`
	Generation         uint64 `json:"generation"`
	ParentBundle       string `json:"parent_bundle,omitempty"`
	ParentBundleSHA256 string `json:"parent_bundle_sha256,omitempty"`
	PayloadBytes       int    `json:"payload_bytes"`
	SealedBytes        int    `json:"sealed_bytes"`
	BundleBytes        int    `json:"bundle_bytes"`
	PayloadSHA256      string `json:"payload_sha256"`
	MeasurementHex     string `json:"measurement"`
	ComponentCount     int    `json:"component_count"`
	SealedAt           string `json:"sealed_at"`
}

type openResult struct {
	OK             bool   `json:"ok"`
	Bundle         string `json:"bundle"`
	Target         string `json:"target"`
	ContentKind    string `json:"content_kind"`
	ContentRef     string `json:"content_ref"`
	Generation     uint64 `json:"generation"`
	BytesWritten   int64  `json:"bytes_written"`
	PayloadSHA256  string `json:"payload_sha256"`
	MeasurementHex string `json:"measurement"`
}

type verifyResult struct {
	OK             bool   `json:"ok"`
	Bundle         string `json:"bundle"`
	ContentKind    string `json:"content_kind"`
	ContentRef     string `json:"content_ref"`
	Generation     uint64 `json:"generation"`
	EnvelopeFormat string `json:"envelope_format"`
	ComponentCount int    `json:"component_count"`
	SealedBytes    int    `json:"sealed_bytes"`
	PayloadSHA256  string `json:"payload_sha256"`
	MeasurementHex string `json:"measurement"`
	SealedAt       string `json:"sealed_at"`
	RestoredVerify string `json:"restored_verify,omitempty"`
}

func emitGenome(w io.Writer, asJSON bool, v any) {
	if asJSON {
		_ = json.NewEncoder(w).Encode(v)
		return
	}
	switch r := v.(type) {
	case sealResult:
		fmt.Fprintf(w, "✓ sealed %s %q  (gen %d)\n", r.ContentKind, r.ContentRef, r.Generation)
		fmt.Fprintf(w, "  output:        %s\n", r.Output)
		if r.ParentBundle != "" {
			fmt.Fprintf(w, "  parent:        %s (sha256:%s…)\n", r.ParentBundle, r.ParentBundleSHA256[:16])
		}
		fmt.Fprintf(w, "  components:    %d\n", r.ComponentCount)
		fmt.Fprintf(w, "  bundle bytes:  %d (%s)\n", r.BundleBytes, humanBytes(int64(r.BundleBytes)))
		fmt.Fprintf(w, "  payload sha256:%s\n", r.PayloadSHA256)
		fmt.Fprintf(w, "  measurement:   %s\n", r.MeasurementHex)
		fmt.Fprintf(w, "  sealed at UTC: %s\n", r.SealedAt)
	case openResult:
		fmt.Fprintf(w, "✓ unsealed %s %q  (gen %d)\n", r.ContentKind, r.ContentRef, r.Generation)
		fmt.Fprintf(w, "  bundle:        %s\n", r.Bundle)
		fmt.Fprintf(w, "  target:        %s\n", r.Target)
		fmt.Fprintf(w, "  bytes written: %d (%s)\n", r.BytesWritten, humanBytes(r.BytesWritten))
		fmt.Fprintf(w, "  payload sha256:%s\n", r.PayloadSHA256)
		fmt.Fprintf(w, "  measurement:   %s\n", r.MeasurementHex)
	case verifyResult:
		marker := "✓"
		if !r.OK {
			marker = "✗"
		}
		fmt.Fprintf(w, "%s envelope %s · %s %q  (gen %d)\n", marker, r.EnvelopeFormat, r.ContentKind, r.ContentRef, r.Generation)
		fmt.Fprintf(w, "  bundle:        %s\n", r.Bundle)
		fmt.Fprintf(w, "  components:    %d\n", r.ComponentCount)
		fmt.Fprintf(w, "  sealed bytes:  %d (%s)\n", r.SealedBytes, humanBytes(int64(r.SealedBytes)))
		fmt.Fprintf(w, "  payload sha256:%s\n", r.PayloadSHA256)
		fmt.Fprintf(w, "  measurement:   %s\n", r.MeasurementHex)
		fmt.Fprintf(w, "  sealed at UTC: %s\n", r.SealedAt)
		if r.RestoredVerify != "" {
			fmt.Fprintf(w, "  restored:      %s\n", r.RestoredVerify)
		}
	}
}
