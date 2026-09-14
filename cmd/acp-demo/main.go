// SPDX-License-Identifier: AGPL-3.0-or-later

// Command acp-demo runs the cross-hardware AI-regeneration flagship end to end,
// in simulation mode (no TEE hardware required), so anyone can see it work with
// one command:
//
//	go run ./cmd/acp-demo          # or: docker run vaultgenome demo
//
// It uses the real platform code — the simulated TEE Sealer, the canonical
// deterministic/integer kernels, the numerical equivalence gate, and the
// determinism-ladder reconstruction — to show:
//
//	① an AI genome sealed at the origin,
//	② byte-exact integrity on receipt (tamper is caught here),
//	③ regeneration on a "pinned" runtime → EXACT, with an Ed25519-signed verdict,
//	④ regeneration after simulated cross-hardware float drift → the ladder falls
//	   through to the byte-portable integer path → EQUIVALENT (the model still
//	   comes up), and
//	⑤ a corrupted genome → no door opens → reconstitution is blocked (fail-closed).
//
// What is real here: attested byte-exact continuity and the cross-hardware
// equivalence gate. What is NOT claimed: rebuilding a real model from a compact
// "generative" recipe — that backend is still a placeholder (see README/STATUS).
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"flag"
	"fmt"
	"math"
	"math/rand"
	"os"

	"github.com/ai-continuity-platform/core/internal/canonical"
	"github.com/ai-continuity-platform/core/internal/shared/crypto"
	"github.com/ai-continuity-platform/core/internal/shared/tee"
	"github.com/ai-continuity-platform/core/internal/validation/equivalence"
	"github.com/ai-continuity-platform/core/internal/validation/reconstruction"
)

const dim, seqLen = 16, 8

// Genome is the sealed asset: the model weights, the reference inputs, and the
// sealed reference outputs (the fixtures the destination must reproduce).
type Genome struct {
	Params   canonical.Params
	Inputs   map[string][]float64
	Fixtures []equivalence.Fixture
}

func f64Tensor(shape []int, vals []float64) equivalence.Tensor {
	raw := make([]byte, len(vals)*8)
	for i, v := range vals {
		binary.LittleEndian.PutUint64(raw[i*8:], math.Float64bits(v))
	}
	return equivalence.Tensor{DType: equivalence.F64, Shape: shape, Raw: raw}
}

func buildGenome(seed int64, nFixtures int) Genome {
	r := rand.New(rand.NewSource(seed))
	rv := func(n int) []float64 {
		out := make([]float64, n)
		for i := range out {
			out[i] = r.NormFloat64()
		}
		return out
	}
	p := canonical.Params{
		D: dim, Wq: rv(dim * dim), Wk: rv(dim * dim), Wv: rv(dim * dim), Wo: rv(dim * dim),
		W1: rv(dim * 4 * dim), W2: rv(4 * dim * dim), G: rv(dim), B: rv(dim), Eps: 1e-5,
	}
	g := Genome{Params: p, Inputs: map[string][]float64{}}
	for i := 0; i < nFixtures; i++ {
		id := string(rune('a' + i))
		rr := rand.New(rand.NewSource(seed*100 + int64(i)))
		x := make([]float64, seqLen*dim)
		for j := range x {
			x[j] = rr.NormFloat64()
		}
		g.Inputs[id] = x
		g.Fixtures = append(g.Fixtures, equivalence.Fixture{
			ID: id, Expected: f64Tensor([]int{seqLen, dim}, p.TransformerBlock(x, seqLen)), Critical: i == 0,
		})
	}
	return g
}

func encodeGenome(g Genome) []byte {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(g); err != nil {
		fatal("encode genome: %v", err)
	}
	return buf.Bytes()
}

func decodeGenome(b []byte) Genome {
	var g Genome
	if err := gob.NewDecoder(bytes.NewReader(b)).Decode(&g); err != nil {
		fatal("decode genome: %v", err)
	}
	return g
}

// pinnedDoor is the top rung: byte-exact replay on a pinned runtime. drift
// simulates a different hardware/BLAS build perturbing the float result by one
// ULP, which fails the tol-0 gate and makes the descent fall through.
func pinnedDoor(g Genome, drift bool) reconstruction.Strategy {
	return reconstruction.PinnedReplayDoor("pinned-f64-replay", func(id string) (equivalence.Tensor, error) {
		out := g.Params.TransformerBlock(g.Inputs[id], seqLen)
		if drift {
			out[0] = math.Nextafter(out[0], math.Inf(1))
		}
		return f64Tensor([]int{seqLen, dim}, out), nil
	})
}

// integerDoor is the byte-portable rung: the same block in integer arithmetic,
// identical on any CPU or GPU by construction.
func integerDoor(g Genome) reconstruction.Strategy {
	fp := canonical.QuantizeParams(g.Params)
	return reconstruction.Strategy{
		Rung: 3, Kind: reconstruction.KindFixedPoint, Name: "integer-portable",
		Tol: equivalence.Tolerance{Atol: 0.05, Rtol: 0.05}, Pol: equivalence.StrictPolicy(),
		Recompute: func(id string) (equivalence.Tensor, error) {
			o := canonical.DequantizeVec(fp.TransformerBlockQ(canonical.QuantizeVec(g.Inputs[id]), seqLen))
			return f64Tensor([]int{seqLen, dim}, o), nil
		},
	}
}

func main() {
	modelPath := flag.String("model", "", "optional path to a file to seal byte-exact as the genome asset")
	flag.Parse()

	fmt.Print(banner)

	seed := sha256.Sum256([]byte("vaultgenome-demo-workload"))
	origin, err := tee.NewSimulated([]byte("vaultgenome-origin"), seed[:])
	if err != nil {
		fatal("init origin TEE: %v", err)
	}

	// ① ORIGIN — build + seal the genome.
	g := buildGenome(1, 4)
	raw := encodeGenome(g)
	addr := sha256.Sum256(raw)
	sealed, err := origin.Seal(raw, addr[:])
	if err != nil {
		fatal("seal: %v", err)
	}
	section("① ORIGIN NODE — sealing the AI genome")
	info("model: sample transformer (d=%d, seq=%d), %d sealed reference fixtures", dim, seqLen, len(g.Fixtures))
	info("genome content-address: %x…", addr[:10])
	info("sealed under simulated TEE, measurement %x…", []byte(origin.Measurement())[:10])

	// ② DESTINATION — integrity on receipt (the backup layer).
	section("② DESTINATION NODE — receiving on different hardware")
	dest, _ := tee.NewSimulated([]byte("vaultgenome-origin"), seed[:]) // same code → same measurement
	got, err := dest.Unseal(sealed, addr[:])
	if err != nil || sha256.Sum256(got) != addr {
		fatal("integrity check failed — genome rejected")
	}
	ok("integrity layer: unsealed bytes hash to the sealed address (a tampered genome is rejected here)")
	rg := decodeGenome(got)

	pub, priv, _ := crypto.GenerateEd25519(nil)

	// ③ Same-hardware regeneration → EXACT.
	section("③ REGENERATION — determinism ladder + attested equivalence gate")
	res, _ := reconstruction.Regenerate("genome-demo", rg.Fixtures,
		[]reconstruction.Strategy{pinnedDoor(rg, false), integerDoor(rg)})
	report(res, pub, priv)

	// ④ Cross-hardware float drift → fall through to the portable integer door.
	section("④ CROSS-HARDWARE — a different BLAS/GPU perturbs the float path")
	res2, _ := reconstruction.Regenerate("genome-demo", rg.Fixtures,
		[]reconstruction.Strategy{pinnedDoor(rg, true), integerDoor(rg)})
	report(res2, pub, priv)

	// ⑤ Corrupted genome → no door opens → blocked.
	section("⑤ SAFETY — a corrupted genome is blocked (fail-closed)")
	corrupt := buildGenome(999, 4) // different weights, genuine fixtures below
	res3, _ := reconstruction.Regenerate("genome-demo", rg.Fixtures,
		[]reconstruction.Strategy{
			pinnedDoor(Genome{Params: corrupt.Params, Inputs: rg.Inputs}, false),
			integerDoor(Genome{Params: corrupt.Params, Inputs: rg.Inputs}),
		})
	report(res3, pub, priv)

	if *modelPath != "" {
		sealRealFile(origin, dest, *modelPath)
	}

	fmt.Print(footer)
}

func report(res reconstruction.LadderResult, pub crypto.PublicKey, priv crypto.PrivateKey) {
	if res.Opened {
		sv, _ := equivalence.Sign(res.Verdict, pub, priv)
		verified := equivalence.VerifySigned(sv) == nil
		ok("door opened: %q (rung %d, kind=%s) → verdict %s", res.Name, res.Rung, res.Kind, res.Verdict.Level)
		info("Ed25519-signed verdict %x… (signature verifies: %v)", sv.Signature[:10], verified)
		info("reconstitution decision: %s — model goes live", reconstruction.Reason(res.Verdict))
		return
	}
	warn("NO door reproduced the sealed reference")
	for _, a := range res.Attempts {
		info("  · door %q (rung %d): %s", a.Name, a.Rung, a.Level)
	}
	warn("reconstitution decision: %s — model is NOT brought up (fail-closed)", reconstruction.Reason(res.Verdict))
}

func sealRealFile(origin, dest *tee.Simulated, path string) {
	section("＋ YOUR FILE — byte-exact sealed continuity")
	data, err := os.ReadFile(path)
	if err != nil {
		warn("could not read %s: %v", path, err)
		return
	}
	addr := sha256.Sum256(data)
	sealed, err := origin.Seal(data, addr[:])
	if err != nil {
		warn("seal failed: %v", err)
		return
	}
	got, err := dest.Unseal(sealed, addr[:])
	if err != nil || sha256.Sum256(got) != addr || !bytes.Equal(got, data) {
		warn("restore mismatch — file NOT byte-exact")
		return
	}
	ok("%s (%d bytes) sealed and restored BYTE-EXACT; address %x…", path, len(data), addr[:10])
	info("note: the equivalence gate needs reference input→output fixtures from YOUR model's")
	info("inference to certify a live recompute; byte-exact restore above needs no fixtures.")
}

// ---- terminal presentation -------------------------------------------------

const banner = `
┌──────────────────────────────────────────────────────────────────────┐
│  VaultGenome · AI Continuity Platform — cross-hardware regeneration    │
│  demonstration (simulation mode, no TEE hardware required)             │
└──────────────────────────────────────────────────────────────────────┘
`

const footer = `
────────────────────────────────────────────────────────────────────────
Done. This ran the real platform code: simulated TEE seal/unseal, the
canonical kernels, the equivalence gate, and the determinism ladder.
For REAL SEV-SNP attestation, run the daemon inside a confidential VM
(see docs). Byte-exact continuity + the cross-hardware gate are real;
generative rebuild from a compact recipe is a labelled placeholder.
────────────────────────────────────────────────────────────────────────
`

func section(s string)        { fmt.Printf("\n\033[1;36m%s\033[0m\n", s) }
func ok(f string, a ...any)   { fmt.Printf("  \033[32m✓\033[0m "+f+"\n", a...) }
func info(f string, a ...any) { fmt.Printf("    "+f+"\n", a...) }
func warn(f string, a ...any) { fmt.Printf("  \033[33m▲\033[0m "+f+"\n", a...) }
func fatal(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "\033[31mfatal:\033[0m "+f+"\n", a...)
	os.Exit(1)
}
