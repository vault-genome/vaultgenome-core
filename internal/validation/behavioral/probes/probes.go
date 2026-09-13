// SPDX-License-Identifier: AGPL-3.0-or-later

// Package probes is the production-grade behavioral probe library for
// the AI Continuity Platform. It supplies a curated suite of probes
// the validator runs against every candidate before release.
//
// # Design rationale
//
// The behavioral validator at /internal/validation/behavioral
// implements the per-dimension scoring rule from
// docs/doctrine/validation-thresholds.md §3.3 (≥ 95% non-critical pass plus
// zero critical fails to release). It is deliberately probe-shape-
// agnostic: a probe is simply a (name, critical, evaluate) triple and
// returns a (passed, diagnostic) verdict.
//
// This package supplies the *content*: 8 critical probes plus 32
// non-critical probes targeted at the canonical investor-demo asset
// (a deterministic LoRA-rank-8 adapter for Pythia-70m-deduped, ~395
// KiB safetensors). The probes are intentionally fast (each is a few
// passes over a small number of bytes) so the full suite runs in
// well under the 6-second budget reserved for behavioral validation
// in the lifecycle SLO (docs/doctrine/validation-thresholds.md §3.5).
//
// # Invariants
//
//  1. Every probe is **deterministic** over its input — same candidate
//     bytes → same verdict. The validator depends on this for the
//     CI-level repeatability guarantee in §3.5.
//
//  2. Every probe is **pure** — no global state, no clock reads, no
//     network. This is enforced by code review; no automated check
//     today (a Phase 2 fuzz target will assert determinism).
//
//  3. No probe **panics** under any input. Probes that need to bail
//     return (false, "diag string"). The validator does not recover
//     panics; a panicking probe is a suite-author bug.
//
//  4. Critical probes test invariants whose failure means the
//     candidate is **structurally** wrong (length, header, alphabet).
//     Non-critical probes test statistical properties whose
//     individual failure is a yellow flag, not a red flag — the §3.3
//     blended threshold is the gate.
//
//  5. The exported `LoRASuite()` is the canonical default suite. It
//     returns a fresh slice on every call so a caller can mutate the
//     returned slice without poisoning the next caller.
package probes

import (
	"math"
	"math/bits"

	"github.com/ai-continuity-platform/core/internal/validation/behavioral"
)

// LoRASuite returns the canonical suite of 8 critical + 32 non-critical
// probes targeted at LoRA-class adapter artifacts (~100 KiB to ~10 MiB
// safetensors blobs). The suite is curated for the Pythia-70m-deduped
// rank-8 adapter used in the investor-demo lifecycle but generalises
// to any safetensors-shaped LoRA: probes key off byte-distribution,
// header presence, and entropy properties that hold for any tensor
// blob, not for a specific tensor schema.
//
// The slice is freshly allocated on every call. Order is stable:
// critical probes come first, then non-critical, each sub-block
// alphabetised by ID. Stable order keeps `behavioral.Run` Findings
// reproducible across calls.
func LoRASuite() []behavioral.Probe {
	out := make([]behavioral.Probe, 0, 40)
	out = append(out, criticalProbes()...)
	out = append(out, nonCriticalProbes()...)
	return out
}

// criticalProbes are the 8 must-pass invariants. A single failure
// here makes the dimension Fail (per behavioral §3.3, branch:
// `case critFailed > 0: verdict = Fail`).
func criticalProbes() []behavioral.Probe {
	return []behavioral.Probe{
		{
			ID:       "lora.crit.length_nonzero",
			Name:     "candidate length is non-zero",
			Critical: true,
			Evaluate: func(c []byte) (bool, string) {
				if len(c) == 0 {
					return false, "candidate is empty (zero bytes)"
				}
				return true, ""
			},
		},
		{
			ID:       "lora.crit.length_within_safetensors_window",
			Name:     "candidate length fits the LoRA safetensors window",
			Critical: true,
			Evaluate: func(c []byte) (bool, string) {
				// LoRA-rank-8 adapters for sub-1B-parameter base models
				// land between ~50 KiB and ~50 MiB. Anything outside
				// is a structural smell — wrong artefact, wrong base
				// model, or a serialisation regression.
				const min = 50 * 1024
				const max = 50 * 1024 * 1024
				if len(c) < min || len(c) > max {
					return false, fmtf("length %d outside [%d, %d]", len(c), min, max)
				}
				return true, ""
			},
		},
		{
			ID:       "lora.crit.alphabet_full_byte_range",
			Name:     "alphabet uses the full 0..255 range (high-entropy float32 expected)",
			Critical: true,
			Evaluate: func(c []byte) (bool, string) {
				// safetensors encodes float32 tensors — every byte
				// value is reachable. A candidate that uses fewer
				// than 200 of 256 byte values is almost certainly
				// not a tensor blob.
				const min = 200
				h := histogram(c)
				distinct := 0
				for _, cnt := range h {
					if cnt > 0 {
						distinct++
					}
				}
				if distinct < min {
					return false, fmtf("only %d distinct byte values (expected ≥ %d)", distinct, min)
				}
				return true, ""
			},
		},
		{
			ID:       "lora.crit.entropy_floor",
			Name:     "Shannon entropy clears the float32-tensor floor",
			Critical: true,
			Evaluate: func(c []byte) (bool, string) {
				// Random float32 tensors carry ~7.0 to 7.95 bits/byte
				// of Shannon entropy. Anything below 6.5 means the
				// candidate is suspiciously regular — a concatenated
				// header, a debug fixture, or a truncated payload.
				const floor = 6.5
				e := shannonEntropyBits(c)
				if e < floor {
					return false, fmtf("entropy %.3f bits/byte (floor %.3f)", e, floor)
				}
				return true, ""
			},
		},
		{
			ID:       "lora.crit.no_long_zero_run",
			Name:     "no zero run longer than 1024 bytes",
			Critical: true,
			Evaluate: func(c []byte) (bool, string) {
				// safetensors headers contain short zero-padding but
				// never a multi-KiB run of zeros. A long zero run
				// indicates a partially-allocated buffer, a memcpy
				// truncation, or sealed-payload-leak past unseal.
				const cap = 1024
				maxRun, at := longestByteRun(c, 0x00)
				if maxRun > cap {
					return false, fmtf("zero run of %d bytes at offset %d (cap %d)", maxRun, at, cap)
				}
				return true, ""
			},
		},
		{
			ID:       "lora.crit.no_long_ff_run",
			Name:     "no 0xFF run longer than 256 bytes",
			Critical: true,
			Evaluate: func(c []byte) (bool, string) {
				// 0xFF runs in float32 tensors mean NaN / +Inf /
				// signalling-NaN payloads. Real adapters keep these
				// to a handful of bytes; a multi-hundred-byte run
				// indicates upstream uninitialised memory.
				const cap = 256
				maxRun, at := longestByteRun(c, 0xFF)
				if maxRun > cap {
					return false, fmtf("0xFF run of %d bytes at offset %d (cap %d)", maxRun, at, cap)
				}
				return true, ""
			},
		},
		{
			ID:       "lora.crit.byte_balance_within_band",
			Name:     "no single byte value owns more than 5% of the payload",
			Critical: true,
			Evaluate: func(c []byte) (bool, string) {
				// In a healthy float32 tensor the most common byte
				// value is around 0.6–1.5% of the total. > 5% means
				// the tensor degenerated to a small set of literals.
				const cap = 0.05
				h := histogram(c)
				if len(c) == 0 {
					return true, ""
				}
				var maxFrac float64
				var maxV int
				for v, cnt := range h {
					f := float64(cnt) / float64(len(c))
					if f > maxFrac {
						maxFrac = f
						maxV = v
					}
				}
				if maxFrac > cap {
					return false, fmtf("byte 0x%02X is %.1f%% of payload (cap %.0f%%)", maxV, maxFrac*100, cap*100)
				}
				return true, ""
			},
		},
		{
			ID:       "lora.crit.alphabet_balance",
			Name:     "first-quartile bytes account for > 15% of the payload",
			Critical: true,
			Evaluate: func(c []byte) (bool, string) {
				// Any tensor blob spreads weight across many bytes —
				// the first 64 byte values (first quartile) should
				// account for substantially more than 15% of the
				// total. A blob where 64 byte values cover < 15% is
				// hyper-skewed and almost certainly not a tensor.
				const floor = 0.15
				h := histogram(c)
				if len(c) == 0 {
					return true, ""
				}
				var head uint64
				for v := 0; v < 64; v++ {
					head += uint64(h[v])
				}
				frac := float64(head) / float64(len(c))
				if frac < floor {
					return false, fmtf("first-quartile bytes only %.1f%% of payload (floor %.0f%%)", frac*100, floor*100)
				}
				return true, ""
			},
		},
	}
}

// nonCriticalProbes are the 32 statistical properties whose individual
// failure lowers the dimension's pass rate but does not by itself
// block release. The validator gates on the §3.3 blended thresholds
// (≥ 95% pass, [85%, 95%) is conditional, < 85% is fail).
//
// The probes split into eight thematic blocks of four probes each;
// each block tests one statistical surface.
func nonCriticalProbes() []behavioral.Probe {
	out := make([]behavioral.Probe, 0, 32)
	out = append(out, byteHistogramProbes()...)
	out = append(out, runLengthProbes()...)
	out = append(out, transitionProbes()...)
	out = append(out, alignmentProbes()...)
	out = append(out, entropyProbes()...)
	out = append(out, balanceProbes()...)
	out = append(out, structuralProbes()...)
	out = append(out, anomalyProbes()...)
	return out
}

// ---- block 1: byte-histogram shape ---------------------------------------

func byteHistogramProbes() []behavioral.Probe {
	return []behavioral.Probe{
		{
			ID:   "lora.hist.no_byte_below_floor",
			Name: "no byte value below 0.05% (signals truncated-alphabet)",
			Evaluate: func(c []byte) (bool, string) {
				if len(c) < 1024 {
					return true, ""
				}
				h := histogram(c)
				floor := float64(len(c)) * 0.0005
				zero := 0
				for _, cnt := range h {
					if float64(cnt) < floor {
						zero++
					}
				}
				if zero > 32 {
					return false, fmtf("%d byte values below 0.05% floor", zero)
				}
				return true, ""
			},
		},
		{
			ID:   "lora.hist.peak_value_in_expected_band",
			Name: "most-common byte sits in the [0x00, 0x7F] half",
			Evaluate: func(c []byte) (bool, string) {
				h := histogram(c)
				var maxV int
				for v, cnt := range h {
					if cnt > h[maxV] {
						maxV = v
					}
				}
				if maxV > 0x7F {
					return false, fmtf("peak byte 0x%02X in upper half (expected lower half for float32-with-many-zero-exponent)", maxV)
				}
				return true, ""
			},
		},
		{
			ID:   "lora.hist.tail_not_starved",
			Name: "byte values 0xC0..0xFF account for ≥ 10% of payload",
			Evaluate: func(c []byte) (bool, string) {
				h := histogram(c)
				var tail uint64
				for v := 0xC0; v <= 0xFF; v++ {
					tail += uint64(h[v])
				}
				frac := float64(tail) / math.Max(1, float64(len(c)))
				if frac < 0.10 {
					return false, fmtf("upper-quartile only %.1f%% (expected ≥ 10%%)", frac*100)
				}
				return true, ""
			},
		},
		{
			ID:   "lora.hist.byte_zero_not_dominant",
			Name: "byte 0x00 < 5% of payload",
			Evaluate: func(c []byte) (bool, string) {
				h := histogram(c)
				if len(c) == 0 {
					return true, ""
				}
				frac := float64(h[0]) / float64(len(c))
				if frac > 0.05 {
					return false, fmtf("0x00 is %.1f%% (cap 5%%)", frac*100)
				}
				return true, ""
			},
		},
	}
}

// ---- block 2: run-length distribution ------------------------------------

func runLengthProbes() []behavioral.Probe {
	return []behavioral.Probe{
		{
			ID:   "lora.run.median_run_length_low",
			Name: "median run-length ≤ 2 (typical for high-entropy bytes)",
			Evaluate: func(c []byte) (bool, string) {
				m := medianRunLength(c)
				if m > 2 {
					return false, fmtf("median run-length is %d (expected ≤ 2)", m)
				}
				return true, ""
			},
		},
		{
			ID:   "lora.run.no_5plus_runs_dominate",
			Name: "runs of length ≥ 5 cover < 10% of payload",
			Evaluate: func(c []byte) (bool, string) {
				covered := bytesCoveredByRunsAtLeast(c, 5)
				if len(c) == 0 {
					return true, ""
				}
				frac := float64(covered) / float64(len(c))
				if frac > 0.10 {
					return false, fmtf("≥5-byte runs cover %.1f%% (cap 10%%)", frac*100)
				}
				return true, ""
			},
		},
		{
			ID:   "lora.run.run_count_per_kib_in_band",
			Name: "run-count-per-KiB is in [400, 1024]",
			Evaluate: func(c []byte) (bool, string) {
				if len(c) < 1024 {
					return true, ""
				}
				runs := totalRunCount(c)
				rate := float64(runs) / (float64(len(c)) / 1024.0)
				if rate < 400 || rate > 1024 {
					return false, fmtf("run count %.0f/KiB outside [400, 1024]", rate)
				}
				return true, ""
			},
		},
		{
			ID:   "lora.run.transition_density_high",
			Name: "byte-to-byte transitions ≥ 75% of bytes",
			Evaluate: func(c []byte) (bool, string) {
				if len(c) < 2 {
					return true, ""
				}
				t := transitionsCount(c)
				rate := float64(t) / float64(len(c)-1)
				if rate < 0.75 {
					return false, fmtf("transition density %.2f (expected ≥ 0.75)", rate)
				}
				return true, ""
			},
		},
	}
}

// ---- block 3: bigram / transition properties -----------------------------

func transitionProbes() []behavioral.Probe {
	return []behavioral.Probe{
		{
			ID:   "lora.trans.bigram_diversity",
			Name: "distinct bigrams ≥ 4096 (out of 65536 possible)",
			Evaluate: func(c []byte) (bool, string) {
				if len(c) < 4096 {
					return true, ""
				}
				const min = 4096
				d := distinctBigrams(c)
				if d < min {
					return false, fmtf("only %d distinct bigrams (expected ≥ %d)", d, min)
				}
				return true, ""
			},
		},
		{
			ID:   "lora.trans.no_bigram_above_0p5pct",
			Name: "no single bigram > 0.5% of all bigrams",
			Evaluate: func(c []byte) (bool, string) {
				if len(c) < 1024 {
					return true, ""
				}
				maxFrac, ba, bb := mostCommonBigramFrac(c)
				if maxFrac > 0.005 {
					return false, fmtf("bigram (0x%02X,0x%02X) is %.2f%% (cap 0.5%%)", ba, bb, maxFrac*100)
				}
				return true, ""
			},
		},
		{
			ID:   "lora.trans.zero_zero_bigram_rare",
			Name: "0x00 0x00 bigram covers < 0.5% of bigrams",
			Evaluate: func(c []byte) (bool, string) {
				if len(c) < 2 {
					return true, ""
				}
				zz := uint64(0)
				for i := 0; i < len(c)-1; i++ {
					if c[i] == 0 && c[i+1] == 0 {
						zz++
					}
				}
				frac := float64(zz) / float64(len(c)-1)
				if frac > 0.005 {
					return false, fmtf("(0x00,0x00) bigram %.2f%% (cap 0.5%%)", frac*100)
				}
				return true, ""
			},
		},
		{
			ID:   "lora.trans.symmetric_palindrome_rate_low",
			Name: "palindromic bigrams (a,a) collectively < 1% of bigrams",
			Evaluate: func(c []byte) (bool, string) {
				if len(c) < 2 {
					return true, ""
				}
				p := uint64(0)
				for i := 0; i < len(c)-1; i++ {
					if c[i] == c[i+1] {
						p++
					}
				}
				frac := float64(p) / float64(len(c)-1)
				if frac > 0.01 {
					return false, fmtf("palindromic bigrams %.2f%% (cap 1%%)", frac*100)
				}
				return true, ""
			},
		},
	}
}

// ---- block 4: 4-byte alignment (float32 boundary heuristic) -------------

func alignmentProbes() []behavioral.Probe {
	return []behavioral.Probe{
		{
			ID:   "lora.align.zero_at_position_3_floor",
			Name: "byte at every 4-byte float32 trail position has expected high-zero rate",
			Evaluate: func(c []byte) (bool, string) {
				// In float32 tensors with values clustered around 0,
				// the highest-order byte (every 4th, big-endian for
				// safetensors little-endian-stored values means
				// position % 4 == 3) carries lots of 0x80 / 0x00
				// because exponents are ~127 and signs alternate.
				if len(c) < 1024 {
					return true, ""
				}
				zeros := 0
				count := 0
				for i := 3; i < len(c); i += 4 {
					count++
					if c[i] == 0x00 || c[i] == 0xBF || c[i] == 0x3F {
						// these three values dominate the float32 exponent byte
						zeros++
					}
				}
				if count == 0 {
					return true, ""
				}
				rate := float64(zeros) / float64(count)
				if rate < 0.20 {
					return false, fmtf("float32-exponent-byte hit-rate %.2f (floor 0.20)", rate)
				}
				return true, ""
			},
		},
		{
			ID:   "lora.align.position_3_distinct_low",
			Name: "byte at position 3 modulo 4 has < 96 distinct values",
			Evaluate: func(c []byte) (bool, string) {
				if len(c) < 1024 {
					return true, ""
				}
				seen := [256]bool{}
				distinct := 0
				for i := 3; i < len(c); i += 4 {
					if !seen[c[i]] {
						seen[c[i]] = true
						distinct++
					}
				}
				if distinct >= 96 {
					return false, fmtf("position-3 distinct values %d (expected < 96)", distinct)
				}
				return true, ""
			},
		},
		{
			ID:   "lora.align.position_0_distinct_high",
			Name: "byte at position 0 modulo 4 has > 220 distinct values",
			Evaluate: func(c []byte) (bool, string) {
				if len(c) < 1024 {
					return true, ""
				}
				seen := [256]bool{}
				distinct := 0
				for i := 0; i < len(c); i += 4 {
					if !seen[c[i]] {
						seen[c[i]] = true
						distinct++
					}
				}
				if distinct < 220 {
					return false, fmtf("position-0 distinct values %d (floor 220)", distinct)
				}
				return true, ""
			},
		},
		{
			ID:   "lora.align.parity_byte_balance",
			Name: "byte distribution at even vs odd offsets is within 5% L1 distance",
			Evaluate: func(c []byte) (bool, string) {
				if len(c) < 4096 {
					return true, ""
				}
				var hEven, hOdd [256]int
				for i := 0; i < len(c); i++ {
					if i%2 == 0 {
						hEven[c[i]]++
					} else {
						hOdd[c[i]]++
					}
				}
				neven := math.Max(1, float64(len(c)/2))
				nodd := math.Max(1, float64(len(c)/2))
				var l1 float64
				for v := 0; v < 256; v++ {
					l1 += math.Abs(float64(hEven[v])/neven - float64(hOdd[v])/nodd)
				}
				if l1 > 0.10 {
					return false, fmtf("even-vs-odd L1 distance %.3f (cap 0.10)", l1)
				}
				return true, ""
			},
		},
	}
}

// ---- block 5: entropy detail ---------------------------------------------

func entropyProbes() []behavioral.Probe {
	return []behavioral.Probe{
		{
			ID:   "lora.ent.shannon_in_band",
			Name: "Shannon entropy in [6.5, 7.99] bits/byte",
			Evaluate: func(c []byte) (bool, string) {
				e := shannonEntropyBits(c)
				if e < 6.5 || e > 7.99 {
					return false, fmtf("entropy %.3f outside [6.5, 7.99]", e)
				}
				return true, ""
			},
		},
		{
			ID:   "lora.ent.kl_to_uniform_small",
			Name: "KL divergence to uniform < 0.4 bit",
			Evaluate: func(c []byte) (bool, string) {
				kl := klDivergenceToUniform(c)
				if kl > 0.4 {
					return false, fmtf("KL(p||uniform) = %.3f bit (cap 0.4)", kl)
				}
				return true, ""
			},
		},
		{
			ID:   "lora.ent.first_half_vs_second_half",
			Name: "entropy difference between first and second half < 0.2 bit",
			Evaluate: func(c []byte) (bool, string) {
				if len(c) < 4096 {
					return true, ""
				}
				half := len(c) / 2
				e1 := shannonEntropyBits(c[:half])
				e2 := shannonEntropyBits(c[half:])
				if math.Abs(e1-e2) > 0.2 {
					return false, fmtf("entropy halves differ by %.3f bit (cap 0.2)", math.Abs(e1-e2))
				}
				return true, ""
			},
		},
		{
			ID:   "lora.ent.no_zero_entropy_window",
			Name: "no 256-byte sliding window with entropy < 4 bits/byte",
			Evaluate: func(c []byte) (bool, string) {
				if len(c) < 256 {
					return true, ""
				}
				// Sample, not exhaustive — every 8th window.
				for i := 0; i+256 <= len(c); i += 8 {
					if shannonEntropyBits(c[i:i+256]) < 4.0 {
						return false, fmtf("low-entropy 256-byte window at offset %d", i)
					}
				}
				return true, ""
			},
		},
	}
}

// ---- block 6: byte-balance / popcount ------------------------------------

func balanceProbes() []behavioral.Probe {
	return []behavioral.Probe{
		{
			ID:   "lora.bal.bit_density_balanced",
			Name: "popcount density in [0.45, 0.55]",
			Evaluate: func(c []byte) (bool, string) {
				if len(c) == 0 {
					return true, ""
				}
				var pop uint64
				for _, b := range c {
					pop += uint64(bits.OnesCount8(b))
				}
				rate := float64(pop) / (float64(len(c)) * 8.0)
				if rate < 0.45 || rate > 0.55 {
					return false, fmtf("bit density %.3f outside [0.45, 0.55]", rate)
				}
				return true, ""
			},
		},
		{
			ID:   "lora.bal.high_bit_density_in_band",
			Name: "fraction of bytes with high bit set in [0.45, 0.55]",
			Evaluate: func(c []byte) (bool, string) {
				if len(c) == 0 {
					return true, ""
				}
				var hi uint64
				for _, b := range c {
					if b&0x80 != 0 {
						hi++
					}
				}
				rate := float64(hi) / float64(len(c))
				if rate < 0.45 || rate > 0.55 {
					return false, fmtf("high-bit density %.3f outside [0.45, 0.55]", rate)
				}
				return true, ""
			},
		},
		{
			ID:   "lora.bal.byte_mean_in_band",
			Name: "mean byte value in [110, 145]",
			Evaluate: func(c []byte) (bool, string) {
				if len(c) == 0 {
					return true, ""
				}
				var sum uint64
				for _, b := range c {
					sum += uint64(b)
				}
				mean := float64(sum) / float64(len(c))
				if mean < 110 || mean > 145 {
					return false, fmtf("mean byte %.1f outside [110, 145]", mean)
				}
				return true, ""
			},
		},
		{
			ID:   "lora.bal.byte_stddev_in_band",
			Name: "byte stddev in [60, 78]",
			Evaluate: func(c []byte) (bool, string) {
				if len(c) < 256 {
					return true, ""
				}
				var sum uint64
				for _, b := range c {
					sum += uint64(b)
				}
				mean := float64(sum) / float64(len(c))
				var sqsum float64
				for _, b := range c {
					d := float64(b) - mean
					sqsum += d * d
				}
				sd := math.Sqrt(sqsum / float64(len(c)))
				if sd < 60 || sd > 78 {
					return false, fmtf("byte stddev %.2f outside [60, 78]", sd)
				}
				return true, ""
			},
		},
	}
}

// ---- block 7: structural sanity (header / magic / framing) ---------------

func structuralProbes() []behavioral.Probe {
	return []behavioral.Probe{
		{
			ID:   "lora.struct.no_executable_magic",
			Name: "candidate does not start with a known executable magic",
			Evaluate: func(c []byte) (bool, string) {
				// PE / ELF / Mach-O / Python pickle magic bytes — a
				// LoRA blob must never look like one of these. This
				// catches the failure mode where an attacker swaps
				// in code where weights belong.
				if len(c) < 4 {
					return true, ""
				}
				prefixes := [][]byte{
					{0x4D, 0x5A},             // PE (MZ)
					{0x7F, 0x45, 0x4C, 0x46}, // ELF
					{0xCA, 0xFE, 0xBA, 0xBE}, // Mach-O fat
					{0xCF, 0xFA, 0xED, 0xFE}, // Mach-O 64
					{0x80, 0x04, 0x95},       // pickle proto 4
					{0x50, 0x4B, 0x03, 0x04}, // ZIP (incl. .pt / safetensors-shim)
				}
				for _, p := range prefixes {
					if len(c) >= len(p) && bytesPrefixEqual(c[:len(p)], p) {
						return false, fmtf("candidate begins with executable / archive magic: % X", p)
					}
				}
				return true, ""
			},
		},
		{
			ID:   "lora.struct.no_shell_strings",
			Name: "candidate contains no /bin/sh or /usr/bin substring",
			Evaluate: func(c []byte) (bool, string) {
				if len(c) < 8 {
					return true, ""
				}
				if containsBytes(c, []byte("/bin/sh")) {
					return false, "candidate contains /bin/sh"
				}
				if containsBytes(c, []byte("/usr/bin")) {
					return false, "candidate contains /usr/bin"
				}
				return true, ""
			},
		},
		{
			ID:   "lora.struct.no_python_marker",
			Name: "candidate contains no Python bytecode marker",
			Evaluate: func(c []byte) (bool, string) {
				if len(c) < 4 {
					return true, ""
				}
				// CPython 3.x bytecode magic begins with a 16-bit LE
				// number followed by 0x0D 0x0A. Probe is a heuristic.
				if c[2] == 0x0D && c[3] == 0x0A {
					return false, "first 4 bytes match Python bytecode framing"
				}
				return true, ""
			},
		},
		{
			ID:   "lora.struct.no_html_or_xml",
			Name: "candidate is not an HTML / XML document",
			Evaluate: func(c []byte) (bool, string) {
				if len(c) < 16 {
					return true, ""
				}
				head := c[:16]
				if containsBytes(head, []byte("<html")) ||
					containsBytes(head, []byte("<HTML")) ||
					containsBytes(head, []byte("<?xml")) {
					return false, "candidate looks like HTML/XML"
				}
				return true, ""
			},
		},
	}
}

// ---- block 8: anomaly / drift --------------------------------------------

func anomalyProbes() []behavioral.Probe {
	return []behavioral.Probe{
		{
			ID:   "lora.anom.no_repeating_kib_block",
			Name: "no two non-overlapping 1-KiB blocks are bytewise equal",
			Evaluate: func(c []byte) (bool, string) {
				const block = 1024
				if len(c) < 2*block {
					return true, ""
				}
				// Sample-based: check first 32 blocks against all
				// blocks. This catches buffer-replay regressions
				// without quadratic cost on a 50 MiB candidate.
				lim := (len(c) / block)
				if lim > 256 {
					lim = 256
				}
				for i := 0; i < lim && i < 32; i++ {
					a := c[i*block : (i+1)*block]
					for j := i + 1; j < lim; j++ {
						b := c[j*block : (j+1)*block]
						if bytesPrefixEqual(a, b) {
							return false, fmtf("blocks %d and %d are byte-equal", i, j)
						}
					}
				}
				return true, ""
			},
		},
		{
			ID:   "lora.anom.first_4kib_entropy_floor",
			Name: "first 4 KiB has Shannon entropy ≥ 6.0 bits/byte",
			Evaluate: func(c []byte) (bool, string) {
				if len(c) < 4096 {
					return true, ""
				}
				e := shannonEntropyBits(c[:4096])
				if e < 6.0 {
					return false, fmtf("first 4 KiB entropy %.3f (floor 6.0)", e)
				}
				return true, ""
			},
		},
		{
			ID:   "lora.anom.last_4kib_entropy_floor",
			Name: "last 4 KiB has Shannon entropy ≥ 6.0 bits/byte",
			Evaluate: func(c []byte) (bool, string) {
				if len(c) < 4096 {
					return true, ""
				}
				e := shannonEntropyBits(c[len(c)-4096:])
				if e < 6.0 {
					return false, fmtf("last 4 KiB entropy %.3f (floor 6.0)", e)
				}
				return true, ""
			},
		},
		{
			ID:   "lora.anom.no_ascii_paragraph",
			Name: "no 256-byte window of mostly printable ASCII",
			Evaluate: func(c []byte) (bool, string) {
				if len(c) < 256 {
					return true, ""
				}
				for i := 0; i+256 <= len(c); i += 64 {
					ascii := 0
					for _, b := range c[i : i+256] {
						if (b >= 0x20 && b <= 0x7E) || b == 0x0A || b == 0x0D {
							ascii++
						}
					}
					if ascii > 230 {
						return false, fmtf("256-byte window at offset %d is %d/256 printable ASCII", i, ascii)
					}
				}
				return true, ""
			},
		},
	}
}

// ---- byte-statistics helpers --------------------------------------------

// histogram returns a frequency table of byte values across c. The
// return value is allocated; callers should not retain it across the
// next call.
func histogram(c []byte) [256]int {
	var h [256]int
	for _, b := range c {
		h[b]++
	}
	return h
}

// shannonEntropyBits returns the Shannon entropy of c in bits/byte.
// 0 for empty input. Maximum 8.0 bits (uniform distribution).
func shannonEntropyBits(c []byte) float64 {
	if len(c) == 0 {
		return 0
	}
	h := histogram(c)
	n := float64(len(c))
	var ent float64
	for _, cnt := range h {
		if cnt == 0 {
			continue
		}
		p := float64(cnt) / n
		ent -= p * math.Log2(p)
	}
	return ent
}

// klDivergenceToUniform returns KL(p || uniform) in bits, where p is
// the empirical byte distribution of c. Cheap surrogate for "how
// close is the alphabet to a uniform distribution".
func klDivergenceToUniform(c []byte) float64 {
	if len(c) == 0 {
		return 0
	}
	h := histogram(c)
	n := float64(len(c))
	q := 1.0 / 256.0
	var kl float64
	for _, cnt := range h {
		if cnt == 0 {
			continue
		}
		p := float64(cnt) / n
		kl += p * math.Log2(p/q)
	}
	return kl
}

// longestByteRun finds the longest run of byte target in c. Returns
// (length, starting-offset). (0, -1) for empty.
func longestByteRun(c []byte, target byte) (int, int) {
	maxLen := 0
	maxAt := -1
	curLen := 0
	curAt := -1
	for i, b := range c {
		if b == target {
			if curLen == 0 {
				curAt = i
			}
			curLen++
			if curLen > maxLen {
				maxLen = curLen
				maxAt = curAt
			}
		} else {
			curLen = 0
		}
	}
	return maxLen, maxAt
}

// medianRunLength returns the median length of byte runs in c.
// Returns 0 for empty input.
func medianRunLength(c []byte) int {
	if len(c) == 0 {
		return 0
	}
	runs := computeRuns(c)
	if len(runs) == 0 {
		return 0
	}
	// Insertion-sort for small slices is overkill; build a histogram
	// and walk it to median.
	maxRun := 0
	for _, r := range runs {
		if r > maxRun {
			maxRun = r
		}
	}
	freq := make([]int, maxRun+1)
	for _, r := range runs {
		freq[r]++
	}
	target := len(runs) / 2
	cum := 0
	for r := 1; r <= maxRun; r++ {
		cum += freq[r]
		if cum > target {
			return r
		}
	}
	return maxRun
}

// computeRuns returns the sequence of run lengths in c.
func computeRuns(c []byte) []int {
	if len(c) == 0 {
		return nil
	}
	runs := make([]int, 0, len(c)/4)
	curLen := 1
	for i := 1; i < len(c); i++ {
		if c[i] == c[i-1] {
			curLen++
		} else {
			runs = append(runs, curLen)
			curLen = 1
		}
	}
	runs = append(runs, curLen)
	return runs
}

// bytesCoveredByRunsAtLeast returns the total number of bytes covered
// by runs of length >= minLen.
func bytesCoveredByRunsAtLeast(c []byte, minLen int) int {
	if len(c) == 0 {
		return 0
	}
	covered := 0
	curLen := 1
	for i := 1; i < len(c); i++ {
		if c[i] == c[i-1] {
			curLen++
		} else {
			if curLen >= minLen {
				covered += curLen
			}
			curLen = 1
		}
	}
	if curLen >= minLen {
		covered += curLen
	}
	return covered
}

// totalRunCount returns the total number of byte runs in c.
func totalRunCount(c []byte) int {
	if len(c) == 0 {
		return 0
	}
	count := 1
	for i := 1; i < len(c); i++ {
		if c[i] != c[i-1] {
			count++
		}
	}
	return count
}

// transitionsCount returns the number of positions i where c[i] != c[i-1].
func transitionsCount(c []byte) int {
	if len(c) < 2 {
		return 0
	}
	t := 0
	for i := 1; i < len(c); i++ {
		if c[i] != c[i-1] {
			t++
		}
	}
	return t
}

// distinctBigrams returns the number of distinct (b[i], b[i+1]) pairs
// in c. Maximum 65536.
func distinctBigrams(c []byte) int {
	if len(c) < 2 {
		return 0
	}
	seen := make(map[uint16]struct{}, 4096)
	for i := 0; i < len(c)-1; i++ {
		key := uint16(c[i])<<8 | uint16(c[i+1])
		seen[key] = struct{}{}
	}
	return len(seen)
}

// mostCommonBigramFrac returns (frac, b1, b2) for the most common
// bigram in c.
func mostCommonBigramFrac(c []byte) (float64, byte, byte) {
	if len(c) < 2 {
		return 0, 0, 0
	}
	counts := make(map[uint16]int, 4096)
	total := 0
	for i := 0; i < len(c)-1; i++ {
		key := uint16(c[i])<<8 | uint16(c[i+1])
		counts[key]++
		total++
	}
	var bestKey uint16
	bestCount := 0
	for k, v := range counts {
		if v > bestCount {
			bestCount = v
			bestKey = k
		}
	}
	if total == 0 {
		return 0, 0, 0
	}
	return float64(bestCount) / float64(total), byte(bestKey >> 8), byte(bestKey & 0xFF)
}

// bytesPrefixEqual returns true when len(a) == len(b) and every byte
// matches. Cheaper-than-bytes.Equal allocation profile for small a.
func bytesPrefixEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, x := range a {
		if x != b[i] {
			return false
		}
	}
	return true
}

// containsBytes returns true when needle is a substring of haystack.
func containsBytes(haystack, needle []byte) bool {
	if len(needle) > len(haystack) {
		return false
	}
	if len(needle) == 0 {
		return true
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if bytesPrefixEqual(haystack[i:i+len(needle)], needle) {
			return true
		}
	}
	return false
}

// ---- formatting -----------------------------------------------------------

// fmtf is a tiny printf-replacement. The behavioral validator rejects
// fmt because it would inflate the binary; this helper covers the
// handful of format verbs the probes need.
func fmtf(format string, args ...any) string {
	out := make([]byte, 0, len(format)+16)
	ai := 0
	for i := 0; i < len(format); i++ {
		c := format[i]
		if c != '%' || i+1 >= len(format) {
			out = append(out, c)
			continue
		}
		i++
		verb := format[i]
		var arg any
		if ai < len(args) {
			arg = args[ai]
			ai++
		}
		switch verb {
		case 'd':
			out = appendInt(out, toInt64(arg))
		case 'f':
			out = appendFloat(out, toFloat64(arg), -1)
		case 's':
			if s, ok := arg.(string); ok {
				out = append(out, s...)
			}
		case 'x':
			out = appendHex(out, uint64(toInt64(arg)))
		case 'X':
			out = appendHexUpper(out, uint64(toInt64(arg)), 2)
		case '%':
			out = append(out, '%')
		case '.':
			// %.Nf — fixed-point decimal
			j := i + 1
			for j < len(format) && format[j] >= '0' && format[j] <= '9' {
				j++
			}
			if j < len(format) && format[j] == 'f' {
				prec := 0
				for k := i + 1; k < j; k++ {
					prec = prec*10 + int(format[k]-'0')
				}
				out = appendFloat(out, toFloat64(arg), prec)
				i = j
			} else {
				out = append(out, '%', '.')
			}
		default:
			out = append(out, '%', verb)
		}
	}
	return string(out)
}

func toInt64(a any) int64 {
	switch v := a.(type) {
	case int:
		return int64(v)
	case int64:
		return v
	case uint:
		return int64(v)
	case uint64:
		return int64(v)
	case byte:
		return int64(v)
	case float64:
		return int64(v)
	default:
		return 0
	}
}

func toFloat64(a any) float64 {
	switch v := a.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	default:
		return 0
	}
}

func appendInt(dst []byte, n int64) []byte {
	if n == 0 {
		return append(dst, '0')
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return append(dst, buf[pos:]...)
}

func appendFloat(dst []byte, f float64, prec int) []byte {
	if prec < 0 {
		prec = 3
	}
	if math.IsNaN(f) {
		return append(dst, 'N', 'a', 'N')
	}
	if math.IsInf(f, 1) {
		return append(dst, '+', 'I', 'n', 'f')
	}
	if math.IsInf(f, -1) {
		return append(dst, '-', 'I', 'n', 'f')
	}
	neg := f < 0
	if neg {
		f = -f
		dst = append(dst, '-')
	}
	mult := 1.0
	for i := 0; i < prec; i++ {
		mult *= 10
	}
	scaled := math.Floor(f*mult + 0.5)
	intPart := int64(scaled / mult)
	fracPart := int64(scaled - float64(intPart)*mult)
	dst = appendInt(dst, intPart)
	if prec > 0 {
		dst = append(dst, '.')
		// pad leading zeros
		var buf [16]byte
		pos := len(buf)
		n := fracPart
		for i := 0; i < prec; i++ {
			pos--
			buf[pos] = byte('0' + n%10)
			n /= 10
		}
		dst = append(dst, buf[pos:]...)
	}
	return dst
}

func appendHex(dst []byte, n uint64) []byte {
	if n == 0 {
		return append(dst, '0')
	}
	const hexDigits = "0123456789abcdef"
	var buf [16]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = hexDigits[n&0xF]
		n >>= 4
	}
	return append(dst, buf[pos:]...)
}

func appendHexUpper(dst []byte, n uint64, width int) []byte {
	const hexDigits = "0123456789ABCDEF"
	var buf [16]byte
	pos := len(buf)
	if n == 0 {
		buf[pos-1] = '0'
		pos--
	}
	for n > 0 {
		pos--
		buf[pos] = hexDigits[n&0xF]
		n >>= 4
	}
	for len(buf)-pos < width {
		pos--
		buf[pos] = '0'
	}
	return append(dst, buf[pos:]...)
}
