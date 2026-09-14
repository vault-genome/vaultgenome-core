// SPDX-License-Identifier: AGPL-3.0-or-later

// Package lora reads the model side of a genome — the directory the
// vg_genome worker (workers/genome) writes and `acpctl genome seal`
// seals: genome.json (base model manifest, adapter, recipe) and
// fixtures.json (the fine-tuned model's reference outputs).
//
// It turns the fixtures into the equivalence gate's references, so a
// destination that restored the genome can prove the model came back —
// recomputing each fixture on its own hardware and holding the result to
// the sealed reference (internal/validation/reconstruction).
package lora

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ai-continuity-platform/core/internal/validation/equivalence"
)

// Schemas the worker writes.
const (
	GenomeSchema   = "vault-genome/lora-genome/v1"
	FixturesSchema = "vault-genome/lora-fixtures/v1"
)

// Genome is genome.json, as far as the gate needs it.
type Genome struct {
	Schema    string `json:"schema"`
	CreatedAt string `json:"created_at"`
	Base      struct {
		Name     string `json:"name"`
		Manifest struct {
			Files  map[string]string `json:"files"`
			Digest string            `json:"digest"`
		} `json:"manifest"`
	} `json:"base"`
	Adapter struct {
		Dir           string   `json:"dir"`
		Format        string   `json:"format"`
		R             int      `json:"r"`
		Alpha         float64  `json:"alpha"`
		Targets       []string `json:"targets"`
		Parameters    int64    `json:"parameters"`
		WeightsSHA256 string   `json:"weights_sha256"`
	} `json:"adapter"`
	Recipe struct {
		Steps        int       `json:"steps"`
		Seed         int64     `json:"seed"`
		Threads      int       `json:"threads"`
		Losses       []float64 `json:"losses"`
		TrainSeconds float64   `json:"train_seconds"`
	} `json:"recipe"`
	Fixtures struct {
		File     string `json:"file"`
		SHA256   string `json:"sha256"`
		Count    int    `json:"count"`
		Critical int    `json:"critical"`
		TopK     int    `json:"top_k"`
	} `json:"fixtures"`
	Runtime map[string]any `json:"runtime"`
}

type wireTensor struct {
	DType  string `json:"dtype"`
	Shape  []int  `json:"shape"`
	RawB64 string `json:"raw_b64"`
}

type fixtureDoc struct {
	Schema   string `json:"schema"`
	Fixtures []struct {
		ID       string     `json:"id"`
		Critical bool       `json:"critical"`
		Prompt   string     `json:"prompt"`
		Expected wireTensor `json:"expected"`
	} `json:"fixtures"`
}

// Load reads genome.json in dir and checks it names what it needs.
func Load(dir string) (Genome, error) {
	var g Genome
	raw, err := os.ReadFile(filepath.Join(dir, "genome.json"))
	if err != nil {
		return g, err
	}
	if err := json.Unmarshal(raw, &g); err != nil {
		return g, fmt.Errorf("lora: genome.json: %w", err)
	}
	switch {
	case g.Schema != GenomeSchema:
		return g, fmt.Errorf("lora: genome.json schema %q, want %q", g.Schema, GenomeSchema)
	case g.Base.Manifest.Digest == "" || len(g.Base.Manifest.Files) == 0:
		return g, errors.New("lora: genome.json names no base model")
	case g.Adapter.WeightsSHA256 == "" || g.Adapter.Dir == "":
		return g, errors.New("lora: genome.json names no adapter")
	case g.Fixtures.File == "" || g.Fixtures.SHA256 == "":
		return g, errors.New("lora: genome.json names no fixtures")
	case !filepath.IsLocal(g.Fixtures.File) || !filepath.IsLocal(g.Adapter.Dir):
		return g, errors.New("lora: genome.json points outside the genome")
	}
	return g, nil
}

// Fixtures reads the fixtures g names, checks them against g's digest,
// and returns them as gate references.
func Fixtures(dir string, g Genome) ([]equivalence.Fixture, error) {
	raw, err := os.ReadFile(filepath.Join(dir, g.Fixtures.File))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	if "sha256:"+hex.EncodeToString(sum[:]) != g.Fixtures.SHA256 {
		return nil, errors.New("lora: fixtures do not match the genome")
	}
	var doc fixtureDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("lora: fixtures: %w", err)
	}
	if doc.Schema != FixturesSchema {
		return nil, fmt.Errorf("lora: fixtures schema %q, want %q", doc.Schema, FixturesSchema)
	}
	if len(doc.Fixtures) == 0 {
		return nil, errors.New("lora: no fixtures")
	}
	seen := map[string]bool{}
	out := make([]equivalence.Fixture, 0, len(doc.Fixtures))
	for _, f := range doc.Fixtures {
		if f.ID == "" || seen[f.ID] {
			return nil, fmt.Errorf("lora: fixture id %q missing or repeated", f.ID)
		}
		seen[f.ID] = true
		if f.Expected.DType != string(equivalence.F32) && f.Expected.DType != string(equivalence.F64) {
			return nil, fmt.Errorf("lora: fixture %s: dtype %q", f.ID, f.Expected.DType)
		}
		data, err := base64.StdEncoding.DecodeString(f.Expected.RawB64)
		if err != nil {
			return nil, fmt.Errorf("lora: fixture %s: %w", f.ID, err)
		}
		out = append(out, equivalence.Fixture{
			ID:       f.ID,
			Critical: f.Critical,
			Expected: equivalence.Tensor{DType: equivalence.DType(f.Expected.DType), Shape: f.Expected.Shape, Raw: data},
		})
	}
	return out, nil
}

// IDs lists fixture ids in order.
func IDs(fx []equivalence.Fixture) []string {
	out := make([]string, len(fx))
	for i, f := range fx {
		out[i] = f.ID
	}
	return out
}
