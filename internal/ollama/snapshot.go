// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ollama bridges a running Ollama installation into Vault Genome's
// seal/unseal pipeline. It treats Ollama's on-disk model store
// (manifest + content-addressed blobs) as the payload that gets sealed
// inside a TEE Sealer, and provides the inverse operation that materialises
// the same bytes back into a fresh OLLAMA_MODELS directory.
//
// Why this exists: every claim on vaultgenome.com about "model continuity"
// historically resolved to mock byte buffers. This package makes those
// claims resolve to a real Llama 3.2 / Qwen / Mistral model instead, which
// turns the demo into a downloadable artifact a buyer can verify.
package ollama

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ManifestRef mirrors Ollama's on-disk manifest schema (Docker v2-style).
// We only decode the fields we need to enumerate referenced blobs.
type ManifestRef struct {
	SchemaVersion int     `json:"schemaVersion"`
	MediaType     string  `json:"mediaType"`
	Config        Layer   `json:"config"`
	Layers        []Layer `json:"layers"`
}

// Layer is one entry in a manifest — pointer to a content-addressed blob.
type Layer struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"` // "sha256:<hex>"
	Size      int64  `json:"size"`
}

// Component is the in-snapshot record for a single blob (manifest or layer).
// Carried in the genome envelope so an inspector can list the bundle's
// contents without unsealing the payload.
type Component struct {
	Role      string `json:"role"`       // "manifest" | "config" | "layer"
	MediaType string `json:"media_type"` // copied from manifest
	Digest    string `json:"digest"`     // "sha256:<hex>"
	Size      int64  `json:"size"`
}

// Snapshot is the metadata side of a captured Ollama model: enough info to
// describe the bundle (model ref, components, total bytes, payload digest)
// without including the bytes themselves.
type Snapshot struct {
	Model         string      `json:"model"`         // "llama3.2:3b"
	ManifestPath  string      `json:"manifest_path"` // relative to OLLAMA_MODELS
	Manifest      ManifestRef `json:"manifest"`
	Components    []Component `json:"components"` // sorted by digest for determinism
	TotalBytes    int64       `json:"total_bytes"`
	PayloadSHA256 string      `json:"payload_sha256"` // sha256 of the tarball bytes
}

// CapturePayload reads the model identified by modelRef from ollamaHome
// (typically ~/.ollama) and returns:
//
//   - Snapshot: structured metadata describing what's inside the bundle
//   - []byte:   a deterministic uncompressed tar stream containing the
//     manifest and every referenced blob, laid out so Restore
//     can drop it back into a fresh OLLAMA_MODELS directory
//
// Determinism matters here: the same model on the same machine must produce
// byte-identical tar output across runs, so the payload SHA-256 (which gets
// signed into the genome envelope) is reproducible. We achieve this by
// sorting tar entries lexicographically and zeroing per-entry timestamps.
func CapturePayload(modelRef, ollamaHome string) (Snapshot, []byte, error) {
	manifestRel, err := manifestPathFor(modelRef)
	if err != nil {
		return Snapshot{}, nil, err
	}
	manifestAbs := filepath.Join(ollamaHome, "models", manifestRel)

	manifestBytes, err := os.ReadFile(manifestAbs)
	if err != nil {
		return Snapshot{}, nil, fmt.Errorf("ollama snapshot: read manifest %s: %w", manifestAbs, err)
	}

	var mf ManifestRef
	if err := json.Unmarshal(manifestBytes, &mf); err != nil {
		return Snapshot{}, nil, fmt.Errorf("ollama snapshot: parse manifest: %w", err)
	}

	components := []Component{
		{Role: "manifest", MediaType: "application/vnd.ollama.manifest", Digest: digestOf(manifestBytes), Size: int64(len(manifestBytes))},
		{Role: "config", MediaType: mf.Config.MediaType, Digest: mf.Config.Digest, Size: mf.Config.Size},
	}
	for _, l := range mf.Layers {
		components = append(components, Component{
			Role:      "layer",
			MediaType: l.MediaType,
			Digest:    l.Digest,
			Size:      l.Size,
		})
	}

	// Deterministic order so payload bytes are reproducible.
	sort.Slice(components, func(i, j int) bool { return components[i].Digest < components[j].Digest })

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// 1. The manifest, written under its source-relative path so Restore
	//    can drop it back where Ollama expects to find it.
	if err := writeTarEntry(tw, "models/"+manifestRel, manifestBytes); err != nil {
		return Snapshot{}, nil, fmt.Errorf("ollama snapshot: tar manifest: %w", err)
	}

	// 2. Every referenced blob, named by digest (Ollama's on-disk
	//    convention: ~/.ollama/models/blobs/sha256-<hex>).
	seen := map[string]bool{}
	totalBytes := int64(len(manifestBytes))
	addBlob := func(digest string) error {
		if seen[digest] {
			return nil
		}
		seen[digest] = true
		blobName := blobFilename(digest)
		blobPath := filepath.Join(ollamaHome, "models", "blobs", blobName)
		data, err := os.ReadFile(blobPath)
		if err != nil {
			return fmt.Errorf("read blob %s: %w", blobName, err)
		}
		actual := digestOf(data)
		if actual != digest {
			return fmt.Errorf("blob %s: digest mismatch (manifest says %s, on disk %s)", blobName, digest, actual)
		}
		totalBytes += int64(len(data))
		return writeTarEntry(tw, "models/blobs/"+blobName, data)
	}

	if err := addBlob(mf.Config.Digest); err != nil {
		return Snapshot{}, nil, fmt.Errorf("ollama snapshot: %w", err)
	}
	for _, l := range mf.Layers {
		if err := addBlob(l.Digest); err != nil {
			return Snapshot{}, nil, fmt.Errorf("ollama snapshot: %w", err)
		}
	}

	if err := tw.Close(); err != nil {
		return Snapshot{}, nil, fmt.Errorf("ollama snapshot: close tar: %w", err)
	}

	payload := buf.Bytes()
	return Snapshot{
		Model:         modelRef,
		ManifestPath:  manifestRel,
		Manifest:      mf,
		Components:    components,
		TotalBytes:    totalBytes,
		PayloadSHA256: digestOf(payload),
	}, payload, nil
}

// Restore extracts a payload produced by CapturePayload into targetHome,
// reproducing the OLLAMA_MODELS layout under targetHome/models/. Returns
// the number of bytes written. Caller can then point Ollama at targetHome
// via OLLAMA_MODELS env var to load the restored model.
func Restore(payload []byte, targetHome string) (int64, error) {
	if err := os.MkdirAll(filepath.Join(targetHome, "models", "blobs"), 0o755); err != nil {
		return 0, fmt.Errorf("ollama restore: mkdir blobs: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(targetHome, "models", "manifests"), 0o755); err != nil {
		return 0, fmt.Errorf("ollama restore: mkdir manifests: %w", err)
	}

	tr := tar.NewReader(bytes.NewReader(payload))
	var written int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return written, fmt.Errorf("ollama restore: tar read: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		// Defensive — refuse paths that try to escape targetHome.
		clean := filepath.Clean(hdr.Name)
		if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			return written, fmt.Errorf("ollama restore: refusing unsafe path %q", hdr.Name)
		}
		dst := filepath.Join(targetHome, clean)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return written, fmt.Errorf("ollama restore: mkdir for %s: %w", clean, err)
		}
		f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			return written, fmt.Errorf("ollama restore: create %s: %w", clean, err)
		}
		n, err := io.Copy(f, tr)
		_ = f.Close()
		if err != nil {
			return written, fmt.Errorf("ollama restore: write %s: %w", clean, err)
		}
		written += n
	}
	return written, nil
}

// VerifyComponents re-hashes every blob in a restored OLLAMA_MODELS layout
// and returns an error if any hash diverges from the snapshot's record.
// Used by `acpctl genome verify` after a restore to prove that what came
// out of the seal is bit-identical to what went in.
func VerifyComponents(snap Snapshot, restoredHome string) error {
	for _, c := range snap.Components {
		if c.Role == "manifest" {
			continue // manifest hash recomputed inline below
		}
		path := filepath.Join(restoredHome, "models", "blobs", blobFilename(c.Digest))
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("verify: read %s: %w", path, err)
		}
		got := digestOf(data)
		if got != c.Digest {
			return fmt.Errorf("verify: blob %s: digest mismatch (snapshot %s, on-disk %s)", c.Digest, c.Digest, got)
		}
	}
	manifestPath := filepath.Join(restoredHome, "models", snap.ManifestPath)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("verify: read manifest %s: %w", manifestPath, err)
	}
	if got := digestOf(data); got != snap.Components[0].Digest && !manifestDigestMatches(snap.Components, got) {
		return fmt.Errorf("verify: manifest digest mismatch (on-disk %s)", got)
	}
	return nil
}

func manifestDigestMatches(components []Component, got string) bool {
	for _, c := range components {
		if c.Role == "manifest" && c.Digest == got {
			return true
		}
	}
	return false
}

// manifestPathFor turns "llama3.2:3b" into the relative on-disk path
// "manifests/registry.ollama.ai/library/llama3.2/3b". Any explicit
// registry/namespace prefix is honoured; the bare-name shortcut assumes
// the canonical Ollama registry.
func manifestPathFor(modelRef string) (string, error) {
	if modelRef == "" {
		return "", errors.New("ollama snapshot: model ref must not be empty")
	}
	name, tag, ok := strings.Cut(modelRef, ":")
	if !ok {
		tag = "latest"
		name = modelRef
	}
	// Normalise the registry/namespace prefix.
	parts := strings.Split(name, "/")
	switch len(parts) {
	case 1:
		return filepath.Join("manifests", "registry.ollama.ai", "library", parts[0], tag), nil
	case 2:
		return filepath.Join("manifests", "registry.ollama.ai", parts[0], parts[1], tag), nil
	case 3:
		return filepath.Join("manifests", parts[0], parts[1], parts[2], tag), nil
	default:
		return "", fmt.Errorf("ollama snapshot: cannot parse model ref %q", modelRef)
	}
}

func blobFilename(digest string) string {
	// "sha256:abcd..." → "sha256-abcd..." (Ollama's on-disk convention)
	return strings.Replace(digest, ":", "-", 1)
}

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// writeTarEntry writes a single regular file with deterministic header
// fields (mtime=0, uid/gid=0, mode=0644) so the tar bytes are reproducible
// across hosts and clocks.
func writeTarEntry(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{
		Name:     name,
		Mode:     0o644,
		Size:     int64(len(data)),
		Typeflag: tar.TypeReg,
		Format:   tar.FormatPAX,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}
