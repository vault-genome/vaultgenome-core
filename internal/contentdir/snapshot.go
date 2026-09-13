// SPDX-License-Identifier: AGPL-3.0-or-later

// Package contentdir is a generic directory-sealing payload source for
// Vault Genome bundles. It complements internal/ollama (which knows about
// Ollama's manifest+blob layout) by handling the case where the workload
// is "an arbitrary directory of files" — for example, a LoRA adapter
// produced by mlx_lm.lora, a fine-tune checkpoint, a RAG corpus, or any
// other on-disk artefact a TEE-aware operator wants under continuity.
//
// Determinism: the tar layout is sorted by path, mtime is zeroed, and
// uid/gid/mode are normalised so the payload SHA-256 is reproducible
// across hosts and clocks.
package contentdir

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Component is the in-snapshot record for one file inside a sealed dir.
// Carried in the genome envelope so an inspector can list contents
// without unsealing.
type Component struct {
	Path   string `json:"path"`   // forward-slash, relative to the sealed root
	Digest string `json:"digest"` // "sha256:<hex>"
	Size   int64  `json:"size"`
}

// Snapshot describes a sealed directory: the source path, the per-file
// components, total bytes, and the payload SHA-256. The bundle envelope
// embeds this verbatim.
type Snapshot struct {
	SourceDir     string      `json:"source_dir"`     // absolute path the snapshot came from
	Components    []Component `json:"components"`     // sorted by path (deterministic)
	TotalBytes    int64       `json:"total_bytes"`    // sum of every component's size
	PayloadSHA256 string      `json:"payload_sha256"` // sha256 of the tar bytes
}

// CapturePayload reads every regular file under sourceDir (recursively),
// packs them into a deterministic uncompressed tar, and returns the
// snapshot metadata + the tar bytes. Symlinks, devices, and other
// non-regular entries are ignored.
//
// The tar entry name for each file is its path relative to sourceDir
// using forward slashes — so a file at sourceDir/adapters.safetensors
// is stored as "adapters.safetensors" in the tar (not under any prefix).
func CapturePayload(sourceDir string) (Snapshot, []byte, error) {
	abs, err := filepath.Abs(sourceDir)
	if err != nil {
		return Snapshot{}, nil, fmt.Errorf("contentdir: abs %s: %w", sourceDir, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return Snapshot{}, nil, fmt.Errorf("contentdir: stat %s: %w", abs, err)
	}
	if !info.IsDir() {
		return Snapshot{}, nil, fmt.Errorf("contentdir: %s is not a directory", abs)
	}

	type entry struct {
		rel  string
		data []byte
	}
	var entries []entry

	err = filepath.WalkDir(abs, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(abs, path)
		if err != nil {
			return fmt.Errorf("rel %s: %w", path, err)
		}
		// Forward-slash for tar portability.
		rel = filepath.ToSlash(rel)
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		entries = append(entries, entry{rel: rel, data: data})
		return nil
	})
	if err != nil {
		return Snapshot{}, nil, fmt.Errorf("contentdir: walk: %w", err)
	}
	if len(entries) == 0 {
		return Snapshot{}, nil, fmt.Errorf("contentdir: %s contains no regular files", abs)
	}

	// Deterministic tar order.
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	components := make([]Component, 0, len(entries))
	var total int64
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.rel,
			Mode:     0o644,
			Size:     int64(len(e.data)),
			Typeflag: tar.TypeReg,
			Format:   tar.FormatPAX,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return Snapshot{}, nil, fmt.Errorf("contentdir: tar header %s: %w", e.rel, err)
		}
		if _, err := tw.Write(e.data); err != nil {
			return Snapshot{}, nil, fmt.Errorf("contentdir: tar body %s: %w", e.rel, err)
		}
		total += int64(len(e.data))
		sum := sha256.Sum256(e.data)
		components = append(components, Component{
			Path:   e.rel,
			Digest: "sha256:" + hex.EncodeToString(sum[:]),
			Size:   int64(len(e.data)),
		})
	}
	if err := tw.Close(); err != nil {
		return Snapshot{}, nil, fmt.Errorf("contentdir: close tar: %w", err)
	}

	payload := buf.Bytes()
	psum := sha256.Sum256(payload)
	return Snapshot{
		SourceDir:     abs,
		Components:    components,
		TotalBytes:    total,
		PayloadSHA256: "sha256:" + hex.EncodeToString(psum[:]),
	}, payload, nil
}

// Restore extracts a payload produced by CapturePayload into targetDir,
// recreating the original directory structure. Returns the number of
// bytes written.
func Restore(payload []byte, targetDir string) (int64, error) {
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return 0, fmt.Errorf("contentdir restore: mkdir target: %w", err)
	}
	tr := tar.NewReader(bytes.NewReader(payload))
	var written int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return written, fmt.Errorf("contentdir restore: tar read: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		clean := filepath.Clean(hdr.Name)
		if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			return written, fmt.Errorf("contentdir restore: refusing unsafe path %q", hdr.Name)
		}
		dst := filepath.Join(targetDir, clean)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return written, fmt.Errorf("contentdir restore: mkdir for %s: %w", clean, err)
		}
		f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			return written, fmt.Errorf("contentdir restore: create %s: %w", clean, err)
		}
		n, err := io.Copy(f, tr)
		_ = f.Close()
		if err != nil {
			return written, fmt.Errorf("contentdir restore: write %s: %w", clean, err)
		}
		written += n
	}
	return written, nil
}
