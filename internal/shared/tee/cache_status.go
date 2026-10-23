// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// What a verifier keeps on disk so that it need not ask a vendor again:
// the VCEKs it fetched from AMD KDS (one DER per CHIP_ID and TCB), the TCB
// info and QE identity it fetched from Intel PCS (each with the issuer
// chain it came with), NVIDIA's NRAS key set, the RIM manifests and the
// OCSP answers. Every cached document is checked on use exactly like a
// fresh one — a cache is never trusted on its own — and the ones with a
// validity period stop being used once it ends. CacheStatus reads those
// directories and says what is there and until when, so an operator of
// a host without a route to the vendors (an air-gapped site) can fill
// the caches while connected and know when to fill them again.

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

// CacheDirs names the directories a verifier reads before it asks a
// vendor. An empty field means the verifier has no such cache.
type CacheDirs struct {
	// VCEK is GCPSEVVerifierConfig.VCEKCacheDir / AzureCGPUVerifierConfig.VCEKCacheDir.
	VCEK string
	// PCS is GCPTDXVerifierConfig.PCSCacheDir.
	PCS string
	// NRAS is AzureCGPUVerifierConfig.NRASCacheDir.
	NRAS string
	// RIM is AzureCGPUVerifierConfig.RIMCacheDir: the RIM manifests and,
	// beside them, the OCSP answers.
	RIM string
}

// The kinds of cached document CacheStatus reports.
const (
	CacheKindVCEK     = "vcek"
	CacheKindPCS      = "pcs"
	CacheKindNRASJWKS = "nras-jwks"
	CacheKindRIM      = "rim"
	CacheKindOCSP     = "ocsp"
)

// CacheEntry is one cached document and how long it is good for.
type CacheEntry struct {
	Kind    string `json:"kind"`
	Dir     string `json:"dir"`
	File    string `json:"file"`
	Subject string `json:"subject,omitempty"`
	// NotBefore and NotAfter bound the document's validity; a zero
	// NotAfter means the document does not expire by itself.
	NotBefore time.Time `json:"not_before,omitempty"`
	NotAfter  time.Time `json:"not_after,omitempty"`
	// Current is whether the verifier would use the document now.
	Current bool   `json:"current"`
	Note    string `json:"note,omitempty"`
}

// Path is the document's path on disk.
func (e CacheEntry) Path() string { return filepath.Join(e.Dir, e.File) }

// CacheStatus reads the cache directories and reports every document
// found, sorted by kind and file. A directory that does not exist is an
// empty cache, not an error; a file that does not parse is reported as
// not current, with the reason.
func CacheStatus(dirs CacheDirs, now time.Time) []CacheEntry {
	var out []CacheEntry
	out = append(out, vcekCacheStatus(dirs.VCEK, now)...)
	out = append(out, pcsCacheStatus(dirs.PCS, now)...)
	out = append(out, nrasCacheStatus(dirs.NRAS)...)
	out = append(out, rimCacheStatus(dirs.RIM, now)...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].File < out[j].File
	})
	return out
}

// EarliestExpiry is the soonest NotAfter among the entries that expire,
// and false when none does.
func EarliestExpiry(entries []CacheEntry) (time.Time, bool) {
	var earliest time.Time
	for _, e := range entries {
		if e.NotAfter.IsZero() {
			continue
		}
		if earliest.IsZero() || e.NotAfter.Before(earliest) {
			earliest = e.NotAfter
		}
	}
	return earliest, !earliest.IsZero()
}

func listDir(dir string) []os.DirEntry {
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	return entries
}

// vcekCacheStatus: <chip id hex>-<tcb>.der, a certificate each.
func vcekCacheStatus(dir string, now time.Time) []CacheEntry {
	var out []CacheEntry
	for _, f := range listDir(dir) {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".der") || strings.HasPrefix(f.Name(), ".") {
			continue
		}
		e := CacheEntry{Kind: CacheKindVCEK, Dir: dir, File: f.Name()}
		der, err := os.ReadFile(filepath.Join(dir, f.Name()))
		if err != nil {
			e.Note = "unreadable: " + err.Error()
			out = append(out, e)
			continue
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			e.Note = "not a certificate: " + err.Error()
			out = append(out, e)
			continue
		}
		e.Subject = cert.Subject.CommonName
		e.NotBefore, e.NotAfter = cert.NotBefore, cert.NotAfter
		e.Current = !now.Before(cert.NotBefore) && now.Before(cert.NotAfter)
		if key := strings.TrimSuffix(f.Name(), ".der"); len(key) > 128 && key[128] == '-' {
			e.Note = fmt.Sprintf("chip %s…, TCB %s", key[:16], key[129:])
		}
		out = append(out, e)
	}
	return out
}

// pcsCacheStatus: <name>.json (the document as PCS served it) beside
// <name>.issuer-chain.pem; the inner object carries issueDate and
// nextUpdate.
func pcsCacheStatus(dir string, now time.Time) []CacheEntry {
	var out []CacheEntry
	for _, f := range listDir(dir) {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") || strings.HasPrefix(f.Name(), ".") {
			continue
		}
		name := strings.TrimSuffix(f.Name(), ".json")
		e := CacheEntry{Kind: CacheKindPCS, Dir: dir, File: f.Name()}
		body, err := os.ReadFile(filepath.Join(dir, f.Name()))
		if err != nil {
			e.Note = "unreadable: " + err.Error()
			out = append(out, e)
			continue
		}
		var top map[string]json.RawMessage
		if err := json.Unmarshal(body, &top); err != nil {
			e.Note = "not a PCS document: " + err.Error()
			out = append(out, e)
			continue
		}
		var inner json.RawMessage
		var key string
		for _, k := range []string{"tcbInfo", "enclaveIdentity"} {
			if v, ok := top[k]; ok {
				inner, key = v, k
				break
			}
		}
		if inner == nil {
			e.Note = "not a PCS document: neither tcbInfo nor enclaveIdentity"
			out = append(out, e)
			continue
		}
		var meta struct {
			ID         string    `json:"id"`
			FMSPC      string    `json:"fmspc"`
			IssueDate  time.Time `json:"issueDate"`
			NextUpdate time.Time `json:"nextUpdate"`
		}
		if err := json.Unmarshal(inner, &meta); err != nil {
			e.Note = key + " does not decode: " + err.Error()
			out = append(out, e)
			continue
		}
		e.Subject = key + " " + meta.ID
		if meta.FMSPC != "" {
			e.Subject += " fmspc=" + strings.ToLower(meta.FMSPC)
		}
		e.NotBefore, e.NotAfter = meta.IssueDate, meta.NextUpdate
		e.Current = documentCurrent(inner, now)
		if _, err := os.Stat(filepath.Join(dir, name+".issuer-chain.pem")); err != nil {
			e.Current = false
			e.Note = "issuer chain file missing (" + name + ".issuer-chain.pem): the verifier will not use it"
		} else if !e.Current {
			e.Note = "past nextUpdate: the verifier fetches it again"
		}
		out = append(out, e)
	}
	return out
}

// nrasCacheStatus: nras-jwks.json, NVIDIA's key set; it does not expire,
// the verifier refreshes it when a token names a key it lacks.
func nrasCacheStatus(dir string) []CacheEntry {
	var out []CacheEntry
	for _, f := range listDir(dir) {
		if f.IsDir() || f.Name() != "nras-jwks.json" {
			continue
		}
		e := CacheEntry{Kind: CacheKindNRASJWKS, Dir: dir, File: f.Name(), Subject: "NRAS key set"}
		body, err := os.ReadFile(filepath.Join(dir, f.Name()))
		if err != nil {
			e.Note = "unreadable: " + err.Error()
			out = append(out, e)
			continue
		}
		var set struct {
			Keys []json.RawMessage `json:"keys"`
		}
		if err := json.Unmarshal(body, &set); err != nil || len(set.Keys) == 0 {
			e.Note = "not a key set"
			out = append(out, e)
			continue
		}
		e.Current = true
		e.Note = fmt.Sprintf("%d keys; a key set does not expire — the verifier refreshes it when a token names a key it lacks", len(set.Keys))
		out = append(out, e)
	}
	return out
}

// rimCacheStatus: <id>.json, a RIM manifest each (checked under NVIDIA's
// RIM signing certificate on use; no expiry of its own), and
// ocsp-<hash>.der, an OCSP answer each, good until its nextUpdate.
func rimCacheStatus(dir string, now time.Time) []CacheEntry {
	var out []CacheEntry
	for _, f := range listDir(dir) {
		if f.IsDir() || strings.HasPrefix(f.Name(), ".") {
			continue
		}
		switch {
		case strings.HasPrefix(f.Name(), "ocsp-") && strings.HasSuffix(f.Name(), ".der"):
			e := CacheEntry{Kind: CacheKindOCSP, Dir: dir, File: f.Name()}
			der, err := os.ReadFile(filepath.Join(dir, f.Name()))
			if err != nil {
				e.Note = "unreadable: " + err.Error()
				out = append(out, e)
				continue
			}
			resp, err := ocsp.ParseResponse(der, nil)
			if err != nil {
				e.Note = "not an OCSP response: " + err.Error()
				out = append(out, e)
				continue
			}
			e.Subject = "serial " + resp.SerialNumber.Text(16)
			e.NotBefore, e.NotAfter = resp.ThisUpdate, resp.NextUpdate
			e.Current = !now.Before(resp.ThisUpdate) && (resp.NextUpdate.IsZero() || now.Before(resp.NextUpdate))
			e.Note = "status " + ocspStatusName(resp.Status)
			if !e.Current {
				e.Note += "; past nextUpdate: the verifier asks again"
			}
			out = append(out, e)
		case strings.HasSuffix(f.Name(), ".json"):
			e := CacheEntry{Kind: CacheKindRIM, Dir: dir, File: f.Name(), Subject: strings.TrimSuffix(f.Name(), ".json")}
			body, err := os.ReadFile(filepath.Join(dir, f.Name()))
			if err != nil {
				e.Note = "unreadable: " + err.Error()
				out = append(out, e)
				continue
			}
			if !json.Valid(body) {
				e.Note = "not a RIM manifest (not JSON)"
				out = append(out, e)
				continue
			}
			e.Current = true
			e.Note = "a RIM manifest does not expire; it is checked under NVIDIA's RIM signing certificate on use"
			out = append(out, e)
		}
	}
	return out
}

func ocspStatusName(s int) string {
	switch s {
	case ocsp.Good:
		return "good"
	case ocsp.Revoked:
		return "revoked"
	default:
		return "unknown"
	}
}
