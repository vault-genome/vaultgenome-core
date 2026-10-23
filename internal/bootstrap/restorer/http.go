// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package restorer

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/vault-genome/vaultgenome-core/internal/genome/bundle"
)

// Routes returns the Restorer's endpoints, for the daemon's API listener
// (TLS, and mTLS or bearer beyond loopback):
//
//	GET  /v1/genome/restores           — every restore's record
//	GET  /v1/genome/receipt?key_id=ID  — a completed restore's signed receipt
//	POST /v1/genome/bundles            — a sealed bundle, into BundleDir
//
// With a bearer token set, every request must carry it.
func (r *Restorer) Routes(bearerToken string) map[string]http.HandlerFunc {
	guardMethod := func(method string, next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			if req.Method != method {
				w.Header().Set("Allow", method)
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			if bearerToken != "" {
				got, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
				if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(bearerToken)) != 1 {
					writeError(w, http.StatusUnauthorized, "bearer token missing or invalid")
					return
				}
			}
			next(w, req)
		}
	}
	guard := func(next http.HandlerFunc) http.HandlerFunc { return guardMethod(http.MethodGet, next) }
	return map[string]http.HandlerFunc{
		"/v1/genome/bundles": guardMethod(http.MethodPost, r.receiveBundle),
		"/v1/genome/restores": guard(func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{"restores": r.Records()})
		}),
		"/v1/genome/receipt": guard(func(w http.ResponseWriter, req *http.Request) {
			kid := req.URL.Query().Get("key_id")
			if kid == "" {
				writeError(w, http.StatusBadRequest, "key_id required")
				return
			}
			signed, rec, ok := r.Receipt(kid)
			switch {
			case !ok:
				writeError(w, http.StatusNotFound, "no key "+kid+" was released to this destination")
			case signed.Receipt == nil && rec.State == StateFailed:
				// Final: asking again will not bring a receipt.
				writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "restore failed: " + rec.Error, "restore": rec})
			case signed.Receipt == nil:
				writeJSON(w, http.StatusConflict, map[string]any{"error": "restore not complete", "restore": rec})
			default:
				writeJSON(w, http.StatusOK, signed)
			}
		}),
	}
}

// receiveBundle takes a sealed bundle into BundleDir (ADR 0036) through
// bundle.Store, which owns bundle files: at most MaxBundleBytes, the v3
// header checked, stored as <sha256>.genome by a rename, one bundle per
// key. The key comes only from a release, and the receipt names the
// bundle's SHA-256, which the source holds to its own (ADR 0011): a
// bundle swapped on the way is caught there.
func (r *Restorer) receiveBundle(w http.ResponseWriter, req *http.Request) {
	max := r.cfg.MaxBundleBytes
	if req.ContentLength > max {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("a bundle of %d bytes exceeds the %d this destination takes", req.ContentLength, max))
		return
	}
	r.uploadMu.Lock()
	stored, err := bundle.Store(r.cfg.BundleDir, req.Body, max)
	r.uploadMu.Unlock()
	var taken *bundle.KeyTakenError
	switch {
	case errors.Is(err, bundle.ErrStoreTooLarge):
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("the bundle exceeds the %d bytes this destination takes", max))
		return
	case errors.Is(err, bundle.ErrStoreEmpty):
		writeError(w, http.StatusBadRequest, "empty body: a sealed .genome bundle is expected")
		return
	case errors.Is(err, bundle.ErrStoreNotBundle):
		writeError(w, http.StatusBadRequest, "not a v3 genome bundle")
		return
	case errors.As(err, &taken):
		writeError(w, http.StatusConflict, fmt.Sprintf("another bundle for key %s is already here (%s)", taken.KeyID, taken.Existing))
		return
	case err != nil:
		r.log.Error("genome bundle: cannot store", slog.String("err", err.Error()))
		writeError(w, http.StatusInternalServerError, "cannot store the bundle")
		return
	}
	if stored.AlreadyHere {
		writeJSON(w, http.StatusOK, map[string]any{"key_id": stored.KeyID, "bundle_sha256": stored.SHA256, "bytes": stored.Bytes, "already_here": true})
		return
	}
	r.log.Info("genome bundle received", slog.String("key_id", stored.KeyID), slog.String("bundle_sha256", stored.SHA256), slog.Int64("bytes", stored.Bytes))
	select { // a key already released for this bundle is restored now, not at the next rescan
	case r.wake <- struct{}{}:
	default:
	}
	writeJSON(w, http.StatusCreated, map[string]any{"key_id": stored.KeyID, "bundle_sha256": stored.SHA256, "bytes": stored.Bytes})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
