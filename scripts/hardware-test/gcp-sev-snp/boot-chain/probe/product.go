// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// probe product <dir> <boot>: the code that ships, on this guest. The
// gcp-sev-snp-vtpm producer quotes for a fresh nonce; the verifier, pinned to
// the boot the first call recorded (<dir>/pinned-pcr-digest), checks the
// evidence; the chip-and-vTPM sealer seals once and opens on every later
// boot. The evidence, its nonce and the VCEK the verifier fetched are kept
// under <dir>/<boot>/ for the offline tests.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

func product(dir, boot string) int {
	out := filepath.Join(dir, "product-"+boot)
	if err := os.MkdirAll(out, 0o755); err != nil {
		fmt.Println("product FAIL:", err)
		return 1
	}
	p, err := tee.NewGCPSEVVTPMProducer(tee.GCPSEVVTPMProducerConfig{})
	if err != nil {
		fmt.Println("producer FAIL:", err)
		return 1
	}
	defer p.Close()
	sels, digest := p.VTPMBoot()
	sel := make([]string, 0, len(sels))
	for _, s := range sels {
		sel = append(sel, s.String())
	}
	m := p.Measurement()
	fmt.Printf("producer ok: measurement %x boot %s digest %x\n", []byte(m), strings.Join(sel, "+"), digest)

	pinPath := filepath.Join(dir, "pinned-pcr-digest")
	pinHex, err := os.ReadFile(pinPath)
	if os.IsNotExist(err) {
		pinHex = []byte(hex.EncodeToString(digest))
		if err := os.WriteFile(pinPath, pinHex, 0o644); err != nil {
			fmt.Println("pin FAIL:", err)
			return 1
		}
		fmt.Printf("pinned this boot: %s\n", pinHex)
	}
	pin, err := hex.DecodeString(strings.TrimSpace(string(pinHex)))
	if err != nil {
		fmt.Println("pin FAIL:", err)
		return 1
	}

	chainPath := filepath.Join(dir, "amd-milan-chain.pem")
	chain, err := os.ReadFile(chainPath)
	if os.IsNotExist(err) {
		chain, _, err = tee.FetchAMDCertChain("", "milan")
		if err == nil {
			err = os.WriteFile(chainPath, chain, 0o644)
		}
	}
	if err != nil {
		fmt.Println("AMD chain FAIL:", err)
		return 1
	}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		fmt.Println("nonce FAIL:", err)
		return 1
	}
	ev, err := p.Quote(nonce)
	if err != nil {
		fmt.Println("quote FAIL:", err)
		return 1
	}
	_ = os.WriteFile(filepath.Join(out, "evidence.json"), ev, 0o644)
	_ = os.WriteFile(filepath.Join(out, "nonce.hex"), []byte(hex.EncodeToString(nonce)+"\n"), 0o644)

	cache := filepath.Join(dir, "vcek-cache")
	_ = os.MkdirAll(cache, 0o755)
	v, err := tee.NewGCPSEVVTPMVerifier(nil, m, tee.GCPSEVVTPMVerifierConfig{
		SEV:                  tee.GCPSEVVerifierConfig{AMDRootPEM: chain, VCEKCacheDir: cache},
		AcceptablePCRDigests: [][]byte{pin},
	})
	if err != nil {
		fmt.Println("verifier FAIL:", err)
		return 1
	}
	if verdict, err := v.VerifyEvidence(ev, nonce); err != nil {
		fmt.Println("verify REFUSED:", err)
	} else {
		fmt.Printf("verify ok: instance %s/%s production=%v, boot digest %x\n", verdict.Instance.ProjectID, verdict.Instance.InstanceName, verdict.Instance.IsProduction, verdict.PCRDigest)
	}

	dev, err := os.OpenFile("/dev/sev-guest", os.O_RDWR, 0)
	if err != nil {
		fmt.Println("both FAIL:", err)
		return 1
	}
	defer dev.Close()
	vt, err := tee.NewVTPMSealer(tee.VTPMSealerConfig{PCRs: tee.DefaultGCEBootPCRs})
	if err != nil {
		fmt.Println("both FAIL:", err)
		return 1
	}
	both, err := tee.NewSEVSNPVTPMSealer(tee.NewGCPSEVSealer(dev, m, p.Policy()), vt)
	if err != nil {
		fmt.Println("both FAIL:", err)
		return 1
	}
	sealedPath := filepath.Join(dir, "both.sealed")
	aad := []byte("boot-chain probe, both")
	if blob, err := os.ReadFile(sealedPath); os.IsNotExist(err) {
		blob, err := both.Seal(probeText, aad)
		if err == nil {
			err = os.WriteFile(sealedPath, blob, 0o600)
		}
		if err != nil {
			fmt.Println("both seal FAIL:", err)
			return 1
		}
		fmt.Printf("both seal ok (%d bytes)\n", len(blob))
	} else if got, err := both.Unseal(blob, aad); err != nil {
		fmt.Println("both open REFUSED:", err)
	} else if string(got) != string(probeText) {
		fmt.Println("both open FAIL: other bytes")
		return 1
	} else {
		fmt.Println("both open ok")
	}
	return 0
}
