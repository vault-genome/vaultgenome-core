// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command probe seals a fixed text with the sealers a GCP SEV-SNP guest
// has — the chip's derived key (gcp_sev_snp_seal.go), and the guest's vTPM
// (vtpm_sealer.go) under each PCR selection named on the command line —
// and, on a later boot, opens each, printing one line per sealer. The
// boot-chain kit seals on one boot and opens on the next boots: the same
// kernel again, then another kernel.
//
//	probe seal <dir> [sha256:<pcrs> ...]
//	probe open <dir> [sha256:<pcrs> ...]
//	probe product <dir> <boot>     (product.go)
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

var probeText = []byte("vault-genome boot-chain probe: the same text, sealed twice")

func main() {
	if len(os.Args) == 4 && os.Args[1] == "product" {
		os.Exit(product(os.Args[2], os.Args[3]))
	}
	if len(os.Args) < 3 || (os.Args[1] != "seal" && os.Args[1] != "open") {
		fmt.Fprintln(os.Stderr, "usage: probe seal|open <dir> [sha256:<pcrs> ...]")
		os.Exit(2)
	}
	mode, dir, selections := os.Args[1], os.Args[2], os.Args[3:]
	if len(selections) == 0 {
		selections = []string{tee.DefaultVTPMSealPCRs}
	}
	p, err := tee.NewGCPSEVProducer(tee.GCPSEVProducerConfig{})
	if err != nil {
		fmt.Println("producer FAIL:", err)
		os.Exit(1)
	}
	defer p.Close()
	m := p.Measurement()
	fmt.Printf("measurement %s policy 0x%x\n", hex.EncodeToString(m[:]), p.Policy())

	dev, err := os.OpenFile("/dev/sev-guest", os.O_RDWR, 0)
	if err != nil {
		fmt.Println("chip FAIL: open /dev/sev-guest:", err)
		os.Exit(1)
	}
	defer dev.Close()
	sealers := []struct {
		name string
		s    tee.Sealer
	}{{"chip", tee.NewGCPSEVSealer(dev, m, p.Policy())}}
	for _, sel := range selections {
		vt, err := tee.NewVTPMSealer(tee.VTPMSealerConfig{PCRs: sel})
		if err != nil {
			fmt.Println("vtpm FAIL:", err)
			os.Exit(1)
		}
		sealers = append(sealers, struct {
			name string
			s    tee.Sealer
		}{"vtpm[" + sel + "]", vt})
	}
	aad := []byte("boot-chain probe")
	failed := false
	for _, x := range sealers {
		file := filepath.Join(dir, strings.NewReplacer("[", "-", "]", "", ":", "-", ",", "_").Replace(x.name)+".sealed")
		switch mode {
		case "seal":
			blob, err := x.s.Seal(probeText, aad)
			if err == nil {
				err = os.WriteFile(file, blob, 0o600)
			}
			if err != nil {
				fmt.Printf("%s seal FAIL: %v\n", x.name, err)
				failed = true
				continue
			}
			fmt.Printf("%s seal ok (%d bytes)\n", x.name, len(blob))
		case "open":
			blob, err := os.ReadFile(file)
			if err != nil {
				fmt.Printf("%s open FAIL: %v\n", x.name, err)
				failed = true
				continue
			}
			got, err := x.s.Unseal(blob, aad)
			switch {
			case err != nil:
				fmt.Printf("%s open REFUSED: %v\n", x.name, err)
			case !bytes.Equal(got, probeText):
				fmt.Printf("%s open FAIL: opened to other bytes\n", x.name)
				failed = true
			default:
				fmt.Printf("%s open ok\n", x.name)
			}
		}
	}
	if failed {
		os.Exit(1)
	}
}
