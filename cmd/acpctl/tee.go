// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// teeCmd dispatches `acpctl tee <subcommand>`: what an operator needs from
// the hardware vendors before the daemons verify a peer.
//
//	fetch-amd-chain  — the ASK+ARK chain of an AMD product line from AMD
//	                   KDS, verified against the roots this build pins
//	                   (ADR 0024), written for amd_cert_chain_path
func teeCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: acpctl tee <fetch-amd-chain> [flags]")
		return 2
	}
	switch args[0] {
	case "fetch-amd-chain":
		return teeFetchAMDChainCmd(args[1:], stdout, stderr)
	case "help", "--help", "-h":
		fmt.Fprintln(stdout, "tee subcommands:")
		fmt.Fprintln(stdout, "  fetch-amd-chain  — fetch an AMD product line's ASK+ARK chain from AMD KDS, verify it against the pinned roots, write it for amd_cert_chain_path")
		return 0
	default:
		fmt.Fprintf(stderr, "acpctl tee: unknown subcommand %q\n", args[0])
		return 2
	}
}

func teeFetchAMDChainCmd(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("tee fetch-amd-chain", flag.ContinueOnError)
	flags.SetOutput(stderr)
	product := flags.String("product", "", "the chip's AMD product line: milan, genoa or turin (required)")
	out := flags.String("out", "", "where to write the ASK+ARK chain, PEM (required)")
	kdsURL := flags.String("kds-url", "", "AMD KDS base URL (default https://kdsintf.amd.com; a mirror for a site that cannot reach it)")
	force := flags.Bool("force", false, "overwrite --out if it exists")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *product == "" || *out == "" {
		fmt.Fprintln(stderr, "acpctl tee fetch-amd-chain: --product and --out are required")
		flags.Usage()
		return 2
	}
	if _, err := os.Stat(*out); err == nil && !*force {
		fmt.Fprintf(stderr, "acpctl tee fetch-amd-chain: %s exists; pass --force to overwrite it\n", *out)
		return 2
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(stderr, "acpctl tee fetch-amd-chain: stat %s: %v\n", *out, err)
		return 1
	}
	chain, info, err := tee.FetchAMDCertChain(*kdsURL, *product)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl tee fetch-amd-chain: %v\n", err)
		return 1
	}
	if err := os.WriteFile(*out, chain, 0o644); err != nil {
		fmt.Fprintf(stderr, "acpctl tee fetch-amd-chain: write %s: %v\n", *out, err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote %s: the %s chain, %d bytes\n", *out, info.Product, len(chain))
	fmt.Fprintf(stdout, "  ASK: CN=%s\n", info.ASKSubjectCN)
	fmt.Fprintf(stdout, "  ARK: CN=%s, sha256 %s — a root this build pins (ADR 0024)\n", info.ARKSubjectCN, info.ARKFingerprintSHA256)
	return 0
}
