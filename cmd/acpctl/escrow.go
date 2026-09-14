// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ai-continuity-platform/core/internal/genome/escrow"
)

// escrowCmd implements `acpctl escrow keygen`: the release authority's
// key-escrow key pair. Sealers encapsulate each genome key to the public
// half (`acpctl genome seal --escrow-to`); the private half stays on the
// release host, which opens an envelope only to release its key to an
// attested destination (`sagvd crosscloud-restore -key-escrow`).
func escrowCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "keygen" {
		if len(args) > 0 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
			fmt.Fprintln(stdout, "usage: acpctl escrow keygen --out PRIVATE --pub PUBLIC.pem")
			return 0
		}
		fmt.Fprintln(stderr, "usage: acpctl escrow keygen --out PRIVATE --pub PUBLIC.pem")
		return 2
	}
	fs := flag.NewFlagSet("escrow keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "Where to write the private key (32 raw bytes, mode 0600; never overwritten)")
	pub := fs.String("pub", "", "Where to write the public key (PEM) that sealers use")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *out == "" || *pub == "" {
		fmt.Fprintln(stderr, "acpctl escrow keygen: --out and --pub are required")
		return 2
	}
	priv, err := escrow.GenerateKey()
	if err != nil {
		fmt.Fprintf(stderr, "acpctl escrow keygen: %v\n", err)
		return 1
	}
	pemBytes, err := escrow.PublicPEM(priv.PublicKey())
	if err != nil {
		fmt.Fprintf(stderr, "acpctl escrow keygen: %v\n", err)
		return 1
	}
	if err := writeKeyFile(*out, priv.Bytes(), false); err != nil {
		fmt.Fprintf(stderr, "acpctl escrow keygen: %v\n", err)
		return 1
	}
	if err := os.WriteFile(*pub, pemBytes, 0o644); err != nil {
		fmt.Fprintf(stderr, "acpctl escrow keygen: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "escrow key %s: private %s (keep it on the release host), public %s (give it to sealers)\n",
		escrow.KeyTag(priv.PublicKey()), *out, *pub)
	return 0
}
