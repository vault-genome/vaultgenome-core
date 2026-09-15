// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"
)

var (
	version = "0.0.0-dev"
	commit  = "none"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-v":
			fmt.Printf("acpctl %s (commit %s)\n", version, commit)
			return
		case "help", "--help", "-h":
			printUsage()
			return
		case "recover":
			os.Exit(recoverCmd(os.Args[2:], os.Stdout, os.Stderr))
		case "status":
			os.Exit(statusCmd(os.Args[2:], os.Stdout, os.Stderr))
		case "audit":
			os.Exit(auditCmd(os.Args[2:], os.Stdout, os.Stderr))
		case "lineage":
			os.Exit(lineageCmd(os.Args[2:], os.Stdout, os.Stderr))
		case "genome":
			os.Exit(genomeCmd(os.Args[2:], os.Stdout, os.Stderr))
		case "stop":
			os.Exit(stopCmd(os.Args[2:], os.Stdout, os.Stderr))
		case "escrow":
			os.Exit(escrowCmd(os.Args[2:], os.Stdout, os.Stderr))
		case "sentinel":
			os.Exit(sentinelCmd(os.Args[2:], os.Stdout, os.Stderr))
		case "failover":
			os.Exit(failoverCmd(os.Args[2:], os.Stdout, os.Stderr))
		}
	}

	printUsage()
	os.Exit(2)
}

func printUsage() {
	fmt.Println("acpctl — AI Continuity Platform administrative CLI")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  acpctl <command> [flags]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  version       Print the build version and exit")
	fmt.Println("  help          Print this message")
	fmt.Println("  recover       Restore a sealed vault inside a fresh TEE")
	fmt.Println("  status        Print a read-only summary of the audit log")
	fmt.Println("  audit query   List events filtered by kind / session / time")
	fmt.Println("  audit verify  Replay the audit chain and verify hashes + signatures")
	fmt.Println("  lineage       Trace events tied to a session or manifest ID")
	fmt.Println("  genome seal   Seal a model or directory into a bundle; its key goes to --key-out")
	fmt.Println("  genome open   Restore a bundle with its --key-file, all or nothing (alias: rewind)")
	fmt.Println("  genome verify Check a bundle (and, with --restored, a restored tree) against its seal")
	fmt.Println("  genome inspect Print a bundle's header without its key")
	fmt.Println("  genome chain  Validate the lineage of a directory of bundles")
	fmt.Println("  stop keygen   Create the operator key that signs stop lists")
	fmt.Println("  stop issue    Sign a list that stops all key releases or revokes destinations")
	fmt.Println("  stop verify   Check a stop list against the operator public key")
	fmt.Println("  escrow keygen Create the release authority's key-escrow key pair")
	fmt.Println("  sentinel keygen  Create the sentinel's signing key")
	fmt.Println("  sentinel watch   Keep a running model's state sealed; report when a tripwire fires")
	fmt.Println("  failover issue   Sign the operator's failover policy: which standby, on which signs of failure")
	fmt.Println("  failover verify  Check a failover policy against the operator public key")
	fmt.Println()
	fmt.Println("Run `acpctl <command> --help` for per-subcommand flags.")
}
