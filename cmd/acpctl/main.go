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
	fmt.Println("  genome seal   Capture an Ollama model and seal it inside a TEE bundle")
	fmt.Println("  genome open   Restore a sealed bundle into a target OLLAMA_MODELS directory")
	fmt.Println("  genome verify Re-hash a bundle and confirm components match envelope record")
	fmt.Println("  genome inspect Print envelope metadata without unsealing")
	fmt.Println()
	fmt.Println("Run `acpctl <command> --help` for per-subcommand flags.")
}
