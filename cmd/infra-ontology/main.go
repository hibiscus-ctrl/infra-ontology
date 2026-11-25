// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

// Command infra-ontology builds a read-only, cited snapshot of a cloud estate
// and its Terraform state. So far it can verify a snapshot, compare two and
// (as a test and development path) build one from a JSON file; reading state
// and inventory comes later.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/hibiscus-ctrl/infra-ontology/internal/version"
)

// Exit codes.
const (
	exitOK           = 0
	exitFailed       = 1
	exitUsage        = 2
	exitVerifyFailed = 4 // a snapshot or an answer did not verify
)

const usage = `usage: infra-ontology <command> [flags]

commands:
  snapshot verify [--json] <dir>      check a snapshot folder against its manifest
  query <dir> --sql TEXT              read-only SQL over a snapshot, with row caps and a
  query <dir> --stored NAME [--param k=v ...]
                                      citation of the snapshot, query and result
                                      (--json, --answer-out FILE, --list)
  verify --answer FILE [--snapshot <dir>]
                                      re-run a cited answer against its snapshot
  diff [--json] <a> [<b>]             what changed from snapshot a to snapshot b
                                      (b defaults to a's parent: what changed in a)
  serve-mcp <dir> [--tools LIST] [--audit-log FILE]
                                      an MCP server on stdio over a verified snapshot:
                                      inventory, blast_radius, query, snapshot_info
  snapshot build --from-json FILE     build a snapshot from a JSON file (for tests
                                      and development; state and inventory readers
                                      come later)
  version                             print the version

exit codes: 0 ok, 1 failed, 2 usage error, 4 a snapshot or an answer did not verify
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the command line and returns the process's exit code.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "version" || args[0] == "--version" {
		fmt.Fprintf(stdout, "infra-ontology %s\n", version.Version)
		return exitOK
	}
	switch args[0] {
	case "snapshot":
		return runSnapshot(args[1:], stdout, stderr)
	case "diff":
		return runDiff(args[1:], stdout, stderr)
	case "query":
		return runQuery(args[1:], stdout, stderr)
	case "verify":
		return runVerifyTop(args[1:], stdout, stderr)
	case "serve-mcp":
		return runServeMCP(args[1:], stdout, stderr)
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return exitOK
	}
	fmt.Fprintf(stderr, "infra-ontology: unknown command %q\n\n%s", args[0], usage)
	return exitUsage
}

func runSnapshot(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, "infra-ontology snapshot: say what to do: verify or build\n\n"+usage)
		return exitUsage
	}
	switch args[0] {
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "build":
		return runBuild(args[1:], stdout, stderr)
	}
	fmt.Fprintf(stderr, "infra-ontology snapshot: unknown subcommand %q\n\n%s", args[0], usage)
	return exitUsage
}
