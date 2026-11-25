// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

// Command infra-ontology builds a read-only, cited snapshot of a cloud estate
// and its Terraform state. The commands are not written yet: for now it
// prints its version.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/hibiscus-ctrl/infra-ontology/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the command line and returns the process's exit code: 0 on
// success, 2 on a usage error.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "version" || args[0] == "--version" {
		fmt.Fprintf(stdout, "infra-ontology %s\n", version.Version)
		return 0
	}
	fmt.Fprintf(stderr, "infra-ontology: unknown command %q (only \"version\" exists so far)\n", args[0])
	return 2
}
