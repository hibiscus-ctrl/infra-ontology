// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/hibiscus-ctrl/infra-ontology/internal/export"
	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
	"github.com/hibiscus-ctrl/infra-ontology/internal/version"
)

// runExport is `export`.
func runExport(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "graph" {
		fmt.Fprint(stderr, "infra-ontology export: say what to write: graph\n\n"+usage)
		return exitUsage
	}
	fs := newFlags("export graph", stderr)
	out := fs.String("o", "", "write the document to this file (default: standard output)")
	fs.StringVar(out, "output", "", "same as -o")
	cloud := fs.String("cloud", "", "the cloud to export, aws, azure or google; needed when the snapshot has resources in more than one")
	dirs, ok := parse(fs, args[1:], 1, 1, stderr)
	if !ok {
		return exitUsage
	}
	l, err := snapshot.Load(dirs[0])
	if err != nil {
		fmt.Fprintf(stderr, "infra-ontology export graph: %v\n", err)
		return exitVerifyFailed
	}
	res, err := export.ToGraph(l, export.Options{Cloud: *cloud, Tool: snapshot.Tool{Name: "infra-ontology", Version: version.Version}})
	if err != nil {
		fmt.Fprintf(stderr, "infra-ontology export graph: %v\n", err)
		return exitFailed
	}
	raw, err := export.Marshal(res.Graph)
	if err != nil {
		fmt.Fprintf(stderr, "infra-ontology export graph: %v\n", err)
		return exitFailed
	}
	if *out == "" {
		_, _ = stdout.Write(raw)
	} else {
		if err := os.WriteFile(*out, raw, 0o644); err != nil { //nolint:gosec // a document meant to be shared
			fmt.Fprintf(stderr, "infra-ontology export graph: %v\n", err)
			return exitFailed
		}
		fmt.Fprintf(stdout, "%s: %d nodes, %d edges\n", printable(*out), len(res.Graph.Nodes), len(res.Graph.Edges))
	}
	if n, e := res.Dropped.Total(); n+e > 0 {
		fmt.Fprintf(stderr, "left out of graph/v1 (%s)\n", res.Dropped)
	}
	return exitOK
}
