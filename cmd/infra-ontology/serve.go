// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hibiscus-ctrl/infra-ontology/internal/mcpserver"
	"github.com/hibiscus-ctrl/infra-ontology/internal/query"
	"github.com/hibiscus-ctrl/infra-ontology/internal/version"
)

// stdin is what serve-mcp reads requests from. A test replaces it.
var stdin io.Reader = os.Stdin

// nopWriteCloser lets the server write to stdout without closing it.
type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// runServeMCP is `serve-mcp`: an MCP server on stdio over one snapshot. Its
// standard output carries the protocol and nothing else; the audit log goes
// to standard error unless --audit-log names a file.
func runServeMCP(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("serve-mcp", stderr)
	tools := fs.String("tools", "", "the tools to enable, comma-separated: "+strings.Join(mcpserver.ToolNames, ", ")+" (default: all)")
	auditLog := fs.String("audit-log", "", "append one JSON line for each tool call to this file (default: standard error)")
	memory := fs.String("memory", "512MB", "the engine's memory limit")
	dirs, ok := parse(fs, args, 1, 1, stderr)
	if !ok {
		return exitUsage
	}
	enabled, err := mcpserver.ParseTools(*tools)
	if err != nil {
		fmt.Fprintf(stderr, "infra-ontology serve-mcp: --tools: %v\n", err)
		return exitUsage
	}
	cfg := mcpserver.Config{Dir: dirs[0], MemoryLimit: *memory, Tools: enabled, Audit: stderr, Version: version.Version}
	if *auditLog != "" {
		// Append-only: the log is never truncated, and others cannot read it.
		f, err := os.OpenFile(*auditLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			fmt.Fprintf(stderr, "infra-ontology serve-mcp: %v\n", err)
			return exitFailed
		}
		defer func() { _ = f.Close() }()
		cfg.Audit = f
	}
	ctx, stop := signalContext()
	defer stop()
	err = mcpserver.Serve(ctx, cfg, &mcp.IOTransport{Reader: io.NopCloser(stdin), Writer: nopWriteCloser{stdout}})
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, mcpserver.ErrNotVerified):
		fmt.Fprintf(stderr, "infra-ontology serve-mcp: not serving: %v\n", err)
		return exitVerifyFailed
	case errors.Is(err, query.ErrUnavailable):
		fmt.Fprintf(stderr, "infra-ontology serve-mcp: unavailable: %v\nBuild the command without the noduckdb tag to serve a snapshot over MCP.\n", err)
		return exitFailed
	}
	fmt.Fprintf(stderr, "infra-ontology serve-mcp: %v\n", err)
	return exitFailed
}
