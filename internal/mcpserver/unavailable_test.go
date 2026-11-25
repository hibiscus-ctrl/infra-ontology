// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

//go:build noduckdb

package mcpserver

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hibiscus-ctrl/infra-ontology/internal/query"
)

var estate = filepath.Join("..", "snapshot", "testdata", "golden", "estate")

// A build without the engine serves nothing, and says why.
func TestServeWithoutTheEngine(t *testing.T) {
	st, _ := mcp.NewInMemoryTransports()
	err := Serve(t.Context(), Config{Dir: estate}, st)
	if !errors.Is(err, query.ErrUnavailable) {
		t.Errorf("served: %v", err)
	}
	// The snapshot is still checked first.
	if err := Serve(t.Context(), Config{Dir: t.TempDir()}, st); !errors.Is(err, ErrNotVerified) {
		t.Errorf("an empty folder: %v", err)
	}
}

func TestParseToolsWithoutTheEngine(t *testing.T) {
	if got, err := ParseTools("query"); err != nil || len(got) != 1 {
		t.Errorf("%v, %v", got, err)
	}
}
