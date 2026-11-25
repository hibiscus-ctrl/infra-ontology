// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

//go:build noduckdb

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var estate = filepath.Join("..", "..", "internal", "snapshot", "testdata", "golden", "estate")

// The build without the engine says so, and hands over the SQL to run with
// DuckDB itself.
func TestQueryWithoutTheEngine(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"query", estate, "--stored", "blast", "--param", "node=module.network"}, &out, &errb)
	got := errb.String()
	if code != 1 || out.Len() != 0 {
		t.Fatalf("exit %d, stdout %q", code, out.String())
	}
	for _, want := range []string{"query engine not built in (noduckdb build)", "CREATE TABLE nodes AS SELECT * FROM read_parquet(", "nodes.parquet", "WITH RECURSIVE targets", "'module.network'", "56eda5cee850"} {
		if !strings.Contains(got, want) {
			t.Errorf("stderr lacks %q:\n%s", want, got)
		}
	}
}

func TestVerifyAnswerWithoutTheEngine(t *testing.T) {
	var out, errb bytes.Buffer
	file := filepath.Join(t.TempDir(), "a.json")
	answer := `{"snapshot_id": "56eda5cee85096e7c09c20074c7f7f315519b1f66ab23ab06c0695167a88afbc", "query": "SELECT 1"}`
	if err := os.WriteFile(file, []byte(answer), 0o644); err != nil {
		t.Fatal(err)
	}
	code := run([]string{"verify", "--answer", file, "--snapshot", estate}, &out, &errb)
	if code != 1 || !strings.Contains(errb.String(), "noduckdb build") {
		t.Errorf("exit %d: %s", code, errb.String())
	}
}

// serve-mcp needs the engine: the build without it says so and serves nothing.
func TestServeMCPWithoutTheEngine(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"serve-mcp", estate}, &out, &errb)
	if code != 1 || out.Len() != 0 {
		t.Fatalf("exit %d, stdout %q", code, out.String())
	}
	for _, want := range []string{"serve-mcp: unavailable", "query engine not built in (noduckdb build)", "without the noduckdb tag"} {
		if !strings.Contains(errb.String(), want) {
			t.Errorf("stderr lacks %q:\n%s", want, errb.String())
		}
	}
}
