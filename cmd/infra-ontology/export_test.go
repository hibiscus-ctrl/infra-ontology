// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const graphGolden = "../../internal/export/testdata/estate.graph.json"

func TestExportGraphToStdoutAndToAFile(t *testing.T) {
	_, dir := build(t)
	want, err := os.ReadFile(graphGolden)
	if err != nil {
		t.Fatal(err)
	}
	code, out, errs := exec(t, "export", "graph", dir)
	if code != 0 || out != string(want) {
		t.Fatalf("exit %d, stdout differs from the golden export (stderr %q)", code, errs)
	}
	// The same snapshot gives the same bytes, with the flags before or after it.
	file := filepath.Join(t.TempDir(), "graph.json")
	code, out, errs = exec(t, "export", "graph", dir, "-o", file)
	if code != 0 || !strings.HasSuffix(out, ": 10 nodes, 4 edges\n") {
		t.Fatalf("exit %d: %q %q", code, out, errs)
	}
	for _, want := range []string{"nodes: account 2, external 1, state_root 2", "edges: contained_in 3, defined_in 2, reads_state_of 2"} {
		if !strings.Contains(errs, want) {
			t.Errorf("stderr lacks %q: %q", want, errs)
		}
	}
	got, err := os.ReadFile(file)
	if err != nil || string(got) != string(want) {
		t.Errorf("the file differs from the golden export: %v", err)
	}
	if code, _, _ = exec(t, "export", "graph", "-o", file, "--cloud", "aws", dir); code != 0 {
		t.Errorf("--cloud aws exited %d", code)
	}
}

func TestExportGraphRefusals(t *testing.T) {
	_, dir := build(t)
	cases := []struct {
		name string
		args []string
		code int
	}{
		{"nothing to export", []string{"export"}, exitUsage},
		{"an unknown document", []string{"export", "mermaid", dir}, exitUsage},
		{"no folder", []string{"export", "graph"}, exitUsage},
		{"a bad flag", []string{"export", "graph", dir, "--format", "x"}, exitUsage},
		{"a cloud with no resources", []string{"export", "graph", dir, "--cloud", "azure"}, exitFailed},
		{"an unknown cloud", []string{"export", "graph", dir, "--cloud", "oracle"}, exitFailed},
		{"no snapshot", []string{"export", "graph", filepath.Join(t.TempDir(), "none")}, exitVerifyFailed},
		{"an unwritable file", []string{"export", "graph", dir, "-o", filepath.Join(t.TempDir(), "no", "such", "dir.json")}, exitFailed},
	}
	for _, c := range cases {
		code, out, _ := exec(t, c.args...)
		if code != c.code {
			t.Errorf("%s: exit %d, want %d", c.name, code, c.code)
		}
		if strings.HasPrefix(out, "{") {
			t.Errorf("%s: wrote a document", c.name)
		}
	}
}

func TestExportGraphRefusesATamperedSnapshot(t *testing.T) {
	_, dir := build(t)
	nodes := filepath.Join(dir, "nodes.parquet")
	raw, err := os.ReadFile(nodes)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0xff
	if err := os.WriteFile(nodes, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := exec(t, "export", "graph", dir); code != exitVerifyFailed || out != "" {
		t.Errorf("exit %d, stdout %q", code, out)
	}
}
