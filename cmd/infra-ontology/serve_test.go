// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !noduckdb

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// serveCLI runs `serve-mcp` with the given arguments, its standard input and
// output on pipes a client talks over, and returns the client's session and a
// function that waits for the command to exit.
func serveCLI(t *testing.T, args ...string) (*mcp.ClientSession, func() (code int, stdout, stderr string)) {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	var errb bytes.Buffer
	old := stdin
	stdin = inR
	t.Cleanup(func() { stdin = old })
	done := make(chan int, 1)
	go func() {
		code := run(append([]string{"serve-mcp"}, args...), outW, &errb)
		_ = outW.Close()
		done <- code
	}()
	client := mcp.NewClient(&mcp.Implementation{Name: "cli-test"}, nil)
	cs, err := client.Connect(t.Context(), &mcp.IOTransport{Reader: outR, Writer: inW}, nil)
	if err != nil {
		t.Fatalf("connect: %v\n%s", err, errb.String())
	}
	return cs, func() (int, string, string) {
		_ = cs.Close()
		_ = inW.Close()
		return <-done, "", errb.String()
	}
}

func TestServeMCPOverStdio(t *testing.T) {
	log := filepath.Join(t.TempDir(), "audit.jsonl")
	cs, wait := serveCLI(t, estate, "--tools", "snapshot_info,query", "--audit-log", log)
	list, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range list.Tools {
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"query", "snapshot_info"}) {
		t.Errorf("tools %v", names)
	}
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "query", Arguments: map[string]any{"sql": "SELECT count(*) AS n FROM nodes"}})
	if err != nil || res.IsError {
		t.Fatalf("query: %v %+v", err, res)
	}
	if !strings.Contains(string(mustJSON(t, res.StructuredContent)), estateID) {
		t.Errorf("the answer does not cite the snapshot: %v", res.StructuredContent)
	}
	code, _, stderr := wait()
	if code != 0 {
		t.Errorf("exit %d: %s", code, stderr)
	}
	// With --audit-log the log is the file, not standard error.
	raw, err := os.ReadFile(log)
	if err != nil || strings.Count(string(raw), "\n") != 1 || !strings.Contains(string(raw), `"tool":"query"`) {
		t.Errorf("audit file %q, %v", raw, err)
	}
	if strings.Contains(stderr, `"tool"`) {
		t.Errorf("the audit log also went to standard error: %s", stderr)
	}
	if info, err := os.Stat(log); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("audit file mode %v, %v", info, err)
	}
}

func TestServeMCPAppendsToTheAuditLog(t *testing.T) {
	log := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(log, []byte("{\"earlier\":true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cs, wait := serveCLI(t, estate, "--audit-log", log)
	if _, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "snapshot_info"}); err != nil {
		t.Fatal(err)
	}
	wait()
	raw, _ := os.ReadFile(log)
	if lines := strings.Split(strings.TrimSpace(string(raw)), "\n"); len(lines) != 2 || lines[0] != `{"earlier":true}` {
		t.Errorf("audit file %q", raw)
	}
}

func TestServeMCPWritesTheAuditLogToStderrByDefault(t *testing.T) {
	cs, wait := serveCLI(t, estate)
	if _, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "snapshot_info"}); err != nil {
		t.Fatal(err)
	}
	_, _, stderr := wait()
	if !strings.Contains(stderr, `"tool":"snapshot_info"`) {
		t.Errorf("stderr %q", stderr)
	}
}

func TestServeMCPUsage(t *testing.T) {
	for _, args := range [][]string{
		{"serve-mcp"},
		{"serve-mcp", estate, estate},
		{"serve-mcp", estate, "--tools", "inventory,drop"},
		{"serve-mcp", estate, "--nope"},
	} {
		code, out, errs := runCLI(t, args...)
		if code != 2 || out != "" || errs == "" {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", args, code, out, errs)
		}
	}
}

func TestServeMCPRefusesASnapshotThatDoesNotVerify(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"manifest.json", "nodes.parquet", "edges.parquet", "sources.parquet"} {
		b, err := os.ReadFile(filepath.Join(estate, f))
		if err != nil {
			t.Fatal(err)
		}
		if f == "edges.parquet" {
			b = append(b, 0)
		}
		if err := os.WriteFile(filepath.Join(dir, f), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	code, out, errs := runCLI(t, "serve-mcp", dir)
	if code != 4 || out != "" || !strings.Contains(errs, "not serving") || !strings.Contains(errs, "does not verify") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, errs)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
