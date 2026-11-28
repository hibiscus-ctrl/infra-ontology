// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !noduckdb

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var estate = filepath.Join("..", "..", "internal", "snapshot", "testdata", "golden", "estate")

const estateID = "99688f074a1df1b1d4191ef98054e274628382e85aee41c72f8fa9257ed83401"

func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestQueryPrintsTheTableAndItsCitation(t *testing.T) {
	code, out, errs := runCLI(t, "query", estate, "--sql", "SELECT kind, count(*) AS n FROM nodes GROUP BY kind ORDER BY kind")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	for _, want := range []string{"kind", "resource", "snapshot  " + estateID, "query     sha256:", "result    sha256:", "engine    duckdb 2.", "infra-ontology/sql/v1", "oldest source 2026-11-25T09:05:00Z", "0 failed sources"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestQueryTellsWhenTheCapCutTheResult(t *testing.T) {
	code, out, _ := runCLI(t, "query", estate, "--sql", "SELECT * FROM nodes", "--limit", "3")
	if code != 0 || !strings.Contains(out, "3 rows, cut by the rows cap: more exist") {
		t.Errorf("exit %d:\n%s", code, out)
	}
}

func TestQueryRefusesWhatTheDialectRefuses(t *testing.T) {
	for _, sql := range []string{"SELECT * FROM read_csv('/etc/passwd')", "DROP TABLE nodes", "SELECT 1; SELECT 2", "SET threads = 1"} {
		code, out, errs := runCLI(t, "query", estate, "--sql", sql)
		if code != 1 || out != "" || !strings.Contains(errs, "rejected by the read-only dialect") {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", sql, code, out, errs)
		}
	}
}

func TestQueryUsage(t *testing.T) {
	for _, args := range [][]string{
		{"query"},
		{"query", estate},
		{"query", estate, "--sql", "SELECT 1", "--stored", "blast"},
		{"query", estate, "--sql", "SELECT 1", "--param", "a=b"},
		{"query", estate, "--stored", "blast", "--param", "novalue"},
		{"query", estate, "--stored", "blast", "--param", "a=1", "--param", "a=2"},
		{"query", estate, "other", "--sql", "SELECT 1"},
		{"verify"},
		{"verify", "--answer", "a.json", estate},
	} {
		if code, _, _ := runCLI(t, args...); code != 2 {
			t.Errorf("%q: exit %d, want 2", args, code)
		}
	}
	if code, _, errs := runCLI(t, "query", estate, "--stored", "blast"); code != 1 || !strings.Contains(errs, "--param node=") {
		t.Errorf("a missing parameter: exit %d, %q", code, errs)
	}
	if code, _, errs := runCLI(t, "query", estate, "--stored", "nope"); code != 1 || !strings.Contains(errs, "blast") {
		t.Errorf("an unknown stored query: exit %d, %q", code, errs)
	}
}

func TestQueryList(t *testing.T) {
	code, out, _ := runCLI(t, "query", "--list")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"blast (version 2)", "cone (version 2)", "unmanaged", "summary", "--param node=<string>", "(required)", "int 0..50"} {
		if !strings.Contains(out, want) {
			t.Errorf("--list lacks %q:\n%s", want, out)
		}
	}
}

func TestQueryJSONThenVerify(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "answer.json")
	code, out, errs := runCLI(t, "query", estate, "--stored", "unmanaged", "--json", "--answer-out", file)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var got struct {
		Columns []string `json:"columns"`
		Rows    [][]any  `json:"rows"`
		Answer  struct {
			StoredQuery string `json:"stored_query"`
			SnapshotID  string `json:"snapshot_id"`
			RowCount    int    `json:"row_count"`
		} `json:"answer"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if got.Answer.StoredQuery != "unmanaged" || got.Answer.SnapshotID != estateID || got.Answer.RowCount != 1 || len(got.Rows) != 1 {
		t.Errorf("--json: %+v", got)
	}

	// The answer file, and the whole --json output, both verify.
	if code, out, errs := runCLI(t, "verify", "--answer", file, "--snapshot", estate); code != 0 || !strings.Contains(out, "the answer is reproduced") {
		t.Errorf("verify the answer file: exit %d: %s%s", code, out, errs)
	}
	full := filepath.Join(dir, "full.json")
	if err := os.WriteFile(full, []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out, errs := runCLI(t, "verify", "--answer", full, "--snapshot", estate, "--json"); code != 0 || !strings.Contains(out, `"ok": true`) {
		t.Errorf("verify the --json output: exit %d: %s%s", code, out, errs)
	}

	// A changed result hash does not verify.
	raw, _ := os.ReadFile(file)
	bad := strings.Replace(string(raw), `"result_hash": "sha256:`, `"result_hash": "sha256:0`, 1)
	badFile := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badFile, []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ = runCLI(t, "verify", "--answer", badFile, "--snapshot", estate)
	if code != 4 || !strings.Contains(out, "FAILED") || !strings.Contains(out, "result_hash") {
		t.Errorf("a tampered answer: exit %d:\n%s", code, out)
	}

	// Without --snapshot the snapshot is looked up by its id in a folder of snapshots.
	root := filepath.Join(dir, "snapshots")
	if err := os.CopyFS(filepath.Join(root, "20261125T101500Z-99688f074a1d"), os.DirFS(estate)); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := runCLI(t, "verify", "--answer", file, "--snapshots", root); code != 0 {
		t.Errorf("verify by id: exit %d: %s", code, errs)
	}
	if code, _, errs := runCLI(t, "verify", "--answer", file, "--snapshots", filepath.Join(dir, "none")); code != 1 || !strings.Contains(errs, "--snapshot DIR") {
		t.Errorf("verify with no snapshot: exit %d: %s", code, errs)
	}
	// A snapshot that does not verify is exit 4.
	other := filepath.Join(dir, "other")
	if err := os.CopyFS(other, os.DirFS(estate)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "nodes.parquet"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runCLI(t, "verify", "--answer", file, "--snapshot", other); code != 4 {
		t.Errorf("a snapshot that does not verify: exit %d", code)
	}
}

func TestVerifyWithAFolderIsSnapshotVerify(t *testing.T) {
	if code, out, _ := runCLI(t, "verify", estate); code != 0 || !strings.Contains(out, "ok: ") {
		t.Errorf("exit %d: %s", code, out)
	}
}

func TestVerifyRefusesAnythingButAnAnswer(t *testing.T) {
	f := filepath.Join(t.TempDir(), "x.json")
	for _, content := range []string{"not json", `{"foo": 1}`, `{"answer": null}`} {
		if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if code, _, _ := runCLI(t, "verify", "--answer", f, "--snapshot", estate); code != 1 {
			t.Errorf("%q: exit %d, want 1", content, code)
		}
	}
}
