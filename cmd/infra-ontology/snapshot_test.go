// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const estateJSON = "../../internal/snapshot/testdata/estate.json"

func exec(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

// build writes the fixture estate as a snapshot in a new folder and returns the
// snapshot's folder.
func build(t *testing.T) (parent, dir string) {
	t.Helper()
	parent = t.TempDir()
	code, out, errs := exec(t, "snapshot", "build", "--from-json", estateJSON, "--out", parent)
	if code != 0 {
		t.Fatalf("build exited %d: %s", code, errs)
	}
	dir = strings.SplitN(out, "\n", 2)[0]
	if filepath.Dir(dir) != parent || !strings.HasPrefix(filepath.Base(dir), "20261125T101500Z-") {
		t.Fatalf("build printed %q", out)
	}
	return parent, dir
}

func TestBuildThenVerify(t *testing.T) {
	_, dir := build(t)
	code, out, errs := exec(t, "snapshot", "verify", dir)
	if code != 0 || errs != "" {
		t.Fatalf("verify exited %d: %s%s", code, out, errs)
	}
	for _, want := range []string{"ok: " + dir, "label     baseline", "nodes     15 rows", "edges     15 rows", "sources   3 rows"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	code, out, _ = exec(t, "snapshot", "verify", "--json", dir)
	var res struct {
		OK         bool     `json:"ok"`
		SnapshotID string   `json:"snapshot_id"`
		Problems   []string `json:"problems"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil || code != 0 || !res.OK || len(res.SnapshotID) != 64 || len(res.Problems) != 0 {
		t.Errorf("--json: code %d, %+v, %v\n%s", code, res, err, out)
	}
}

func TestBuildMatchesTheGoldenSnapshot(t *testing.T) {
	_, dir := build(t)
	for _, name := range []string{"manifest.json", "nodes.parquet", "edges.parquet", "sources.parquet"} {
		got, _ := os.ReadFile(filepath.Join(dir, name))
		want, err := os.ReadFile(filepath.Join("../../internal/snapshot/testdata/golden/estate", name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s built from the JSON fixture differs from the golden file", name)
		}
	}
}

func TestVerifyFailsOnATamperedTable(t *testing.T) {
	_, dir := build(t)
	p := filepath.Join(dir, "nodes.parquet")
	b, _ := os.ReadFile(p)
	b[len(b)/2] ^= 1
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ := exec(t, "snapshot", "verify", dir)
	if code != 4 || !strings.Contains(out, "FAILED") || !strings.Contains(out, "nodes.parquet: sha256") {
		t.Errorf("exit %d, output %q, want 4 and the table named", code, out)
	}
	code, out, _ = exec(t, "snapshot", "verify", "--json", dir)
	var res struct {
		OK       bool     `json:"ok"`
		Problems []string `json:"problems"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil || code != 4 || res.OK || len(res.Problems) == 0 {
		t.Errorf("--json: code %d, %+v, %v", code, res, err)
	}
}

func TestBuildRefusesAttributeValues(t *testing.T) {
	raw, _ := os.ReadFile(estateJSON)
	bad := strings.Replace(string(raw), `"nodes": [`, `"nodes": [ {"node_id": "x", "attributes": {"password": "hunter2"}},`, 1)
	file := filepath.Join(t.TempDir(), "bad.json")
	_ = os.WriteFile(file, []byte(bad), 0o644)
	code, _, errs := exec(t, "snapshot", "build", "--from-json", file, "--out", t.TempDir())
	if code != 1 || !strings.Contains(errs, "unknown field") {
		t.Errorf("exit %d, stderr %q, want 1 and an unknown-field error", code, errs)
	}
}

func TestDiffByDefaultAgainstTheParent(t *testing.T) {
	parent, first := build(t)
	// A second snapshot, from a fixture without the legacy bucket, that follows the first.
	raw, _ := os.ReadFile(estateJSON)
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	nodes := doc["nodes"].([]any)
	var kept []any
	var legacyID string
	for _, n := range nodes {
		if n.(map[string]any)["native_id"] == "acme-legacy-uploads" {
			legacyID = n.(map[string]any)["node_id"].(string)
			continue
		}
		kept = append(kept, n)
	}
	var edges []any
	for _, e := range doc["edges"].([]any) {
		if e.(map[string]any)["from_id"] != legacyID {
			edges = append(edges, e)
		}
	}
	doc["nodes"], doc["edges"] = kept, edges
	next, _ := json.Marshal(doc)
	file := filepath.Join(t.TempDir(), "next.json")
	_ = os.WriteFile(file, next, 0o644)
	_, out, _ := exec(t, "snapshot", "verify", "--json", first)
	var v struct {
		SnapshotID string `json:"snapshot_id"`
	}
	_ = json.Unmarshal([]byte(out), &v)
	code, out, errs := exec(t, "snapshot", "build", "--from-json", file, "--out", parent, "--parent", v.SnapshotID,
		"--label", "bucket removed", "--created-at", "2026-11-26T08:00:00Z")
	if code != 0 {
		t.Fatalf("build exited %d: %s", code, errs)
	}
	second := strings.SplitN(out, "\n", 2)[0]

	for _, args := range [][]string{{"diff", first, second}, {"diff", second}} {
		code, out, errs = exec(t, args...)
		if code != 0 || errs != "" {
			t.Fatalf("%v exited %d: %s", args, code, errs)
		}
		for _, want := range []string{"(baseline)", "(bucket removed)", "nodes: 0 added, 1 removed, 0 changed",
			"- aws_s3_bucket acme-legacy-uploads [111111111111]", "edges: 0 added, 1 removed, 0 changed",
			"- contained_in: acme-legacy-uploads -> prod-account"} {
			if !strings.Contains(out, want) {
				t.Errorf("%v: output lacks %q:\n%s", args, want, out)
			}
		}
	}

	code, out, _ = exec(t, "diff", "--json", first, second)
	var d struct {
		Summary struct {
			NodesRemoved int `json:"nodes_removed"`
			EdgesRemoved int `json:"edges_removed"`
			NodesAdded   int `json:"nodes_added"`
		} `json:"summary"`
		Nodes struct {
			Removed []struct {
				Name string `json:"name"`
			} `json:"removed"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal([]byte(out), &d); err != nil || code != 0 || d.Summary.NodesRemoved != 1 || d.Summary.EdgesRemoved != 1 ||
		d.Summary.NodesAdded != 0 || d.Nodes.Removed[0].Name != "acme-legacy-uploads" {
		t.Errorf("--json: code %d, %+v, %v", code, d, err)
	}

	code, out, _ = exec(t, "diff", first, first)
	if code != 0 || !strings.Contains(out, "no changes") {
		t.Errorf("diff of a snapshot with itself: %d %q", code, out)
	}
}

func TestDiffErrors(t *testing.T) {
	_, dir := build(t)
	if code, _, errs := exec(t, "diff", dir); code != 1 || !strings.Contains(errs, "no parent") {
		t.Errorf("diff of a first snapshot: %d %q, want 1 and no parent", code, errs)
	}
	if code, _, _ := exec(t, "diff"); code != 2 {
		t.Errorf("diff with no folder: %d, want 2", code)
	}
	if code, _, _ := exec(t, "diff", dir, dir, dir); code != 2 {
		t.Errorf("diff with three folders: %d, want 2", code)
	}
	p := filepath.Join(dir, "edges.parquet")
	b, _ := os.ReadFile(p)
	b[len(b)/2] ^= 1
	_ = os.WriteFile(p, b, 0o644)
	if code, _, errs := exec(t, "diff", dir, dir); code != 4 || !strings.Contains(errs, "does not verify") {
		t.Errorf("diff of a tampered snapshot: %d %q, want 4", code, errs)
	}
}

func TestSnapshotUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"snapshot"}, {"snapshot", "nope"}, {"snapshot", "verify"}, {"snapshot", "build"},
		{"snapshot", "verify", "--bogus", "x"},
	} {
		if code, _, _ := exec(t, args...); code != 2 {
			t.Errorf("run(%v) = %d, want 2", args, code)
		}
	}
}

func TestPrintableEscapesControlCharacters(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"plain label":           "plain label",
		"red\x1b[31mtext":       `red\x1b[31mtext`,
		"two\nlines":            `two\nlines`,
		"bell\a and \"quotes\"": `bell\a and \"quotes\"`,
	} {
		if got := printable(in); got != want {
			t.Errorf("printable(%q) = %q, want %q", in, got, want)
		}
	}
}
