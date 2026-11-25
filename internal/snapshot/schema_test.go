// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package snapshot_test

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
	"github.com/hibiscus-ctrl/infra-ontology/schemas"
)

func compile(t *testing.T) map[string]*jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()
	out := map[string]*jsonschema.Schema{}
	for _, name := range schemas.Names {
		raw, err := fs.ReadFile(schemas.FS, schemas.File(name))
		if err != nil {
			t.Fatal(err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var meta struct {
			ID string `json:"$id"`
		}
		_ = json.Unmarshal(raw, &meta)
		if err := c.AddResource(meta.ID, doc); err != nil {
			t.Fatal(err)
		}
		if out[name], err = c.Compile(meta.ID); err != nil {
			t.Fatalf("%s does not compile: %v", name, err)
		}
	}
	return out
}

// validate checks a Go value, written as JSON, against a schema.
func validate(t *testing.T, s *jsonschema.Schema, v any) error {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return s.Validate(doc)
}

// A written snapshot's manifest, and every row of its tables exported as JSON,
// validate against the published schemas.
func TestWrittenDocumentsValidateAgainstTheSchemas(t *testing.T) {
	sch := compile(t)
	dir := t.TempDir()
	l := writeAndLoadGolden(t, dir)
	if err := validate(t, sch["snapshot"], l.Manifest); err != nil {
		t.Errorf("manifest: %v", err)
	}
	raw, err := readFile(dir, snapshot.ManifestFile)
	if err != nil {
		t.Fatal(err)
	}
	var onDisk any
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatal(err)
	}
	if err := validate(t, sch["snapshot"], onDisk); err != nil {
		t.Errorf("manifest.json: %v", err)
	}
	for i, n := range l.Tables.Nodes {
		if err := validate(t, sch["node"], n); err != nil {
			t.Fatalf("node %d: %v", i, err)
		}
	}
	for i, e := range l.Tables.Edges {
		if err := validate(t, sch["edge"], e); err != nil {
			t.Fatalf("edge %d: %v", i, err)
		}
	}
	for i, s := range l.Tables.Sources {
		if err := validate(t, sch["source"], s); err != nil {
			t.Fatalf("source %d: %v", i, err)
		}
	}
	if len(l.Tables.Nodes) == 0 || len(l.Tables.Edges) == 0 || len(l.Tables.Sources) == 0 {
		t.Fatal("the estate has an empty table: the test proves nothing")
	}
}

func TestPartialManifestValidates(t *testing.T) {
	sch := compile(t)
	in := snapshot.Tables{}
	s, err := snapshot.Build(in, snapshot.BuildOptions{CreatedAt: fixedTime})
	if err != nil {
		t.Fatal(err)
	}
	if err := validate(t, sch["snapshot"], s.Manifest); err != nil {
		t.Errorf("an empty snapshot's manifest: %v", err)
	}
}

func TestAnswerValidates(t *testing.T) {
	sch := compile(t)
	hash := "sha256:" + strings.Repeat("ab", 32)
	a := snapshot.Answer{
		Query: "SELECT 1", QueryHash: hash, SnapshotID: strings.Repeat("c", 64), Dialect: "infra-ontology/sql/v1",
		Engine: "duckdb 2.0.1", RowCount: 1, ResultHash: hash,
		Caps:   snapshot.AnswerCaps{MaxRows: 1000, MaxColumns: 64, MaxBytes: 4 << 20},
		Limits: snapshot.AnswerLimits{OldestSource: "2026-11-25T09:12:00Z", FailedSources: 1, UncoveredTypes: []string{"aws_msk_cluster"}},
	}
	if err := validate(t, sch["answer"], a); err != nil {
		t.Errorf("answer: %v", err)
	}
	a.QueryHash = "sha256:short"
	if err := validate(t, sch["answer"], a); err == nil {
		t.Error("the answer schema accepted a malformed hash")
	}
}

// The schemas are what keeps attribute values out: a node or an edge with a
// member the schema does not name is refused, and so are bad enums.
func TestSchemasRefuseWhatTheyShould(t *testing.T) {
	sch := compile(t)
	node := map[string]any{
		"node_id": strings.Repeat("a", 64), "kind": "resource", "managed_status": "managed",
		"confidence": "observed", "source_id": "s",
	}
	if err := validate(t, sch["node"], node); err != nil {
		t.Fatalf("a minimal node: %v", err)
	}
	bad := map[string]func(map[string]any){
		"an attribute member":    func(n map[string]any) { n["attributes"] = map[string]any{"password": "hunter2"} },
		"a values member":        func(n map[string]any) { n["values"] = "x" },
		"an unknown kind":        func(n map[string]any) { n["kind"] = "thing" },
		"an unknown status":      func(n map[string]any) { n["managed_status"] = "maybe" },
		"a short node id":        func(n map[string]any) { n["node_id"] = "abc" },
		"a non-string tag value": func(n map[string]any) { n["tags"] = map[string]any{"k": 1} },
		"a missing source":       func(n map[string]any) { delete(n, "source_id") },
	}
	for name, change := range bad {
		n := map[string]any{}
		for k, v := range node {
			n[k] = v
		}
		change(n)
		if err := validate(t, sch["node"], n); err == nil {
			t.Errorf("the node schema accepted %s", name)
		}
	}
	edge := map[string]any{
		"edge_id": strings.Repeat("a", 64), "from_id": strings.Repeat("b", 64), "to_id": strings.Repeat("c", 64),
		"kind": "depends_on", "confidence": "observed", "basis": "state_dependency", "source_id": "s",
	}
	if err := validate(t, sch["edge"], edge); err != nil {
		t.Fatalf("a minimal edge: %v", err)
	}
	edge["kind"] = "a_kind_a_later_minor_adds" // open to additions
	if err := validate(t, sch["edge"], edge); err != nil {
		t.Errorf("the edge schema refused a new kind: %v", err)
	}
	edge["weight"] = 3
	if err := validate(t, sch["edge"], edge); err == nil {
		t.Error("the edge schema accepted an unknown member")
	}
}

var fixedTime = time.Date(2026, 11, 25, 10, 15, 0, 0, time.UTC)

func readFile(dir, name string) ([]byte, error) { return os.ReadFile(filepath.Join(dir, name)) }

// writeAndLoadGolden writes the golden estate with the same files the internal
// tests pin, by copying them, and loads it.
func writeAndLoadGolden(t *testing.T, dir string) *snapshot.Loaded {
	t.Helper()
	src := filepath.Join("testdata", "golden", "estate")
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	l, err := snapshot.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return l
}
