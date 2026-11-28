// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !noduckdb

package mcpserver

import (
	"slices"
	"testing"
	"time"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// accessSnapshot writes a snapshot where app depends on db, and an anonymous
// principal can assume a role (inferred) that app also depends on.
func accessSnapshot(t *testing.T) (dir string, id map[string]string) {
	t.Helper()
	id = map[string]string{}
	var tb snapshot.Tables
	tb.Sources = []snapshot.Source{{
		SourceID: "state-a", Kind: snapshot.SourceState, CollectedAt: "2026-11-25T09:00:00Z", Status: snapshot.StatusOK,
	}}
	for _, name := range []string{"app", "db", "role", "anon"} {
		nid := snapshot.NodeID(snapshot.KindResource, "aws", "111111111111", "eu-west-1", "aws_thing", name)
		id[name] = nid
		tb.Nodes = append(tb.Nodes, snapshot.Node{
			NodeID: nid, Kind: snapshot.KindResource, Cloud: "aws", Account: "111111111111", Region: "eu-west-1",
			TFType: "aws_thing", NativeID: name, Name: name, Address: "aws_thing." + name,
			ManagedStatus: snapshot.Managed, Confidence: snapshot.Observed, SourceID: "state-a",
		})
	}
	edge := func(from, to, kind, conf string) {
		tb.Edges = append(tb.Edges, snapshot.Edge{FromID: id[from], ToID: id[to], Kind: kind, Confidence: conf, Basis: "test", SourceID: "state-a"})
	}
	edge("app", "db", snapshot.EdgeDependsOn, snapshot.Observed)
	edge("app", "role", snapshot.EdgeDependsOn, snapshot.Observed)
	edge("anon", "role", snapshot.EdgeCanAssume, snapshot.Inferred)
	s, err := snapshot.Build(tb, snapshot.BuildOptions{
		CreatedAt: time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC), Tool: snapshot.Tool{Name: "infra-ontology", Version: "test"},
		Redaction: snapshot.Redaction{HashAlgorithm: "none"}, Limits: "A generated graph.",
	})
	if err != nil {
		t.Fatal(err)
	}
	dir, err = s.Write(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir, id
}

// blast_radius lists dependents only; access edges are opt-in, and every
// dependent says which kind of edge reached it and how sure that is.
func TestBlastRadiusSkipsAccessEdgesUnlessAsked(t *testing.T) {
	dir, id := accessSnapshot(t)
	cs := connect(t, Config{Dir: dir})
	ids := func(out BlastOut) []string {
		var got []string
		for _, r := range out.Dependents {
			got = append(got, nodeID(t, out.Columns, r))
		}
		return got
	}
	out, res := call[BlastOut](t, cs, "blast_radius", map[string]any{"target": id["role"]})
	if res.IsError {
		t.Fatal(text(res))
	}
	if got := ids(out); !slices.Equal(got, []string{id["app"]}) {
		t.Errorf("dependents of the role by default: %v", got)
	}
	if out.IncludeAccess {
		t.Errorf("include_access echoed as on")
	}
	ik, ic := slices.Index(out.Columns, "edge_kind"), slices.Index(out.Columns, "confidence")
	if ik < 0 || ic < 0 {
		t.Fatalf("no edge_kind or confidence column in %v", out.Columns)
	}
	if r := out.Dependents[0]; r[ik] != "depends_on" || r[ic] != "observed" {
		t.Errorf("app reached by %v, %v", r[ik], r[ic])
	}
	if out.Answer.Parameters["include_access"] != "0" {
		t.Errorf("citation parameters %v", out.Answer.Parameters)
	}

	out, _ = call[BlastOut](t, cs, "blast_radius", map[string]any{"target": id["role"], "include_access": true})
	got := ids(out)
	slices.Sort(got)
	want := []string{id["anon"], id["app"]}
	slices.Sort(want)
	if !slices.Equal(got, want) || !out.IncludeAccess {
		t.Fatalf("dependents with access: %v (include_access %v)", got, out.IncludeAccess)
	}
	for _, r := range out.Dependents {
		if nodeID(t, out.Columns, r) == id["anon"] && (r[ik] != "can_assume" || r[ic] != "inferred") {
			t.Errorf("anonymous reached by %v, %v", r[ik], r[ic])
		}
	}
	if out.Answer.Parameters["include_access"] != "1" {
		t.Errorf("citation parameters %v", out.Answer.Parameters)
	}
}
