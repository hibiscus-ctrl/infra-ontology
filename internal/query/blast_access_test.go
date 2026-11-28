// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !noduckdb

package query

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
	"github.com/hibiscus-ctrl/infra-ontology/queries"
)

// accessGraph writes a snapshot where an application depends on a database
// and a role, an anonymous principal can assume the role (inferred), and a
// cross-account principal can read the database (inferred):
//
//	app --depends_on--> db      app --depends_on--> role
//	anon --can_assume--> role   other --can_read--> db
func accessGraph(t testing.TB) (dir string, id map[string]string) {
	t.Helper()
	id = map[string]string{}
	var tb snapshot.Tables
	tb.Sources = []snapshot.Source{{
		SourceID: "state-a", Kind: snapshot.SourceState, CollectedAt: "2026-11-25T09:00:00Z", Status: snapshot.StatusOK,
	}}
	for _, name := range []string{"app", "db", "role", "anon", "other"} {
		nid := snapshot.NodeID(snapshot.KindResource, "aws", "111111111111", "eu-west-1", "aws_thing", name)
		id[name] = nid
		tb.Nodes = append(tb.Nodes, snapshot.Node{
			NodeID: nid, Kind: snapshot.KindResource, Cloud: "aws", Account: "111111111111", Region: "eu-west-1",
			TFType: "aws_thing", NativeID: name, Name: name, Address: "aws_thing." + name,
			ManagedStatus: snapshot.Managed, Confidence: snapshot.Observed, SourceID: "state-a",
		})
	}
	edge := func(from, to, kind, conf string) {
		tb.Edges = append(tb.Edges, snapshot.Edge{
			FromID: id[from], ToID: id[to], Kind: kind, Confidence: conf, Basis: "test", SourceID: "state-a",
		})
	}
	edge("app", "db", snapshot.EdgeDependsOn, snapshot.Observed)
	edge("app", "role", snapshot.EdgeDependsOn, snapshot.Computed)
	edge("anon", "role", snapshot.EdgeCanAssume, snapshot.Inferred)
	edge("other", "db", snapshot.EdgeCanRead, snapshot.Inferred)
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

// reached maps the name of each node a result reaches to its row.
func reached(t testing.TB, r *Result) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, row := range r.Rows {
		m := map[string]any{}
		for i, c := range r.Columns {
			m[c] = row[i]
		}
		out[m["name"].(string)] = m
	}
	return out
}

func names(m map[string]map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// Blast and cone follow dependencies only, unless the caller asks for access
// edges, and say which kind of edge reached each node and how sure it is.
func TestBlastAndConeSkipAccessEdgesByDefault(t *testing.T) {
	dir, id := accessGraph(t)
	loaded, err := snapshot.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range modes {
		s := open(t, dir, mode)
		ask := func(name string, params map[string]string) map[string]map[string]any {
			t.Helper()
			out, err := Ask(context.Background(), s, loaded.Manifest, Request{Stored: name, Params: params})
			if err != nil {
				t.Fatal(err)
			}
			return reached(t, out.Result)
		}
		got := ask("blast", map[string]string{"node": id["db"]})
		if want := []string{"app", "db"}; !slices.Equal(names(got), want) {
			t.Errorf("%s: blast of db by default reaches %v, want %v", mode, names(got), want)
		}
		if g := got["app"]; g["edge_kind"] != "depends_on" || g["confidence"] != "observed" {
			t.Errorf("%s: app reached by %v %v", mode, g["edge_kind"], g["confidence"])
		}
		got = ask("blast", map[string]string{"node": id["db"], "include_access": "1"})
		if want := []string{"app", "db", "other"}; !slices.Equal(names(got), want) {
			t.Errorf("%s: blast of db with access reaches %v, want %v", mode, names(got), want)
		}
		if g := got["other"]; g["edge_kind"] != "can_read" || g["confidence"] != "inferred" {
			t.Errorf("%s: other reached by %v %v", mode, g["edge_kind"], g["confidence"])
		}
		// anon reaches the role by can_assume; the role's dependent app is a
		// dependency walk, so anon sits two hops from db only through access.
		got = ask("blast", map[string]string{"node": id["role"], "include_access": "1"})
		if g := got["anon"]; g["edge_kind"] != "can_assume" || g["confidence"] != "inferred" || g["depth"] != int64(1) {
			t.Errorf("%s: anon reached by %v", mode, g)
		}
		if got = ask("blast", map[string]string{"node": id["role"]}); slices.Contains(names(got), "anon") {
			t.Errorf("%s: blast of the role lists the anonymous principal by default: %v", mode, names(got))
		}
		// The confidence is the weakest along the path: app -> role is
		// computed, so a node reached through it is at most computed.
		if g := ask("blast", map[string]string{"node": id["role"]})["app"]; g["confidence"] != "computed" {
			t.Errorf("%s: app confidence %v", mode, g["confidence"])
		}
		// cone
		got = ask("cone", map[string]string{"node": id["anon"]})
		if want := []string{"anon"}; !slices.Equal(names(got), want) {
			t.Errorf("%s: cone of anon by default reaches %v, want %v", mode, names(got), want)
		}
		got = ask("cone", map[string]string{"node": id["anon"], "include_access": "1"})
		if want := []string{"anon", "role"}; !slices.Equal(names(got), want) {
			t.Errorf("%s: cone of anon with access reaches %v, want %v", mode, names(got), want)
		}

		// The macros: two arguments are dependency-only, a third turns access on.
		count := func(q string) int {
			return len(query(t, s, q, Caps{}).Rows)
		}
		if n := count("SELECT * FROM blast('" + id["role"] + "', 5)"); n != 2 {
			t.Errorf("%s: blast macro by default: %d rows, want 2", mode, n)
		}
		r := query(t, s, "SELECT node_id, depth, edge_kind, confidence FROM blast('"+id["role"]+"', 5, true)", Caps{})
		if len(r.Rows) != 3 {
			t.Errorf("%s: blast macro with access: %d rows, want 3", mode, len(r.Rows))
		}
		if n := count("SELECT * FROM cone('" + id["anon"] + "', 5, false)"); n != 1 {
			t.Errorf("%s: cone macro, access off: %d rows, want 1", mode, n)
		}
	}
}

// The stored files and the macros name the same access kinds as the code.
func TestAccessKindsAreListedWhereTheWalkFilters(t *testing.T) {
	for _, f := range []string{"blast.sql", "cone.sql"} {
		raw, err := queries.FS.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range AccessEdgeKinds {
			if !strings.Contains(string(raw), "'"+k+"'") {
				t.Errorf("%s does not filter %s", f, k)
			}
		}
	}
	for _, k := range []string{snapshot.EdgeCanAssume, snapshot.EdgeCanRead, snapshot.EdgeCanWrite} {
		if !slices.Contains(AccessEdgeKinds, k) {
			t.Errorf("AccessEdgeKinds lacks %s", k)
		}
	}
}
