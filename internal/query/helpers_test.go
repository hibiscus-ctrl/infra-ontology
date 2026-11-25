// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !noduckdb

package query

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
	"github.com/hibiscus-ctrl/infra-ontology/schemas"
)

// graph builds a snapshot of n nodes whose edges form a chain, a few cycles
// and some cross links, writes it to a new folder and returns the folder and
// the edges as (from, to) pairs of node ids.
func graph(t testing.TB, n int) (dir string, edges [][2]string, ids []string) {
	t.Helper()
	var tb snapshot.Tables
	tb.Sources = []snapshot.Source{{
		SourceID: "state-a", Kind: snapshot.SourceState, CollectedAt: "2026-11-25T09:00:00Z", Status: snapshot.StatusOK,
	}}
	for i := range n {
		id := snapshot.NodeID(snapshot.KindResource, "aws", "111111111111", "eu-west-1", "aws_thing", "thing-"+strconv.Itoa(i))
		ids = append(ids, id)
		tb.Nodes = append(tb.Nodes, snapshot.Node{
			NodeID: id, Kind: snapshot.KindResource, Cloud: "aws", Account: "111111111111", Region: "eu-west-1",
			TFType: "aws_thing", NativeID: "thing-" + strconv.Itoa(i), Name: "thing-" + strconv.Itoa(i),
			Address: "aws_thing.t" + strconv.Itoa(i), ManagedStatus: snapshot.Managed, Confidence: snapshot.Observed,
			SourceID: "state-a", Tags: map[string]string{"n": strconv.Itoa(i % 7)},
		})
	}
	seen := map[[2]int]bool{}
	link := func(a, b int) {
		a, b = a%n, b%n
		if a == b || seen[[2]int{a, b}] {
			return
		}
		seen[[2]int{a, b}] = true
		edges = append(edges, [2]string{ids[a], ids[b]})
		tb.Edges = append(tb.Edges, snapshot.Edge{
			FromID: ids[a], ToID: ids[b], Kind: snapshot.EdgeDependsOn, Confidence: snapshot.Observed,
			Basis: "state_dependency", SourceID: "state-a",
		})
	}
	for i := range n {
		link(i, i+1)     // a chain that closes into one big cycle
		link(i, i*7+3)   // cross links
		link(i*5+1, i+2) // and more
	}
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
	return dir, edges, ids
}

// bfs is the reference for blast and cone: the nodes reached from start in at
// most depth hops, with the fewest hops to each. forward follows an edge from
// its from end to its to end (cone); otherwise backwards (blast).
func bfs(edges [][2]string, start string, depth int, forward bool) map[string]int {
	next := map[string][]string{}
	for _, e := range edges {
		if forward {
			next[e[0]] = append(next[e[0]], e[1])
		} else {
			next[e[1]] = append(next[e[1]], e[0])
		}
	}
	dist := map[string]int{start: 0}
	queue := []string{start}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if dist[cur] >= depth {
			continue
		}
		for _, nb := range next[cur] {
			if _, ok := dist[nb]; !ok {
				dist[nb] = dist[cur] + 1
				queue = append(queue, nb)
			}
		}
	}
	return dist
}

// answerSchema compiles the published answer schema.
func answerSchema(t testing.TB) *jsonschema.Schema {
	t.Helper()
	raw, err := fs.ReadFile(schemas.FS, schemas.File("answer"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		ID string `json:"$id"`
	}
	_ = json.Unmarshal(raw, &meta)
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()
	if err := c.AddResource(meta.ID, doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile(meta.ID)
	if err != nil {
		t.Fatal(err)
	}
	return sch
}

// validAnswer checks an answer against the schema.
func validAnswer(t testing.TB, a snapshot.Answer) error {
	t.Helper()
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return answerSchema(t).Validate(doc)
}

// column returns one column of a result as strings.
func column(t testing.TB, r *Result, name string) []string {
	t.Helper()
	i := slices.Index(r.Columns, name)
	if i < 0 {
		t.Fatalf("no column %q in %v", name, r.Columns)
	}
	out := make([]string, len(r.Rows))
	for j, row := range r.Rows {
		out[j] = fmt.Sprint(row[i])
	}
	return out
}
