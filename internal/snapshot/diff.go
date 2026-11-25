// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package snapshot

import (
	"maps"
	"slices"
)

// Diff is what changed going from one snapshot to another: the nodes and edges
// the second has and the first lacks (added), the reverse (removed), and those
// both have whose fields differ (changed). A change names the fields that
// differ and never their values.
type Diff struct {
	From    string     `json:"from"`
	To      string     `json:"to"`
	Nodes   NodeDiff   `json:"nodes"`
	Edges   EdgeDiff   `json:"edges"`
	Summary DiffCounts `json:"summary"`
}

// NodeDiff holds the node changes.
type NodeDiff struct {
	Added   []NodeRef    `json:"added"`
	Removed []NodeRef    `json:"removed"`
	Changed []NodeChange `json:"changed"`
}

// EdgeDiff holds the edge changes.
type EdgeDiff struct {
	Added   []EdgeRef    `json:"added"`
	Removed []EdgeRef    `json:"removed"`
	Changed []EdgeChange `json:"changed"`
}

// DiffCounts is the size of each list.
type DiffCounts struct {
	NodesAdded   int `json:"nodes_added"`
	NodesRemoved int `json:"nodes_removed"`
	NodesChanged int `json:"nodes_changed"`
	EdgesAdded   int `json:"edges_added"`
	EdgesRemoved int `json:"edges_removed"`
	EdgesChanged int `json:"edges_changed"`
}

// Empty reports whether the two snapshots hold the same nodes and edges.
func (c DiffCounts) Empty() bool { return c == DiffCounts{} }

// NodeRef names a node the way a person would look for it.
type NodeRef struct {
	NodeID  string `json:"node_id"`
	Kind    string `json:"kind"`
	Type    string `json:"type,omitempty"`
	Name    string `json:"name,omitempty"`
	Address string `json:"address,omitempty"`
	Account string `json:"account,omitempty"`
}

// NodeChange is a node in both snapshots with fields that differ.
type NodeChange struct {
	NodeRef
	Fields []string `json:"fields"`
}

// EdgeRef names an edge by its kind and ends.
type EdgeRef struct {
	Kind   string `json:"kind"`
	FromID string `json:"from_id"`
	ToID   string `json:"to_id"`
	// FromLabel and ToLabel say what the ends are: the address, the name, the
	// native id or the start of the node id, whichever is first known.
	FromLabel string `json:"from,omitempty"`
	ToLabel   string `json:"to,omitempty"`
}

// EdgeChange is an edge in both snapshots with fields that differ.
type EdgeChange struct {
	EdgeRef
	Fields []string `json:"fields"`
}

func nodeRef(n Node) NodeRef {
	typ := n.TFType
	if typ == "" {
		typ = n.InventoryType
	}
	return NodeRef{NodeID: n.NodeID, Kind: n.Kind, Type: typ, Name: n.Name, Address: n.Address, Account: n.Account}
}

// changedNodeFields lists the columns, other than the id and the source, that
// differ. The source is provenance and changes whenever a state is read again,
// so it would flag every node.
func changedNodeFields(a, b Node) []string {
	var f []string
	for _, c := range []struct {
		name string
		diff bool
	}{
		{"kind", a.Kind != b.Kind},
		{"cloud", a.Cloud != b.Cloud},
		{"account", a.Account != b.Account},
		{"region", a.Region != b.Region},
		{"tf_type", a.TFType != b.TFType},
		{"inventory_type", a.InventoryType != b.InventoryType},
		{"native_id", a.NativeID != b.NativeID},
		{"arn_or_path", a.ARNOrPath != b.ARNOrPath},
		{"name", a.Name != b.Name},
		{"address", a.Address != b.Address},
		{"module", a.Module != b.Module},
		{"root", a.Root != b.Root},
		{"managed_status", a.ManagedStatus != b.ManagedStatus},
		{"environment", a.Environment != b.Environment},
		{"tags", !maps.Equal(a.Tags, b.Tags)},
		{"confidence", a.Confidence != b.Confidence},
	} {
		if c.diff {
			f = append(f, c.name)
		}
	}
	return f
}

func changedEdgeFields(a, b Edge) []string {
	var f []string
	if a.Confidence != b.Confidence {
		f = append(f, "confidence")
	}
	if a.Basis != b.Basis {
		f = append(f, "basis")
	}
	return f
}

// DiffSnapshots compares two verified snapshots: a merge join of the nodes on
// node_id and of the edges on (from_id, to_id, kind). Every list is sorted.
func DiffSnapshots(a, b *Loaded) Diff {
	d := Diff{
		From:  a.Manifest.SnapshotID,
		To:    b.Manifest.SnapshotID,
		Nodes: NodeDiff{Added: []NodeRef{}, Removed: []NodeRef{}, Changed: []NodeChange{}},
		Edges: EdgeDiff{Added: []EdgeRef{}, Removed: []EdgeRef{}, Changed: []EdgeChange{}},
	}

	an, bn := sortedNodes(a.Tables.Nodes), sortedNodes(b.Tables.Nodes)
	mergeJoin(len(an), len(bn),
		func(i, j int) int { return compare(an[i].NodeID, bn[j].NodeID) },
		func(i int) { d.Nodes.Removed = append(d.Nodes.Removed, nodeRef(an[i])) },
		func(j int) { d.Nodes.Added = append(d.Nodes.Added, nodeRef(bn[j])) },
		func(i, j int) {
			if f := changedNodeFields(an[i], bn[j]); len(f) > 0 {
				d.Nodes.Changed = append(d.Nodes.Changed, NodeChange{NodeRef: nodeRef(bn[j]), Fields: f})
			}
		})

	ae, be := sortedEdges(a.Tables.Edges), sortedEdges(b.Tables.Edges)
	labels := nodeLabels(an, bn)
	ref := func(e Edge) EdgeRef {
		return EdgeRef{Kind: e.Kind, FromID: e.FromID, ToID: e.ToID, FromLabel: labels[e.FromID], ToLabel: labels[e.ToID]}
	}
	mergeJoin(len(ae), len(be),
		func(i, j int) int { return edgeCmp(ae[i], be[j]) },
		func(i int) { d.Edges.Removed = append(d.Edges.Removed, ref(ae[i])) },
		func(j int) { d.Edges.Added = append(d.Edges.Added, ref(be[j])) },
		func(i, j int) {
			if f := changedEdgeFields(ae[i], be[j]); len(f) > 0 {
				d.Edges.Changed = append(d.Edges.Changed, EdgeChange{EdgeRef: ref(be[j]), Fields: f})
			}
		})

	d.Summary = DiffCounts{
		NodesAdded: len(d.Nodes.Added), NodesRemoved: len(d.Nodes.Removed), NodesChanged: len(d.Nodes.Changed),
		EdgesAdded: len(d.Edges.Added), EdgesRemoved: len(d.Edges.Removed), EdgesChanged: len(d.Edges.Changed),
	}
	return d
}

func edgeCmp(a, b Edge) int {
	return cmpChain(compare(a.FromID, b.FromID), compare(a.ToID, b.ToID), compare(a.Kind, b.Kind))
}

func sortedNodes(in []Node) []Node {
	out := slices.Clone(in)
	slices.SortFunc(out, func(a, b Node) int { return compare(a.NodeID, b.NodeID) })
	return out
}

func sortedEdges(in []Edge) []Edge {
	out := slices.Clone(in)
	slices.SortFunc(out, edgeCmp)
	return out
}

// mergeJoin walks two lists sorted by the same key, calling left for an item
// only in the first, right for one only in the second and both for a pair.
func mergeJoin(nl, nr int, cmp func(i, j int) int, left, right func(int), both func(i, j int)) {
	i, j := 0, 0
	for i < nl && j < nr {
		switch c := cmp(i, j); {
		case c < 0:
			left(i)
			i++
		case c > 0:
			right(j)
			j++
		default:
			both(i, j)
			i++
			j++
		}
	}
	for ; i < nl; i++ {
		left(i)
	}
	for ; j < nr; j++ {
		right(j)
	}
}

// nodeLabels names every node of both lists, the second list's name winning.
func nodeLabels(lists ...[]Node) map[string]string {
	labels := map[string]string{}
	for _, nodes := range lists {
		for _, n := range nodes {
			labels[n.NodeID] = Label(n)
		}
	}
	return labels
}

// Label is what a person calls a node: its address, else its name, else its
// native id, else the start of its node id.
func Label(n Node) string {
	for _, s := range []string{n.Address, n.Name, n.NativeID} {
		if s != "" {
			return s
		}
	}
	return n.NodeID[:min(12, len(n.NodeID))]
}
