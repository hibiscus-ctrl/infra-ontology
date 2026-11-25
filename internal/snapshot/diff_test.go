// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package snapshot

import (
	"reflect"
	"slices"
	"testing"
)

// loadVariant builds the estate with a change applied and reads it back, so the
// diff runs on what a person's files would hold.
func loadVariant(t *testing.T, change func(*Tables)) *Loaded {
	t.Helper()
	in := estate()
	if change != nil {
		change(&in)
	}
	l, err := Load(mustWrite(t, mustBuild(t, in, estateOptions()), t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func nodeByAddress(t *Tables, addr string) *Node {
	for i := range t.Nodes {
		if t.Nodes[i].Address == addr {
			return &t.Nodes[i]
		}
	}
	panic("no node " + addr)
}

func TestDiffOfTheSameSnapshotIsEmpty(t *testing.T) {
	a := loadVariant(t, nil)
	d := DiffSnapshots(a, a)
	if !d.Summary.Empty() {
		t.Errorf("summary = %+v, want empty", d.Summary)
	}
}

func TestDiffNodes(t *testing.T) {
	a := loadVariant(t, nil)
	var removedID string
	b := loadVariant(t, func(t *Tables) {
		// Added: a new bucket in staging.
		t.Nodes = append(t.Nodes, Node{
			NodeID: NodeID(KindResource, "aws", "222222222222", "eu-west-1", "aws_s3_bucket", "acme-staging-new"),
			Kind:   KindResource, Cloud: "aws", Account: "222222222222", Region: "eu-west-1", TFType: "aws_s3_bucket",
			NativeID: "acme-staging-new", Name: "acme-staging-new", Address: "aws_s3_bucket.new",
			ManagedStatus: Managed, Confidence: Observed, SourceID: "state-staging",
		})
		// Removed: the unmanaged legacy bucket, and the edge that placed it.
		for i, n := range t.Nodes {
			if n.NativeID == "acme-legacy-uploads" {
				removedID = n.NodeID
				t.Nodes = slices.Delete(t.Nodes, i, i+1)
				break
			}
		}
		t.Edges = slices.DeleteFunc(t.Edges, func(e Edge) bool { return e.FromID == removedID })
		// Changed: the logs bucket's tags and managed status; a source change alone is not a change.
		logs := nodeByAddress(t, "aws_s3_bucket.logs")
		logs.Tags = map[string]string{"environment": "prod", "owner": "data"}
		logs.ManagedStatus = OtherIaC
		nodeByAddress(t, "aws_instance.app").SourceID = "inventory-aws"
	})
	d := DiffSnapshots(a, b)

	if len(d.Nodes.Added) != 1 || d.Nodes.Added[0].Address != "aws_s3_bucket.new" || d.Nodes.Added[0].Type != "aws_s3_bucket" {
		t.Errorf("added = %+v", d.Nodes.Added)
	}
	if len(d.Nodes.Removed) != 1 || d.Nodes.Removed[0].NodeID != removedID || d.Nodes.Removed[0].Name != "acme-legacy-uploads" {
		t.Errorf("removed = %+v", d.Nodes.Removed)
	}
	if len(d.Nodes.Changed) != 1 || d.Nodes.Changed[0].Address != "aws_s3_bucket.logs" ||
		!reflect.DeepEqual(d.Nodes.Changed[0].Fields, []string{"managed_status", "tags"}) {
		t.Errorf("changed = %+v", d.Nodes.Changed)
	}
	if want := (DiffCounts{NodesAdded: 1, NodesRemoved: 1, NodesChanged: 1, EdgesRemoved: 1}); d.Summary != want {
		t.Errorf("summary = %+v, want %+v", d.Summary, want)
	}
	// The removed edge names its ends by label, which the removed node's snapshot supplies.
	if len(d.Edges.Removed) != 1 || d.Edges.Removed[0].FromLabel != "acme-legacy-uploads" || d.Edges.Removed[0].ToLabel != "prod-account" {
		t.Errorf("removed edges = %+v", d.Edges.Removed)
	}
	if d.From != a.Manifest.SnapshotID || d.To != b.Manifest.SnapshotID {
		t.Errorf("from/to = %s/%s", d.From, d.To)
	}
}

func TestDiffEdges(t *testing.T) {
	a := loadVariant(t, nil)
	var added, changed EdgeRef
	b := loadVariant(t, func(t *Tables) {
		vpc := nodeByAddress(t, "module.network.aws_vpc.main").NodeID
		inst := nodeByAddress(t, "aws_instance.app").NodeID
		added = EdgeRef{Kind: EdgeDependsOn, FromID: inst, ToID: vpc}
		t.Edges = append(t.Edges, Edge{FromID: inst, ToID: vpc, Kind: EdgeDependsOn, Basis: "state_dependency", Confidence: Observed, SourceID: "state-prod"})
		// Changed: confidence and basis of an existing edge. Its source alone would not count.
		for i, e := range t.Edges {
			if e.Kind == EdgeReadsStateOf && e.Basis == "remote_state" && e.Confidence == Observed {
				t.Edges[i].Confidence, t.Edges[i].Basis = Inferred, "resource_path"
				changed = EdgeRef{Kind: e.Kind, FromID: e.FromID, ToID: e.ToID}
				break
			}
		}
	})
	d := DiffSnapshots(a, b)
	if len(d.Edges.Added) != 1 || d.Edges.Added[0].Kind != added.Kind || d.Edges.Added[0].FromID != added.FromID || d.Edges.Added[0].ToID != added.ToID {
		t.Errorf("added = %+v, want %+v", d.Edges.Added, added)
	}
	if d.Edges.Added[0].FromLabel != "aws_instance.app" || d.Edges.Added[0].ToLabel != "module.network.aws_vpc.main" {
		t.Errorf("labels = %q, %q", d.Edges.Added[0].FromLabel, d.Edges.Added[0].ToLabel)
	}
	if len(d.Edges.Changed) != 1 || d.Edges.Changed[0].FromID != changed.FromID || d.Edges.Changed[0].ToID != changed.ToID ||
		!reflect.DeepEqual(d.Edges.Changed[0].Fields, []string{"confidence", "basis"}) {
		t.Errorf("changed = %+v", d.Edges.Changed)
	}
	if len(d.Edges.Removed) != 0 || len(d.Nodes.Added)+len(d.Nodes.Removed)+len(d.Nodes.Changed) != 0 {
		t.Errorf("unexpected changes: %+v", d.Summary)
	}
}

func TestDiffReversedSwapsAddedAndRemoved(t *testing.T) {
	a := loadVariant(t, nil)
	b := loadVariant(t, func(t *Tables) {
		legacy := slices.IndexFunc(t.Nodes, func(n Node) bool { return n.NativeID == "acme-legacy-uploads" })
		id := t.Nodes[legacy].NodeID
		t.Nodes = slices.Delete(t.Nodes, legacy, legacy+1)
		t.Edges = slices.DeleteFunc(t.Edges, func(e Edge) bool { return e.FromID == id })
	})
	fwd, rev := DiffSnapshots(a, b), DiffSnapshots(b, a)
	if !reflect.DeepEqual(fwd.Nodes.Removed, rev.Nodes.Added) || !reflect.DeepEqual(fwd.Edges.Removed, rev.Edges.Added) {
		t.Errorf("forward removed %+v / %+v, reverse added %+v / %+v", fwd.Nodes.Removed, fwd.Edges.Removed, rev.Nodes.Added, rev.Edges.Added)
	}
	if len(fwd.Nodes.Added)+len(rev.Nodes.Removed) != 0 {
		t.Error("a pure removal also reports an addition")
	}
}
