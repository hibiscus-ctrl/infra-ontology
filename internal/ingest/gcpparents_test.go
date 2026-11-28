// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"sort"
	"strings"
	"testing"

	"github.com/IgnatG/infraharvest/pkg/secretscan"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

const (
	gcpDataset = "projects/acme-prod/datasets/ds"
	gcpTable   = "projects/acme-prod/datasets/ds/tables/t"
	gcpInst    = "projects/acme-prod/zones/europe-west2-b/instances/vm"
	gcpSubnet  = "projects/acme-prod/regions/europe-west2/subnetworks/sub"
	gcpNetwork = "projects/acme-prod/global/networks/net"
)

func gcpInventory(extra ...Resource) []InventoryRead {
	r := func(typ, id string) Resource {
		return Resource{Cloud: "gcp", Account: "acme-prod", Type: typ, ID: id, Status: "unmanaged", Basis: "none"}
	}
	inv := Inventory{
		Location: "gcp.parents.inventory.json", Schema: SchemaInventory, Tool: "infraharvest",
		Resources: append([]Resource{
			r("google_compute_instance", gcpInst),
			r("google_compute_subnetwork", gcpSubnet),
			r("google_compute_network", gcpNetwork),
			r("google_bigquery_dataset", gcpDataset),
			r("google_bigquery_table", gcpTable),
			r("google_storage_bucket", "acme-prod-assets"),
		}, extra...),
	}
	inv.Digest = digestOf(inv)
	return []InventoryRead{{Location: inv.Location, Inv: inv}}
}

// gcpNode finds the Google node with a native ID as the build wrote it,
// hashed under key, if there is one.
func gcpNode(t *testing.T, tb snapshot.Tables, key []byte, native string) snapshot.Node {
	t.Helper()
	want := native
	if key != nil {
		want = secretscan.Hash(key, native)
	}
	var found []snapshot.Node
	for _, n := range tb.Nodes {
		if n.Cloud == "gcp" && n.NativeID == want {
			found = append(found, n)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d gcp nodes with native ID %s, want 1", len(found), native)
	}
	return found[0]
}

func parentsOf(tb snapshot.Tables, n snapshot.Node) []snapshot.Edge {
	var out []snapshot.Edge
	for _, e := range tb.Edges {
		if e.FromID == n.NodeID && e.Kind == snapshot.EdgeContainedIn {
			out = append(out, e)
		}
	}
	return out
}

func wantParent(t *testing.T, tb snapshot.Tables, child, parent snapshot.Node, basis string) {
	t.Helper()
	es := parentsOf(tb, child)
	if len(es) != 1 || es[0].ToID != parent.NodeID || es[0].Basis != basis || es[0].Confidence != snapshot.Computed || es[0].SourceID == "" {
		t.Errorf("%s: contained_in edges %+v, want one to %s (%s)", child.NativeID, es, parent.NativeID, basis)
	}
}

func TestGCPResourcesAreInTheirParentsAndProject(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  []byte
	}{{"plain", nil}, {"hashed", testKey}} {
		t.Run(tc.name, func(t *testing.T) {
			o := opts
			o.HashKey = tc.key
			res, err := BuildAll(nil, gcpInventory(), o)
			if err != nil {
				t.Fatal(err)
			}
			tb := res.Tables
			project := gcpNode(t, tb, tc.key, "projects/acme-prod")
			if project.Kind != snapshot.KindAccount || project.Account != "acme-prod" || project.Cloud != "gcp" || project.Address != "" ||
				project.ManagedStatus != snapshot.Unknown || project.Confidence != snapshot.Computed {
				t.Errorf("project: %+v", project)
			}
			// A resource with no parent in the snapshot is in its project.
			wantParent(t, tb, gcpNode(t, tb, tc.key, gcpInst), project, BasisProject)
			wantParent(t, tb, gcpNode(t, tb, tc.key, "acme-prod-assets"), project, BasisProject)
			wantParent(t, tb, gcpNode(t, tb, tc.key, gcpDataset), project, BasisProject)
			// A resource whose path continues from another is in that one, and
			// not also in the project.
			wantParent(t, tb, gcpNode(t, tb, tc.key, gcpTable), gcpNode(t, tb, tc.key, gcpDataset), BasisResourcePath)
			// A subnetwork's ID does not name its network: it is in its project.
			wantParent(t, tb, gcpNode(t, tb, tc.key, gcpSubnet), project, BasisProject)
			wantParent(t, tb, gcpNode(t, tb, tc.key, gcpNetwork), project, BasisProject)
			if err := snapshot.Validate(&tb); err != nil {
				t.Errorf("invalid: %v", err)
			}
			if tc.key != nil {
				for _, n := range tb.Nodes {
					if strings.Contains(n.NativeID, "acme-prod") || strings.Contains(n.ARNOrPath, "acme-prod") {
						t.Errorf("hashed build left an ID in clear: %+v", n)
					}
				}
			}
		})
	}
}

// Hashing changes the identifiers, not the shape: the same edges join the same
// nodes.
func TestGCPParentsAreTheSameHashedOrNot(t *testing.T) {
	shape := func(key []byte) []string {
		o := opts
		o.HashKey = key
		res, err := BuildAll(nil, gcpInventory(), o)
		if err != nil {
			t.Fatal(err)
		}
		names := map[string]string{}
		for _, n := range res.Tables.Nodes {
			names[n.NodeID] = n.TFType + "|" + n.Kind
		}
		var out []string
		for _, e := range res.Tables.Edges {
			out = append(out, names[e.FromID]+" > "+names[e.ToID]+" "+e.Basis)
		}
		sort.Strings(out)
		return out
	}
	if a, b := shape(nil), shape(testKey); strings.Join(a, "\n") != strings.Join(b, "\n") {
		t.Errorf("hashed edges differ:\n%s\n%s", strings.Join(a, "\n"), strings.Join(b, "\n"))
	}
}

// Google IDs are case-sensitive: a table of DS is not in the dataset ds.
func TestGCPParentsAreNotMatchedAcrossCase(t *testing.T) {
	invs := gcpInventory(Resource{Cloud: "gcp", Account: "acme-prod", Type: "google_bigquery_table",
		ID: "projects/acme-prod/datasets/DS/tables/t", Status: "unmanaged", Basis: "none"})
	res, err := BuildAll(nil, invs, opts)
	if err != nil {
		t.Fatal(err)
	}
	tb := res.Tables
	project := gcpNode(t, tb, nil, "projects/acme-prod")
	upper := gcpNode(t, tb, nil, "projects/acme-prod/datasets/DS/tables/t")
	wantParent(t, tb, upper, project, BasisProject)
	wantParent(t, tb, gcpNode(t, tb, nil, gcpTable), gcpNode(t, tb, nil, gcpDataset), BasisResourcePath)
	// Nor is a project of another case the same project: a project ID is in
	// lower case, so one that is not is no account, and has no project node of its own.
	other := gcpInventory(Resource{Cloud: "gcp", Account: "Acme-Prod", Type: "google_compute_instance",
		ID: "projects/Acme-Prod/zones/europe-west2-b/instances/vm", Status: "unmanaged", Basis: "none"})
	res, err = BuildAll(nil, other, opts)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, x := range res.Tables.Nodes {
		if x.Kind == snapshot.KindAccount {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d project nodes, want only acme-prod: Acme-Prod is not a project ID", n)
	}
}

// A part of a resource that has the resource's ID is the resource's, and the
// resource a child path names is the whole one.
func TestGCPParentIsTheResourceNotItsPart(t *testing.T) {
	invs := gcpInventory(Resource{Cloud: "gcp", Account: "acme-prod", Type: "google_bigquery_dataset_iam_member",
		ID: gcpDataset, Status: "unmanaged", Basis: "none"})
	res, err := BuildAll(nil, invs, opts)
	if err != nil {
		t.Fatal(err)
	}
	tb := res.Tables
	var dataset snapshot.Node
	for _, n := range tb.Nodes {
		if n.TFType == "google_bigquery_dataset" {
			dataset = n
		}
	}
	wantParent(t, tb, gcpNode(t, tb, nil, gcpTable), dataset, BasisResourcePath)
}

// A snapshot of state alone, and Azure inventories, get no project node.
func TestGCPProjectsAreMadeOnlyForGoogleInventoryResources(t *testing.T) {
	tb := buildBoth(t, fixtureReads(t), inventoryReads(t)).Tables
	projects := map[string]bool{}
	for _, n := range tb.Nodes {
		if n.Kind == snapshot.KindAccount {
			projects[n.Cloud+"|"+n.NativeID] = true
		}
	}
	if len(projects) != 1 || !projects["gcp|projects/acme-prod"] {
		t.Errorf("account nodes: %v", projects)
	}
	for _, n := range tb.Nodes {
		if n.Cloud == "azure" && n.Kind == snapshot.KindResource {
			for _, e := range parentsOf(tb, n) {
				if e.Basis == BasisProject {
					t.Errorf("azure resource %s in a project", n.NativeID)
				}
			}
		}
	}
	if es := parentsOf(tb, gcpNode(t, tb, nil, "projects/acme-prod/zones/europe-west2-b/instances/vm")); len(es) != 1 || es[0].Basis != BasisProject {
		t.Errorf("instance edges: %+v", es)
	}
	if n := len(buildBoth(t, fixtureReads(t), nil).Tables.Edges); n == 0 {
		t.Error("state edges missing")
	}
}

func TestGCPParents(t *testing.T) {
	for id, want := range map[string]string{
		"projects/p/datasets/d/tables/t":          "projects/p/datasets/d/tables,projects/p/datasets/d,projects/p/datasets",
		"projects/p/global/networks/n":            "projects/p/global/networks,projects/p/global",
		"projects/p":                              "",
		"acme-prod-assets":                        "",
		"p/europe-west1/cluster/pool":             "",
		"Projects/p/datasets/d":                   "",
		"projects/p//datasets/d":                  "",
		"/subscriptions/s/resourceGroups/r/x/y/z": "",
	} {
		if got := strings.Join(gcpParents(id), ","); got != want {
			t.Errorf("%s: %q, want %q", id, got, want)
		}
	}
}

// An inventory that hashed its IDs has no path to read: its Google resources
// are in their project, which its account names, and nothing nearer.
func TestGCPParentsOfAnInventoryThatHashedItsIDs(t *testing.T) {
	h := func(s string) string { return secretscan.Hash(testKey, s) }
	inv := Inventory{
		Location: "hashed.inventory.json", Schema: SchemaInventory, Tool: "infraharvest", IDsHashed: true,
		Resources: []Resource{
			{Cloud: "gcp", Account: "acme-prod", Type: "google_bigquery_dataset", ID: h(gcpDataset), Status: "unmanaged", Basis: "none"},
			{Cloud: "gcp", Account: "acme-prod", Type: "google_bigquery_table", ID: h(gcpTable), Status: "unmanaged", Basis: "none"},
		},
	}
	inv.Digest = digestOf(inv)
	o := opts
	o.HashKey = testKey
	res, err := BuildAll(nil, []InventoryRead{{Location: inv.Location, Inv: inv}}, o)
	if err != nil {
		t.Fatal(err)
	}
	tb := res.Tables
	project := gcpNode(t, tb, testKey, "projects/acme-prod")
	wantParent(t, tb, gcpNode(t, tb, testKey, gcpTable), project, BasisProject)
	wantParent(t, tb, gcpNode(t, tb, testKey, gcpDataset), project, BasisProject)
}
