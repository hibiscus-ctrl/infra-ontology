// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IgnatG/infraharvest/pkg/tfstate"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

const boundsRoot = "s3://acme-tfstate/prod/bounds.tfstate"

func boundsInstance(typ, name string, i int, deps ...string) tfstate.Instance {
	return tfstate.Instance{
		Mode: "managed", Type: typ, Name: name, Address: fmt.Sprintf("%s.%s[%d]", typ, name, i),
		Provider: `provider["registry.terraform.io/hashicorp/aws"]`,
		ID:       fmt.Sprintf("%s-%s-%d", typ, name, i), Dependencies: deps,
	}
}

func boundsBuild(t *testing.T, instances []tfstate.Instance) Result {
	t.Helper()
	return build(t, []Read{{Location: boundsRoot, Docs: []tfstate.Document{{Source: boundsRoot, Serial: 1, Lineage: "l", Instances: instances}}}})
}

func dependsOnEdges(tb snapshot.Tables) int {
	n := 0
	for _, e := range tb.Edges {
		if e.Kind == snapshot.EdgeDependsOn {
			n++
		}
	}
	return n
}

func TestSmallDependenciesStayInstanceToInstance(t *testing.T) {
	var in []tfstate.Instance
	for i := range 3 {
		in = append(in, boundsInstance("aws_subnet", "s", i))
	}
	for i := range 3 {
		in = append(in, boundsInstance("aws_instance", "web", i, "aws_subnet.s"))
	}
	res := boundsBuild(t, in)
	if got := dependsOnEdges(res.Tables); got != 9 {
		t.Errorf("%d depends_on edges, want 9 (3 instances of 3)", got)
	}
}

func TestLargeDependenciesCollapseToOneEdge(t *testing.T) {
	var in []tfstate.Instance
	for i := range 100 {
		in = append(in, boundsInstance("aws_subnet", "s", i))
	}
	for i := range 100 {
		in = append(in, boundsInstance("aws_instance", "web", i, "aws_subnet.s"))
	}
	res := boundsBuild(t, in)
	if got := dependsOnEdges(res.Tables); got != 1 {
		t.Errorf("%d depends_on edges, want 1 for 100 instances depending on 100", got)
	}
	if !strings.Contains(res.Limits, "collapsed") {
		t.Errorf("limits do not say dependencies were collapsed: %s", res.Limits)
	}
}

func TestInstancesWithoutAnAddressDoNotShareTheirDependencies(t *testing.T) {
	var in []tfstate.Instance
	for i := range 40 {
		in = append(in, boundsInstance("aws_subnet", fmt.Sprintf("s%d", i), 0))
	}
	// A state that does not name its instances gives each an empty address.
	for i := range 40 {
		x := boundsInstance("aws_instance", "web", i, fmt.Sprintf("aws_subnet.s%d", i))
		x.Address = ""
		in = append(in, x)
	}
	res := boundsBuild(t, in)
	if got := dependsOnEdges(res.Tables); got > 40 {
		t.Errorf("%d depends_on edges for 40 dependencies: instances share one another's", got)
	}
}

func TestInstanceAndEdgeCapsAreReported(t *testing.T) {
	old1, old2 := maxStateInstances, maxStateEdges
	maxStateInstances, maxStateEdges = 30, 10
	t.Cleanup(func() { maxStateInstances, maxStateEdges = old1, old2 })
	var in []tfstate.Instance
	for i := range 20 {
		in = append(in, boundsInstance("aws_subnet", "s", i))
	}
	for i := range 20 {
		in = append(in, boundsInstance("aws_instance", "web", i, fmt.Sprintf("aws_subnet.s[%d]", i)))
	}
	res := boundsBuild(t, in)
	resources := 0
	for _, n := range res.Tables.Nodes {
		if n.Kind == snapshot.KindResource {
			resources++
		}
	}
	if resources != 30 {
		t.Errorf("%d instances kept, want the cap of 30", resources)
	}
	if got := dependsOnEdges(res.Tables); got > 10 {
		t.Errorf("%d depends_on edges, want at most the cap of 10", got)
	}
	for _, want := range []string{"10 instances", "past the cap"} {
		if !strings.Contains(res.Limits, want) {
			t.Errorf("limits lack %q: %s", want, res.Limits)
		}
	}
}

func TestInventoryFileSizeIsCapped(t *testing.T) {
	old := maxInventoryBytes
	maxInventoryBytes = 200
	t.Cleanup(func() { maxInventoryBytes = old })
	path := filepath.Join(t.TempDir(), "big.json")
	if err := os.WriteFile(path, []byte(`{"schema":"infraharvest/inventory/v1","resources":[`+strings.Repeat(" ", 400)+`]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ReadInventory(path)
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("an inventory past the cap was read: %v", err)
	}
	if err != nil && strings.Contains(err.Error(), path) {
		t.Errorf("error holds the path: %v", err)
	}
}
