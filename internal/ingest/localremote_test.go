// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"strings"
	"testing"

	"github.com/IgnatG/infraharvest/pkg/tfstate"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// A local terraform_remote_state's path is taken from the directory of the
// state that holds it, so ../network/terraform.tfstate finds the state of the
// sibling directory, and a path that leads elsewhere finds nothing.
func TestLocalRemoteStatePath(t *testing.T) {
	const (
		appSrc = "/work/app/terraform.tfstate"
		netSrc = "/work/network/terraform.tfstate"
	)
	reads := []Read{
		{Location: appSrc, Docs: []tfstate.Document{parseFixture(t, "local/app/terraform.tfstate", appSrc)}},
		{Location: netSrc, Docs: []tfstate.Document{parseFixture(t, "local/network/terraform.tfstate", netSrc)}},
	}
	res := build(t, reads)
	tb := res.Tables
	root := func(loc string) string { return snapshot.NodeID(snapshot.KindStateRoot, "", "", "", "", loc) }
	reads2 := func(name, to string) bool {
		return hasEdge(tb, snapshot.EdgeReadsStateOf, BasisRemoteState,
			nodeAt(t, tb, appSrc, "data.terraform_remote_state."+name).NodeID, to)
	}
	if !reads2("net", root(netSrc)) {
		t.Error("the remote state with a relative path (.. and ./ segments) does not read the state of the sibling directory")
	}
	for _, name := range []string{"elsewhere", "outside"} {
		if reads2(name, root(netSrc)) {
			t.Errorf("data.terraform_remote_state.%s reads the network state, but its path leads elsewhere", name)
		}
	}
	// What is not matched is a placeholder at the path it resolves to.
	externals := map[string]bool{}
	for _, n := range tb.Nodes {
		if n.Kind == snapshot.KindExternal {
			externals[n.Name] = true
		}
	}
	for _, want := range []string{"/work/other/terraform.tfstate", "/network/terraform.tfstate"} {
		if !externals[want] {
			t.Errorf("no placeholder for %s: %v", want, keys(externals))
		}
	}
	if strings.Contains(res.Limits, "config") {
		t.Errorf("limits quote the configuration: %s", res.Limits)
	}
}

func TestLocalPath(t *testing.T) {
	for _, c := range []struct{ key, from, want string }{
		{"../network/terraform.tfstate", "/work/app/terraform.tfstate", "/work/network/terraform.tfstate"},
		{"./../network/./terraform.tfstate", "/work/app/terraform.tfstate", "/work/network/terraform.tfstate"},
		{"terraform.tfstate", "/work/app/terraform.tfstate", "/work/app/terraform.tfstate"},
		{"/abs/../srv/terraform.tfstate", "/work/app/terraform.tfstate", "/srv/terraform.tfstate"},
		{"../network/terraform.tfstate", "app/terraform.tfstate", "network/terraform.tfstate"},
		{"../network/terraform.tfstate", "s3://b/app.tfstate", "../network/terraform.tfstate"},
		{"../network/terraform.tfstate", "", "../network/terraform.tfstate"},
	} {
		got := localPath(c.key, c.from)
		if got != c.want {
			t.Errorf("localPath(%q, %q) = %q, want %q", c.key, c.from, got, c.want)
		}
	}
}
