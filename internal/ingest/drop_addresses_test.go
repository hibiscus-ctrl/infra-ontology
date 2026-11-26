// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"strings"
	"testing"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// A build that drops addresses has no address or module path on a node, not
// even in the native ID of a module call or the name of the placeholder of a
// state no one can place, and it keeps what the addresses were used for: the
// edges and the statuses. It works with a key too.
func TestDropAddressesLeavesNoAddress(t *testing.T) {
	plain := build(t, fixtureReads(t))
	var addrs []string
	for _, n := range plain.Tables.Nodes {
		addrs = append(addrs, n.Address, n.Module)
	}

	for name, key := range map[string][]byte{"plain": nil, "hashed": testKey} {
		t.Run(name, func(t *testing.T) {
			o := hashedOpts(key)
			o.DropAddresses = true
			res, err := Build(fixtureReads(t), o)
			if err != nil {
				t.Fatal(err)
			}
			if !res.Redaction.AddressesDropped {
				t.Errorf("redaction: %+v", res.Redaction)
			}
			if !strings.Contains(res.Limits, "addresses and module paths are left out") {
				t.Errorf("limits: %s", res.Limits)
			}
			for _, n := range res.Tables.Nodes {
				if n.Address != "" || n.Module != "" {
					t.Errorf("node %s keeps %q, %q", n.NodeID, n.Address, n.Module)
				}
				if n.Kind == snapshot.KindModuleCall && n.NativeID != "" {
					t.Errorf("a module call keeps its native ID %q", n.NativeID)
				}
			}
			for name, files := range map[string]map[string][]byte{"files": writeHashed(t, res)} {
				for file, data := range files {
					for _, a := range addrs {
						if a != "" && strings.Contains(string(data), a) {
							t.Errorf("%s %s says %q", name, file, a)
						}
					}
				}
			}
			if len(res.Tables.Nodes) != len(plain.Tables.Nodes) || len(res.Tables.Edges) != len(plain.Tables.Edges) {
				t.Errorf("%d nodes, %d edges; want %d, %d", len(res.Tables.Nodes), len(res.Tables.Edges),
					len(plain.Tables.Nodes), len(plain.Tables.Edges))
			}
			if key != nil {
				return // the names are hashed
			}
			placeholders := 0
			for _, n := range res.Tables.Nodes {
				if strings.HasPrefix(n.Name, "(unplaced)") {
					placeholders++
					if !strings.HasSuffix(n.Name, "backend of a data source") {
						t.Errorf("placeholder: %+v", n)
					}
				}
			}
			if placeholders != 1 {
				t.Errorf("%d placeholders of a state no one can place, want 1", placeholders)
			}
		})
	}
}

// The inventories are matched to the states by address before the addresses
// are dropped, so dropping them changes no status.
func TestDropAddressesKeepsTheMatching(t *testing.T) {
	invs := inventoryReads(t)
	want, err := BuildAll(fixtureReads(t), invs, opts)
	if err != nil {
		t.Fatal(err)
	}
	o := opts
	o.DropAddresses = true
	got, err := BuildAll(fixtureReads(t), invs, o)
	if err != nil {
		t.Fatal(err)
	}
	if statusCounts(got.Tables) != statusCounts(want.Tables) || joinedCount(got.Tables) != joinedCount(want.Tables) {
		t.Errorf("statuses %s joined %d; want %s joined %d",
			statusCounts(got.Tables), joinedCount(got.Tables), statusCounts(want.Tables), joinedCount(want.Tables))
	}
	for _, n := range got.Tables.Nodes {
		if n.Address != "" || n.Module != "" {
			t.Errorf("node %s keeps %q, %q", n.NodeID, n.Address, n.Module)
		}
	}
}
