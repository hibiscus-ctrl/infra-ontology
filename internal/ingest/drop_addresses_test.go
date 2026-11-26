// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"regexp"
	"strings"
	"testing"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// A build that drops addresses has no address, module path or Terraform name
// on a node, not even in the native ID or name of a module call or the name of
// the placeholder of a state no one can place, and it keeps what the addresses
// were used for: the edges, the node IDs and the statuses. It works with a key
// too.
func TestDropAddressesLeavesNoAddress(t *testing.T) {
	plain := build(t, fixtureReads(t))
	var addrs []string
	// frags are the pieces that give an address away alone: type.name, the name
	// of a module call and its key (endpoints, ["s3"], network), and the name
	// of a resource a state holds when it is not a word the fixtures say for
	// another reason: main (a cloud name), platform (a state file), this
	// (English), and names of three characters or fewer (a, db, vm, app...).
	frags := map[string]bool{}
	key := regexp.MustCompile(`\["[^"]*"\]`)
	for _, n := range plain.Tables.Nodes {
		addrs = append(addrs, n.Address, n.Module)
		for _, k := range key.FindAllString(n.Address, -1) {
			frags[k] = true
		}
		switch {
		case n.Kind == snapshot.KindModuleCall:
			frags[n.Name] = true
			if i := strings.IndexByte(n.Name, '['); i > 0 {
				frags[n.Name[:i]] = true
			}
		case n.Kind == snapshot.KindResource && n.Address != "" && n.TFType != "":
			frags[n.TFType+"."+n.Name] = true
			if len(n.Name) > 3 && n.Name != "main" && n.Name != "platform" && n.Name != "this" {
				frags[n.Name] = true
			}
		}
	}
	for _, f := range []string{"aws_vpc.main", "endpoints", `["s3"]`, `endpoints["s3"]`, "network", "aws_lb.front"} {
		if !frags[f] {
			t.Fatalf("the fragments %v lack %q", frags, f)
		}
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
			if !strings.Contains(res.Limits, "Terraform addresses, module paths and the Terraform names") ||
				strings.Contains(res.Limits, "unkeyed SHA-256") != (key == nil) {
				t.Errorf("limits: %s", res.Limits)
			}
			for _, n := range res.Tables.Nodes {
				if n.Address != "" || n.Module != "" {
					t.Errorf("node %s keeps %q, %q", n.NodeID, n.Address, n.Module)
				}
				if n.Kind == snapshot.KindModuleCall && n.NativeID != "" {
					t.Errorf("a module call keeps its native ID %q", n.NativeID)
				}
				if n.Kind == snapshot.KindModuleCall && n.Name != "" {
					t.Errorf("a module call keeps its name %q", n.Name)
				}
				if n.Kind == snapshot.KindResource && n.SourceID != "" && strings.HasPrefix(n.SourceID, "state-") && n.Name != "" {
					t.Errorf("a resource of a state keeps its name %q", n.Name)
				}
			}
			for name, files := range map[string]map[string][]byte{"files": writeHashed(t, res)} {
				for file, data := range files {
					for _, a := range addrs {
						if a != "" && strings.Contains(string(data), a) {
							t.Errorf("%s %s says %q", name, file, a)
						}
					}
					for f := range frags {
						if strings.Contains(string(data), f) && !chance(string(data), f) {
							t.Errorf("%s %s says %q", name, file, f)
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

// chance says whether a fragment is in text only as the end of something
// longer a type or a cloud's own name says (virtual_network, acme-logs): a
// word of letters, digits and underscores counts only when nothing joins it to
// the left. Anything else (["s3"], aws_vpc.main) is never by chance.
func chance(text, f string) bool {
	if !regexp.MustCompile(`^[a-z0-9_]+$`).MatchString(f) {
		return false
	}
	return !regexp.MustCompile(`(?:^|[^a-zA-Z0-9_./-])` + regexp.QuoteMeta(f)).MatchString(text)
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
