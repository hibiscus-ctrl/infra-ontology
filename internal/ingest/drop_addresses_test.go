// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"regexp"
	"strings"
	"testing"

	"github.com/IgnatG/infraharvest/pkg/tfstate"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// A build that drops addresses has no address, module path or Terraform name
// on a node, not even in the native ID or name of a module call or the name of
// the placeholder of a state no one can place, and it keeps what the addresses
// were used for: the edges, the node IDs and the statuses. It works with a key
// too.
func TestDropAddressesLeavesNoAddress(t *testing.T) {
	plain := build(t, leakyReads(t))
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
			res, err := Build(leakyReads(t), o)
			if err != nil {
				t.Fatal(err)
			}
			checkLeakyTags(t, res)
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

const leakyRoot = "s3://acme-tfstate/prod/leaky.tfstate"

// leakyReads are the fixtures and a state whose resource, in a module, has
// tags that hold its address, its module path and its Terraform name (in
// another case too), and one that names none of them. The data source has
// tags a looked-up resource would have, which are not carried at all.
func leakyReads(t *testing.T) []Read {
	t.Helper()
	const state = `{"version":4,"serial":1,"lineage":"l","terraform_version":"1.9.0","outputs":{},"resources":[
	 {"module":"module.edge_net","mode":"managed","type":"aws_instance","name":"gateway","provider":"provider[\"registry.terraform.io/hashicorp/aws\"]",
	  "instances":[{"attributes":{"id":"i-0c0ffee0","tags":{"tf_address":"module.edge_net.aws_instance.gateway","tf_module":"MODULE.EDGE_NET",
	   "Name":"Gateway","gateway_owner":"ops","team":"payments"}}}]},
	 {"module":"module.edge_net","mode":"data","type":"aws_ami","name":"imagelookup","provider":"provider[\"registry.terraform.io/hashicorp/aws\"]",
	  "instances":[{"attributes":{"id":"ami-0aa11bb2","tags":{"source":"looked-up"}}}]}]}`
	d, err := tfstate.Parse([]byte(state), leakyRoot)
	if err != nil {
		t.Fatal(err)
	}
	return append(fixtureReads(t), Read{Location: leakyRoot, Docs: []tfstate.Document{d}})
}

// checkLeakyTags checks that the resource of leakyReads kept the one tag that
// names nothing, that the dropped ones are counted and their keys not listed,
// and that the data source has no tag.
func checkLeakyTags(t *testing.T, res Result) {
	t.Helper()
	var kept int
	for _, n := range res.Tables.Nodes {
		if n.Tags["team"] == "payments" {
			kept++
			if len(n.Tags) != 1 {
				t.Errorf("the resource keeps %v, want only team", n.Tags)
			}
		}
		if n.Tags["source"] != "" {
			t.Errorf("a data source has tags %v", n.Tags)
		}
	}
	if kept != 1 {
		t.Errorf("%d nodes keep the unrelated tag, want 1", kept)
	}
	if !strings.Contains(res.Limits, "4 tags look like secrets, or were dropped by request") {
		t.Errorf("limits do not count the tags that gave an address away: %s", res.Limits)
	}
	for _, k := range res.Redaction.TagKeysDropped {
		if strings.EqualFold(k, "gateway_owner") || strings.EqualFold(k, "tf_address") || strings.EqualFold(k, "tf_module") {
			t.Errorf("the dropped keys list %q", k)
		}
	}
}
