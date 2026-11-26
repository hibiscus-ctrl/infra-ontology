// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// fixtureAddresses are the Terraform addresses and module paths the fixture
// states and inventories give, read from a snapshot built without
// --drop-addresses.
func fixtureAddresses(t *testing.T, l *snapshot.Loaded) []string {
	t.Helper()
	seen := map[string]bool{}
	for _, n := range l.Tables.Nodes {
		for _, a := range []string{n.Address, n.Module} {
			if a != "" {
				seen[a] = true
			}
		}
	}
	var all []string
	for a := range seen {
		all = append(all, a)
	}
	sort.Strings(all)
	return all
}

// chanceWords are Terraform names of the fixtures that a snapshot says for
// another reason, so finding one proves nothing and the scan skips them as
// words of their own: "main" (the cloud names of inventory resources), "platform" (a
// state file, so a location) and "this" (an English word, as in the limits).
// Names of three characters or fewer (a, app, db, dns, hub, net, odd, vm) are
// skipped too, as they are in state file names, types and ARNs. What the
// scan does look for: every "type.name" (aws_vpc.main), every other name, and
// the name and key of every module call.
var chanceWords = map[string]bool{"main": true, "platform": true, "this": true}

// leaks says whether text gives a fragment away. A name of letters, digits
// and underscores (network, front, logs) is looked for as a word that does not
// continue another one to its left (not virtual_network, subnetwork,
// microsoft.network or acme-logs, which a type or a cloud's own name says);
// anything with other characters in it (["s3"], endpoints["s3"],
// aws_vpc.main) is looked for as it is.
func leaks(text, fragment string) bool {
	if !wordRE.MatchString(fragment) {
		return strings.Contains(text, fragment)
	}
	return regexp.MustCompile(`(?:^|[^a-zA-Z0-9_./-])` + regexp.QuoteMeta(fragment)).MatchString(text)
}

var wordRE = regexp.MustCompile(`^[a-z0-9_]+$`)

var keyRE = regexp.MustCompile(`\["[^"]*"\]`)

// fixtureFragments are the pieces of an address that give it away alone, read
// from a snapshot built without --drop-addresses: "type.name" of every
// resource, its name, the name and key of every module call (endpoints,
// ["s3"], endpoints["s3"], network) and the key of every instance.
func fixtureFragments(t *testing.T, l *snapshot.Loaded) []string {
	t.Helper()
	seen := map[string]bool{}
	add := func(f string) {
		if len(f) > 3 && !chanceWords[f] {
			seen[f] = true
		}
	}
	for _, n := range l.Tables.Nodes {
		for _, k := range keyRE.FindAllString(n.Address, -1) {
			add(k)
		}
		switch n.Kind {
		case snapshot.KindModuleCall:
			add(n.Name)
			if i := strings.IndexByte(n.Name, '['); i > 0 {
				add(n.Name[:i])
			} else {
				add(n.Name)
			}
		case snapshot.KindResource:
			if n.Address == "" || n.TFType == "" {
				continue
			}
			add(n.Name)
			seen[n.TFType+"."+n.Name] = true
		}
	}
	var all []string
	for f := range seen {
		all = append(all, f)
	}
	sort.Strings(all)
	return all
}

// textOf is every file of a snapshot folder as one text, and its tables as
// JSON, in case a file stores them in a way that hides a string.
func textOf(t *testing.T, dir string, l *snapshot.Loaded) []string {
	t.Helper()
	var all []string
	for name, data := range snapshotFiles(t, dir) {
		all = append(all, name, string(data))
	}
	rows, err := json.Marshal(l.Tables)
	if err != nil {
		t.Fatal(err)
	}
	man, err := json.Marshal(l.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	return append(all, string(rows), string(man))
}

func TestDropAddressesLeavesNoAddressInASnapshot(t *testing.T) {
	clearKeyEnv(t)
	_, plainDir, _, _ := buildState(t, hashArgs()...)
	plain := loadSnapshot(t, plainDir)
	addrs := fixtureAddresses(t, plain)
	frags := fixtureFragments(t, plain)
	for _, f := range []string{"aws_vpc.main", "endpoints", `["s3"]`, `endpoints["s3"]`, "network", "front", "aws_lb.front"} {
		if !slices.Contains(frags, f) {
			t.Fatalf("the fragments %v lack %q", frags, f)
		}
	}
	if len(addrs) < 10 {
		t.Fatalf("the fixtures give %d addresses: %v", len(addrs), addrs)
	}
	for _, a := range []string{"aws_vpc.main", "module.net"} {
		found := false
		for _, have := range addrs {
			found = found || strings.Contains(have, a)
		}
		if !found {
			t.Fatalf("the fixtures have no address with %s", a)
		}
	}

	keyFile := writeKey(t, hashKey)
	for name, extra := range map[string][]string{
		"alone":    {"--drop-addresses"},
		"hash-ids": {"--drop-addresses", "--hash-ids", "--hash-key-file", keyFile},
	} {
		t.Run(name, func(t *testing.T) {
			clearKeyEnv(t)
			code, dir, out, errs := buildState(t, hashArgs(extra...)...)
			if code != 0 || errs != "" || dir == "" {
				t.Fatalf("exit %d: %s%s", code, out, errs)
			}
			l := loadSnapshot(t, dir)
			if !l.Manifest.Redaction.AddressesDropped {
				t.Errorf("the manifest does not say the addresses were dropped: %+v", l.Manifest.Redaction)
			}
			if l.Manifest.Redaction.IDsHashed != (name == "hash-ids") {
				t.Errorf("ids_hashed: %+v", l.Manifest.Redaction)
			}
			if !strings.Contains(l.Manifest.Limits, "Terraform addresses, module paths and the Terraform names") ||
				strings.Contains(l.Manifest.Limits, "unkeyed SHA-256") != (name == "alone") {
				t.Errorf("limits: %s", l.Manifest.Limits)
			}
			for _, n := range l.Tables.Nodes {
				if n.Address != "" || n.Module != "" {
					t.Errorf("node %s keeps %q, %q", n.NodeID, n.Address, n.Module)
				}
				// The Terraform name is the last part of the address; only a
				// resource an inventory alone holds has a name left, and the
				// cloud gives it. (hashed: it is a hash.)
				if n.Kind == snapshot.KindModuleCall && n.Name != "" {
					t.Errorf("module call %s keeps its name %q", n.NodeID, n.Name)
				}
				if n.Kind == snapshot.KindResource && n.TFType != "" && n.Name != "" && n.SourceID != "" && n.ManagedStatus == snapshot.Managed {
					t.Errorf("resource %s of a state keeps its name %q", n.NodeID, n.Name)
				}
			}

			// Nothing else says them: not a node, edge or source, not the
			// manifest, not a file's name, not the output.
			texts := append(textOf(t, dir, l), out, errs)
			for _, text := range texts {
				for _, a := range addrs {
					if strings.Contains(text, a) {
						t.Errorf("%q is in the snapshot or the output: %.200s", a, text[max(0, strings.Index(text, a)-60):])
					}
				}
				for _, f := range frags {
					if leaks(text, f) {
						t.Errorf("the address fragment %q is in the snapshot or the output: %.200s", f, text[max(0, strings.Index(text, f)-60):])
					}
				}
			}

			// The rest of the snapshot is what it was.
			if len(l.Tables.Nodes) != len(plain.Tables.Nodes) || len(l.Tables.Edges) != len(plain.Tables.Edges) ||
				len(l.Tables.Sources) != len(plain.Tables.Sources) {
				t.Errorf("rows: %d nodes, %d edges, %d sources; want %d, %d, %d",
					len(l.Tables.Nodes), len(l.Tables.Edges), len(l.Tables.Sources),
					len(plain.Tables.Nodes), len(plain.Tables.Edges), len(plain.Tables.Sources))
			}
			counts := statusCounts(l)
			if want := statusCounts(plain); counts[snapshot.Managed] != want[snapshot.Managed] ||
				counts[snapshot.Unmanaged] != want[snapshot.Unmanaged] {
				t.Errorf("statuses: %v, want %v", counts, want)
			}

			// The commands that read a snapshot give none away either: verify,
			// export, and diff between two snapshots that both dropped them
			// (the second holds fewer states, so every side has rows to name).
			code, other, _, errs := buildState(t, append([]string{"--label", "prod", "--state", "net.tfstate", "--state", "app.tfstate"}, extra...)...)
			if code != 0 || other == "" {
				t.Fatalf("exit %d: %s", code, errs)
			}
			for _, args := range [][]string{
				{"verify", dir}, {"export", "graph", "--cloud", "aws", dir}, {"export", "graph", dir},
				{"diff", "--json", other, dir}, {"diff", other, dir}, {"diff", "--json", dir, other}, {"diff", dir, other},
			} {
				code, out, errs := exec(t, args...)
				if code != 0 && (args[0] != "export" || len(args) != 3) && args[0] != "diff" {
					t.Errorf("%v: exit %d: %s", args, code, errs)
				}
				if args[0] == "diff" && out == "" {
					t.Errorf("%v: no output to check: exit %d: %s", args, code, errs)
				}
				for _, a := range addrs {
					if strings.Contains(out+errs, a) {
						t.Errorf("%v gives %q away", args, a)
					}
				}
				for _, f := range frags {
					if leaks(out+errs, f) {
						t.Errorf("%v gives %q away", args, f)
					}
				}
			}
			_, graph, _ := exec(t, "export", "graph", "--cloud", "aws", dir)
			if !strings.Contains(graph, `"addresses": "dropped"`) {
				t.Errorf("the graph does not say the addresses were dropped: %.300s", graph)
			}
		})
	}
}

// The same estate with --drop-addresses is the same snapshot every time.
func TestDropAddressesIsRepeatable(t *testing.T) {
	clearKeyEnv(t)
	_, a, _, _ := buildState(t, hashArgs("--drop-addresses")...)
	_, b, _, _ := buildState(t, hashArgs("--drop-addresses")...)
	if loadSnapshot(t, a).Manifest.SnapshotID != loadSnapshot(t, b).Manifest.SnapshotID {
		t.Error("two builds differ")
	}
}

func TestDropAddressesNeedsWhatItDrops(t *testing.T) {
	t.Chdir(statesDir)
	out := t.TempDir()
	code, stdout, errs := exec(t, "snapshot", "build", "--out", out, "--drop-addresses", "--from-json", "x.json")
	if code != 2 || stdout != "" || !strings.Contains(errs, "--drop-addresses applies to") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, stdout, errs)
	}
	if entries, _ := os.ReadDir(out); len(entries) != 0 {
		t.Errorf("wrote %v", entries)
	}
}
