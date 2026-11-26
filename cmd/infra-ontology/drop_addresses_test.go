// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"os"
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
			if !strings.Contains(l.Manifest.Limits, "addresses and module paths are left out") {
				t.Errorf("limits: %s", l.Manifest.Limits)
			}
			for _, n := range l.Tables.Nodes {
				if n.Address != "" || n.Module != "" {
					t.Errorf("node %s keeps %q, %q", n.NodeID, n.Address, n.Module)
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

			// The commands that read a snapshot give none away either.
			for _, args := range [][]string{{"verify", dir}, {"export", "graph", "--cloud", "aws", dir}, {"diff", "--json", plainDir, dir}} {
				code, out, errs := exec(t, args...)
				if code != 0 && args[0] != "diff" {
					t.Errorf("%v: exit %d: %s", args, code, errs)
				}
				for _, a := range addrs {
					if args[0] != "diff" && strings.Contains(out+errs, a) {
						t.Errorf("%v gives %q away", args, a)
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
