// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IgnatG/infraharvest/pkg/secretscan"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// hashKey is a test key, not a secret: it has the 16 bytes or more that
// --hash-ids asks for.
const hashKey = "cmd-test-key-0123456789-abcdef"

func writeKey(t *testing.T, key string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// clearKeyEnv keeps a key in the environment of whoever runs the tests out of
// them.
func clearKeyEnv(t *testing.T) {
	t.Helper()
	t.Setenv(keyEnv, "")
	t.Setenv(secretscan.KeyEnv, "")
}

var hashStates = []string{"--state", "net.tfstate", "--state", "app.tfstate", "--state", "hub.tfstate", "--state", "dns.tfstate"}

func hashArgs(extra ...string) []string {
	return append(append([]string{"--label", "prod"}, hashStates...), append(allInventories(), extra...)...)
}

func snapshotFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	_ = fs.WalkDir(os.DirFS(dir), ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, rerr := os.ReadFile(filepath.Join(dir, p))
			if rerr != nil {
				t.Fatal(rerr)
			}
			files[p] = b
		}
		return nil
	})
	return files
}

func TestHashIDsWritesAHashedSnapshot(t *testing.T) {
	clearKeyEnv(t)
	keyFile := writeKey(t, hashKey)
	code, dir, out, errs := buildState(t, hashArgs("--hash-ids", "--hash-key-file", keyFile)...)
	if code != 0 || errs != "" || dir == "" {
		t.Fatalf("exit %d: %s%s", code, out, errs)
	}
	l := loadSnapshot(t, dir)
	if r := l.Manifest.Redaction; r.HashAlgorithm != "hmac-sha256" || !r.IDsHashed || r.AddressesDropped {
		t.Errorf("redaction: %+v", r)
	}
	if !strings.Contains(l.Manifest.Limits, "HMAC-SHA256 hashes") {
		t.Errorf("limits: %s", l.Manifest.Limits)
	}

	// A managed resource is joined to its inventory entry, by hash.
	want := secretscan.Hash([]byte(hashKey), "vpc-0a1b")
	found := false
	for _, n := range l.Tables.Nodes {
		if n.NativeID == want {
			found = true
			if n.ManagedStatus != snapshot.Managed || n.InventoryType != "aws_vpc" || n.Account != "111111111111" {
				t.Errorf("vpc: %+v", n)
			}
		}
	}
	if !found {
		t.Errorf("no node with the hash of vpc-0a1b, %s", want)
	}
	counts := statusCounts(l)
	if counts[snapshot.Managed] != 18 || counts[snapshot.Unmanaged] != 9 || counts[snapshot.OtherIaC] != 1 {
		t.Errorf("statuses: %v", counts)
	}

	// Neither the key nor anything it hides is in a file, or on the output.
	hidden := []string{"vpc-0a1b", "net.tfstate", "acme-tfstate", "acme-orphan", "aws_vpc.main", "acme-logs-app", "Hub-VNet"}
	all := append([]string{out, errs}, "")
	for name, data := range snapshotFiles(t, dir) {
		all = append(all, name, string(data))
	}
	for _, text := range all {
		for _, secret := range append(hidden, hashKey, hex.EncodeToString([]byte(hashKey))) {
			if strings.Contains(text, secret) {
				t.Errorf("%q is in the output", secret)
			}
		}
	}

	// A snapshot of the same states and key is the same snapshot, whether
	// the key comes from a file or from either variable, and with another key
	// it is not.
	id := l.Manifest.SnapshotID
	for name, set := range map[string]func(*testing.T) []string{
		"file with another name": func(t *testing.T) []string { return []string{"--hash-key-file", writeKey(t, hashKey)} },
		keyEnv:                   func(t *testing.T) []string { t.Setenv(keyEnv, hashKey); return nil },
		secretscan.KeyEnv:        func(t *testing.T) []string { t.Setenv(secretscan.KeyEnv, hashKey); return nil },
	} {
		clearKeyEnv(t)
		extra := set(t)
		code, dir2, _, errs := buildState(t, hashArgs(append([]string{"--hash-ids"}, extra...)...)...)
		if code != 0 {
			t.Fatalf("%s: exit %d: %s", name, code, errs)
		}
		if got := loadSnapshot(t, dir2).Manifest.SnapshotID; got != id {
			t.Errorf("%s: snapshot %s, want %s", name, got, id)
		}
	}
	clearKeyEnv(t)
	_, dir3, _, _ := buildState(t, hashArgs("--hash-ids", "--hash-key-file", writeKey(t, hashKey+"-other"))...)
	if loadSnapshot(t, dir3).Manifest.SnapshotID == id {
		t.Error("another key gives the same snapshot")
	}
	// The variable of this tool comes before infraharvest's.
	t.Setenv(keyEnv, hashKey)
	t.Setenv(secretscan.KeyEnv, hashKey+"-other")
	_, dir4, _, _ := buildState(t, hashArgs("--hash-ids")...)
	if loadSnapshot(t, dir4).Manifest.SnapshotID != id {
		t.Error("INFRAHARVEST_EXPORT_KEY wins over INFRA_ONTOLOGY_KEY")
	}
}

func TestHashedSnapshotsVerifyAndDiff(t *testing.T) {
	clearKeyEnv(t)
	keyFile := writeKey(t, hashKey)
	_, first, _, _ := buildState(t, "--hash-ids", "--hash-key-file", keyFile, "--state", "net.tfstate", "--state", "app.tfstate")
	l := loadSnapshot(t, first)
	_, second, _, _ := buildState(t, "--hash-ids", "--hash-key-file", keyFile, "--parent", l.Manifest.SnapshotID,
		"--state", "net.tfstate", "--state", "app.tfstate", "--state", "dns.tfstate")

	code, out, errs := exec(t, "verify", second)
	if code != 0 {
		t.Fatalf("verify: %d %s%s", code, out, errs)
	}
	code, out, errs = exec(t, "diff", "--json", first, second)
	if code != 0 {
		t.Fatalf("diff: %d %s", code, errs)
	}
	var d snapshot.Diff
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatal(err)
	}
	if d.Summary.NodesAdded == 0 || d.Summary.NodesRemoved != 0 {
		t.Errorf("diff: %+v", d.Summary)
	}
	if strings.Contains(out, hashKey) || strings.Contains(out, "dns.tfstate") {
		t.Errorf("the diff gives away what is hashed: %s", out)
	}
	// The picture of a hashed snapshot carries the hashes over.
	code, out, errs = exec(t, "export", "graph", "--cloud", "aws", second)
	if code != 0 || !strings.Contains(out, "\"ids_hashed\": true") || strings.Contains(out, hashKey) {
		t.Errorf("export graph: %d %s", code, errs)
	}
	// The same states, hashed and not, are two snapshots that share no node.
	_, plain, _, _ := buildState(t, "--state", "net.tfstate", "--state", "app.tfstate")
	if code, out, _ := exec(t, "diff", "--json", plain, first); code != 0 || !bytes.Contains([]byte(out), []byte("nodes_added")) {
		t.Errorf("diff of a plain and a hashed snapshot: %d %s", code, out)
	}
}

func TestHashIDsNeedsAKeyYouHold(t *testing.T) {
	clearKeyEnv(t)
	short := writeKey(t, "too-short")
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no key", []string{"--hash-ids", "--state", "net.tfstate"}, "needs a key you hold"},
		{"short key", []string{"--hash-ids", "--hash-key-file", short, "--state", "net.tfstate"}, "at least 16 bytes"},
		{"no such key file", []string{"--hash-ids", "--hash-key-file", filepath.Join(t.TempDir(), "none"), "--state", "net.tfstate"}, "--hash-key-file"},
		{"key file without --hash-ids", []string{"--hash-key-file", writeKey(t, hashKey), "--state", "net.tfstate"}, "--hash-key-file is for --hash-ids"},
		{"from json", []string{"--hash-ids", "--hash-key-file", writeKey(t, hashKey), "--from-json", "x.json"}, "not --from-json"},
	}
	for _, c := range cases {
		t.Chdir(statesDir)
		out := t.TempDir()
		code, stdout, errs := exec(t, append([]string{"snapshot", "build", "--out", out}, c.args...)...)
		if code != 2 || stdout != "" || !strings.Contains(errs, c.want) {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want 2 and %q", c.name, code, stdout, errs, c.want)
		}
		if strings.Contains(errs, hashKey) || strings.Contains(errs, "too-short") {
			t.Errorf("%s: the key is in the message: %s", c.name, errs)
		}
		if entries, _ := os.ReadDir(out); len(entries) != 0 {
			t.Errorf("%s: wrote %v", c.name, entries)
		}
	}
}

// A key that is a variable of the environment and not a file works for a key
// read from either name, and a short one is refused whichever it is.
func TestHashKeyFromTheEnvironmentIsChecked(t *testing.T) {
	clearKeyEnv(t)
	t.Setenv(keyEnv, "short")
	t.Chdir(statesDir)
	code, _, errs := exec(t, "snapshot", "build", "--out", t.TempDir(), "--hash-ids", "--state", "net.tfstate")
	if code != 2 || !strings.Contains(errs, "at least 16 bytes") || strings.Contains(errs, "short\n") {
		t.Errorf("exit %d: %s", code, errs)
	}
}
