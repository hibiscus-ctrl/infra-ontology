// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package snapshot

import (
	"bytes"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func mustBuild(t *testing.T, tables Tables, opts BuildOptions) *Snapshot {
	t.Helper()
	s, err := Build(tables, opts)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return s
}

func mustWrite(t *testing.T, s *Snapshot, parent string) string {
	t.Helper()
	dir, err := s.Write(parent)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	return dir
}

// TestGolden pins the bytes of a small estate: a change to the writer, its
// settings or the library that alters one byte fails here, and -update shows
// the new files for review.
func TestGolden(t *testing.T) {
	s := mustBuild(t, estate(), estateOptions())
	if *update {
		if err := os.MkdirAll(goldenDir(), 0o755); err != nil {
			t.Fatal(err)
		}
		for name, data := range s.Files {
			if err := os.WriteFile(filepath.Join(goldenDir(), name), data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		writeEstateJSON(t, filepath.Join("testdata", "estate.json"))
	}
	for name, got := range s.Files {
		want, err := os.ReadFile(filepath.Join(goldenDir(), name))
		if err != nil {
			t.Fatalf("%v (run go test ./internal/snapshot -update)", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from the golden file (run go test ./internal/snapshot -update and review the diff)", name)
		}
	}
	// The golden folder is itself a valid snapshot.
	if res := Verify(goldenDir()); !res.OK() {
		t.Errorf("golden snapshot does not verify:\n%s", res.Error())
	}
}

func TestBuildIsDeterministic(t *testing.T) {
	base := mustBuild(t, estate(), estateOptions())
	for seed := int64(1); seed <= 20; seed++ {
		in := estate()
		r := rand.New(rand.NewSource(seed))
		r.Shuffle(len(in.Nodes), func(i, j int) { in.Nodes[i], in.Nodes[j] = in.Nodes[j], in.Nodes[i] })
		r.Shuffle(len(in.Edges), func(i, j int) { in.Edges[i], in.Edges[j] = in.Edges[j], in.Edges[i] })
		r.Shuffle(len(in.Sources), func(i, j int) { in.Sources[i], in.Sources[j] = in.Sources[j], in.Sources[i] })
		opts := estateOptions()
		opts.CreatedAt = fixedTime.In(time.FixedZone("x", 3600)) // the same instant in another zone
		opts.Redaction.TagKeysDropped = []string{"api_key", "password", "api_key"}
		got := mustBuild(t, in, opts)
		if got.Manifest.SnapshotID != base.Manifest.SnapshotID {
			t.Fatalf("seed %d: id %s, want %s", seed, got.Manifest.SnapshotID, base.Manifest.SnapshotID)
		}
		for name, want := range base.Files {
			if !bytes.Equal(got.Files[name], want) {
				t.Fatalf("seed %d: %s differs for the same estate in another order", seed, name)
			}
		}
	}
}

func TestBuildDoesNotChangeItsInput(t *testing.T) {
	in := estate()
	want := estate()
	mustBuild(t, in, estateOptions())
	if !reflect.DeepEqual(in, want) {
		t.Error("Build changed the rows it was given")
	}
}

func TestIDChangesWithAnyInput(t *testing.T) {
	base := mustBuild(t, estate(), estateOptions()).Manifest.SnapshotID
	changes := map[string]func(*Tables, *BuildOptions){
		"a tag":         func(t *Tables, _ *BuildOptions) { t.Nodes[0].Tags = map[string]string{"k": "v"} },
		"a node name":   func(t *Tables, _ *BuildOptions) { t.Nodes[3].Name += "x" },
		"an edge basis": func(t *Tables, _ *BuildOptions) { t.Edges[0].Basis = "other_basis" },
		"a source":      func(t *Tables, _ *BuildOptions) { t.Sources[0].Reason = "r" },
		"created at":    func(_ *Tables, o *BuildOptions) { o.CreatedAt = o.CreatedAt.Add(time.Second) },
		"the label":     func(_ *Tables, o *BuildOptions) { o.Label = "other" },
		"the parent":    func(_ *Tables, o *BuildOptions) { o.ParentID = strings.Repeat("a", 64) },
		"the redaction": func(_ *Tables, o *BuildOptions) { o.Redaction.AllTagsDropped = true },
		"the limits":    func(_ *Tables, o *BuildOptions) { o.Limits += "." },
	}
	for name, change := range changes {
		in, opts := estate(), estateOptions()
		change(&in, &opts)
		if got := mustBuild(t, in, opts).Manifest.SnapshotID; got == base {
			t.Errorf("changing %s kept the id", name)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	s := mustBuild(t, estate(), estateOptions())
	dir := mustWrite(t, s, t.TempDir())
	l, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := normalise(estate())
	if !reflect.DeepEqual(l.Tables, want) {
		t.Errorf("rows read back differ from the rows written")
	}
	if l.Manifest.SnapshotID != s.Manifest.SnapshotID {
		t.Errorf("id %s, want %s", l.Manifest.SnapshotID, s.Manifest.SnapshotID)
	}
	// The collected_at of the inventory was given with an offset: it is stored in UTC.
	for _, src := range l.Tables.Sources {
		if src.SourceID == "inventory-aws" && src.CollectedAt != "2026-11-25T09:05:00Z" {
			t.Errorf("collected_at = %s, want 2026-11-25T09:05:00Z", src.CollectedAt)
		}
	}
	name, _ := DirName(s.Manifest)
	if filepath.Base(dir) != name || !strings.HasPrefix(name, "20261125T101500Z-") {
		t.Errorf("folder %s, want 20261125T101500Z-<id>", filepath.Base(dir))
	}
}

func TestWriteIsImmutable(t *testing.T) {
	parent := t.TempDir()
	s := mustBuild(t, estate(), estateOptions())
	dir := mustWrite(t, s, parent)
	if again := mustWrite(t, s, parent); again != dir {
		t.Errorf("second write went to %s, want %s", again, dir)
	}
	// A folder with the right name but a changed table is not overwritten and is reported.
	nodes := filepath.Join(dir, NodesFile)
	data, _ := os.ReadFile(nodes)
	data[len(data)/2] ^= 0xff
	if err := os.WriteFile(nodes, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write(parent); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("Write over a tampered folder: %v, want a verification error", err)
	}
	if entries, _ := os.ReadDir(parent); len(entries) != 1 {
		t.Errorf("parent has %d entries, want only the snapshot folder", len(entries))
	}
}

func TestPartialStatusAndCoverage(t *testing.T) {
	in := estate()
	in.Sources[0].Status, in.Sources[0].Reason = StatusPartial, "3 resources had no id"
	m := mustBuild(t, in, estateOptions()).Manifest
	if m.Status != StatusPartial {
		t.Errorf("status = %s, want partial", m.Status)
	}
	want := []FailedSource{{SourceID: "inventory-aws", Status: "partial", Reason: "3 resources had no id"}}
	// Sources sort by id, so the first in the input is "state-prod" or "inventory-aws" by what it is.
	if in.Sources[0].SourceID != "state-prod" {
		t.Fatal("test assumes the first source is state-prod")
	}
	want[0].SourceID = "state-prod"
	if !reflect.DeepEqual(m.Coverage.FailedSources, want) {
		t.Errorf("failed sources = %+v, want %+v", m.Coverage.FailedSources, want)
	}
	if !slices.Equal(m.Coverage.Clouds, []string{"aws"}) || !slices.Equal(m.Coverage.Accounts, []string{"111111111111", "222222222222"}) {
		t.Errorf("coverage = %+v", m.Coverage)
	}
	if m.SourcesSummary.Count != 3 || m.SourcesSummary.ByKind["state"] != 2 ||
		m.SourcesSummary.OldestCollectedAt != "2026-11-25T09:05:00Z" || m.SourcesSummary.NewestCollectedAt != "2026-11-25T09:59:00Z" {
		t.Errorf("sources summary = %+v", m.SourcesSummary)
	}
}

func TestBuildRejectsInvalidRows(t *testing.T) {
	cases := map[string]func(*Tables, *BuildOptions){
		"no created_at":                func(_ *Tables, o *BuildOptions) { o.CreatedAt = time.Time{} },
		"a bad parent id":              func(_ *Tables, o *BuildOptions) { o.ParentID = "nope" },
		"a duplicate node":             func(t *Tables, _ *BuildOptions) { t.Nodes = append(t.Nodes, t.Nodes[0]) },
		"a node id that is not a hash": func(t *Tables, _ *BuildOptions) { t.Nodes[0].NodeID = "abc" },
		"an unknown node kind":         func(t *Tables, _ *BuildOptions) { t.Nodes[0].Kind = "thing" },
		"an unknown managed status":    func(t *Tables, _ *BuildOptions) { t.Nodes[0].ManagedStatus = "maybe" },
		"a node citing no source":      func(t *Tables, _ *BuildOptions) { t.Nodes[0].SourceID = "nowhere" },
		"a dangling edge":              func(t *Tables, _ *BuildOptions) { t.Edges[0].ToID = strings.Repeat("0", 64) },
		"a duplicate edge":             func(t *Tables, _ *BuildOptions) { t.Edges = append(t.Edges, t.Edges[0]) },
		"a wrong edge id":              func(t *Tables, _ *BuildOptions) { t.Edges[0].EdgeID = strings.Repeat("1", 64) },
		"an edge kind with spaces":     func(t *Tables, _ *BuildOptions) { t.Edges[0].Kind = "Depends On" },
		"a duplicate source":           func(t *Tables, _ *BuildOptions) { t.Sources = append(t.Sources, t.Sources[0]) },
		"a source time":                func(t *Tables, _ *BuildOptions) { t.Sources[0].CollectedAt = "yesterday" },
	}
	for name, change := range cases {
		in, opts := estate(), estateOptions()
		change(&in, &opts)
		if _, err := Build(in, opts); err == nil {
			t.Errorf("Build accepted %s", name)
		}
	}
}

func TestEmptySnapshot(t *testing.T) {
	s := mustBuild(t, Tables{}, estateOptions())
	dir := mustWrite(t, s, t.TempDir())
	l, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Tables.Nodes)+len(l.Tables.Edges)+len(l.Tables.Sources) != 0 {
		t.Error("an empty snapshot read back with rows")
	}
}

func TestManifestIDIgnoresFormattingAndSeesUnknownMembers(t *testing.T) {
	a, err := ManifestID([]byte(`{"snapshot_id":"x","b":1,"a":[1,2.50],"c":"<&>"}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := ManifestID([]byte("{\n  \"c\": \"<&>\", \"a\": [1, 2.50], \"b\": 1\n}\n"))
	if a != b {
		t.Error("the id depends on the order or spacing of the manifest's members")
	}
	if c, _ := ManifestID([]byte(`{"a":[1,2.50],"b":1,"c":"<&>","later":true}`)); c == a {
		t.Error("a member this version does not know is left out of the id")
	}
	if _, err := ManifestID([]byte(`{} {}`)); err == nil {
		t.Error("ManifestID accepted two documents")
	}
}
