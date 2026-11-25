// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package snapshot

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writtenEstate(t *testing.T) string {
	t.Helper()
	return mustWrite(t, mustBuild(t, estate(), estateOptions()), t.TempDir())
}

func TestVerifyAcceptsASnapshot(t *testing.T) {
	res := Verify(writtenEstate(t))
	if !res.OK() {
		t.Fatalf("a written snapshot does not verify:\n%s", res.Error())
	}
	if len(res.Tables) != 3 || res.Label != "baseline" || len(res.SnapshotID) != 64 {
		t.Errorf("result = %+v", res)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	flip := func(file string) func(t *testing.T, dir string) {
		return func(t *testing.T, dir string) {
			p := filepath.Join(dir, file)
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			b[len(b)/2] ^= 0x01 // one bit, in the middle of the file
			if err := os.WriteFile(p, b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	replaceInManifest := func(old, repl string) func(t *testing.T, dir string) {
		return func(t *testing.T, dir string) {
			p := filepath.Join(dir, ManifestFile)
			b, _ := os.ReadFile(p)
			if !strings.Contains(string(b), old) {
				t.Fatalf("manifest has no %q", old)
			}
			if err := os.WriteFile(p, []byte(strings.Replace(string(b), old, repl, 1)), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	cases := []struct {
		name   string
		tamper func(t *testing.T, dir string)
		want   string
	}{
		{"a byte of nodes.parquet", flip(NodesFile), "nodes.parquet: sha256"},
		{"a byte of edges.parquet", flip(EdgesFile), "edges.parquet: sha256"},
		{"a byte of sources.parquet", flip(SourcesFile), "sources.parquet: sha256"},
		{"a table truncated", func(_ *testing.T, dir string) {
			p := filepath.Join(dir, NodesFile)
			b, _ := os.ReadFile(p)
			_ = os.WriteFile(p, b[:len(b)/2], 0o644)
		}, "nodes.parquet: sha256"},
		{"a table removed", func(_ *testing.T, dir string) { _ = os.Remove(filepath.Join(dir, EdgesFile)) }, "edges.parquet:"},
		{"the label in the manifest", replaceInManifest(`"baseline"`, `"changed"`), "snapshot_id is"},
		{"the parent in the manifest", replaceInManifest(`"parent_id": ""`, `"parent_id": "`+strings.Repeat("b", 64)+`"`), "snapshot_id is"},
		{"a table hash in the manifest", replaceInManifest(`"rows": 3`, `"rows": 4`), "snapshot_id is"},
		{"the id in the manifest", func(_ *testing.T, dir string) {
			p := filepath.Join(dir, ManifestFile)
			b, _ := os.ReadFile(p)
			s := string(b)
			i := strings.Index(s, `"snapshot_id": "`) + len(`"snapshot_id": "`)
			c := "0"
			if s[i] == '0' {
				c = "1"
			}
			_ = os.WriteFile(p, []byte(s[:i]+c+s[i+1:]), 0o644)
		}, "snapshot_id is"},
		{"a table added", func(_ *testing.T, dir string) {
			_ = os.WriteFile(filepath.Join(dir, "extra.parquet"), []byte("PAR1"), 0o644)
		}, "extra.parquet: a table the manifest does not list"},
		{"a manifest removed", func(_ *testing.T, dir string) { _ = os.Remove(filepath.Join(dir, ManifestFile)) }, "manifest.json:"},
		{"a manifest that is not JSON", func(_ *testing.T, dir string) {
			_ = os.WriteFile(filepath.Join(dir, ManifestFile), []byte("not json"), 0o644)
		}, "not a manifest"},
		{"a newer major version", replaceInManifest(`snapshot/v1`, `snapshot/v2`), "not supported"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writtenEstate(t)
			tc.tamper(t, dir)
			res := Verify(dir)
			if res.OK() {
				t.Fatal("Verify accepted a tampered snapshot")
			}
			if !strings.Contains(res.Error(), tc.want) {
				t.Errorf("problems = %q, want one containing %q", res.Error(), tc.want)
			}
			if _, err := Load(dir); err == nil {
				t.Error("Load read a tampered snapshot")
			}
		})
	}
}

// A table a writer got wrong but hashed honestly (so the manifest and the
// hashes agree) is still caught, by the row checks.
func TestVerifyChecksRowsConsistencyEvenWhenHashesAgree(t *testing.T) {
	s := mustBuild(t, estate(), estateOptions())
	in := normalise(estate())
	in.Edges[0].ToID = strings.Repeat("0", 64) // a dangling edge
	edges, err := encodeEdges(in.Edges)
	if err != nil {
		t.Fatal(err)
	}
	s.Files[EdgesFile] = edges
	for i := range s.Manifest.Tables {
		if s.Manifest.Tables[i].Name == "edges" {
			s.Manifest.Tables[i].SHA256 = sha256Hex(edges)
		}
	}
	s.Manifest.SnapshotID = ""
	raw, _ := marshalManifest(s.Manifest)
	s.Manifest.SnapshotID, _ = ManifestID(raw)
	s.Files[ManifestFile], _ = marshalManifest(s.Manifest)
	dir := t.TempDir()
	for name, data := range s.Files {
		_ = os.WriteFile(filepath.Join(dir, name), data, 0o644)
	}
	res := Verify(dir)
	if res.OK() || !strings.Contains(res.Error(), "is not a node") {
		t.Errorf("Verify = %q, want a dangling-edge problem", res.Error())
	}
}

func TestFindParent(t *testing.T) {
	parent := t.TempDir()
	first := mustBuild(t, estate(), estateOptions())
	firstDir := mustWrite(t, first, parent)
	if p, err := FindParent(firstDir); err != nil || p != "" {
		t.Errorf("FindParent(first) = %q, %v, want none", p, err)
	}
	opts := estateOptions()
	opts.ParentID, opts.Label, opts.CreatedAt = first.Manifest.SnapshotID, "next", fixedTime.Add(time.Hour)
	secondDir := mustWrite(t, mustBuild(t, estate(), opts), parent)
	if p, err := FindParent(secondDir); err != nil || p != firstDir {
		t.Errorf("FindParent(second) = %q, %v, want %q", p, err, firstDir)
	}
	if err := os.RemoveAll(firstDir); err != nil {
		t.Fatal(err)
	}
	if _, err := FindParent(secondDir); err == nil {
		t.Error("FindParent found a parent that is not there")
	}
}

func TestFindParentRejectsAMalformedParentID(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "child")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"abc", "zz" + strings.Repeat("0", 62)} {
		raw := []byte(`{"parent_id":"` + id + `"}`)
		if err := os.WriteFile(filepath.Join(dir, ManifestFile), raw, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := FindParent(dir); err == nil || !strings.Contains(err.Error(), "not a snapshot id") {
			t.Errorf("FindParent with parent_id %q: want an error, got %v", id, err)
		}
	}
}

func TestLoadAndVerifyReturnTheManifestBytesTheyHashed(t *testing.T) {
	dir := writtenEstate(t)
	want, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		t.Fatal(err)
	}
	l, err := Load(dir)
	if err != nil || !bytes.Equal(l.ManifestRaw, want) {
		t.Errorf("Load: %v, bytes equal %v", err, err == nil && bytes.Equal(l.ManifestRaw, want))
	}
	res, raw := VerifyWithManifest(dir)
	if !res.OK() || !bytes.Equal(raw, want) {
		t.Errorf("VerifyWithManifest: %+v", res)
	}
	// A folder that does not verify still returns the bytes it read.
	if err := os.Remove(filepath.Join(dir, EdgesFile)); err != nil {
		t.Fatal(err)
	}
	if res, raw = VerifyWithManifest(dir); res.OK() || !bytes.Equal(raw, want) {
		t.Errorf("a folder that does not verify: %+v", res)
	}
	if res, raw = VerifyWithManifest(filepath.Join(dir, "nothing")); res.OK() || raw != nil {
		t.Errorf("no folder: %+v", res)
	}
}
