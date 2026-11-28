// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package snapshot

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// A file that is a link or a device is no part of a snapshot: reading one
// could hang or read what the snapshot does not hold.
func TestVerifyRefusesFilesThatAreNotRegular(t *testing.T) {
	for _, name := range []string{ManifestFile, NodesFile, EdgesFile, SourcesFile} {
		dir := writtenEstate(t)
		elsewhere := filepath.Join(t.TempDir(), name)
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(elsewhere, b, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, filepath.Join(dir, name)); err != nil {
			t.Skipf("no symbolic links here: %v", err)
		}
		res := Verify(dir)
		if res.OK() || !strings.Contains(res.Error(), name+": not a regular file") {
			t.Errorf("%s as a symbolic link: %v", name, res.Problems)
		}
		if _, err := Load(dir); err == nil {
			t.Errorf("%s as a symbolic link was loaded", name)
		}
	}
	// A directory in a file's place.
	dir := writtenEstate(t)
	_ = os.Remove(filepath.Join(dir, NodesFile))
	if err := os.Mkdir(filepath.Join(dir, NodesFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if res := Verify(dir); res.OK() || !strings.Contains(res.Error(), "not a regular file") {
		t.Errorf("a directory for nodes.parquet: %v", res.Problems)
	}
}

// A snapshot is read whole, so its files and rows are capped before they are
// read or decoded.
func TestVerifyCapsFilesAndRows(t *testing.T) {
	dir := writtenEstate(t)
	st, err := os.Stat(filepath.Join(dir, NodesFile))
	if err != nil {
		t.Fatal(err)
	}
	with := func(bytes int64, rows int, manifest int64) VerifyResult {
		ob, or, om := maxTableBytes, maxTableRows, maxManifestBytes
		maxTableBytes, maxTableRows, maxManifestBytes = bytes, rows, manifest
		defer func() { maxTableBytes, maxTableRows, maxManifestBytes = ob, or, om }()
		return Verify(dir)
	}

	res := with(st.Size()-1, maxTableRows, maxManifestBytes)
	if res.OK() || !strings.Contains(res.Error(), "nodes.parquet: "+itoa(st.Size())+" bytes, over the limit of "+itoa(st.Size()-1)) {
		t.Errorf("a table over the size limit: %v", res.Problems)
	}
	res = with(maxTableBytes, 2, maxManifestBytes)
	if res.OK() || !strings.Contains(res.Error(), "nodes.parquet: 15 rows, over the limit of 2") {
		t.Errorf("a table over the row limit: %v", res.Problems)
	}
	res = with(maxTableBytes, maxTableRows, 100)
	if res.OK() || !strings.Contains(res.Error(), "manifest.json: ") || !strings.Contains(res.Error(), "over the limit of 100") {
		t.Errorf("a manifest over the size limit: %v", res.Problems)
	}
	if res := Verify(dir); !res.OK() {
		t.Errorf("the default limits refuse a small snapshot: %v", res.Problems)
	}

	// The limits are generous: the default admits a large estate.
	if maxTableBytes < 256<<20 || maxTableRows < 1_000_000 {
		t.Errorf("limits too tight: %d bytes, %d rows", maxTableBytes, maxTableRows)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
