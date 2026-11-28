// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package query

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// swapEngine overwrites the snapshot folder when it is opened, as an attacker
// who wins the race between verifying and opening would, then records what
// the folder it was told to read holds.
type swapEngine struct {
	orig string
	dir  string
	got  map[string][]byte
	mode os.FileMode
}

func (e *swapEngine) Name() string { return "swap" }

func (e *swapEngine) Open(_ context.Context, dir string, _ Options) (Session, error) {
	for _, f := range []string{snapshot.NodesFile, snapshot.EdgesFile, snapshot.SourcesFile, snapshot.ManifestFile} {
		if err := os.WriteFile(filepath.Join(e.orig, f), []byte("swapped"), 0o644); err != nil {
			return nil, err
		}
	}
	e.dir, e.got = dir, map[string][]byte{}
	if st, err := os.Stat(dir); err == nil {
		e.mode = st.Mode().Perm()
	}
	for _, f := range []string{snapshot.NodesFile, snapshot.EdgesFile, snapshot.SourcesFile, snapshot.ManifestFile} {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			return nil, err
		}
		e.got[f] = b
	}
	return stubSession{}, nil
}

type stubSession struct{}

func (stubSession) Query(context.Context, string, Caps) (*Result, error) {
	return nil, errors.New("stub")
}
func (stubSession) Close() error { return nil }

// copyEstate copies the golden snapshot to a folder the test may change.
func copyEstate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	entries, err := os.ReadDir(filepath.Join("..", "snapshot", "testdata", "golden", "estate"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join("..", "snapshot", "testdata", "golden", "estate", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// What the engine reads is the bytes that were verified, whatever happens to
// the folder after, and the private copy is gone when Open returns.
func TestRunOpensTheBytesItVerified(t *testing.T) {
	dir := copyEstate(t)
	want := map[string][]byte{}
	for _, f := range []string{snapshot.NodesFile, snapshot.EdgesFile, snapshot.SourcesFile, snapshot.ManifestFile} {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		want[f] = b
	}
	eng := &swapEngine{orig: dir}
	_, err := Run(context.Background(), eng, dir, Options{}, Request{SQL: "SELECT 1"})
	if err == nil || err.Error() != "stub" {
		t.Fatalf("Run: %v", err)
	}
	if eng.dir == dir {
		t.Fatal("the engine opened the folder that was verified, which can change before it reads it")
	}
	for f, b := range want {
		if !bytes.Equal(eng.got[f], b) {
			t.Errorf("%s: the engine read other bytes than the ones verified", f)
		}
	}
	if eng.mode != 0o700 {
		t.Errorf("the private copy is %v, want 0700", eng.mode)
	}
	if _, err := os.Stat(eng.dir); !os.IsNotExist(err) {
		t.Errorf("the private copy was left behind: %v", err)
	}
}
