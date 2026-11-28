// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/hibiscus-ctrl/infra-ontology/internal/query"
)

// swapEngine overwrites the snapshot folder when it is opened and records
// what the folder it was told to read holds.
type swapEngine struct {
	orig, dir string
	got       map[string][]byte
}

func (e *swapEngine) Name() string { return "swap" }

var snapshotFiles = []string{"nodes.parquet", "edges.parquet", "sources.parquet", "manifest.json"}

func (e *swapEngine) Open(_ context.Context, dir string, _ query.Options) (query.Session, error) {
	for _, f := range snapshotFiles {
		if err := os.WriteFile(filepath.Join(e.orig, f), []byte("swapped"), 0o644); err != nil {
			return nil, err
		}
	}
	e.dir, e.got = dir, map[string][]byte{}
	for _, f := range snapshotFiles {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			return nil, err
		}
		e.got[f] = b
	}
	return nil, errors.New("stub")
}

// The server serves the bytes it verified, not a second read of the folder.
func TestServerOpensTheBytesItVerified(t *testing.T) {
	dir := t.TempDir()
	want := map[string][]byte{}
	for _, f := range snapshotFiles {
		b, err := os.ReadFile(filepath.Join(estate, f))
		if err != nil {
			t.Fatal(err)
		}
		want[f] = b
		if err := os.WriteFile(filepath.Join(dir, f), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	eng := &swapEngine{orig: dir}
	if _, err := newServer(t.Context(), Config{Dir: dir, Engine: eng}); err == nil || err.Error() != "stub" {
		t.Fatalf("newServer: %v", err)
	}
	if eng.dir == dir {
		t.Fatal("the engine opened the folder that was verified")
	}
	for f, b := range want {
		if !bytes.Equal(eng.got[f], b) {
			t.Errorf("%s: the engine read other bytes than the ones verified", f)
		}
	}
	if _, err := os.Stat(eng.dir); !os.IsNotExist(err) {
		t.Errorf("the private copy was left behind: %v", err)
	}
}
