// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package query

import (
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

// Every stored query parses, is named for its file, carries a version, and
// renders with its defaults and no placeholder left. That the rendered text
// passes the dialect and answers is tested with the engine.
func TestStoredQueriesLoad(t *testing.T) {
	all, err := StoredQueries()
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, s := range all {
		names[s.Name] = true
		if s.Version < 1 || s.Description == "" || !strings.HasPrefix(s.Hash, "sha256:") {
			t.Errorf("%s: %+v", s.Name, s)
		}
		given := map[string]string{}
		for _, p := range s.Params {
			if p.Required {
				given[p.Name] = "x"
			}
		}
		text, used, err := s.Render(given)
		if err != nil || strings.Contains(text, "{{") || len(used) != len(s.Params) {
			t.Errorf("%s: renders to %q, %v, %v", s.Name, text, used, err)
		}
	}
	for _, want := range []string{"blast", "cone", "unmanaged", "summary"} {
		if !names[want] {
			t.Errorf("no stored query %q", want)
		}
	}
}

func TestStoredQueryHeaders(t *testing.T) {
	const ok = "-- name: q\n-- version: 2\n-- description: d\n"
	cases := []struct {
		name, file string
		want       string // an error containing this, or "" for none
	}{
		{"fine", ok + "-- param: a string - x\nSELECT {{a}}", ""},
		{"no body", ok, "no query text"},
		{"no name", "-- version: 1\n-- description: d\nSELECT 1", "needs a name"},
		{"bad version", "-- name: q\n-- version: 0\n-- description: d\nSELECT 1", "positive"},
		{"undeclared placeholder", ok + "SELECT {{a}}", "not a declared parameter"},
		{"unused parameter", ok + "-- param: a string - x\nSELECT 1", "never used"},
		{"duplicate parameter", ok + "-- param: a string - x\n-- param: a string - y\nSELECT {{a}}", "twice"},
		{"bad type", ok + "-- param: a float - x\nSELECT {{a}}", "not string or int"},
		{"short param", ok + "-- param: a string\nSELECT {{a}}", "want <name>"},
		{"bad int default", ok + "-- param: a int[0..5] 9 x\nSELECT {{a}}", "outside"},
		{"bad name", ok + "-- param: A string - x\nSELECT {{A}}", "lower-case"},
	}
	for _, c := range cases {
		_, err := parseStored(c.file)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: error %v, want one with %q", c.name, err, c.want)
		}
	}
	files := fstest.MapFS{"other.sql": {Data: []byte(ok + "SELECT 1")}}
	if _, err := loadStored(fs.FS(files)); err == nil || !strings.Contains(err.Error(), "named for") {
		t.Errorf("a file not named for its query: %v", err)
	}
}

func TestStoredRender(t *testing.T) {
	s, err := parseStored("-- name: q\n-- version: 1\n-- description: d\n-- param: who string required text\n-- param: n int[1..9] 3 count\nSELECT {{who}}, {{n}}, {{who}}")
	if err != nil {
		t.Fatal(err)
	}
	text, used, err := s.Render(map[string]string{"who": "o'neil {{n}}"})
	if err != nil || text != "SELECT 'o''neil {{n}}', 3, 'o''neil {{n}}'" || used["n"] != "3" {
		t.Errorf("%q, %v, %v", text, used, err)
	}
	for _, bad := range []map[string]string{{}, {"who": "x", "n": "0"}, {"who": "x", "n": "10"}, {"who": "x", "n": "1.5"}, {"who": "x", "n": " 2"}, {"who": "x", "z": "1"}, {"who": "a\nb"}} {
		if _, _, err := s.Render(bad); err == nil {
			t.Errorf("%v was accepted", bad)
		}
	}
}
