// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package query

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const (
	corpusFile     = "testdata/corpus.txt"
	serializedFile = "testdata/serialized.json"
)

type corpusEntry struct {
	SQL   string
	Allow bool
}

// readCorpus reads the query corpus: "+ sql" must be allowed, "- sql" refused.
func readCorpus(t testing.TB) []corpusEntry {
	t.Helper()
	f, err := os.Open(corpusFile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var out []corpusEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		sign, rest := line[0], strings.TrimSpace(line[1:])
		if sign != '+' && sign != '-' {
			t.Fatalf("%s: a line must start with + or -: %q", corpusFile, line)
		}
		out = append(out, corpusEntry{SQL: rest, Allow: sign == '+'})
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// readSerialized reads the recorded output of json_serialize_sql, by query.
func readSerialized(t testing.TB) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(serializedFile)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}
