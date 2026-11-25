// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunPrintsTheVersion(t *testing.T) {
	for _, args := range [][]string{nil, {"version"}, {"--version"}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 0 {
			t.Fatalf("run(%q) = %d, want 0 (stderr: %s)", args, code, stderr.String())
		}
		if got := stdout.String(); !strings.HasPrefix(got, "infra-ontology ") || !strings.HasSuffix(got, "\n") {
			t.Errorf("run(%q) printed %q, want \"infra-ontology <version>\"", args, got)
		}
	}
}

func TestRunRejectsAnUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"frobnicate"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run(frobnicate) = %d, want 2", code)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "unknown command") {
		t.Errorf("stdout %q, stderr %q: want an error on stderr only", stdout.String(), stderr.String())
	}
}
