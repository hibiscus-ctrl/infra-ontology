// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildTimeoutIsAFlag(t *testing.T) {
	code, _, _, errs := buildState(t, "--timeout", "-1s", "--state", "net.tfstate")
	if code != exitUsage || !strings.Contains(errs, "--timeout") {
		t.Errorf("a negative timeout: exit %d: %s", code, errs)
	}
	// 0 is no deadline; an ample one reads the state.
	for _, d := range []string{"0", "5m"} {
		if code, dir, _, errs := buildState(t, "--timeout", d, "--state", "net.tfstate"); code != exitOK || dir == "" {
			t.Errorf("--timeout %s: exit %d: %s", d, code, errs)
		}
	}
}

func TestBuildPastItsTimeoutReadsNothing(t *testing.T) {
	code, dir, _, errs := buildState(t, "--timeout", "1ns", "--state", "net.tfstate")
	if code != exitFailed || dir != "" || !strings.Contains(errs, "deadline") {
		t.Errorf("exit %d, dir %q: %s", code, dir, errs)
	}
}

// With --hash-ids the text a failed build prints holds no location and no
// store error, which the snapshot's own reasons do not either.
func TestHashedBuildFailureDoesNotPrintTheLocation(t *testing.T) {
	clearKeyEnv(t)
	dir := filepath.Join(t.TempDir(), "private-team-dir")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad.tfstate")
	if err := os.WriteFile(bad, []byte(`{"version": 4, "resources": [`), 0o644); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	run := func(extra ...string) (int, string) {
		code, _, errs := exec(t, append([]string{"snapshot", "build", "--out", out, "--created-at", "2026-11-25T12:00:00Z", "--state", bad}, extra...)...)
		return code, errs
	}
	code, errs := run()
	if code != exitFailed || !strings.Contains(errs, "bad.tfstate") {
		t.Fatalf("the plain build: exit %d: %s", code, errs)
	}
	code, errs = run("--hash-ids", "--hash-key-file", writeKey(t, hashKey))
	if code != exitFailed {
		t.Fatalf("the hashed build: exit %d: %s", code, errs)
	}
	for _, leak := range []string{"private-team-dir", "bad.tfstate", dir} {
		if strings.Contains(errs, leak) {
			t.Errorf("stderr holds %q: %s", leak, errs)
		}
	}
	if !strings.Contains(errs, "the cause is not kept") {
		t.Errorf("stderr lacks the withheld text: %s", errs)
	}
}
