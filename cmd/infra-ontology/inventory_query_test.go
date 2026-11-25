// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !noduckdb

package main

import (
	"strings"
	"testing"
)

// The stored query for unmanaged resources answers from a snapshot of state
// and inventory: what only the inventory lists, and nothing the state holds.
func TestUnmanagedQueryOverStateAndInventory(t *testing.T) {
	args := append([]string{"--state", "net.tfstate", "--state", "app.tfstate", "--state", "hub.tfstate", "--state", "dns.tfstate"}, allInventories()...)
	code, dir, _, errs := buildWithInventory(t, args...)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	code, out, errs := runCLI(t, "query", dir, "--stored", "unmanaged")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	for _, want := range []string{"acme-orphan", "stray", "snet-a", "acme-prod-assets"} {
		if !strings.Contains(out, want) {
			t.Errorf("unmanaged lacks %q:\n%s", want, out)
		}
	}
	for _, not := range []string{"vpc-0a1b", "subnet-0c21", "legacy-admin"} {
		if strings.Contains(out, not) {
			t.Errorf("unmanaged lists %q:\n%s", not, out)
		}
	}
}
