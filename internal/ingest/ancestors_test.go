// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func gcpParents(id string) []string   { return slices.Collect(gcpAncestors(id)) }
func azureParents(id string) []string { return slices.Collect(azureAncestors(id)) }

func TestAzureParents(t *testing.T) {
	const rg = "/subscriptions/s/resourcegroups/r"
	for id, want := range map[string]string{
		rg + "/providers/microsoft.network/virtualnetworks/v/subnets/s": rg + "/providers/microsoft.network/virtualnetworks/v," + rg,
		rg + "/providers/microsoft.compute/virtualmachines/vm":          rg,
		rg + "/providers/microsoft.a/b/c/d/e/f/g":                       rg + "/providers/microsoft.a/b/c/d/e," + rg + "/providers/microsoft.a/b/c," + rg,
		rg + "/providers//microsoft.a/b/c/d/e/":                         rg + "/providers/microsoft.a/b/c," + rg,
		"/subscriptions/s/providers/microsoft.a/b/c/d/e":                "/subscriptions/s/providers/microsoft.a/b/c",
		"/subscriptions/s/resourcegroups/r":                             "",
	} {
		if got := strings.Join(azureParents(id), ","); got != want {
			t.Errorf("%s: %q, want %q", id, got, want)
		}
	}
}

// An inventory file has no size limit: an ID of a million segments must cost
// time and memory in proportion to its length, not to its length squared, and
// one past the segment cap has no path parent.
func TestHostileIDsAreCheapToWalk(t *testing.T) {
	hostile := map[string]struct {
		id    string
		parts func(string) []string
		want  []string
	}{
		"gcp": {"projects/p/" + strings.Repeat("a/", 500_000) + "z", gcpParents, nil},
		"azure": {"/subscriptions/s/resourcegroups/r/providers/microsoft.a/" + strings.Repeat("a/", 500_000) + "z",
			azureParents, []string{"/subscriptions/s/resourcegroups/r"}},
	}
	for name, h := range hostile {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			got := h.parts(h.id)
			if d := time.Since(start); d > 200*time.Millisecond {
				t.Errorf("took %s", d)
			}
			if !slices.Equal(got, h.want) {
				t.Errorf("parents: %q, want %q", got, h.want)
			}
			if n := testing.AllocsPerRun(3, func() { h.parts(h.id) }); n > 8 {
				t.Errorf("%v allocations", n)
			}
			// A caller that stops at the first match walks only that far.
			if n := testing.AllocsPerRun(3, func() {
				for range gcpAncestors(h.id) {
					break
				}
				for range azureAncestors(h.id) {
					break
				}
			}); n != 0 {
				t.Errorf("%v allocations to stop early", n)
			}
		})
	}
	// Just inside the cap, every ancestor is still offered.
	id := "projects/p/" + strings.Repeat("a/", maxPathSegments-3) + "z"
	if got := len(gcpParents(id)); got != maxPathSegments-3 {
		t.Errorf("%d parents of an ID at the cap", got)
	}
	if got := gcpParents(id + "/z"); got != nil {
		t.Errorf("%d parents of an ID over the cap", len(got))
	}
}
