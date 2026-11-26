// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package snapshot

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

var (
	hexID     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	codeName  = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	nodeKinds = set(KindResource, KindModuleCall, KindStateRoot, KindAccount, KindExternal)
	managed   = set(Managed, OtherIaC, Unmanaged, Unknown, Missing)
	confs     = set(Observed, Computed, Inferred)
	srcKinds  = set(SourceState, SourceInventory, SourcePlan)
	statuses  = set(StatusOK, StatusPartial, StatusFailed)
)

func set(values ...string) map[string]bool {
	m := make(map[string]bool, len(values))
	for _, v := range values {
		m[v] = true
	}
	return m
}

// maxProblems caps the problems Validate reports, so a broken input of a
// million rows does not build a million messages.
const maxProblems = 50

// Validate checks the rows against the rules the schemas can't state: ids are
// unique, every edge joins two nodes, and every node, edge and source cites a
// source that exists. It returns every problem it finds, up to a cap, as one
// error.
func Validate(t *Tables) error {
	var problems []error
	add := func(format string, args ...any) {
		if len(problems) < maxProblems {
			problems = append(problems, fmt.Errorf(format, args...))
		}
	}

	sources := make(map[string]bool, len(t.Sources))
	for i, s := range t.Sources {
		switch {
		case s.SourceID == "":
			add("sources[%d]: source_id is empty", i)
		case sources[s.SourceID]:
			add("sources[%d]: duplicate source_id %q", i, s.SourceID)
		}
		sources[s.SourceID] = true
		if !srcKinds[s.Kind] {
			add("source %q: unknown kind %q", s.SourceID, s.Kind)
		}
		if !statuses[s.Status] {
			add("source %q: unknown status %q", s.SourceID, s.Status)
		}
		if _, err := time.Parse(time.RFC3339, s.CollectedAt); err != nil {
			add("source %q: collected_at %q is not RFC 3339", s.SourceID, s.CollectedAt)
		}
		if s.DocumentSHA256 != "" && !hexID.MatchString(s.DocumentSHA256) {
			add("source %q: document_sha256 is not a hex SHA-256", s.SourceID)
		}
		if s.Serial != nil && *s.Serial < 0 {
			add("source %q: serial is negative", s.SourceID)
		}
	}

	nodes := make(map[string]bool, len(t.Nodes))
	for i, n := range t.Nodes {
		switch {
		case !hexID.MatchString(n.NodeID):
			add("nodes[%d]: node_id %q is not a hex SHA-256", i, n.NodeID)
		case nodes[n.NodeID]:
			add("nodes[%d]: duplicate node_id %s", i, n.NodeID)
		}
		nodes[n.NodeID] = true
		if !nodeKinds[n.Kind] {
			add("node %s: unknown kind %q", n.NodeID, n.Kind)
		}
		if !managed[n.ManagedStatus] {
			add("node %s: unknown managed_status %q", n.NodeID, n.ManagedStatus)
		}
		if !confs[n.Confidence] {
			add("node %s: unknown confidence %q", n.NodeID, n.Confidence)
		}
		if !sources[n.SourceID] {
			add("node %s: source_id %q is not in sources", n.NodeID, n.SourceID)
		}
	}

	type edgeKey struct{ from, to, kind string }
	edges := make(map[edgeKey]bool, len(t.Edges))
	for i, e := range t.Edges {
		k := edgeKey{e.FromID, e.ToID, e.Kind}
		if edges[k] {
			add("edges[%d]: duplicate edge %s %s -> %s", i, e.Kind, e.FromID, e.ToID)
		}
		edges[k] = true
		if !nodes[e.FromID] {
			add("edges[%d]: from_id %q is not a node", i, e.FromID)
		}
		if !nodes[e.ToID] {
			add("edges[%d]: to_id %q is not a node", i, e.ToID)
		}
		if !codeName.MatchString(e.Kind) {
			add("edges[%d]: kind %q is not a lower-case code", i, e.Kind)
		}
		if !codeName.MatchString(e.Basis) {
			add("edges[%d]: basis %q is not a lower-case code", i, e.Basis)
		}
		if !confs[e.Confidence] {
			add("edges[%d]: unknown confidence %q", i, e.Confidence)
		}
		if !sources[e.SourceID] {
			add("edges[%d]: source_id %q is not in sources", i, e.SourceID)
		}
		if want := EdgeID(e.Kind, e.FromID, e.ToID); e.EdgeID != want {
			add("edges[%d]: edge_id %q is not the hash of its kind and ends", i, e.EdgeID)
		}
	}
	return errors.Join(problems...)
}
