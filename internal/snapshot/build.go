// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package snapshot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// BuildOptions are what a snapshot says about itself besides its rows.
type BuildOptions struct {
	// CreatedAt is when the snapshot is written. The caller passes it in, so
	// the same input and time give the same bytes and the same id. It is
	// part of the hash.
	CreatedAt time.Time
	// ParentID is the id of the snapshot this one follows, or empty.
	ParentID string
	// Label is a free-text name for the snapshot.
	Label string
	// Tool names the program writing the snapshot.
	Tool Tool
	// Redaction says what was hidden before the rows reached the writer.
	Redaction Redaction
	// Limits is plain text on what the snapshot cannot tell you.
	Limits string
}

// Snapshot is a written snapshot held in memory: the manifest and the bytes of
// every file in the folder.
type Snapshot struct {
	Manifest Manifest
	// Files maps a file name (manifest.json, nodes.parquet, ...) to its bytes.
	Files map[string][]byte
}

// Build validates the rows and encodes them as a snapshot. The output is a
// function of the rows and the options alone: rows are sorted (nodes by
// node_id, edges by from_id, to_id and kind, sources by source_id), the
// Parquet writer's settings are fixed, and the manifest's id is the hash of
// its canonical form. The same estate in any order gives the same bytes.
func Build(in Tables, opts BuildOptions) (*Snapshot, error) {
	if opts.CreatedAt.IsZero() {
		return nil, errors.New("snapshot: CreatedAt is required: the writer does not read the clock")
	}
	if opts.ParentID != "" && !hexID.MatchString(opts.ParentID) {
		return nil, fmt.Errorf("snapshot: parent id %q is not a hex SHA-256", opts.ParentID)
	}
	t := normalise(in)
	if err := Validate(&t); err != nil {
		return nil, fmt.Errorf("snapshot: invalid rows:\n%w", err)
	}

	nodes, err := encodeNodes(t.Nodes)
	if err != nil {
		return nil, err
	}
	edges, err := encodeEdges(t.Edges)
	if err != nil {
		return nil, err
	}
	sources, err := encodeSources(t.Sources)
	if err != nil {
		return nil, err
	}

	m := Manifest{
		Format:      Format,
		FormatMinor: FormatMinor,
		ParentID:    opts.ParentID,
		Label:       opts.Label,
		CreatedAt:   opts.CreatedAt.UTC().Format(time.RFC3339),
		Tool:        opts.Tool,
		Status:      StatusOK,
		Tables: []TableInfo{
			{Name: "edges", File: EdgesFile, SHA256: sha256Hex(edges), Rows: len(t.Edges), Schema: EdgeSchema},
			{Name: "nodes", File: NodesFile, SHA256: sha256Hex(nodes), Rows: len(t.Nodes), Schema: NodeSchema},
			{Name: "sources", File: SourcesFile, SHA256: sha256Hex(sources), Rows: len(t.Sources), Schema: SourceSchema},
		},
		SourcesSummary: summarise(t.Sources),
		Redaction:      opts.Redaction,
		Coverage:       cover(t),
		Limits:         opts.Limits,
	}
	if m.Redaction.HashAlgorithm == "" {
		m.Redaction.HashAlgorithm = "none"
	}
	m.Redaction.TagKeysDropped = sortedCopy(m.Redaction.TagKeysDropped)
	if len(m.Coverage.FailedSources) > 0 {
		m.Status = StatusPartial
	}

	// The id hashes the manifest as it will be written, without the id.
	unsigned, err := marshalManifest(m)
	if err != nil {
		return nil, err
	}
	if m.SnapshotID, err = ManifestID(unsigned); err != nil {
		return nil, err
	}
	raw, err := marshalManifest(m)
	if err != nil {
		return nil, err
	}
	return &Snapshot{
		Manifest: m,
		Files: map[string][]byte{
			ManifestFile: raw, NodesFile: nodes, EdgesFile: edges, SourcesFile: sources,
		},
	}, nil
}

func marshalManifest(m Manifest) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// normalise copies the rows, puts times in UTC, fills in edge ids and sorts
// them. The input is left as it was.
func normalise(in Tables) Tables {
	t := Tables{
		Nodes:   slices.Clone(in.Nodes),
		Edges:   slices.Clone(in.Edges),
		Sources: slices.Clone(in.Sources),
	}
	for i, s := range t.Sources {
		if ts, err := time.Parse(time.RFC3339, s.CollectedAt); err == nil {
			t.Sources[i].CollectedAt = ts.UTC().Format(time.RFC3339)
		}
	}
	for i, e := range t.Edges {
		if e.EdgeID == "" {
			t.Edges[i].EdgeID = EdgeID(e.Kind, e.FromID, e.ToID)
		}
	}
	slices.SortFunc(t.Nodes, func(a, b Node) int { return compare(a.NodeID, b.NodeID) })
	slices.SortFunc(t.Edges, func(a, b Edge) int {
		return cmpChain(compare(a.FromID, b.FromID), compare(a.ToID, b.ToID), compare(a.Kind, b.Kind))
	})
	slices.SortFunc(t.Sources, func(a, b Source) int { return compare(a.SourceID, b.SourceID) })
	return t
}

func cmpChain(cs ...int) int {
	for _, c := range cs {
		if c != 0 {
			return c
		}
	}
	return 0
}

func summarise(sources []Source) SourcesSummary {
	s := SourcesSummary{Count: len(sources), ByKind: map[string]int{}}
	for _, src := range sources {
		s.ByKind[src.Kind]++
		if s.OldestCollectedAt == "" || src.CollectedAt < s.OldestCollectedAt {
			s.OldestCollectedAt = src.CollectedAt
		}
		if src.CollectedAt > s.NewestCollectedAt {
			s.NewestCollectedAt = src.CollectedAt
		}
	}
	return s
}

func cover(t Tables) Coverage {
	clouds, accounts, types := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, n := range t.Nodes {
		if n.Cloud != "" {
			clouds[n.Cloud] = true
		}
		if n.Account != "" {
			accounts[n.Account] = true
		}
		if n.TFType != "" {
			types[n.TFType] = true
		}
	}
	c := Coverage{
		Clouds:        sortedKeys(clouds),
		Accounts:      sortedKeys(accounts),
		Types:         sortedKeys(types),
		FailedSources: []FailedSource{},
	}
	for _, s := range t.Sources { // already sorted by source_id
		if s.Status != StatusOK {
			c.FailedSources = append(c.FailedSources, FailedSource{SourceID: s.SourceID, Status: s.Status, Reason: s.Reason})
		}
	}
	return c
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// sortedCopy returns the strings sorted and without repeats, never nil.
func sortedCopy(in []string) []string {
	out := slices.Clone(in)
	if out == nil {
		out = []string{}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Write puts the snapshot in a new folder inside parent, named by DirName, and
// returns the folder's path. The folder is written under a temporary name and
// renamed, so a reader never sees half a snapshot. A snapshot is immutable: if
// the folder already exists and verifies, it is the same snapshot and Write
// leaves it alone; if it does not verify, Write fails.
func (s *Snapshot) Write(parent string) (string, error) {
	name, err := DirName(s.Manifest)
	if err != nil {
		return "", err
	}
	final := filepath.Join(parent, name)
	if _, err := os.Stat(final); err == nil {
		if res := Verify(final); !res.OK() {
			return "", fmt.Errorf("snapshot: %s exists and does not verify:\n%s", final, res.Error())
		}
		return final, nil
	}
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return "", err
	}
	tmp, err := os.MkdirTemp(parent, ".tmp-"+name+"-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp) //nolint:errcheck // gone after the rename; best effort otherwise
	for file, data := range s.Files {
		if err := os.WriteFile(filepath.Join(tmp, file), data, 0o644); err != nil { //nolint:gosec // snapshots are meant to be read by others
			return "", err
		}
	}
	if err := os.Rename(tmp, final); err != nil {
		return "", err
	}
	return final, nil
}
