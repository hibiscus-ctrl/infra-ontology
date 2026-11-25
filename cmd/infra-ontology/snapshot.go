// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
	"github.com/hibiscus-ctrl/infra-ontology/internal/version"
)

// newFlags makes a flag set that reports its own errors on stderr and lets run
// return the usage code.
func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("infra-ontology "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// parse reads the flags (which may come after the folders) and returns the
// folders, or false if the command line was wrong.
func parse(fs *flag.FlagSet, args []string, lo, hi int, stderr io.Writer) ([]string, bool) {
	var rest []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, false
		}
		if fs.NArg() == 0 {
			break
		}
		rest = append(rest, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(rest) < lo || len(rest) > hi {
		fmt.Fprintf(stderr, "%s: want %s folder(s), got %d\n", fs.Name(), countWord(lo, hi), len(rest))
		return nil, false
	}
	return rest, true
}

func countWord(lo, hi int) string {
	if lo == hi {
		return fmt.Sprint(lo)
	}
	return fmt.Sprintf("%d or %d", lo, hi)
}

func writeJSON(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// runVerify is `snapshot verify`.
func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("snapshot verify", stderr)
	asJSON := fs.Bool("json", false, "print the result as JSON")
	dirs, ok := parse(fs, args, 1, 1, stderr)
	if !ok {
		return exitUsage
	}
	res := snapshot.Verify(dirs[0])
	switch {
	case *asJSON:
		writeJSON(stdout, struct {
			OK bool `json:"ok"`
			snapshot.VerifyResult
		}{res.OK(), res})
	case res.OK():
		fmt.Fprintf(stdout, "ok: %s\n  snapshot  %s\n", res.Dir, res.SnapshotID)
		if res.ParentID != "" {
			fmt.Fprintf(stdout, "  parent    %s\n", res.ParentID)
		}
		if res.Label != "" {
			fmt.Fprintf(stdout, "  label     %s\n", res.Label)
		}
		for _, t := range res.Tables {
			fmt.Fprintf(stdout, "  %-9s %d rows, sha256 %s\n", t.Name, t.Rows, t.SHA256)
		}
	default:
		fmt.Fprintf(stdout, "FAILED: %s does not verify\n", res.Dir)
		for _, p := range res.Problems {
			fmt.Fprintf(stdout, "  - %s\n", p)
		}
	}
	if !res.OK() {
		return exitVerifyFailed
	}
	return exitOK
}

// runDiff is `diff`.
func runDiff(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("diff", stderr)
	asJSON := fs.Bool("json", false, "print the result as JSON")
	dirs, ok := parse(fs, args, 1, 2, stderr)
	if !ok {
		return exitUsage
	}
	from, to := dirs[0], ""
	if len(dirs) == 2 {
		to = dirs[1]
	} else {
		// One folder: what changed in it since its parent.
		parent, err := snapshot.FindParent(dirs[0])
		switch {
		case err != nil:
			fmt.Fprintf(stderr, "infra-ontology diff: %v\n", err)
			return exitFailed
		case parent == "":
			fmt.Fprintf(stderr, "infra-ontology diff: %s has no parent snapshot; give a second folder\n", dirs[0])
			return exitFailed
		}
		from, to = parent, dirs[0]
	}
	a, err := snapshot.Load(from)
	if err != nil {
		fmt.Fprintf(stderr, "infra-ontology diff: %v\n", err)
		return exitVerifyFailed
	}
	b, err := snapshot.Load(to)
	if err != nil {
		fmt.Fprintf(stderr, "infra-ontology diff: %v\n", err)
		return exitVerifyFailed
	}
	d := snapshot.DiffSnapshots(a, b)
	if *asJSON {
		writeJSON(stdout, d)
		return exitOK
	}
	printDiff(stdout, d, a, b)
	return exitOK
}

func printDiff(w io.Writer, d snapshot.Diff, a, b *snapshot.Loaded) {
	fmt.Fprintf(w, "from %s%s\n", short(d.From), labelOf(a.Manifest))
	fmt.Fprintf(w, "to   %s%s\n", short(d.To), labelOf(b.Manifest))
	if d.Summary.Empty() {
		fmt.Fprintln(w, "no changes")
		return
	}
	s := d.Summary
	fmt.Fprintf(w, "nodes: %d added, %d removed, %d changed\n", s.NodesAdded, s.NodesRemoved, s.NodesChanged)
	for _, n := range d.Nodes.Added {
		fmt.Fprintf(w, "  + %s\n", describe(n))
	}
	for _, n := range d.Nodes.Removed {
		fmt.Fprintf(w, "  - %s\n", describe(n))
	}
	for _, n := range d.Nodes.Changed {
		fmt.Fprintf(w, "  ~ %s: %s\n", describe(n.NodeRef), printable(strings.Join(n.Fields, ", ")))
	}
	fmt.Fprintf(w, "edges: %d added, %d removed, %d changed\n", s.EdgesAdded, s.EdgesRemoved, s.EdgesChanged)
	for _, e := range d.Edges.Added {
		fmt.Fprintf(w, "  + %s\n", edge(e))
	}
	for _, e := range d.Edges.Removed {
		fmt.Fprintf(w, "  - %s\n", edge(e))
	}
	for _, e := range d.Edges.Changed {
		fmt.Fprintf(w, "  ~ %s: %s\n", edge(e.EdgeRef), printable(strings.Join(e.Fields, ", ")))
	}
}

func short(id string) string { return printable(id[:min(12, len(id))]) }

// printable escapes control characters, so a value read from a snapshot
// cannot move the cursor, recolour or rewrite the terminal it is printed to.
func printable(s string) string {
	// Decide on the bytes as well as the runes: an invalid byte such as a
	// lone 0x9b decodes to U+FFFD, yet some terminals read it as an escape.
	if utf8.ValidString(s) && !strings.ContainsFunc(s, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
	}) {
		return s
	}
	q := strconv.QuoteToGraphic(s)
	return q[1 : len(q)-1]
}

func labelOf(m snapshot.Manifest) string {
	if m.Label == "" {
		return ""
	}
	return " (" + printable(m.Label) + ")"
}

func describe(n snapshot.NodeRef) string {
	label := printable(first(n.Address, n.Name, short(n.NodeID)))
	typ := printable(first(n.Type, n.Kind))
	if n.Account != "" {
		return fmt.Sprintf("%s %s [%s]", typ, label, printable(n.Account))
	}
	return typ + " " + label
}

func edge(e snapshot.EdgeRef) string {
	return fmt.Sprintf("%s: %s -> %s", printable(e.Kind), printable(first(e.FromLabel, short(e.FromID))), printable(first(e.ToLabel, short(e.ToID))))
}

func first(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// estateFile is the JSON `snapshot build --from-json` reads. It is the rows of
// the three tables, plus what the manifest says about itself. Unknown members
// are an error, so a file with attribute values in it is refused.
type estateFile struct {
	CreatedAt string              `json:"created_at"`
	ParentID  string              `json:"parent_id"`
	Label     string              `json:"label"`
	Limits    string              `json:"limits"`
	Redaction *snapshot.Redaction `json:"redaction"`
	Nodes     []snapshot.Node     `json:"nodes"`
	Edges     []snapshot.Edge     `json:"edges"`
	Sources   []snapshot.Source   `json:"sources"`
}

// runBuild is `snapshot build --from-json`: a test and development path that
// writes a snapshot from a JSON file. The readers of state and inventory that
// replace it come later.
func runBuild(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("snapshot build", stderr)
	from := fs.String("from-json", "", "the JSON file of nodes, edges and sources to build from (test and development path)")
	out := fs.String("out", filepath.Join(".infra-ontology", "snapshots"), "the folder to write the snapshot folder into")
	label := fs.String("label", "", "a name for the snapshot (overrides the file's)")
	parent := fs.String("parent", "", "the id of the snapshot this one follows (overrides the file's)")
	created := fs.String("created-at", "", "when the snapshot is written, as RFC 3339 (default: the file's, else now)")
	if _, ok := parse(fs, args, 0, 0, stderr); !ok {
		return exitUsage
	}
	if *from == "" {
		fmt.Fprintln(stderr, "infra-ontology snapshot build: --from-json FILE is required (reading state and inventory comes later)")
		return exitUsage
	}
	raw, err := os.ReadFile(*from)
	if err != nil {
		fmt.Fprintf(stderr, "infra-ontology snapshot build: %v\n", err)
		return exitFailed
	}
	var est estateFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&est); err != nil {
		fmt.Fprintf(stderr, "infra-ontology snapshot build: %s: %v\n", *from, err)
		return exitFailed
	}
	opts := snapshot.BuildOptions{
		ParentID: first(*parent, est.ParentID),
		Label:    first(*label, est.Label),
		Limits:   est.Limits,
		Tool:     snapshot.Tool{Name: "infra-ontology", Version: version.Version},
	}
	if est.Redaction != nil {
		opts.Redaction = *est.Redaction
	}
	opts.CreatedAt = time.Now()
	if at := first(*created, est.CreatedAt); at != "" {
		if opts.CreatedAt, err = time.Parse(time.RFC3339, at); err != nil {
			fmt.Fprintf(stderr, "infra-ontology snapshot build: created_at: %v\n", err)
			return exitUsage
		}
	}
	s, err := snapshot.Build(snapshot.Tables{Nodes: est.Nodes, Edges: est.Edges, Sources: est.Sources}, opts)
	if err != nil {
		fmt.Fprintf(stderr, "infra-ontology snapshot build: %v\n", err)
		return exitFailed
	}
	dir, err := s.Write(*out)
	if err != nil {
		fmt.Fprintf(stderr, "infra-ontology snapshot build: %v\n", err)
		return exitFailed
	}
	fmt.Fprintf(stdout, "%s\nsnapshot %s\n", dir, s.Manifest.SnapshotID)
	return exitOK
}
