// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/hibiscus-ctrl/infra-ontology/internal/query"
	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// params is a repeatable --param name=value flag.
type params map[string]string

func (p params) String() string { return fmt.Sprint(map[string]string(p)) }

func (p params) Set(v string) error {
	name, value, ok := strings.Cut(v, "=")
	if !ok || name == "" {
		return fmt.Errorf("want name=value, got %q", v)
	}
	if _, dup := p[name]; dup {
		return fmt.Errorf("parameter %q is given twice", name)
	}
	p[name] = value
	return nil
}

// runQuery is `query`: read-only SQL over a snapshot, under row caps, with
// the answer's citation.
func runQuery(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("query", stderr)
	sqlText := fs.String("sql", "", "the SQL to run: one SELECT or WITH ... SELECT over nodes, edges, sources and snapshot")
	stored := fs.String("stored", "", "the name of a stored query to run instead of SQL text (see --list)")
	list := fs.Bool("list", false, "list the stored queries and their parameters")
	ps := params{}
	fs.Var(ps, "param", "a parameter of the stored query, name=value (repeatable)")
	asJSON := fs.Bool("json", false, "print the columns, the rows and the citation as JSON")
	answerOut := fs.String("answer-out", "", "write the citation to this file, for `verify --answer`")
	limit := fs.Int("limit", query.DefaultMaxRows, fmt.Sprintf("the most rows to return (at most %d)", query.HardMaxRows))
	maxBytes := fs.Int64("max-bytes", query.DefaultMaxBytes, "the approximate most bytes of result")
	timeout := fs.Duration("timeout", query.DefaultTimeout, "stop the query after this long")
	memory := fs.String("memory", "512MB", "the engine's memory limit")
	dirs, ok := parse(fs, args, 0, 1, stderr)
	if !ok {
		return exitUsage
	}
	if *list {
		return listStored(stdout, stderr)
	}
	switch {
	case len(dirs) == 0:
		fmt.Fprintln(stderr, "infra-ontology query: give the snapshot folder")
		return exitUsage
	case (*sqlText == "") == (*stored == ""):
		fmt.Fprintln(stderr, "infra-ontology query: give --sql TEXT or --stored NAME, one of them")
		return exitUsage
	case *stored == "" && len(ps) > 0:
		fmt.Fprintln(stderr, "infra-ontology query: --param goes with --stored")
		return exitUsage
	}
	req := query.Request{
		SQL: *sqlText, Stored: *stored, Params: ps,
		Caps: query.Caps{MaxRows: *limit, MaxBytes: *maxBytes, Timeout: *timeout},
	}
	ctx, stop := signalContext()
	defer stop()
	out, err := query.Run(ctx, query.New(), dirs[0], query.Options{Mode: query.ModeTables, MemoryLimit: *memory}, req)
	if err != nil {
		if errors.Is(err, query.ErrUnavailable) {
			explainNoEngine(stderr, dirs[0], req)
		} else {
			fmt.Fprintf(stderr, "infra-ontology query: %v\n", err)
		}
		return exitFailed
	}
	if *answerOut != "" {
		if err := writeAnswer(*answerOut, out.Answer); err != nil {
			fmt.Fprintf(stderr, "infra-ontology query: %v\n", err)
			return exitFailed
		}
	}
	if *asJSON {
		writeJSON(stdout, struct {
			Columns []string        `json:"columns"`
			Rows    [][]any         `json:"rows"`
			Answer  snapshot.Answer `json:"answer"`
		}{out.Result.Columns, out.Result.Rows, out.Answer})
		return exitOK
	}
	printResult(stdout, out)
	return exitOK
}

// signalContext is cancelled by an interrupt, which stops a running query.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt)
}

func writeAnswer(path string, a snapshot.Answer) error {
	raw, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644) //nolint:gosec // an answer is meant to be shared
}

func listStored(stdout, stderr io.Writer) int {
	all, err := query.StoredQueries()
	if err != nil {
		fmt.Fprintf(stderr, "infra-ontology query: %v\n", err)
		return exitFailed
	}
	for _, s := range all {
		fmt.Fprintf(stdout, "%s (version %d)\n  %s\n", s.Name, s.Version, s.Description)
		for _, p := range s.Params {
			def := "default " + p.Default
			switch {
			case p.Required:
				def = "required"
			case p.Default == "":
				def = "optional"
			}
			kind := p.Type
			if p.Type == "int" {
				kind = fmt.Sprintf("int %d..%d", p.Min, p.Max)
			}
			fmt.Fprintf(stdout, "  --param %s=<%s>  %s (%s)\n", p.Name, kind, p.Description, def)
		}
	}
	return exitOK
}

// explainNoEngine is what the build without DuckDB says: how to get the
// answer with DuckDB itself, and the fields of the citation to fill in.
func explainNoEngine(w io.Writer, dir string, req query.Request) {
	fmt.Fprintf(w, "infra-ontology query: %v\n", query.ErrUnavailable)
	text := req.SQL
	if req.Stored != "" {
		s, err := query.StoredQuery(req.Stored)
		if err != nil {
			return
		}
		if text, _, err = s.Render(req.Params); err != nil {
			return
		}
	}
	p := func(f string) string { return "'" + strings.ReplaceAll(filepath.Join(dir, f), "'", "''") + "'" }
	fmt.Fprintf(w, "\nWith DuckDB installed, run this in the snapshot folder's place:\n\n")
	for _, t := range []string{"nodes", "edges", "sources"} {
		fmt.Fprintf(w, "  CREATE TABLE %s AS SELECT * FROM read_parquet(%s);\n", t, p(t+".parquet"))
	}
	fmt.Fprintf(w, "  %s;\n\n", strings.TrimRight(strings.TrimSpace(text), ";"))
	if res := snapshot.Verify(dir); res.OK() {
		fmt.Fprintf(w, "That answer is not cited. Its snapshot_id is %s; the query hash, the caps and the result hash need this tool built with DuckDB.\n", res.SnapshotID)
	}
}

func printResult(w io.Writer, out *query.Output) {
	r, a := out.Result, out.Answer
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	heads := make([]string, len(r.Columns))
	for i, c := range r.Columns {
		heads[i] = printable(c)
	}
	fmt.Fprintln(tw, strings.Join(heads, "\t"))
	for _, row := range r.Rows {
		cells := make([]string, len(row))
		for i, v := range row {
			cells[i] = cell(v)
		}
		fmt.Fprintln(tw, strings.Join(cells, "\t"))
	}
	_ = tw.Flush()

	fmt.Fprintf(w, "\n%d row%s", a.RowCount, plural(a.RowCount))
	if a.Truncated {
		fmt.Fprintf(w, ", cut by the %s cap: more exist (caps: %d rows, %d bytes)", a.TruncatedBy, a.Caps.MaxRows, a.Caps.MaxBytes)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "snapshot  %s\n", a.SnapshotID)
	if a.StoredQuery != "" {
		fmt.Fprintf(w, "stored    %s version %d, %s\n", a.StoredQuery, a.StoredQueryVersion, a.StoredQueryHash)
	}
	fmt.Fprintf(w, "query     %s\n", a.QueryHash)
	fmt.Fprintf(w, "result    %s\n", a.ResultHash)
	fmt.Fprintf(w, "engine    %s, dialect %s\n", a.Engine, a.Dialect)
	fmt.Fprintf(w, "limits    snapshot %s", a.Limits.Status)
	if a.Limits.OldestSource != "" {
		fmt.Fprintf(w, ", oldest source %s", a.Limits.OldestSource)
	}
	fmt.Fprintf(w, ", %d failed source%s\n", a.Limits.FailedSources, plural(a.Limits.FailedSources))
	for _, f := range a.Limits.Failed {
		fmt.Fprintf(w, "            %s: %s\n", printable(f.SourceID), printable(f.Reason))
	}
	if a.Limits.Note != "" {
		fmt.Fprintf(w, "            %s\n", printable(a.Limits.Note))
	}
	fmt.Fprintln(w, "add --json for the full citation, --answer-out FILE to keep it for `verify --answer`")
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// cell writes a value for the terminal: text with its control characters
// escaped, NULL for nothing, JSON for a list or a struct.
func cell(v any) string {
	switch t := v.(type) {
	case nil:
		return "NULL"
	case string:
		return printable(t)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return printable(fmt.Sprint(v))
	}
	return printable(string(b))
}

// runVerifyTop is `verify`: with --answer, re-run a cited answer against its
// snapshot; with a snapshot folder alone, the same check as `snapshot verify`.
func runVerifyTop(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("verify", stderr)
	answer := fs.String("answer", "", "an answer file (from query --answer-out, or query --json): re-run it against its snapshot")
	snap := fs.String("snapshot", "", "the snapshot folder the answer cites (default: look for it by id in --snapshots)")
	root := fs.String("snapshots", filepath.Join(".infra-ontology", "snapshots"), "the folder of snapshots to look in")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	timeout := fs.Duration("timeout", query.DefaultTimeout, "stop the re-run after this long")
	vf := addVerifyFlags(fs)
	dirs, ok := parse(fs, args, 0, 1, stderr)
	if !ok {
		return exitUsage
	}
	if *answer == "" {
		if len(dirs) != 1 {
			fmt.Fprintln(stderr, "infra-ontology verify: give --answer FILE, or a snapshot folder to check")
			return exitUsage
		}
		return runVerify(args, stdout, stderr)
	}
	if len(dirs) > 0 {
		fmt.Fprintln(stderr, "infra-ontology verify: name the snapshot with --snapshot DIR")
		return exitUsage
	}
	if vf.set() {
		fmt.Fprintln(stderr, "infra-ontology verify: the signature flags check a snapshot folder; run verify on the folder without --answer")
		return exitUsage
	}
	a, err := readAnswer(*answer)
	if err != nil {
		fmt.Fprintf(stderr, "infra-ontology verify: %v\n", err)
		return exitFailed
	}
	dir := *snap
	if dir == "" {
		if dir, err = findSnapshot(*root, a.SnapshotID); err != nil {
			fmt.Fprintf(stderr, "infra-ontology verify: %v\n", err)
			return exitFailed
		}
	}
	ctx, stop := signalContext()
	defer stop()
	loaded, err := snapshot.Load(dir)
	if err != nil {
		fmt.Fprintf(stderr, "infra-ontology verify: %v\n", err)
		return exitVerifyFailed
	}
	sess, err := query.OpenVerified(ctx, query.New(), loaded, query.Options{Mode: query.ModeTables})
	if err != nil {
		fmt.Fprintf(stderr, "infra-ontology verify: %v\n", err)
		return exitFailed
	}
	defer func() { _ = sess.Close() }()
	res, err := query.Reverify(ctx, sess, loaded.Manifest, a, *timeout)
	if err != nil {
		fmt.Fprintf(stderr, "infra-ontology verify: %v\n", err)
		return exitFailed
	}
	switch {
	case *asJSON:
		writeJSON(stdout, struct {
			OK       bool   `json:"ok"`
			Snapshot string `json:"snapshot"`
			query.Outcome
		}{res.OK(), dir, res})
	case res.OK():
		fmt.Fprintf(stdout, "ok: the answer is reproduced\n  snapshot  %s\n  query     %s\n  result    %s (%d rows)\n", a.SnapshotID, a.QueryHash, a.ResultHash, a.RowCount)
		for _, n := range res.Notes {
			fmt.Fprintf(stdout, "  note: %s\n", printable(n))
		}
	default:
		fmt.Fprintf(stdout, "FAILED: the answer is not reproduced by %s\n", dir)
		for _, p := range res.Problems {
			fmt.Fprintf(stdout, "  - %s\n", printable(p))
		}
		for _, n := range res.Notes {
			fmt.Fprintf(stdout, "  note: %s\n", printable(n))
		}
	}
	if !res.OK() {
		return exitVerifyFailed
	}
	return exitOK
}

// readAnswer reads an answer file: the citation itself, or the JSON that
// `query --json` prints, which holds it under "answer".
func readAnswer(path string) (snapshot.Answer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return snapshot.Answer{}, err
	}
	var wrapped struct {
		Answer *snapshot.Answer `json:"answer"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return snapshot.Answer{}, fmt.Errorf("%s: not JSON: %w", path, err)
	}
	if wrapped.Answer != nil {
		return *wrapped.Answer, nil
	}
	var a snapshot.Answer
	if err := json.Unmarshal(raw, &a); err != nil {
		return a, fmt.Errorf("%s: not an answer: %w", path, err)
	}
	if a.SnapshotID == "" || a.Query == "" {
		return a, fmt.Errorf("%s: not an answer: it names no snapshot and no query", path)
	}
	return a, nil
}

// findSnapshot looks in a folder of snapshots for the one with this id. A
// snapshot folder is named for its creation time and the start of its id.
func findSnapshot(root, id string) (string, error) {
	if len(id) < 12 {
		return "", fmt.Errorf("the answer's snapshot id %q is not a snapshot id", id)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", fmt.Errorf("no snapshot folder %s: name the snapshot with --snapshot DIR (%w)", root, err)
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasSuffix(e.Name(), "-"+id[:12]) {
			if res := snapshot.Verify(filepath.Join(root, e.Name())); res.SnapshotID == id {
				return filepath.Join(root, e.Name()), nil
			}
		}
	}
	return "", fmt.Errorf("no snapshot %s in %s: name the snapshot with --snapshot DIR", id, root)
}
