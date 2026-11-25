// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !noduckdb

package query

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// estate is the golden snapshot the snapshot package pins.
var estate = filepath.Join("..", "snapshot", "testdata", "golden", "estate")

// update rewrites testdata/serialized.json, the recorded parse trees:
// go test ./internal/query -update. It needs the DuckDB build.
var update = flag.Bool("update", false, "rewrite the recorded parse trees")

var modes = []string{ModeTables, ModeROAttach}

func open(t testing.TB, dir, mode string) *session {
	t.Helper()
	s, err := New().Open(context.Background(), dir, Options{Mode: mode})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s.(*session)
}

func query(t testing.TB, s Session, sql string, c Caps) *Result {
	t.Helper()
	r, err := s.Query(context.Background(), sql, c)
	if err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return r
}

// TestUpdateRecordedTrees rewrites serialized.json from the engine.
func TestUpdateRecordedTrees(t *testing.T) {
	if !*update {
		t.Skip("run with -update to record the parse trees")
	}
	s := open(t, estate, ModeTables)
	out := map[string]string{}
	for _, e := range readCorpus(t) {
		var js string
		if err := s.db.QueryRowContext(context.Background(), "SELECT json_serialize_sql(?)::VARCHAR", e.SQL).Scan(&js); err != nil {
			t.Fatalf("%q: %v", e.SQL, err)
		}
		out[e.SQL] = js
	}
	raw, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(serializedFile, append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The recorded trees are what this DuckDB writes today: a new DuckDB that
// serialises a query differently shows here, and the corpus is re-recorded and
// reviewed.
func TestRecordedTreesAreCurrent(t *testing.T) {
	s := open(t, estate, ModeTables)
	for sql, want := range readSerialized(t) {
		var got string
		if err := s.db.QueryRowContext(context.Background(), "SELECT json_serialize_sql(?)::VARCHAR", sql).Scan(&got); err != nil {
			t.Fatalf("%q: %v", sql, err)
		}
		if got != want {
			t.Errorf("%q: DuckDB now serialises it differently: run go test ./internal/query -update and review", sql)
		}
	}
}

// Every corpus query, through the engine, in both modes.
func TestCorpusThroughTheEngine(t *testing.T) {
	for _, mode := range modes {
		s := open(t, estate, mode)
		for _, e := range readCorpus(t) {
			_, err := s.Query(context.Background(), e.SQL, Caps{})
			switch {
			case e.Allow && err != nil:
				t.Errorf("%s: allowed query failed: %s\n  %v", mode, e.SQL, err)
			case !e.Allow && !errors.Is(err, ErrRejected):
				t.Errorf("%s: refused query was not refused: %s\n  %v", mode, e.SQL, err)
			}
		}
	}
}

// The text that runs is the engine's own rewrite of the checked tree. It goes
// through the checker again when it is cited and run again, and gives the same
// result; spelling and white space do not change it or its hash.
func TestCanonicalTextIsChecked(t *testing.T) {
	s := open(t, estate, ModeTables)
	ctx := context.Background()
	for _, e := range readCorpus(t) {
		if !e.Allow {
			continue
		}
		first, err := s.Query(ctx, e.SQL, Caps{})
		if err != nil {
			t.Fatalf("%s: %v", e.SQL, err)
		}
		again, err := s.Query(ctx, first.SQL, Caps{})
		if err != nil {
			t.Errorf("%s: its canonical text %q was refused: %v", e.SQL, first.SQL, err)
			continue
		}
		h1, _ := ResultHash(first.Columns, first.Rows, first.Ordered)
		h2, _ := ResultHash(again.Columns, again.Rows, again.Ordered)
		if h1 != h2 {
			t.Errorf("%s: its canonical text %q gives another result", e.SQL, first.SQL)
		}
	}
	a := query(t, s, "select   count(*)  from nodes -- the count", Caps{})
	b := query(t, s, "SELECT count(*) FROM nodes", Caps{})
	if a.SQL != b.SQL || HashQuery(a.SQL) != HashQuery(b.SQL) {
		t.Errorf("two spellings of one query differ: %q and %q", a.SQL, b.SQL)
	}
}

func fileSums(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		sum := sha256.Sum256(b)
		out[p] = hex.EncodeToString(sum[:])
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The engine's own lock, with no dialect check in front: what a session
// refuses when the checker is out of the picture. The snapshot folder must
// come out unchanged, and nothing must appear beside it.
func TestEngineLockAlone(t *testing.T) {
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "snap")
			if err := os.CopyFS(dir, os.DirFS(estate)); err != nil {
				t.Fatal(err)
			}
			secret := filepath.Join(root, "secret.csv")
			if err := os.WriteFile(secret, []byte("a,b\n1,2\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(root, "out")
			before := fileSums(t, root)
			s := open(t, dir, mode)
			ctx := context.Background()

			refused := []string{
				"COPY (SELECT 1) TO '" + out + ".csv'",
				"COPY (SELECT 1) TO '" + filepath.Join(dir, "evil.parquet") + "'",
				"COPY (SELECT 1) TO '" + filepath.Join(dir, "nodes.parquet") + "' (USE_TMP_FILE false)",
				"COPY nodes TO '" + out + ".parquet' (FORMAT parquet)",
				"EXPORT DATABASE '" + out + "'",
				"SELECT * FROM read_csv('" + secret + "')",
				"SELECT * FROM read_text('" + secret + "')",
				"SELECT * FROM read_blob('" + secret + "')",
				"SELECT * FROM read_json('" + secret + "')",
				"SELECT * FROM '" + secret + "'",
				"SELECT * FROM read_parquet('" + filepath.Join(dir, "nodes.parquet") + "')",
				"SELECT * FROM glob('" + root + "/*')",
				"SELECT * FROM sniff_csv('" + secret + "')",
				"SELECT * FROM read_csv('http://127.0.0.1:9/x.csv')",
				"INSTALL httpfs",
				"LOAD httpfs",
				"ATTACH '" + out + ".db' AS x",
				"SET threads = 8",
				"SET memory_limit = '64GB'",
				"SET enable_external_access = true",
				"SET allowed_directories = ['" + root + "']",
				"SET allowed_paths = ['" + secret + "']",
				"SET lock_configuration = false",
				"SET temp_directory = '" + out + "'",
				"RESET threads",
				"RESET enable_external_access",
				"PRAGMA memory_limit = '64GB'",
			}
			if mode == ModeROAttach {
				refused = append(refused,
					"INSERT INTO nodes SELECT * FROM nodes",
					"DELETE FROM nodes",
					"DROP TABLE nodes",
					"CREATE TABLE evil AS SELECT 1",
					"CREATE OR REPLACE TABLE nodes AS SELECT 1",
					"CREATE MACRO evil() AS 1",
					"ALTER TABLE nodes ADD COLUMN x INTEGER",
				)
			}
			for _, q := range refused {
				if err := s.Raw(ctx, q); err == nil {
					t.Errorf("the session ran %s", q)
				}
			}
			// The data is intact and still readable.
			var n int
			if err := s.db.QueryRowContext(context.Background(), "SELECT count(*) FROM nodes").Scan(&n); err != nil || n != 15 {
				t.Errorf("nodes: %d rows, %v; want 15", n, err)
			}
			if after := fileSums(t, root); !equalMaps(before, after) {
				t.Errorf("files changed or appeared:\nbefore %v\nafter  %v", before, after)
			}
		})
	}
}

func equalMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestRowCap(t *testing.T) {
	dir, _, _ := graph(t, 300)
	for _, mode := range modes {
		s := open(t, dir, mode)
		r := query(t, s, "SELECT node_id FROM nodes ORDER BY node_id", Caps{MaxRows: 100})
		if r.RowCount != 100 || !r.Truncated || r.TruncatedBy != ByRows || len(r.Rows) != 100 {
			t.Errorf("%s: cap 100: %d rows, truncated %t by %q", mode, r.RowCount, r.Truncated, r.TruncatedBy)
		}
		if !strings.HasSuffix(r.SQL, "ORDER BY node_id") && !strings.Contains(r.SQL, "ORDER BY") {
			t.Errorf("%s: the canonical query lost its ORDER BY: %s", mode, r.SQL)
		}
		// The cap equal to the rows there are is not a truncation.
		r = query(t, s, "SELECT node_id FROM nodes", Caps{MaxRows: 300})
		if r.RowCount != 300 || r.Truncated {
			t.Errorf("%s: cap 300 of 300: %d rows, truncated %t", mode, r.RowCount, r.Truncated)
		}
		// A cap above the hard maximum is clamped to it.
		r = query(t, s, "SELECT n.node_id FROM nodes n, nodes m", Caps{MaxRows: 1_000_000, MaxBytes: HardMaxBytes})
		if r.RowCount != HardMaxRows || !r.Truncated {
			t.Errorf("%s: hard cap: %d rows, truncated %t", mode, r.RowCount, r.Truncated)
		}
		// A cross join of a billion rows costs no more than the cap.
		start := time.Now()
		r = query(t, s, "SELECT a.node_id FROM nodes a, nodes b, nodes c, nodes d", Caps{MaxRows: 10})
		if r.RowCount != 10 || !r.Truncated || time.Since(start) > 3*time.Second {
			t.Errorf("%s: cross join: %d rows, truncated %t, %v", mode, r.RowCount, r.Truncated, time.Since(start))
		}
	}
}

func TestByteAndColumnCaps(t *testing.T) {
	dir, _, _ := graph(t, 300)
	s := open(t, dir, ModeTables)
	r := query(t, s, "SELECT * FROM nodes", Caps{MaxBytes: 3000})
	if !r.Truncated || r.TruncatedBy != ByBytes || r.RowCount == 0 || r.RowCount >= 300 {
		t.Errorf("byte cap: %d rows, truncated %t by %q", r.RowCount, r.Truncated, r.TruncatedBy)
	}
	if _, err := s.Query(context.Background(), "SELECT * FROM nodes", Caps{MaxCols: 5}); !errors.Is(err, ErrRejected) {
		t.Errorf("a result of %d columns under a cap of 5: %v", 18, err)
	}
	wide := "SELECT " + strings.TrimSuffix(strings.Repeat("1, ", 70), ", ")
	if _, err := s.Query(context.Background(), wide, Caps{}); !errors.Is(err, ErrRejected) {
		t.Errorf("70 columns: %v", err)
	}
	if _, err := s.Query(context.Background(), "SELECT 1 -- "+strings.Repeat("x", MaxSQLBytes), Caps{}); !errors.Is(err, ErrRejected) {
		t.Errorf("a query over the size limit: %v", err)
	}
}

func TestTimeoutAndCancel(t *testing.T) {
	dir, _, _ := graph(t, 3000)
	s := open(t, dir, ModeTables)
	slow := "SELECT count(*) FROM nodes a, nodes b, nodes c WHERE a.name < b.name AND b.name < c.name"

	start := time.Now()
	_, err := s.Query(context.Background(), slow, Caps{Timeout: 300 * time.Millisecond})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 3*time.Second {
		t.Errorf("timeout: %v after %v", err, time.Since(start))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start = time.Now()
	if _, err = s.Query(ctx, slow, Caps{Timeout: time.Minute}); err == nil || time.Since(start) > 3*time.Second {
		t.Errorf("cancel: %v after %v", err, time.Since(start))
	}
	// The session is still good.
	if r := query(t, s, "SELECT count(*) FROM nodes", Caps{}); r.Rows[0][0] != int64(3000) {
		t.Errorf("after a timeout: %v", r.Rows)
	}
}

func TestMemoryLimit(t *testing.T) {
	dir, _, _ := graph(t, 3000)
	s, err := New().Open(context.Background(), dir, Options{MemoryLimit: "32MB"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	_, err = s.Query(context.Background(), "SELECT array_agg(a.node_id || b.node_id) FROM nodes a, nodes b", Caps{Timeout: 20 * time.Second})
	if err == nil || !strings.Contains(err.Error(), "Out of Memory") {
		t.Errorf("a query that needs a gigabyte under a 32MB limit: %v", err)
	}
	if r := query(t, s, "SELECT count(*) FROM nodes", Caps{}); r.Rows[0][0] != int64(3000) {
		t.Errorf("after the memory error: %v", r.Rows)
	}
}

// blast and cone against a breadth-first search in Go over the same edges,
// on a graph with cycles, in both modes.
func TestMacrosMatchBreadthFirstSearch(t *testing.T) {
	dir, edges, ids := graph(t, 400)
	for _, mode := range modes {
		s := open(t, dir, mode)
		for _, start := range []string{ids[0], ids[17], ids[399]} {
			for _, depth := range []int{0, 1, 3, 8, 60} {
				for _, c := range []struct {
					macro   string
					forward bool
				}{{"blast", false}, {"cone", true}} {
					r := query(t, s, "SELECT node_id, depth FROM "+c.macro+"('"+start+"', "+itoa(depth)+")", Caps{})
					got := map[string]int{}
					for _, row := range r.Rows {
						got[row[0].(string)] = int(row[1].(int64))
					}
					want := bfs(edges, start, min(depth, 50), c.forward)
					if len(got) != len(want) {
						t.Errorf("%s %s(%d): %d nodes, want %d", mode, c.macro, depth, len(got), len(want))
						continue
					}
					for id, d := range want {
						if got[id] != d {
							t.Errorf("%s %s(%d): node %s at depth %d, want %d", mode, c.macro, depth, id[:8], got[id], d)
							break
						}
					}
				}
			}
		}
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// The estate's stored queries, with what the fixture says they must find.
func TestStoredQueriesOnTheEstate(t *testing.T) {
	loaded, err := snapshot.Load(estate)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s := open(t, estate, ModeTables)
	ask := func(name string, params map[string]string) *Output {
		t.Helper()
		out, err := Ask(ctx, s, loaded.Manifest, Request{Stored: name, Params: params})
		if err != nil {
			t.Fatalf("%s %v: %v", name, params, err)
		}
		return out
	}

	// What breaks if the prod network module changes: its resources, and the
	// instance that needs the subnet.
	out := ask("blast", map[string]string{"node": "module.network", "depth": "10"})
	got := column(t, out.Result, "address")
	for _, want := range []string{"module.network", "module.network.aws_vpc.main", "module.network.aws_subnet.private", "aws_instance.app"} {
		if !slices.Contains(got, want) {
			t.Errorf("blast of module.network lacks %s: %v", want, got)
		}
	}
	// Resolved by address, the prod and staging modules are one node each by
	// address only if the address is unique: both have module.network, so
	// both are targets and both environments appear.
	if n := len(out.Result.Rows); n < 8 {
		t.Errorf("blast of module.network: %d rows", n)
	}
	if out.Answer.StoredQuery != "blast" || out.Answer.StoredQueryVersion != 1 || out.Answer.Parameters["depth"] != "10" ||
		!strings.HasPrefix(out.Answer.StoredQueryHash, "sha256:") {
		t.Errorf("the citation does not name the stored query: %+v", out.Answer)
	}

	// What an instance needs: its subnet, the VPC through it, the module and the state root.
	out = ask("cone", map[string]string{"node": "arn:aws:ec2:eu-west-1:111111111111:prod-i-0e3f"})
	got = column(t, out.Result, "name")
	for _, want := range []string{"prod-i-0e3f", "prod-subnet-0c2d", "prod-vpc-0a1b", "network", "prod-net"} {
		if !slices.Contains(got, want) {
			t.Errorf("cone of the prod instance lacks %s: %v", want, got)
		}
	}
	if slices.Contains(got, "staging-vpc-0a1b") {
		t.Errorf("cone of the prod instance reaches staging: %v", got)
	}
	// Depth 0 is the node itself.
	out = ask("cone", map[string]string{"node": "aws_instance.app", "depth": "0"})
	if len(out.Result.Rows) != 2 { // one per environment
		t.Errorf("depth 0: %d rows", len(out.Result.Rows))
	}

	out = ask("unmanaged", nil)
	if got := column(t, out.Result, "name"); !slices.Equal(got, []string{"acme-legacy-uploads"}) {
		t.Errorf("unmanaged: %v", got)
	}
	if out = ask("unmanaged", map[string]string{"account": "222222222222"}); len(out.Result.Rows) != 0 {
		t.Errorf("unmanaged in staging's account: %v", out.Result.Rows)
	}

	out = ask("summary", nil)
	if len(out.Result.Rows) == 0 || out.Answer.StoredQuery != "summary" {
		t.Errorf("summary: %v", out.Result.Rows)
	}
}

// A parameter is data: a value that looks like SQL stays inside its quotes.
func TestStoredQueryParametersCannotInjectSQL(t *testing.T) {
	loaded, err := snapshot.Load(estate)
	if err != nil {
		t.Fatal(err)
	}
	s := open(t, estate, ModeTables)
	for _, v := range []string{
		"x' OR '1'='1", "'; DROP TABLE nodes; --", "x') UNION SELECT * FROM read_csv('/etc/passwd') --", `\`, "a''b",
	} {
		out, err := Ask(context.Background(), s, loaded.Manifest, Request{Stored: "blast", Params: map[string]string{"node": v}})
		if err != nil || len(out.Result.Rows) != 0 {
			t.Errorf("node %q: %v, %v", v, out, err)
		}
	}
	for _, bad := range []map[string]string{
		{},                                  // node is required
		{"node": "x", "nope": "1"},          // unknown
		{"node": "x", "depth": "51"},        // out of range
		{"node": "x", "depth": "-1"},        // out of range
		{"node": "x", "depth": "3; DROP"},   // not a number
		{"node": "x", "depth": "05"},        // not canonical
		{"node": "bad\x00value"},            // control character
		{"node": strings.Repeat("x", 2000)}, // too long
	} {
		if _, err := Ask(context.Background(), s, loaded.Manifest, Request{Stored: "blast", Params: bad}); err == nil {
			t.Errorf("parameters %v were accepted", bad)
		}
	}
	if _, err := Ask(context.Background(), s, loaded.Manifest, Request{SQL: "SELECT 1", Params: map[string]string{"a": "b"}}); err == nil {
		t.Error("parameters with plain SQL were accepted")
	}
	if _, err := Ask(context.Background(), s, loaded.Manifest, Request{Stored: "nothing"}); err == nil || !strings.Contains(err.Error(), "blast") {
		t.Errorf("an unknown stored query: %v", err)
	}
}

func TestCitation(t *testing.T) {
	ctx := context.Background()
	out, err := Run(ctx, New(), estate, Options{}, Request{
		SQL: "select kind, count(*) as n from nodes group by kind order by kind", Caps: Caps{MaxRows: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	a := out.Answer
	loaded, _ := snapshot.Load(estate)
	if err := validAnswer(t, a); err != nil {
		t.Errorf("the citation does not match its schema: %v", err)
	}
	switch {
	case a.SnapshotID != loaded.Manifest.SnapshotID:
		t.Errorf("snapshot id %s", a.SnapshotID)
	case a.Dialect != Dialect || !strings.HasPrefix(a.Engine, "duckdb 2."):
		t.Errorf("dialect %q, engine %q", a.Dialect, a.Engine)
	case a.QueryHash != HashQuery(a.Query) || !strings.Contains(a.Query, "ORDER BY"):
		t.Errorf("query %q, hash %s", a.Query, a.QueryHash)
	case a.RowCount != 2 || !a.Truncated || a.TruncatedBy != ByRows || !a.Ordered:
		t.Errorf("rows %d, truncated %t by %q, ordered %t", a.RowCount, a.Truncated, a.TruncatedBy, a.Ordered)
	case a.Caps.MaxRows != 2 || a.Caps.MaxColumns != 64 || a.Caps.MaxBytes != DefaultMaxBytes:
		t.Errorf("caps %+v", a.Caps)
	case a.Limits.OldestSource != "2026-11-25T09:05:00Z" || a.Limits.Status != "ok" || a.Limits.Note != loaded.Manifest.Limits:
		t.Errorf("limits %+v", a.Limits)
	case a.Limits.Covered == nil || !slices.Equal(a.Limits.Covered.Clouds, []string{"aws"}) || a.Limits.Covered.TypesRead != 4:
		t.Errorf("covered %+v", a.Limits.Covered)
	}
}

func TestLimitsReportFailedSources(t *testing.T) {
	m := snapshot.Manifest{
		SnapshotID: strings.Repeat("a", 64), Status: "partial", Limits: "One state did not read.",
		Coverage: snapshot.Coverage{FailedSources: []snapshot.FailedSource{{SourceID: "state-b", Status: "failed", Reason: "access denied"}}},
	}
	a, err := Cite(m, &Result{Columns: []string{"x"}, Rows: [][]any{{int64(1)}}, RowCount: 1, SQL: "SELECT 1", Engine: "duckdb 2.0.1"}, Caps{})
	if err != nil {
		t.Fatal(err)
	}
	if a.Limits.FailedSources != 1 || a.Limits.Status != "partial" || len(a.Limits.Failed) != 1 || a.Limits.Failed[0].Reason != "access denied" {
		t.Errorf("limits %+v", a.Limits)
	}
	if err := validAnswer(t, a); err != nil {
		t.Error(err)
	}
}

// The same question in either mode, and again, gives one hash: an answer is
// not a function of thread timing or the order the engine returned rows in.
func TestResultHashIsStable(t *testing.T) {
	dir, _, _ := graph(t, 1500)
	loaded, err := snapshot.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, q := range []string{
		"SELECT account, tf_type, count(*) FROM nodes GROUP BY account, tf_type",
		"SELECT n.node_id, count(*) AS c FROM nodes n JOIN edges e ON e.from_id = n.node_id GROUP BY n.node_id",
		"SELECT * FROM nodes ORDER BY node_id",
	} {
		seen := map[string]bool{}
		for _, mode := range modes {
			s := open(t, dir, mode)
			for range 4 {
				out, err := Ask(ctx, s, loaded.Manifest, Request{SQL: q})
				if err != nil {
					t.Fatal(err)
				}
				seen[out.Answer.ResultHash] = true
			}
		}
		if len(seen) != 1 {
			t.Errorf("%s: %d different result hashes", q, len(seen))
		}
	}
}

func TestReverify(t *testing.T) {
	dir, _, _ := graph(t, 500)
	loaded, err := snapshot.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s := open(t, dir, ModeTables)
	out, err := Ask(ctx, s, loaded.Manifest, Request{
		SQL: "SELECT node_id, name FROM nodes ORDER BY node_id", Caps: Caps{MaxRows: 50},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Through JSON and back, as a file, and into another session.
	raw, _ := json.Marshal(out.Answer)
	var a snapshot.Answer
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	s2 := open(t, dir, ModeROAttach)
	res, err := Reverify(ctx, s2, loaded.Manifest, a, 0)
	if err != nil || !res.OK() {
		t.Fatalf("a faithful answer: %+v, %v", res, err)
	}
	tampered := map[string]func(*snapshot.Answer){
		"result hash":   func(a *snapshot.Answer) { a.ResultHash = "sha256:" + strings.Repeat("0", 64) },
		"row count":     func(a *snapshot.Answer) { a.RowCount++ },
		"truncated":     func(a *snapshot.Answer) { a.Truncated = false },
		"snapshot":      func(a *snapshot.Answer) { a.SnapshotID = strings.Repeat("0", 64) },
		"query hash":    func(a *snapshot.Answer) { a.QueryHash = "sha256:" + strings.Repeat("1", 64) },
		"query":         func(a *snapshot.Answer) { a.Query = strings.Replace(a.Query, "name", "tf_type", 1) },
		"dialect":       func(a *snapshot.Answer) { a.Dialect = "infra-ontology/sql/v9" },
		"refused query": func(a *snapshot.Answer) { a.Query = "SELECT * FROM read_csv('/etc/passwd')" },
		"caps":          func(a *snapshot.Answer) { a.Caps.MaxRows = 60 },
		"ordered":       func(a *snapshot.Answer) { a.Ordered = false },
	}
	for name, mutate := range tampered {
		b := a
		mutate(&b)
		res, err := Reverify(ctx, s2, loaded.Manifest, b, 0)
		if err != nil || res.OK() {
			t.Errorf("%s: a tampered answer verified: %+v, %v", name, res, err)
		}
	}
	// A different engine version is a note, not a failure.
	b := a
	b.Engine = "duckdb 1.0.0"
	if res, err := Reverify(ctx, s2, loaded.Manifest, b, 0); err != nil || !res.OK() || len(res.Notes) != 1 {
		t.Errorf("another engine version: %+v, %v", res, err)
	}
}

func TestRunRefusesASnapshotThatDoesNotVerify(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "snap")
	if err := os.CopyFS(dir, os.DirFS(estate)); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, snapshot.NodesFile)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)/2] ^= 0xff
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = Run(context.Background(), New(), dir, Options{}, Request{SQL: "SELECT 1"})
	if err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("a tampered snapshot was queried: %v", err)
	}
}

func TestOpenRefusesBadOptions(t *testing.T) {
	for _, o := range []Options{{Mode: "views"}, {MemoryLimit: "1GB&threads=99"}} {
		if s, err := New().Open(context.Background(), estate, o); err == nil {
			_ = s.Close()
			t.Errorf("Open accepted %+v", o)
		}
	}
	if _, err := New().Open(context.Background(), t.TempDir(), Options{}); err == nil {
		t.Error("Open accepted a folder with no snapshot")
	}
}

func TestConcurrentQueries(t *testing.T) {
	dir, _, _ := graph(t, 200)
	s := open(t, dir, ModeROAttach)
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range 16 {
		wg.Go(func() {
			r, err := s.Query(context.Background(), "SELECT count(*) FROM nodes", Caps{})
			if err == nil && r.Rows[0][0] != int64(200) {
				err = errors.New("wrong count")
			}
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
}

var fuzzOnce sync.Once
var fuzzSession Session

// FuzzQuery throws text at a locked session. Whatever the text, nothing may
// panic, a refusal wraps ErrRejected or is an engine error, an accepted query
// rewrites to a canonical text that is itself accepted, the caps
// hold, and the data is the same afterwards.
func FuzzQuery(f *testing.F) {
	for _, e := range readCorpus(f) {
		f.Add(e.SQL)
	}
	f.Add("SELECT * FROM blast((SELECT node_id FROM nodes LIMIT 1), 3)")
	f.Add("SELECT * FROM nodes WHERE name = '" + strings.Repeat("a", 300) + "'")
	f.Fuzz(func(t *testing.T, sql string) {
		fuzzOnce.Do(func() {
			s, err := New().Open(context.Background(), estate, Options{MemoryLimit: "128MB"})
			if err != nil {
				t.Fatal(err)
			}
			fuzzSession = s
		})
		caps := Caps{MaxRows: 20, MaxBytes: 4096, Timeout: 2 * time.Second}
		r, err := fuzzSession.Query(context.Background(), sql, caps)
		if err != nil {
			return
		}
		if len(r.Rows) > 20 || r.RowCount != len(r.Rows) {
			t.Fatalf("%q: %d rows under a cap of 20", sql, len(r.Rows))
		}
		if _, err := fuzzSession.Query(context.Background(), r.SQL, caps); err != nil {
			t.Fatalf("%q: its canonical text %q was refused: %v", sql, r.SQL, err)
		}
		n, err := fuzzSession.Query(context.Background(), "SELECT count(*) FROM nodes", Caps{})
		if err != nil || n.Rows[0][0] != int64(15) {
			t.Fatalf("%q changed the data: %v, %v", sql, n, err)
		}
	})
}
