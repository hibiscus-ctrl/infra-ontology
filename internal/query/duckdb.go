// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !noduckdb

package query

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	// The DuckDB engine, with the engine's static library inside: cgo.
	_ "github.com/duckdb/duckdb-go/v2"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

type duck struct{}

// New returns the DuckDB engine.
func New() Engine { return duck{} }

func (duck) Name() string { return "duckdb" }

// session is one locked DuckDB database over one snapshot.
type session struct {
	db     *sql.DB
	tmp    string // the private database file's folder, until it is deleted
	engine string // "duckdb 2.0.1"
}

// Open loads the snapshot into tables and locks the session. The order is the
// guarantee:
//
//  1. the settings that cannot be changed later (no extension install or
//     load, no temp directory, memory and threads) go in the DSN;
//  2. the snapshot's Parquet files are read into tables, in memory
//     (ModeTables) or in a private database file that is then attached
//     read-only (ModeROAttach);
//  3. the two macros are created;
//  4. enable_external_access goes off, with no allowed paths: from here on no
//     file can be read or written, and nothing can be attached, installed or
//     loaded;
//  5. lock_configuration freezes every setting, so a query cannot undo 4.
//
// The snapshot's files are not left readable at all, which is why the engine's
// allowed_directories and allowed_paths are not used: both still let a COPY
// overwrite an allowed file.
func (duck) Open(ctx context.Context, dir string, o Options) (Session, error) {
	if o.MemoryLimit == "" {
		o.MemoryLimit = "512MB"
	}
	if o.Threads <= 0 {
		o.Threads = 2
	}
	switch o.Mode {
	case "":
		o.Mode = ModeTables
	case ModeTables, ModeROAttach:
	default:
		return nil, fmt.Errorf("unknown session mode %q", o.Mode)
	}
	if strings.ContainsAny(o.MemoryLimit, "&=?# ") {
		return nil, fmt.Errorf("memory limit %q is not a size such as 512MB", o.MemoryLimit)
	}
	raw, err := os.ReadFile(filepath.Join(dir, snapshot.ManifestFile))
	if err != nil {
		return nil, err
	}
	var m snapshot.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", snapshot.ManifestFile, err)
	}

	dsn := fmt.Sprintf("?threads=%d&memory_limit=%s&temp_directory=&autoinstall_known_extensions=false"+
		"&autoload_known_extensions=false&allow_community_extensions=false&allow_unsigned_extensions=false",
		o.Threads, o.MemoryLimit)
	db, err := sql.Open("duckdb", dsn)
	if err != nil {
		return nil, err
	}
	// One connection: the session's search path and default database are
	// per connection, and a query's temp objects stay in one place. Queries
	// from several goroutines take turns, each under its own time limit.
	db.SetMaxOpenConns(1)
	s := &session{db: db}
	if err := s.load(ctx, dir, m, o); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

func (s *session) exec(ctx context.Context, q string) error {
	_, err := s.db.ExecContext(ctx, q)
	return err
}

func (s *session) load(ctx context.Context, dir string, m snapshot.Manifest, o Options) error {
	// The schema of the "snapshot" table: one row from the manifest, so SQL
	// can read the snapshot id and the age of its sources.
	snapshotSQL := "SELECT " + strings.Join([]string{
		lit(m.SnapshotID) + " AS snapshot_id",
		lit(m.Label) + " AS label",
		lit(m.ParentID) + " AS parent_id",
		lit(m.CreatedAt) + " AS created_at",
		lit(m.Status) + " AS status",
		lit(m.SourcesSummary.OldestCollectedAt) + " AS oldest_source",
		lit(m.SourcesSummary.NewestCollectedAt) + " AS newest_source",
		lit(m.Limits) + " AS limits",
	}, ", ")
	tables := []struct{ name, file string }{
		{"nodes", snapshot.NodesFile}, {"edges", snapshot.EdgesFile}, {"sources", snapshot.SourcesFile},
	}

	prefix, edges := "", "edges"
	steps := []string{}
	if o.Mode == ModeROAttach {
		tmp, err := os.MkdirTemp("", "infra-ontology-session-")
		if err != nil {
			return err
		}
		s.tmp = tmp
		file := filepath.Join(tmp, "snapshot.duckdb")
		steps = append(steps, "ATTACH "+lit(file)+" AS w")
		prefix, edges = "w.", "snap.main.edges"
	}
	for _, t := range tables {
		steps = append(steps, "CREATE TABLE "+prefix+t.name+" AS SELECT * FROM read_parquet("+lit(filepath.Join(dir, t.file))+")")
	}
	steps = append(steps, "CREATE TABLE "+prefix+"snapshot AS "+snapshotSQL)
	if o.Mode == ModeROAttach {
		file := filepath.Join(s.tmp, "snapshot.duckdb")
		steps = append(steps,
			"DETACH w",
			"ATTACH "+lit(file)+" AS snap (READ_ONLY)",
			"USE snap",
			"SET search_path = 'snap.main,memory.main'")
	}
	macro := "memory.main."
	if o.Mode == ModeTables {
		macro = ""
	}
	steps = append(steps, macroSQL(macro+"blast", edges, "e.to_id", "e.from_id"), macroSQL(macro+"cone", edges, "e.from_id", "e.to_id"))
	// The lock.
	steps = append(steps, "SET enable_external_access=false", "SET lock_configuration=true")
	for _, q := range steps {
		if err := s.exec(ctx, q); err != nil {
			return fmt.Errorf("open the snapshot: %w", err)
		}
	}
	if s.tmp != "" {
		// The attached file stays usable once deleted (Linux and macOS).
		_ = os.RemoveAll(s.tmp)
		s.tmp = ""
	}
	var version string
	if err := s.db.QueryRowContext(ctx, "SELECT version()").Scan(&version); err != nil {
		return err
	}
	s.engine = "duckdb " + strings.TrimPrefix(version, "v")
	return nil
}

// macroSQL defines a table macro that walks the edges from a node: from
// follows an edge from one column to the other, so blast reads who depends on
// the node (an edge runs from the dependent to what it needs) and cone reads
// what the node needs. UNION, not UNION ALL, drops a repeated row, which keeps
// a cycle cheap, and the depth is capped at 50 whatever is asked.
//
// The macro has two forms: (start, depth) follows dependency edges only, and
// (start, depth, include_access) also follows can_assume, can_read and
// can_write when the third is true. It returns, for each node, the fewest hops
// to it (depth), the kind of the edge that reached it (edge_kind; null for the
// start) and the weakest confidence along the path (confidence), taking the
// strongest of the paths of that length.
func macroSQL(name, edges, join, next string) string {
	kinds := "'" + strings.Join(AccessEdgeKinds, "', '") + "'"
	form := func(params, allowed string) string {
		return fmt.Sprintf(`(%s) AS TABLE (
WITH RECURSIVE r(node_id, depth, edge_kind, weak) AS (
  SELECT start_id::VARCHAR, 0, NULL::VARCHAR, 0
  UNION
  SELECT %s, r.depth + 1, e.kind,
    greatest(r.weak, CASE e.confidence WHEN 'observed' THEN 1 WHEN 'computed' THEN 2 ELSE 3 END)
  FROM r JOIN %s e ON %s = r.node_id WHERE r.depth < least(max_depth, 50) AND %s
), nearest AS (
  SELECT node_id, min(depth) AS depth FROM r GROUP BY node_id
), strongest AS (
  SELECT r.node_id, r.depth, min(r.weak) AS weak FROM r JOIN nearest USING (node_id, depth) GROUP BY r.node_id, r.depth
)
SELECT s.node_id, s.depth, min(r.edge_kind) AS edge_kind,
  CASE s.weak WHEN 1 THEN 'observed' WHEN 2 THEN 'computed' WHEN 3 THEN 'inferred' END AS confidence
FROM strongest s JOIN r ON r.node_id = s.node_id AND r.depth = s.depth AND r.weak = s.weak
GROUP BY s.node_id, s.depth, s.weak)`, params, next, edges, join, allowed)
	}
	return "CREATE MACRO " + name + form("start_id, max_depth", "e.kind NOT IN ("+kinds+")") + ",\n" +
		form("start_id, max_depth, include_access", "(include_access OR e.kind NOT IN ("+kinds+"))")
}

func (s *session) Close() error {
	err := s.db.Close()
	if s.tmp != "" {
		_ = os.RemoveAll(s.tmp)
	}
	return err
}

// canonical parses the text with DuckDB, checks the parse tree, and returns
// the SQL DuckDB writes back from that same tree. That text is what runs, so
// a difference between how the checker and the executor read the user's text
// cannot exist.
func (s *session) canonical(ctx context.Context, q string) (text string, ordered bool, err error) {
	if len(q) > MaxSQLBytes {
		return "", false, reject("the query is %d bytes, over the limit of %d", len(q), MaxSQLBytes)
	}
	var tree string
	if err := s.db.QueryRowContext(ctx, "SELECT json_serialize_sql(?)::VARCHAR", q).Scan(&tree); err != nil {
		return "", false, s.mapErr(ctx, err)
	}
	ordered, err = checkTree(tree)
	if err != nil {
		return "", false, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT json_deserialize_sql(?::JSON)", tree).Scan(&text); err != nil {
		return "", false, s.mapErr(ctx, err)
	}
	return strings.TrimRight(strings.TrimSpace(text), "; \n"), ordered, nil
}

// Query runs one query under the caps. The text is checked against the
// dialect, rewritten to its canonical form and wrapped as
// SELECT * FROM (<canonical>) AS q LIMIT <rows+1>: the one extra row says
// whether the cap cut the result, with no second query.
func (s *session) Query(ctx context.Context, q string, c Caps) (*Result, error) {
	c = c.WithDefaults()
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	canon, ordered, err := s.canonical(ctx, q)
	if err != nil {
		return nil, err
	}
	// canon is the text of a checked parse tree, and the limit is a number.
	wrapped := fmt.Sprintf("SELECT * FROM (%s) AS q LIMIT %d", canon, c.MaxRows+1) //nolint:gosec // see above
	rows, err := s.db.QueryContext(ctx, wrapped)
	if err != nil {
		return nil, s.mapErr(ctx, err)
	}
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	if err != nil {
		return nil, s.mapErr(ctx, err)
	}
	if len(cols) > c.MaxCols {
		return nil, reject("the result has %d columns, over the cap of %d", len(cols), c.MaxCols)
	}
	res := &Result{Columns: cols, Engine: s.engine, SQL: canon, Ordered: ordered, Rows: [][]any{}}
	var size int64
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, s.mapErr(ctx, err)
		}
		if res.RowCount == c.MaxRows { // the extra row proves more exist; drop it
			res.Truncated, res.TruncatedBy = true, ByRows
			break
		}
		row := make([]any, len(vals))
		for i, v := range vals {
			row[i] = Normalise(v)
		}
		b, err := json.Marshal(row)
		if err != nil {
			return nil, fmt.Errorf("read the result: %w", err)
		}
		if size += int64(len(b)); size > c.MaxBytes {
			res.Truncated, res.TruncatedBy = true, ByBytes
			break
		}
		res.Rows = append(res.Rows, row)
		res.RowCount++
	}
	if err := rows.Err(); err != nil {
		return nil, s.mapErr(ctx, err)
	}
	return res, nil
}

// mapErr says plainly when the time limit or the caller's cancel stopped a
// query.
func (s *session) mapErr(ctx context.Context, err error) error {
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return fmt.Errorf("the query stopped at the time limit: %w", context.DeadlineExceeded)
	case ctx.Err() != nil:
		return fmt.Errorf("the query was cancelled: %w", ctx.Err())
	}
	return err
}
