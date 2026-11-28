// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

// Package query answers read-only SQL over a snapshot and cites every answer.
//
// The engine sits behind an interface: engine.go, dialect.go, result.go and
// the files that build an answer are pure Go, and duckdb.go (the DuckDB
// engine, which needs cgo) is compiled unless the build says noduckdb. The
// snapshot, verify and diff code never import this package.
package query

import (
	"context"
	"errors"
	"time"
)

// Dialect names the SQL dialect an answer was checked against. It changes
// only when what a query may say changes.
const Dialect = "infra-ontology/sql/v1"

// Tables and table functions a query may read. The snapshot table has one
// row, from the manifest.
var (
	tableNames = []string{"nodes", "edges", "sources", "snapshot"}
	// MacroNames are the table functions a query may call: blast(id, depth)
	// and cone(id, depth).
	MacroNames = []string{"blast", "cone"}
)

// AccessEdgeKinds are the edge kinds that say who may act on a node, not what
// needs what: an inferred trust or an iam-lens result is not a dependency, so
// blast, cone and their stored queries skip these unless a caller asks for
// access edges. The stored files (queries/blast.sql and cone.sql) repeat the
// list, and a test keeps them in step.
var AccessEdgeKinds = []string{"can_assume", "can_read", "can_write"}

// ErrUnavailable is returned by a build without the query engine.
var ErrUnavailable = errors.New("query engine not built in (noduckdb build): run duckdb on the snapshot folder")

// ErrRejected wraps every refusal made by the dialect checker and the caps
// checked before a query runs.
var ErrRejected = errors.New("statement rejected by the read-only dialect")

// Session modes.
const (
	// ModeTables copies the snapshot into memory tables: the fast open, for
	// a one-shot query.
	ModeTables = "tables"
	// ModeROAttach builds the tables in a private database file and attaches
	// it read-only, so the engine itself refuses every write to the data and
	// the catalog: for a long-lived session.
	ModeROAttach = "ro-attach"
)

// Options configure a session.
type Options struct {
	Mode        string // ModeTables (default) or ModeROAttach
	MemoryLimit string // default "512MB"
	Threads     int    // default 2
}

// Defaults and hard limits of the caps.
const (
	DefaultMaxRows  = 1000
	HardMaxRows     = 10000
	HardMaxCols     = 64
	DefaultMaxBytes = 4 << 20
	HardMaxBytes    = 64 << 20
	DefaultTimeout  = 10 * time.Second
	HardTimeout     = 5 * time.Minute
	// MaxSQLBytes is the longest query text the checker reads.
	MaxSQLBytes = 64 << 10
)

// Caps bound a query's result and run time. A zero field takes its default;
// a field above its hard limit takes the limit.
type Caps struct {
	MaxRows  int           // rows returned; the query runs with LIMIT MaxRows+1 to tell if more exist
	MaxCols  int           // columns; a wider result is refused
	MaxBytes int64         // approximate size of the result as JSON
	Timeout  time.Duration // the query is cancelled after this
}

// WithDefaults fills the zero fields and clamps the rest to the hard limits.
func (c Caps) WithDefaults() Caps {
	c.MaxRows = clamp(c.MaxRows, DefaultMaxRows, HardMaxRows)
	c.MaxCols = clamp(c.MaxCols, HardMaxCols, HardMaxCols)
	c.MaxBytes = clamp(c.MaxBytes, DefaultMaxBytes, HardMaxBytes)
	c.Timeout = clamp(c.Timeout, DefaultTimeout, HardTimeout)
	return c
}

func clamp[T int | int64 | time.Duration](v, def, hi T) T {
	switch {
	case v <= 0:
		return def
	case v > hi:
		return hi
	}
	return v
}

// Truncation reasons.
const (
	ByRows  = "rows"
	ByBytes = "bytes"
)

// Result is what a query returned.
type Result struct {
	Columns     []string
	Rows        [][]any // JSON-shaped values: nil, bool, int64, float64, string, []any, map[string]any
	RowCount    int
	Truncated   bool
	TruncatedBy string // ByRows or ByBytes, when Truncated
	Ordered     bool   // the query has an ORDER BY of its own: row order is part of the answer
	Engine      string // for example "duckdb 2.0.1"
	SQL         string // the canonical query: what was checked and what ran
}

// Engine opens locked, read-only sessions over snapshot folders.
type Engine interface {
	Name() string
	// Open loads the snapshot folder into a session. The folder must already
	// have verified; Open does not hash it. Callers open a private copy of the
	// bytes that verified (OpenVerified), not the snapshot's own folder.
	Open(ctx context.Context, snapshotDir string, o Options) (Session, error)
}

// Session is safe for concurrent use. Query checks the dialect, runs the
// canonical text under the caps and honours ctx.
type Session interface {
	Query(ctx context.Context, sql string, c Caps) (*Result, error)
	Close() error
}
