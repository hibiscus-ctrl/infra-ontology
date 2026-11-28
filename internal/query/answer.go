// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package query

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// Request is one question: SQL text, or the name of a stored query and its
// parameters. Stored takes precedence over SQL if both are given.
type Request struct {
	SQL    string
	Stored string
	Params map[string]string
	Caps   Caps
}

// Output is a result and the citation that goes with it.
type Output struct {
	Result *Result
	Answer snapshot.Answer
}

// Run verifies the snapshot folder, opens a session over it, asks the
// question and closes the session. Verifying first means an answer never
// cites a snapshot whose files do not match its manifest.
func Run(ctx context.Context, eng Engine, dir string, o Options, req Request) (*Output, error) {
	loaded, err := snapshot.Load(dir)
	if err != nil {
		return nil, err
	}
	return RunLoaded(ctx, eng, loaded, o, req)
}

// RunLoaded is Run over a snapshot already loaded: a caller that checks more
// than the hashes (a signature) loads it, checks, and asks.
func RunLoaded(ctx context.Context, eng Engine, loaded *snapshot.Loaded, o Options, req Request) (*Output, error) {
	sess, err := OpenVerified(ctx, eng, loaded, o)
	if err != nil {
		return nil, err
	}
	defer func() { _ = sess.Close() }()
	return Ask(ctx, sess, loaded.Manifest, req)
}

// OpenVerified opens a session over exactly the bytes Load verified: they are
// written to a private folder, the engine reads that folder, and it is deleted
// before this returns (both session modes have copied the tables by then). The
// snapshot's own folder is not read again, so a file swapped in after the
// hashing is never served and the citation's manifest is the one served.
func OpenVerified(ctx context.Context, eng Engine, l *snapshot.Loaded, o Options) (Session, error) {
	dir, remove, err := l.Materialize()
	if err != nil {
		return nil, err
	}
	defer remove()
	return eng.Open(ctx, dir, o)
}

// Ask runs the question in an open session over the snapshot whose manifest is
// given, and cites it.
func Ask(ctx context.Context, sess Session, m snapshot.Manifest, req Request) (*Output, error) {
	text, stored, used := req.SQL, (*Stored)(nil), map[string]string(nil)
	if req.Stored != "" {
		s, err := StoredQuery(req.Stored)
		if err != nil {
			return nil, err
		}
		if text, used, err = s.Render(req.Params); err != nil {
			return nil, err
		}
		stored = &s
	} else if len(req.Params) > 0 {
		return nil, fmt.Errorf("parameters go with a stored query: the SQL text takes none")
	}
	if strings.TrimSpace(text) == "" {
		return nil, fmt.Errorf("no query: give SQL text or the name of a stored query")
	}
	caps := req.Caps.WithDefaults()
	res, err := sess.Query(ctx, text, caps)
	if err != nil {
		return nil, err
	}
	a, err := Cite(m, res, caps)
	if err != nil {
		return nil, err
	}
	if stored != nil {
		a.StoredQuery, a.StoredQueryVersion, a.StoredQueryHash, a.Parameters = stored.Name, stored.Version, stored.Hash, used
	}
	return &Output{Result: res, Answer: a}, nil
}

// Cite builds the citation for a result: the canonical query and its hash,
// the snapshot, the caps and what they cut, the hash of the result, and the
// limits the snapshot's manifest states.
func Cite(m snapshot.Manifest, res *Result, caps Caps) (snapshot.Answer, error) {
	caps = caps.WithDefaults()
	hash, err := ResultHash(res.Columns, res.Rows, res.Ordered)
	if err != nil {
		return snapshot.Answer{}, err
	}
	failed := m.Coverage.FailedSources
	if failed == nil {
		failed = []snapshot.FailedSource{}
	}
	a := snapshot.Answer{
		Query:      res.SQL,
		QueryHash:  HashQuery(res.SQL),
		SnapshotID: m.SnapshotID,
		Dialect:    Dialect,
		Engine:     res.Engine,
		Caps:       snapshot.AnswerCaps{MaxRows: caps.MaxRows, MaxColumns: caps.MaxCols, MaxBytes: caps.MaxBytes},
		RowCount:   res.RowCount,
		Truncated:  res.Truncated,
		Ordered:    res.Ordered,
		ResultHash: hash,
		Limits: snapshot.AnswerLimits{
			OldestSource:  m.SourcesSummary.OldestCollectedAt,
			FailedSources: len(failed),
			Status:        m.Status,
			Note:          m.Limits,
			Covered: &snapshot.AnswerCovered{
				Clouds: nonNil(m.Coverage.Clouds), Accounts: nonNil(m.Coverage.Accounts), TypesRead: len(m.Coverage.Types),
			},
		},
	}
	if len(failed) > 0 {
		a.Limits.Failed = failed
	}
	if res.Truncated {
		a.TruncatedBy = res.TruncatedBy
	}
	return a, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// Outcome is what re-running an answer found.
type Outcome struct {
	// Problems are what does not match: the answer is not reproduced.
	Problems []string `json:"problems"`
	// Notes are differences that do not make the answer wrong, such as a
	// newer engine.
	Notes []string `json:"notes,omitempty"`
}

// OK reports whether the answer was reproduced.
func (o Outcome) OK() bool { return len(o.Problems) == 0 }

// Reverify runs the cited query again in a session over the cited snapshot,
// under the caps the answer states (and the time limit given: how long an
// answer may take is not part of it), and compares what it finds with what the
// answer says: the snapshot, the query and its hash, the number of rows,
// whether they were cut, and the hash of the result. The cited query goes
// through the dialect check again, like any other text.
func Reverify(ctx context.Context, sess Session, m snapshot.Manifest, a snapshot.Answer, timeout time.Duration) (Outcome, error) {
	var out Outcome
	problem := func(format string, args ...any) { out.Problems = append(out.Problems, fmt.Sprintf(format, args...)) }
	if a.SnapshotID != m.SnapshotID {
		problem("the answer cites snapshot %s, not %s", a.SnapshotID, m.SnapshotID)
	}
	if a.Dialect != Dialect {
		problem("the answer is in dialect %q; this build reads %q", a.Dialect, Dialect)
	}
	if a.Query == "" {
		problem("the answer has no query")
	}
	if len(out.Problems) > 0 {
		return out, nil
	}
	caps := Caps{MaxRows: a.Caps.MaxRows, MaxCols: a.Caps.MaxColumns, MaxBytes: a.Caps.MaxBytes, Timeout: timeout}
	res, err := sess.Query(ctx, a.Query, caps)
	if err != nil {
		problem("the query does not run: %v", err)
		return out, nil
	}
	if got := HashQuery(a.Query); got != a.QueryHash {
		problem("query_hash is %s, the query hashes to %s", a.QueryHash, got)
	}
	got, err := Cite(m, res, caps)
	if err != nil {
		return out, err
	}
	if got.RowCount != a.RowCount {
		problem("the answer says %d rows, the query returns %d", a.RowCount, got.RowCount)
	}
	if got.Truncated != a.Truncated {
		problem("the answer says truncated is %t, the query says %t", a.Truncated, got.Truncated)
	}
	if got.Ordered != a.Ordered {
		problem("the answer says ordered is %t, the query says %t", a.Ordered, got.Ordered)
	}
	if got.ResultHash != a.ResultHash {
		msg := fmt.Sprintf("result_hash is %s, the query now gives %s", a.ResultHash, got.ResultHash)
		if a.Truncated && !a.Ordered {
			msg += " (the result was cut and the query has no ORDER BY, so which rows were kept is not fixed)"
		}
		problem("%s", msg)
	}
	if got.Engine != a.Engine {
		out.Notes = append(out.Notes, fmt.Sprintf("the answer was made with %s; this is %s", a.Engine, got.Engine))
	}
	return out, nil
}
