// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hibiscus-ctrl/infra-ontology/internal/query"
)

// Outcomes of a call, in the audit log.
const (
	OutcomeOK        = "ok"
	OutcomeRefused   = "refused"   // the dialect or a cap refused the query
	OutcomeInvalid   = "invalid"   // the arguments were wrong
	OutcomeTimeout   = "timeout"   // the time limit stopped it
	OutcomeCancelled = "cancelled" // the client cancelled it
	OutcomeError     = "error"
)

// AuditEntry is one line of the audit log: what was asked, of which snapshot,
// and how it ended. It never holds a result row, and it holds the arguments
// only as a hash, except that a refused or an invalid call also keeps the SQL
// it sent, bounded and on one line, so that it can be reviewed.
type AuditEntry struct {
	Time       string `json:"time"`
	Tool       string `json:"tool"`
	Client     string `json:"client,omitempty"`
	SnapshotID string `json:"snapshot_id"`
	ArgsHash   string `json:"args_hash"`
	QueryHash  string `json:"query_hash,omitempty"`
	// QueryText is the SQL of a query call that was refused or invalid, which
	// has no canonical query to hash: at most MaxAuditQueryBytes, on one
	// line, with control characters turned to spaces. It is what the agent
	// sent, so it can hold what the agent had read.
	QueryText          string `json:"query_text,omitempty"`
	QueryTextTruncated bool   `json:"query_text_truncated,omitempty"`
	StoredQuery        string `json:"stored_query,omitempty"`
	RowCount           int    `json:"row_count"`
	Truncated          bool   `json:"truncated"`
	Outcome            string `json:"outcome"`
	DurationMS         int64  `json:"duration_ms"`
}

// MaxAuditQueryBytes is the most bytes of a refused or invalid query kept in
// the audit log.
const MaxAuditQueryBytes = 1024

// auditText makes the text of a query fit on one line of the log: control
// characters and line separators become spaces, runs of white space become
// one, invalid UTF-8 is replaced, and the result is cut at MaxAuditQueryBytes
// on a character boundary. It reports whether it was cut.
func auditText(s string) (string, bool) {
	s = strings.ToValidUTF8(s, "\uFFFD")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= MaxAuditQueryBytes {
		return s, false
	}
	cut := MaxAuditQueryBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut], true
}

// auditor appends entries to a writer, one JSON line each. A call is written
// whole, under a lock, so lines from concurrent calls do not mix.
type auditor struct {
	mu sync.Mutex
	w  io.Writer
}

func (a *auditor) write(e AuditEntry) error {
	if a.w == nil {
		return nil
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_, err = a.w.Write(append(b, '\n'))
	return err
}

// ArgsHash is the SHA-256 of a call's arguments in a canonical JSON form.
func ArgsHash(args any) string {
	b, err := json.Marshal(args)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// invalidError is a call the arguments of which are wrong.
type invalidError struct{ msg string }

func (e invalidError) Error() string { return e.msg }

func invalid(format string, args ...any) error { return invalidError{fmt.Sprintf(format, args...)} }

func outcomeOf(err error) string {
	var inv invalidError
	switch {
	case err == nil:
		return OutcomeOK
	case errors.As(err, &inv):
		return OutcomeInvalid
	case errors.Is(err, query.ErrRejected):
		return OutcomeRefused
	case errors.Is(err, context.DeadlineExceeded):
		return OutcomeTimeout
	case errors.Is(err, context.Canceled):
		return OutcomeCancelled
	}
	return OutcomeError
}

// ran is what a tool's logic returns besides its result: the output of the
// query layer it used, if it ran one, for the audit log.
type ran = *query.Output

// handle wraps a tool's logic into an MCP handler that times the call and
// records it in the audit log. Whatever the logic returns, the call is
// recorded; and if the record cannot be written the result is withheld.
func handle[In, Out any](s *server, tool string, logic func(context.Context, In) (Out, ran, error)) mcp.ToolHandlerFor[In, Out] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, Out, error) {
		start := time.Now()
		out, q, err := logic(ctx, in)
		e := AuditEntry{
			Time: start.UTC().Format(time.RFC3339Nano), Tool: tool, SnapshotID: s.manifest.SnapshotID,
			ArgsHash: ArgsHash(in), Outcome: outcomeOf(err), DurationMS: time.Since(start).Milliseconds(),
		}
		if req != nil && req.Session != nil {
			if p := req.Session.InitializeParams(); p != nil && p.ClientInfo != nil {
				e.Client = p.ClientInfo.Name
			}
		}
		if qi, ok := any(in).(QueryIn); ok && qi.SQL != "" && (e.Outcome == OutcomeRefused || e.Outcome == OutcomeInvalid) {
			e.QueryText, e.QueryTextTruncated = auditText(qi.SQL)
		}
		if q != nil {
			e.QueryHash, e.RowCount, e.Truncated = q.Answer.QueryHash, q.Answer.RowCount, q.Answer.Truncated
			e.StoredQuery = q.Answer.StoredQuery
		}
		if werr := s.audit.write(e); werr != nil {
			var zero Out
			return nil, zero, fmt.Errorf("the call was not recorded in the audit log, so its result is withheld: %w", werr)
		}
		return nil, out, err
	}
}
