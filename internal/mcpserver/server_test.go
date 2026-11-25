// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !noduckdb

package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hibiscus-ctrl/infra-ontology/internal/query"
	"github.com/hibiscus-ctrl/infra-ontology/internal/signing"
	"github.com/hibiscus-ctrl/infra-ontology/internal/signing/signingtest"
)

var estate = filepath.Join("..", "snapshot", "testdata", "golden", "estate")

const (
	estateID = "56eda5cee85096e7c09c20074c7f7f315519b1f66ab23ab06c0695167a88afbc"
	// The prod VPC of the fixture: the subnet, the instance and a module
	// call depend on it.
	prodVPC    = "561eee651d9be57a4c2ecc6e3f0c4fbe1839cfe9ed35c2ccb56d8904ea127749"
	prodSubnet = "6ac4f2c2942b8b2b0a18edc397b70428599be08d7f42b300cf969a69496f6068"
	prodApp    = "5ab51bb328bab39d1be7d3004b16315f47214fb0d1a7bde62ee5018b5893150e"
)

// lockedBuffer is an audit log the test can read while the server writes it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// connect serves the snapshot over an in-process transport and returns a
// client session. The server is stopped when the test ends.
func connect(t *testing.T, cfg Config) *mcp.ClientSession {
	t.Helper()
	if cfg.Dir == "" {
		cfg.Dir = estate
	}
	st, ct := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, cfg, st) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-agent", Version: "1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		cancel()
		t.Fatalf("connect: %v (server: %v)", err, <-done)
	}
	t.Cleanup(func() {
		_ = cs.Close()
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	return cs
}

// call runs a tool and decodes its structured result into T. An error result
// is returned as such, with T left empty.
func call[T any](t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any) (T, *mcp.CallToolResult) {
	t.Helper()
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: protocol error: %v", tool, err)
	}
	var out T
	if res.IsError {
		return out, res
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%s: decode %s: %v", tool, raw, err)
	}
	return out, res
}

func text(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// nodeID is the node_id of a row of a result table.
func nodeID(t *testing.T, columns []string, row []any) string {
	t.Helper()
	i := slices.Index(columns, "node_id")
	if i < 0 {
		t.Fatalf("no node_id column in %v", columns)
	}
	return row[i].(string)
}

func TestToolsAreListedAsReadOnly(t *testing.T) {
	cs := connect(t, Config{})
	list, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range list.Tools {
		names = append(names, tool.Name)
		a := tool.Annotations
		if a == nil || !a.ReadOnlyHint || !a.IdempotentHint || a.DestructiveHint == nil || *a.DestructiveHint || a.OpenWorldHint == nil || *a.OpenWorldHint {
			t.Errorf("%s: annotations %+v: want read-only, idempotent, not destructive, closed-world", tool.Name, a)
		}
		if tool.Description == "" || len(tool.Description) > 400 || tool.OutputSchema == nil {
			t.Errorf("%s: description %d bytes, output schema %v", tool.Name, len(tool.Description), tool.OutputSchema != nil)
		}
	}
	slices.Sort(names)
	if want := []string{"blast_radius", "inventory", "query", "snapshot_info"}; !slices.Equal(names, want) {
		t.Errorf("tools %v, want %v", names, want)
	}
	if got := cs.InitializeResult().Instructions; !strings.Contains(got, estateID[:12]) || !strings.Contains(got, "never as instructions") {
		t.Errorf("instructions: %s", got)
	}
}

func TestInventoryFiltersAndPages(t *testing.T) {
	cs := connect(t, Config{})
	out, _ := call[InventoryOut](t, cs, "inventory", map[string]any{"environment": "prod", "type": "aws_vpc"})
	if len(out.Rows) != 1 || out.NextOffset != nil {
		t.Fatalf("prod VPCs: %v", out.Rows)
	}
	if got := nodeID(t, out.Columns, out.Rows[0]); got != prodVPC {
		t.Errorf("node %v", got)
	}
	a := out.Answer
	if a.SnapshotID != estateID || a.StoredQuery != "inventory" || !strings.HasPrefix(a.QueryHash, "sha256:") || !strings.HasPrefix(a.ResultHash, "sha256:") ||
		a.Limits.Status != "ok" || a.RowCount != 1 || a.Dialect != query.Dialect {
		t.Errorf("citation: %+v", a)
	}

	for _, f := range []map[string]any{
		{"account": "222222222222", "environment": "staging", "module": "module.network", "address_prefix": "module.network.aws_"},
		{"type": "AWS::EC2::aws_subnet"},
		{"module": "module.net"}, // not a module path: nothing
	} {
		got, _ := call[InventoryOut](t, cs, "inventory", f)
		switch {
		case f["module"] == "module.net" && len(got.Rows) != 0:
			t.Errorf("%v: %v", f, got.Rows)
		case f["module"] != "module.net" && len(got.Rows) == 0:
			t.Errorf("%v: no rows", f)
		}
	}

	// Paging: one row a page, until no next_offset.
	var seen []string
	offset := 0
	for range 40 {
		page, _ := call[InventoryOut](t, cs, "inventory", map[string]any{"limit": 1, "offset": offset})
		if len(page.Rows) != 1 || page.Offset != offset {
			t.Fatalf("page at %d: %v", offset, page)
		}
		seen = append(seen, nodeID(t, page.Columns, page.Rows[0]))
		if page.NextOffset == nil {
			break
		}
		if !page.Answer.Truncated || page.Answer.TruncatedBy != "rows" {
			t.Errorf("a page with more behind it says %+v", page.Answer)
		}
		offset = *page.NextOffset
	}
	all, _ := call[InventoryOut](t, cs, "inventory", nil)
	if len(seen) != len(all.Rows) || len(seen) < 10 || all.NextOffset != nil {
		t.Fatalf("paged %d nodes, one page of all has %d", len(seen), len(all.Rows))
	}
	for i, r := range all.Rows {
		if nodeID(t, all.Columns, r) != seen[i] {
			t.Fatalf("row %d: paging and the whole list disagree", i)
		}
	}

	for _, bad := range []map[string]any{{"limit": 1001}, {"limit": -1}, {"offset": -3}} {
		if _, res := call[InventoryOut](t, cs, "inventory", bad); !res.IsError {
			t.Errorf("%v was accepted", bad)
		}
	}
}

func TestBlastRadius(t *testing.T) {
	cs := connect(t, Config{})
	out, _ := call[BlastOut](t, cs, "blast_radius", map[string]any{"target": prodVPC})
	if out.Status != "resolved" || len(out.Targets) != 1 || out.MaxDepth != 5 {
		t.Fatalf("%+v", out)
	}
	var ids []string
	for _, r := range out.Dependents {
		ids = append(ids, nodeID(t, out.Columns, r))
	}
	if !slices.Contains(ids, prodSubnet) || !slices.Contains(ids, prodApp) {
		t.Errorf("dependents of the prod VPC: %v", ids)
	}
	if slices.Contains(ids, prodVPC) || out.DepthReached < 1 {
		t.Errorf("the target is not its own dependent: %v, depth %d", ids, out.DepthReached)
	}
	if out.CountsByType["aws_subnet"] != 1 || out.CountsByAccount["111111111111"] == 0 {
		t.Errorf("counts %v %v", out.CountsByType, out.CountsByAccount)
	}
	if a := out.Answer; a.StoredQuery != "blast" || a.Parameters["node"] != prodVPC || a.Parameters["depth"] != "5" || a.SnapshotID != estateID {
		t.Errorf("citation %+v", a)
	}

	// A target by address that two nodes share is not guessed.
	amb, _ := call[BlastOut](t, cs, "blast_radius", map[string]any{"target": "module.network.aws_vpc.main"})
	if amb.Status != "ambiguous" || len(amb.Targets) != 2 || len(amb.Dependents) != 0 {
		t.Errorf("ambiguous: %+v", amb)
	}
	none, _ := call[BlastOut](t, cs, "blast_radius", map[string]any{"target": "aws_nothing.here"})
	if none.Status != "not_found" || len(none.Targets) != 0 {
		t.Errorf("not found: %+v", none)
	}
	one, _ := call[BlastOut](t, cs, "blast_radius", map[string]any{"target": prodVPC, "max_depth": 3, "limit": 1})
	if len(one.Dependents) != 1 || !one.Answer.Truncated || one.MaxDepth != 3 {
		t.Errorf("one dependent: %+v", one)
	}

	for _, bad := range []map[string]any{{"target": ""}, {"target": prodVPC, "max_depth": 11}, {"target": prodVPC, "max_depth": -1}, {"target": prodVPC, "limit": 5000}} {
		if _, res := call[BlastOut](t, cs, "blast_radius", bad); !res.IsError {
			t.Errorf("%v was accepted", bad)
		}
	}
}

func TestQueryTool(t *testing.T) {
	cs := connect(t, Config{})
	out, _ := call[QueryOut](t, cs, "query", map[string]any{"sql": "SELECT kind, count(*) AS n FROM nodes GROUP BY kind ORDER BY kind"})
	if len(out.Rows) == 0 || out.Columns[0] != "kind" || out.Answer.SnapshotID != estateID || !out.Answer.Ordered || out.Answer.Engine == "" {
		t.Errorf("%+v", out)
	}
	st, _ := call[QueryOut](t, cs, "query", map[string]any{"stored": "summary"})
	if len(st.Rows) == 0 || st.Answer.StoredQuery != "summary" {
		t.Errorf("stored: %+v", st)
	}
	cut, _ := call[QueryOut](t, cs, "query", map[string]any{"sql": "SELECT * FROM nodes", "limit": 2})
	if len(cut.Rows) != 2 || !cut.Answer.Truncated {
		t.Errorf("cut: %+v", cut.Answer)
	}
}

func TestQueryToolRefusesWhatTheDialectRefuses(t *testing.T) {
	audit := &lockedBuffer{}
	cs := connect(t, Config{Audit: audit})
	refused := []string{
		"SELECT * FROM read_csv('/etc/passwd')", "DROP TABLE nodes", "SELECT 1; SELECT 2", "SET threads = 1",
		"ATTACH '/tmp/x.db' AS x", "COPY nodes TO '/tmp/out.csv'", "INSTALL httpfs", "SELECT getenv('HOME')",
		"SELECT * FROM information_schema.tables", "PRAGMA database_list", "CREATE TABLE t AS SELECT 1",
	}
	for _, sql := range refused {
		_, res := call[QueryOut](t, cs, "query", map[string]any{"sql": sql})
		if !res.IsError || !strings.Contains(text(res), "rejected by the read-only dialect") {
			t.Errorf("%s: error %v, %q", sql, res.IsError, text(res))
		}
	}
	for _, args := range []map[string]any{
		{}, {"sql": "SELECT 1", "stored": "summary"}, {"sql": "SELECT 1", "params": map[string]any{"a": "b"}},
		{"stored": "nothing"}, {"stored": "blast"}, {"sql": "SELECT 1", "limit": 99999},
	} {
		if _, res := call[QueryOut](t, cs, "query", args); !res.IsError {
			t.Errorf("%v was accepted", args)
		}
	}
	// After all that the session still answers, and still has its tables.
	out, _ := call[QueryOut](t, cs, "query", map[string]any{"sql": "SELECT count(*) AS n FROM nodes"})
	if len(out.Rows) != 1 {
		t.Errorf("after the refusals: %+v", out)
	}
	entries := readAudit(t, audit)
	refusals := 0
	for _, e := range entries {
		if e.Outcome == OutcomeRefused {
			refusals++
			if e.QueryHash != "" || e.RowCount != 0 {
				t.Errorf("a refused query ran: %+v", e)
			}
		}
	}
	if refusals != len(refused) {
		t.Errorf("%d refusals in the audit log, want %d", refusals, len(refused))
	}
}

func TestSnapshotInfo(t *testing.T) {
	cs := connect(t, Config{Tools: []string{ToolSnapshot, ToolQuery}})
	out, _ := call[InfoOut](t, cs, "snapshot_info", nil)
	if out.SnapshotID != estateID || out.Status != "ok" || out.Tables["nodes"] == 0 || out.Dialect != query.Dialect {
		t.Errorf("%+v", out)
	}
	if len(out.Coverage.Accounts) != 2 || out.Limits == "" || out.Sources.OldestCollectedAt != "2026-11-25T09:05:00Z" || out.Answer.SnapshotID != estateID {
		t.Errorf("coverage, limits or citation: %+v", out)
	}
	var names []string
	for _, s := range out.StoredQueries {
		names = append(names, s.Name)
	}
	for _, want := range []string{"blast", "inventory", "summary"} {
		if !slices.Contains(names, want) {
			t.Errorf("stored queries %v lack %s", names, want)
		}
	}
	if !slices.Equal(out.Tools, []string{ToolQuery, ToolSnapshot}) {
		t.Errorf("tools %v", out.Tools)
	}
}

func TestToolsFlagLimitsTheServer(t *testing.T) {
	cs := connect(t, Config{Tools: []string{ToolBlastRadius, ToolInventory}})
	list, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range list.Tools {
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"blast_radius", "inventory"}) {
		t.Errorf("tools %v", names)
	}
	// A tool that is not enabled does not exist for the client.
	if res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "query", Arguments: map[string]any{"sql": "SELECT 1"}}); err == nil && !res.IsError {
		t.Errorf("a disabled tool ran: %+v", res)
	}
	if got := cs.InitializeResult().Instructions; !strings.Contains(got, "Tools: inventory, blast_radius.") {
		t.Errorf("instructions do not list the tools that are on: %s", got)
	}
}

func TestParseTools(t *testing.T) {
	got, err := ParseTools("query, inventory,query")
	if err != nil || !slices.Equal(got, []string{"inventory", "query"}) {
		t.Errorf("%v, %v", got, err)
	}
	if all, err := ParseTools(""); err != nil || !slices.Equal(all, ToolNames) {
		t.Errorf("default: %v, %v", all, err)
	}
	for _, bad := range []string{"inventory,delete", "Query", ","} {
		if _, err := ParseTools(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	if _, err := newServer(t.Context(), Config{Dir: estate, Tools: []string{"nope"}}); err == nil {
		t.Error("an unknown tool was accepted by the server")
	}
}

func readAudit(t *testing.T, log *lockedBuffer) []AuditEntry {
	t.Helper()
	var out []AuditEntry
	for _, line := range strings.Split(strings.TrimSpace(log.String()), "\n") {
		if line == "" {
			continue
		}
		var e AuditEntry
		dec := json.NewDecoder(strings.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil {
			t.Fatalf("audit line %q: %v", line, err)
		}
		out = append(out, e)
	}
	return out
}

func TestAuditLogHoldsHashesNotRows(t *testing.T) {
	audit := &lockedBuffer{}
	cs := connect(t, Config{Audit: audit})
	sql := "SELECT name, arn_or_path, account FROM nodes WHERE address = 'module.network.aws_vpc.main' ORDER BY node_id"
	q, _ := call[QueryOut](t, cs, "query", map[string]any{"sql": sql})
	call[InventoryOut](t, cs, "inventory", map[string]any{"limit": 3})
	call[BlastOut](t, cs, "blast_radius", map[string]any{"target": prodVPC})
	call[InfoOut](t, cs, "snapshot_info", nil)
	call[QueryOut](t, cs, "query", map[string]any{"sql": "DROP TABLE nodes"})

	entries := readAudit(t, audit)
	if len(entries) != 5 {
		t.Fatalf("%d entries:\n%s", len(entries), audit.String())
	}
	var tools []string
	for _, e := range entries {
		tools = append(tools, e.Tool)
		if e.SnapshotID != estateID || e.Client != "test-agent" || !strings.HasPrefix(e.ArgsHash, "sha256:") || e.Time == "" || e.DurationMS < 0 {
			t.Errorf("entry %+v", e)
		}
	}
	if !slices.Equal(tools, []string{"query", "inventory", "blast_radius", "snapshot_info", "query"}) {
		t.Errorf("tools %v", tools)
	}
	first := entries[0]
	if first.Outcome != OutcomeOK || first.QueryHash != q.Answer.QueryHash || first.RowCount != len(q.Rows) || first.RowCount == 0 || first.Truncated {
		t.Errorf("first entry %+v, answer %+v", first, q.Answer)
	}
	if first.ArgsHash != ArgsHash(QueryIn{SQL: sql}) {
		t.Errorf("args hash %s", first.ArgsHash)
	}
	if entries[1].StoredQuery != "inventory" || entries[1].RowCount != 3 || !entries[1].Truncated {
		t.Errorf("inventory entry %+v", entries[1])
	}
	if entries[4].Outcome != OutcomeRefused || entries[4].QueryHash != "" {
		t.Errorf("refused entry %+v", entries[4])
	}

	// No result row, no node id, no name, no query text and no argument
	// value is in the log.
	log := audit.String()
	for _, secret := range []string{"prod-vpc-0a1b", "arn:aws", "111111111111", prodVPC, prodSubnet, "module.network", "SELECT", "DROP"} {
		if strings.Contains(log, secret) {
			t.Errorf("the audit log holds %q:\n%s", secret, log)
		}
	}
	for _, row := range q.Rows {
		for _, v := range row {
			if s, ok := v.(string); ok && s != "" && strings.Contains(log, s) {
				t.Errorf("the audit log holds the row value %q", s)
			}
		}
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestAnAnswerIsWithheldWhenItCannotBeRecorded(t *testing.T) {
	cs := connect(t, Config{Audit: failingWriter{}})
	out, res := call[QueryOut](t, cs, "query", map[string]any{"sql": "SELECT * FROM nodes"})
	if !res.IsError || !strings.Contains(text(res), "audit log") || len(out.Rows) != 0 {
		t.Errorf("error %v: %q", res.IsError, text(res))
	}
	if strings.Contains(text(res), "node_id") {
		t.Errorf("rows went out unrecorded: %q", text(res))
	}
}

func copyEstate(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	entries, err := os.ReadDir(estate)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(estate, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

func TestRefusesToServeASnapshotThatDoesNotVerify(t *testing.T) {
	for name, damage := range map[string]func(dir string) error{
		"a table changed": func(dir string) error {
			f, err := os.OpenFile(filepath.Join(dir, "nodes.parquet"), os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }()
			_, err = f.Write([]byte{0})
			return err
		},
		"a table missing": func(dir string) error { return os.Remove(filepath.Join(dir, "edges.parquet")) },
		"no manifest":     func(dir string) error { return os.Remove(filepath.Join(dir, "manifest.json")) },
		"a manifest edited": func(dir string) error {
			p := filepath.Join(dir, "manifest.json")
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return os.WriteFile(p, bytes.Replace(b, []byte("A fixture"), []byte("Not a fixture"), 1), 0o600)
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := copyEstate(t)
			if err := damage(dir); err != nil {
				t.Fatal(err)
			}
			audit := &lockedBuffer{}
			st, _ := mcp.NewInMemoryTransports()
			err := Serve(t.Context(), Config{Dir: dir, Audit: audit}, st)
			if !errors.Is(err, ErrNotVerified) {
				t.Errorf("served: %v", err)
			}
			if audit.String() != "" {
				t.Errorf("the audit log has %q", audit.String())
			}
		})
	}
	if err := Serve(t.Context(), Config{Dir: filepath.Join(t.TempDir(), "nothing")}, nil); !errors.Is(err, ErrNotVerified) {
		t.Errorf("a folder that does not exist: %v", err)
	}
}

// modeSpy records how the server opens its session.
type modeSpy struct {
	query.Engine
	mu    sync.Mutex
	modes []string
}

func (s *modeSpy) Open(ctx context.Context, dir string, o query.Options) (query.Session, error) {
	s.mu.Lock()
	s.modes = append(s.modes, o.Mode)
	s.mu.Unlock()
	return s.Engine.Open(ctx, dir, o)
}

func TestOneLockedReadOnlyAttachedSession(t *testing.T) {
	spy := &modeSpy{Engine: query.New()}
	dir := copyEstate(t)
	before := snapshotBytes(t, dir)
	cs := connect(t, Config{Dir: dir, Engine: spy})
	for range 3 {
		call[QueryOut](t, cs, "query", map[string]any{"sql": "SELECT count(*) AS n FROM nodes"})
	}
	if !slices.Equal(spy.modes, []string{query.ModeROAttach}) {
		t.Errorf("sessions opened: %v", spy.modes)
	}
	if after := snapshotBytes(t, dir); before != after {
		t.Error("the snapshot folder changed while it was served")
	}
}

func snapshotBytes(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		b.WriteString(e.Name())
		b.Write(raw)
	}
	return b.String()
}

func TestConcurrentCallsAreAnsweredAndAudited(t *testing.T) {
	audit := &lockedBuffer{}
	cs := connect(t, Config{Audit: audit})
	var wg sync.WaitGroup
	for i := range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch i % 3 {
			case 0:
				call[InventoryOut](t, cs, "inventory", map[string]any{"limit": 5})
			case 1:
				call[BlastOut](t, cs, "blast_radius", map[string]any{"target": prodVPC})
			default:
				call[QueryOut](t, cs, "query", map[string]any{"stored": "summary"})
			}
		}()
	}
	wg.Wait()
	if n := len(readAudit(t, audit)); n != 24 {
		t.Errorf("%d audit lines, want 24", n)
	}
}

func signedEstate(t *testing.T) (dir string, keys signingtest.Keys) {
	t.Helper()
	dir, keys = copyEstate(t), signingtest.NewKeys(t, "p256")
	if err := signing.SignWithKey(dir, keys.Private, nil, false); err != nil {
		t.Fatal(err)
	}
	return dir, keys
}

func TestSnapshotInfoReportsTheSignature(t *testing.T) {
	status := func(cfg Config) signing.Status {
		t.Helper()
		out, _ := call[InfoOut](t, connect(t, cfg), "snapshot_info", nil)
		return out.Signature
	}
	if st := status(Config{Dir: copyEstate(t)}); st.State != signing.Unsigned {
		t.Errorf("an unsigned snapshot: %+v", st)
	}
	dir, keys := signedEstate(t)
	if st := status(Config{Dir: dir}); st.State != signing.SignedUnverified || st.Mode != signing.ModeKey || st.Signer != "" {
		t.Errorf("signed, no verifier: %+v", st)
	}
	st := status(Config{Dir: dir, Signature: signing.Verifier{KeyFile: keys.Public}, RequireSignature: true})
	if st.State != signing.Verified || !strings.HasPrefix(st.Signer, "sha256:") {
		t.Errorf("signed, with the key: %+v", st)
	}
	// A verifier and an unsigned snapshot: reported as unsigned, and served.
	if st := status(Config{Dir: copyEstate(t), Signature: signing.Verifier{KeyFile: keys.Public}}); st.State != signing.Unsigned {
		t.Errorf("unsigned, with a key: %+v", st)
	}
}

func TestTheInstructionsSayHowTheSnapshotIsSigned(t *testing.T) {
	dir, keys := signedEstate(t)
	cs := connect(t, Config{Dir: dir, Signature: signing.Verifier{KeyFile: keys.Public}})
	if got := cs.InitializeResult().Instructions; !strings.Contains(got, "signature: verified (key: sha256:") {
		t.Errorf("instructions: %s", got)
	}
}

func TestRefusesToServeABadOrMissingSignature(t *testing.T) {
	dir, keys := signedEstate(t)
	other := signingtest.NewKeys(t, "p256")
	garbage := copyEstate(t)
	if err := os.WriteFile(filepath.Join(garbage, signing.File), []byte("not a bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, cfg := range map[string]Config{
		"another key":                 {Dir: dir, Signature: signing.Verifier{KeyFile: other.Public}},
		"a file that is no bundle":    {Dir: garbage},
		"unsigned, required":          {Dir: copyEstate(t), Signature: signing.Verifier{KeyFile: keys.Public}, RequireSignature: true},
		"signed, required, unchecked": {Dir: dir, RequireSignature: true},
	} {
		t.Run(name, func(t *testing.T) {
			audit := &lockedBuffer{}
			cfg.Audit = audit
			st, _ := mcp.NewInMemoryTransports()
			err := Serve(t.Context(), cfg, st)
			if err == nil {
				t.Fatal("served")
			}
			if name != "signed, required, unchecked" && !errors.Is(err, ErrNotVerified) {
				t.Errorf("not ErrNotVerified: %v", err)
			}
			if audit.String() != "" {
				t.Errorf("the audit log has %q", audit.String())
			}
		})
	}
}
