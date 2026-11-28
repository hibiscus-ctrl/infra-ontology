// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"context"
	"slices"
	"strconv"
	"time"

	"github.com/hibiscus-ctrl/infra-ontology/internal/query"
	"github.com/hibiscus-ctrl/infra-ontology/internal/signing"
	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// Row limits of the tools. They are lower than the command line's, because an
// agent reads every row in its context.
const (
	defaultInventoryRows = 100
	defaultQueryRows     = 100
	defaultBlastRows     = 200
	maxRows              = 1000
	defaultBlastDepth    = 5
	maxBlastDepth        = 10
)

// caps are the query caps of a call that may return limit rows.
func (s *server) caps(limit int) query.Caps {
	return query.Caps{MaxRows: limit, MaxBytes: s.cfg.MaxBytes, Timeout: s.cfg.Timeout}
}

// rows checks a row limit: zero is the default, and a limit outside 1 to
// maxRows is refused rather than silently changed.
func rows(name string, limit, def int) (int, error) {
	switch {
	case limit == 0:
		return def, nil
	case limit < 0 || limit > maxRows:
		return 0, invalid("%s is %d: use 1 to %d", name, limit, maxRows)
	}
	return limit, nil
}

// ask runs one question over the session.
func (s *server) ask(ctx context.Context, req query.Request) (*query.Output, error) {
	return query.Ask(ctx, s.sess, s.manifest, req)
}

// InventoryIn are the arguments of inventory.
type InventoryIn struct {
	Type          string `json:"type,omitempty" jsonschema:"only this Terraform type (aws_s3_bucket) or inventory type (AWS::S3::Bucket)"`
	Account       string `json:"account,omitempty" jsonschema:"only this account, subscription or project"`
	Environment   string `json:"environment,omitempty" jsonschema:"only this environment, such as prod"`
	Module        string `json:"module,omitempty" jsonschema:"only this module path (module.network) and the modules inside it"`
	AddressPrefix string `json:"address_prefix,omitempty" jsonschema:"only Terraform addresses that start with this text"`
	Limit         int    `json:"limit,omitempty" jsonschema:"rows per page, 1 to 1000; default 100"`
	Offset        int    `json:"offset,omitempty" jsonschema:"rows to skip: the next_offset of the previous page"`
}

// InventoryOut is a page of nodes. Columns and Rows are a table: each row is
// a list of the values of the columns, in order.
type InventoryOut struct {
	Columns []string `json:"columns"`
	Rows    [][]any  `json:"rows"`
	Offset  int      `json:"offset"`
	// NextOffset is set when more rows follow: call again with it as offset.
	NextOffset *int            `json:"next_offset,omitempty"`
	Answer     snapshot.Answer `json:"answer"`
}

func (s *server) inventory(ctx context.Context, in InventoryIn) (InventoryOut, ran, error) {
	limit, err := rows("limit", in.Limit, defaultInventoryRows)
	if err != nil {
		return InventoryOut{}, nil, err
	}
	if in.Offset < 0 {
		return InventoryOut{}, nil, invalid("offset is %d: use 0 or more", in.Offset)
	}
	out, err := s.ask(ctx, query.Request{
		Stored: "inventory", Caps: s.caps(limit),
		Params: map[string]string{
			"type": in.Type, "account": in.Account, "environment": in.Environment, "module": in.Module,
			"address_prefix": in.AddressPrefix, "offset": strconv.Itoa(in.Offset),
		},
	})
	if err != nil {
		return InventoryOut{}, nil, err
	}
	res := InventoryOut{Columns: out.Result.Columns, Rows: out.Result.Rows, Offset: in.Offset, Answer: out.Answer}
	if out.Result.Truncated {
		res.NextOffset = ptr(in.Offset + out.Result.RowCount)
	}
	return res, out, nil
}

// BlastIn are the arguments of blast_radius.
type BlastIn struct {
	Target   string `json:"target" jsonschema:"a node id, Terraform address, ARN or path, or cloud id"`
	MaxDepth int    `json:"max_depth,omitempty" jsonschema:"hops to follow, 1 to 10; default 5"`
	Limit    int    `json:"limit,omitempty" jsonschema:"most dependents to return, 1 to 1000; default 200"`
	// IncludeAccess also follows can_assume, can_read and can_write edges.
	IncludeAccess bool `json:"include_access,omitempty" jsonschema:"also follow access edges (can_assume, can_read, can_write): who may reach the target, not what breaks; default false"`
}

// BlastOut is what depends on a target, by dependency edges unless
// IncludeAccess is set. Each row says which kind of edge reached it
// (edge_kind) and the weakest confidence along the path (confidence). Status says how the target resolved:
// "resolved" (one node), "ambiguous" (several: Targets lists them, and no
// dependents are listed) or "not_found".
type BlastOut struct {
	Status   string `json:"status"`
	Target   string `json:"target"`
	MaxDepth int    `json:"max_depth"`
	// IncludeAccess says whether access edges were followed.
	IncludeAccess bool `json:"include_access"`
	// Columns are those of Targets and Dependents; the first is depth.
	Columns    []string `json:"columns"`
	Targets    [][]any  `json:"targets"`
	Dependents [][]any  `json:"dependents"`
	// DepthReached is the greatest depth among the dependents returned.
	DepthReached int `json:"depth_reached"`
	// The counts cover the dependents returned: if answer.truncated is true
	// there are more than they say.
	CountsByType    map[string]int  `json:"counts_by_type"`
	CountsByAccount map[string]int  `json:"counts_by_account"`
	Answer          snapshot.Answer `json:"answer"`
}

func (s *server) blastRadius(ctx context.Context, in BlastIn) (BlastOut, ran, error) {
	if in.Target == "" {
		return BlastOut{}, nil, invalid("target is empty: give a node id, a Terraform address, an ARN or a cloud id")
	}
	depth := in.MaxDepth
	switch {
	case depth == 0:
		depth = defaultBlastDepth
	case depth < 0 || depth > maxBlastDepth:
		return BlastOut{}, nil, invalid("max_depth is %d: use 1 to %d", in.MaxDepth, maxBlastDepth)
	}
	limit, err := rows("limit", in.Limit, defaultBlastRows)
	if err != nil {
		return BlastOut{}, nil, err
	}
	// The cap is the dependents asked for and the target's own row, so that
	// a target matching several nodes shows at least two rows at depth 0.
	access := "0"
	if in.IncludeAccess {
		access = "1"
	}
	out, err := s.ask(ctx, query.Request{
		Stored: "blast", Params: map[string]string{"node": in.Target, "depth": strconv.Itoa(depth), "include_access": access},
		Caps: s.caps(limit + 1),
	})
	if err != nil {
		return BlastOut{}, nil, err
	}
	res := BlastOut{
		Target: in.Target, MaxDepth: depth, IncludeAccess: in.IncludeAccess, Columns: out.Result.Columns, Answer: out.Answer,
		Targets: [][]any{}, Dependents: [][]any{}, CountsByType: map[string]int{}, CountsByAccount: map[string]int{},
	}
	col := func(name string) int { return slices.Index(out.Result.Columns, name) }
	iDepth, iType, iKind, iAccount := col("depth"), col("tf_type"), col("kind"), col("account")
	for _, r := range out.Result.Rows {
		d, _ := r[iDepth].(int64)
		if d == 0 {
			res.Targets = append(res.Targets, r)
			continue
		}
		res.Dependents = append(res.Dependents, r)
		res.DepthReached = max(res.DepthReached, int(d))
		typ, _ := r[iType].(string)
		if typ == "" {
			typ, _ = r[iKind].(string)
		}
		acct, _ := r[iAccount].(string)
		res.CountsByType[typ]++
		res.CountsByAccount[acct]++
	}
	switch {
	case len(res.Targets) == 0:
		res.Status = "not_found"
	case len(res.Targets) > 1:
		// Never pick one silently: the caller names the node by id.
		res.Status = "ambiguous"
		res.Dependents, res.DepthReached = [][]any{}, 0
		res.CountsByType, res.CountsByAccount = map[string]int{}, map[string]int{}
	default:
		res.Status = "resolved"
	}
	return res, out, nil
}

// QueryIn are the arguments of query: SQL text, or the name of a stored
// query and its parameters.
type QueryIn struct {
	SQL    string            `json:"sql,omitempty" jsonschema:"one SELECT or WITH ... SELECT over nodes, edges, sources and snapshot"`
	Stored string            `json:"stored,omitempty" jsonschema:"the name of a stored query to run instead of sql (see snapshot_info)"`
	Params map[string]string `json:"params,omitempty" jsonschema:"the stored query's parameters, by name"`
	Limit  int               `json:"limit,omitempty" jsonschema:"most rows to return, 1 to 1000; default 100"`
}

// QueryOut is a result table and its citation.
type QueryOut struct {
	Columns []string        `json:"columns"`
	Rows    [][]any         `json:"rows"`
	Answer  snapshot.Answer `json:"answer"`
}

func (s *server) query(ctx context.Context, in QueryIn) (QueryOut, ran, error) {
	switch {
	case (in.SQL == "") == (in.Stored == ""):
		return QueryOut{}, nil, invalid("give sql or stored, one of them")
	case in.SQL != "" && len(in.Params) > 0:
		return QueryOut{}, nil, invalid("params go with a stored query: the sql text takes none")
	}
	limit, err := rows("limit", in.Limit, defaultQueryRows)
	if err != nil {
		return QueryOut{}, nil, err
	}
	out, err := s.ask(ctx, query.Request{SQL: in.SQL, Stored: in.Stored, Params: in.Params, Caps: s.caps(limit)})
	if err != nil {
		return QueryOut{}, nil, err
	}
	return QueryOut{Columns: out.Result.Columns, Rows: out.Result.Rows, Answer: out.Answer}, out, nil
}

// InfoIn has no arguments.
type InfoIn struct{}

// InfoOut describes the snapshot being served.
type InfoOut struct {
	SnapshotID string `json:"snapshot_id"`
	Label      string `json:"label,omitempty"`
	ParentID   string `json:"parent_id,omitempty"`
	CreatedAt  string `json:"created_at"`
	Status     string `json:"status"`
	Tool       string `json:"tool"`
	// Signature is the snapshot's signature: unsigned, signed_unverified
	// (there is a Sigstore bundle and the server was given nothing to check it
	// with) or verified (it checked against the key or identity the server was
	// started with, which Signer names). A signature that does not check, or is
	// no bundle, stops the server, so it is never reported here.
	Signature signing.Status `json:"signature"`
	// Tables are the tables a query may read, with their row counts.
	Tables    map[string]int          `json:"tables"`
	Sources   snapshot.SourcesSummary `json:"sources"`
	Coverage  snapshot.Coverage       `json:"coverage"`
	Redaction snapshot.Redaction      `json:"redaction"`
	// Limits is the snapshot's own statement of what it cannot tell you.
	Limits        string       `json:"limits"`
	Dialect       string       `json:"dialect"`
	Caps          InfoCaps     `json:"caps"`
	Tools         []string     `json:"tools"`
	StoredQueries []InfoStored `json:"stored_queries"`
	// Answer cites the query that read the snapshot's own row.
	Answer snapshot.Answer `json:"answer"`
}

// InfoCaps are the caps of the tools.
type InfoCaps struct {
	DefaultRows    int   `json:"default_rows"`
	MaxRows        int   `json:"max_rows"`
	MaxBytes       int64 `json:"max_bytes"`
	TimeoutSeconds int   `json:"timeout_seconds"`
}

// InfoStored is a stored query the query tool can run.
type InfoStored struct {
	Name        string      `json:"name"`
	Version     int         `json:"version"`
	Description string      `json:"description"`
	Params      []InfoParam `json:"params"`
}

// InfoParam is a parameter of a stored query.
type InfoParam struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Required    bool   `json:"required,omitempty"`
	Default     string `json:"default,omitempty"`
	Description string `json:"description"`
}

func (s *server) info(ctx context.Context, _ InfoIn) (InfoOut, ran, error) {
	// Reading the snapshot's own row through the query layer is what gives
	// the answer its citation.
	out, err := s.ask(ctx, query.Request{
		SQL:  "SELECT snapshot_id, label, parent_id, created_at, status, oldest_source, newest_source FROM snapshot",
		Caps: s.caps(1),
	})
	if err != nil {
		return InfoOut{}, nil, err
	}
	m := s.manifest
	stored, err := query.StoredQueries()
	if err != nil {
		return InfoOut{}, nil, err
	}
	res := InfoOut{
		SnapshotID: m.SnapshotID, Label: m.Label, ParentID: m.ParentID, CreatedAt: m.CreatedAt, Status: m.Status,
		Tool: m.Tool.Name + " " + m.Tool.Version, Signature: s.sig, Tables: map[string]int{}, Sources: m.SourcesSummary, Coverage: m.Coverage,
		Redaction: m.Redaction, Limits: m.Limits, Dialect: query.Dialect, Tools: s.enabled, Answer: out.Answer,
		Caps: InfoCaps{
			DefaultRows: defaultQueryRows, MaxRows: maxRows, MaxBytes: s.cfg.MaxBytes,
			TimeoutSeconds: int(s.caps(1).WithDefaults().Timeout / time.Second),
		},
		StoredQueries: []InfoStored{},
	}
	for _, t := range m.Tables {
		res.Tables[t.Name] = t.Rows
	}
	for _, q := range stored {
		is := InfoStored{Name: q.Name, Version: q.Version, Description: q.Description, Params: []InfoParam{}}
		for _, p := range q.Params {
			is.Params = append(is.Params, InfoParam{Name: p.Name, Type: p.Type, Required: p.Required, Default: p.Default, Description: p.Description})
		}
		res.StoredQueries = append(res.StoredQueries, is)
	}
	return res, out, nil
}
