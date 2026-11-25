// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package query

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The corpus, through the checker, against the recorded parse trees.
func TestCorpusRecorded(t *testing.T) {
	trees := readSerialized(t)
	for _, e := range readCorpus(t) {
		js, ok := trees[e.SQL]
		if !ok {
			t.Errorf("%q has no recorded tree: run go test ./internal/query -update", e.SQL)
			continue
		}
		err := CheckSerialized(js)
		switch {
		case e.Allow && err != nil:
			t.Errorf("allowed query refused: %s\n  %v", e.SQL, err)
		case !e.Allow && err == nil:
			t.Errorf("refused query allowed: %s", e.SQL)
		case err != nil && !errors.Is(err, ErrRejected):
			t.Errorf("%s: the refusal does not wrap ErrRejected: %v", e.SQL, err)
		}
	}
}

// Trees written by hand, for what DuckDB's parser will not produce today: the
// checker must hold even if a later DuckDB does.
func TestCheckerOnHandWrittenTrees(t *testing.T) {
	sel := func(body string) string {
		return `{"error":false,"statements":[{"node":{"type":"SELECT_NODE","modifiers":[],"cte_map":{"map":[]},"select_list":[` + body + `],"from_table":{"type":"EMPTY"}}}]}`
	}
	cases := []struct {
		name, tree string
		ok         bool
	}{
		{"a constant", sel(`{"class":"CONSTANT","type":"VALUE_CONSTANT","value":{"is_null":false}}`), true},
		{"an unlisted class", sel(`{"class":"LAMBDA","type":"LAMBDA"}`), false},
		{"a parameter", sel(`{"class":"PARAMETER","type":"VALUE_PARAMETER"}`), false},
		{"a function not on the list", sel(`{"class":"FUNCTION","type":"FUNCTION","function_name":"read_text","schema":"","catalog":"","is_operator":false,"children":[]}`), false},
		{"a listed function", sel(`{"class":"FUNCTION","type":"FUNCTION","function_name":"lower","schema":"","catalog":"","is_operator":false,"children":[]}`), true},
		{"a qualified listed function", sel(`{"class":"FUNCTION","type":"FUNCTION","function_name":"lower","schema":"main","catalog":"","is_operator":false,"children":[]}`), false},
		{"an operator", sel(`{"class":"FUNCTION","type":"FUNCTION","function_name":"+","schema":"","catalog":"","is_operator":true,"children":[]}`), true},
		{"a function posing as an operator", sel(`{"class":"FUNCTION","type":"FUNCTION","function_name":"read_text","schema":"","catalog":"","is_operator":true,"children":[]}`), false},
		{"a function nested in a case", sel(`{"class":"CASE","type":"CASE_EXPR","case_checks":[{"when_expr":{"class":"FUNCTION","function_name":"getenv","schema":"","catalog":"","is_operator":false},"then_expr":{"class":"CONSTANT","type":"VALUE_CONSTANT"}}]}`), false},
		{"a node type not on the list", `{"error":false,"statements":[{"node":{"type":"INSERT_NODE"}}]}`, false},
		{"a macro as a table function", `{"error":false,"statements":[{"node":{"type":"SELECT_NODE","modifiers":[],"select_list":[],"from_table":{"type":"TABLE_FUNCTION","function":{"class":"FUNCTION","function_name":"blast","schema":"","catalog":"","is_operator":false,"children":[]}}}}]}`, true},
		{"a qualified macro", `{"error":false,"statements":[{"node":{"type":"SELECT_NODE","modifiers":[],"select_list":[],"from_table":{"type":"TABLE_FUNCTION","function":{"class":"FUNCTION","function_name":"blast","schema":"main","catalog":"","is_operator":false,"children":[]}}}}]}`, false},
		{"a file function with a macro's arguments", `{"error":false,"statements":[{"node":{"type":"SELECT_NODE","modifiers":[],"select_list":[],"from_table":{"type":"TABLE_FUNCTION","function":{"class":"FUNCTION","function_name":"read_csv","schema":"","catalog":"","is_operator":false,"children":[]}}}}]}`, false},
		{"a function hidden in a macro's argument", `{"error":false,"statements":[{"node":{"type":"SELECT_NODE","modifiers":[],"select_list":[],"from_table":{"type":"TABLE_FUNCTION","function":{"class":"FUNCTION","function_name":"blast","schema":"","catalog":"","is_operator":false,"children":[{"class":"FUNCTION","function_name":"getenv","schema":"","catalog":"","is_operator":false,"children":[]}]}}}}]}`, false},
		{"a base table", `{"error":false,"statements":[{"node":{"type":"SELECT_NODE","modifiers":[],"select_list":[],"from_table":{"type":"BASE_TABLE","schema_name":"","catalog_name":"","table_name":"Nodes"}}}]}`, true},
		{"a qualified table", `{"error":false,"statements":[{"node":{"type":"SELECT_NODE","modifiers":[],"select_list":[],"from_table":{"type":"BASE_TABLE","schema_name":"main","catalog_name":"","table_name":"nodes"}}}]}`, false},
		{"a table of the catalogue", `{"error":false,"statements":[{"node":{"type":"SELECT_NODE","modifiers":[],"select_list":[],"from_table":{"type":"BASE_TABLE","schema_name":"","catalog_name":"","table_name":"duckdb_settings"}}}]}`, false},
		{"no statements", `{"error":false,"statements":[]}`, false},
		{"two statements", `{"error":false,"statements":[{"node":{"type":"SELECT_NODE"}},{"node":{"type":"SELECT_NODE"}}]}`, false},
		{"a parse error", `{"error":true,"error_type":"parser","error_message":"syntax error"}`, false},
		{"not JSON", `select 1`, false},
		{"a statement with no node", `{"error":false,"statements":[{}]}`, false},
		{"a statement that is not an object", `{"error":false,"statements":[1]}`, false},
	}
	for _, c := range cases {
		err := CheckSerialized(c.tree)
		if c.ok && err != nil {
			t.Errorf("%s: refused: %v", c.name, err)
		}
		if !c.ok && !errors.Is(err, ErrRejected) {
			t.Errorf("%s: want a refusal, got %v", c.name, err)
		}
	}
}

// Trees for what the walker must hold whatever DuckDB writes next: a member it
// has never seen is walked like any other, a name outside a call is refused,
// and a WITH clause is in scope for its own node and no further.
func TestWalkerIsDefaultDeny(t *testing.T) {
	const bad = `{"class":"FUNCTION","type":"FUNCTION","function_name":"getenv","schema":"","catalog":"","is_operator":false,"children":[]}`
	const fn = `{"class":"FUNCTION","type":"FUNCTION","function_name":"%s","schema":"","catalog":"","is_operator":false,"arguments":[%s]}`
	tf := func(name, extra string) string {
		return `{"type":"TABLE_FUNCTION","function":{"class":"FUNCTION","type":"FUNCTION","function_name":"` + name + `","schema":"","catalog":"","is_operator":false,` + extra + `}}`
	}
	sel := func(from, body string) string {
		return `{"error":false,"statements":[{"node":{"type":"SELECT_NODE","modifiers":[],"cte_map":{"map":[]},"select_list":[` + body + `],"from_table":` + from + `}}]}`
	}
	const empty = `{"type":"EMPTY"}`
	const one = `{"class":"CONSTANT","type":"VALUE_CONSTANT"}`
	base := func(name string) string {
		return `{"type":"BASE_TABLE","schema_name":"","catalog_name":"","table_name":"` + name + `"}`
	}
	win := func(name, members string) string {
		return `{"class":"WINDOW","type":"WINDOW_AGGREGATE","function_name":"` + name + `","schema":"","catalog":""` + members + `}`
	}
	cte := func(name, query string) string {
		return `{"key":"` + name + `","value":{"query_node":` + query + `}}`
	}
	sub := func(cteEntries, from string) string {
		return `{"type":"SELECT_NODE","modifiers":[],"cte_map":{"map":[` + cteEntries + `]},"select_list":[],"from_table":` + from + `}`
	}
	cases := []struct {
		name, tree string
		ok         bool
	}{
		{"table function arguments", sel(tf("blast", `"arguments":[{"name":"","expression":`+one+`}]`), one), true},
		{"a bad function in table function arguments", sel(tf("blast", `"arguments":[{"name":"","expression":`+bad+`}]`), one), false},
		{"a bad function in a member DuckDB has not named yet", sel(tf("blast", `"brand_new_member":[{"x":`+bad+`}]`), one), false},
		{"a bad function in a table function filter", sel(tf("blast", `"filter":`+bad), one), false},
		{"a bad function in a table function's order", sel(tf("blast", `"order_bys":{"type":"ORDER_MODIFIER","orders":[{"type":"ORDER_DEFAULT","expression":`+bad+`}]}`), one), false},
		{"a subquery in table function arguments", sel(tf("blast", `"arguments":[{"expression":{"class":"SUBQUERY","type":"SUBQUERY","subquery":{"node":`+sub("", base("duckdb_settings"))+`}}}]`), one), false},
		{"a table function with no function call", sel(`{"type":"TABLE_FUNCTION","function":{"function_name":"blast"}}`, one), false},
		{"a table function with a qualified path", sel(tf("blast", `"qualified_name":{"path":["memory","main","blast"]}`), one), false},
		{"a table function with a plain path", sel(tf("blast", `"qualified_name":{"path":["blast"]}`), one), true},
		{"a function name outside a call", sel(empty, `{"function_name":"read_csv"}`), false},
		{"a function name in a constant", sel(empty, `{"class":"CONSTANT","type":"VALUE_CONSTANT","function_name":"read_csv"}`), false},
		{"a table name outside a table", sel(empty, `{"table_name":"duckdb_settings"}`), false},
		{"a table name in an expression", sel(empty, `{"class":"COLUMN_REF","type":"COLUMN_REF","table_name":"x"}`), false},
		{"a table name in a join", sel(`{"type":"JOIN","table_name":"nodes"}`, one), false},
		{"a table reference posing as an expression", sel(empty, `{"class":"CONSTANT","type":"BASE_TABLE","table_name":"nodes"}`), false},
		{"a base table with a path of another name", sel(`{"type":"BASE_TABLE","schema_name":"","catalog_name":"","table_name":"nodes","qualified_name":{"path":["main","duckdb_settings"]}}`, one), false},
		{"a listed window function", sel(empty, win("row_number", `,"partitions":[`+one+`],"orders":[]`)), true},
		{"an aggregate as a window", sel(empty, win("sum", `,"arguments":[`+one+`]`)), true},
		{"a scalar as a window", sel(empty, win("lower", ``)), false},
		{"an unlisted window function", sel(empty, win("getenv", ``)), false},
		{"a qualified window function", sel(empty, `{"class":"WINDOW","type":"WINDOW_ROW_NUMBER","function_name":"row_number","schema":"main","catalog":""}`), false},
		{"a window function in a catalogue", sel(empty, `{"class":"WINDOW","type":"WINDOW_ROW_NUMBER","function_name":"row_number","schema":"","catalog":"memory"}`), false},
		{"a window whose path names another function", sel(empty, win("row_number", `,"qualified_name":{"path":["read_csv"]}`)), false},
		{"a bad function in a window partition", sel(empty, win("sum", `,"partitions":[`+bad+`]`)), false},
		{"a bad function in a window order", sel(empty, win("sum", `,"orders":[{"type":"ORDER_DEFAULT","expression":`+bad+`}]`)), false},
		{"a bad function in a window filter", sel(empty, win("sum", `,"filter_expr":`+bad)), false},
		{"a bad function in a window frame", sel(empty, win("sum", `,"start_expr":`+bad)), false},
		{"a bad function in a window frame end", sel(empty, win("sum", `,"end_expr":`+bad)), false},
		{"a bad function in a window offset", sel(empty, win("lag", `,"offset_expr":`+bad)), false},
		{"a bad function in a window default", sel(empty, win("lag", `,"default_expr":`+bad)), false},
		{"a bad function in a window argument", sel(empty, win("sum", `,"arguments":[`+bad+`]`)), false},
		{"a star with a bad replacement", sel(empty, `{"class":"STAR","type":"STAR","replace_list":[{"key":"name","value":`+bad+`}]}`), false},
		{"a star with a bad columns expression", sel(empty, `{"class":"STAR","type":"STAR","columns":true,"expr":`+bad+`}`), false},
		{"a case with a bad else", sel(empty, `{"class":"CASE","type":"CASE_EXPR","case_checks":[],"else_expr":`+bad+`}`), false},
		{"a cast of a bad function", sel(empty, `{"class":"CAST","type":"CAST","child":`+bad+`}`), false},
		{"a bad function under a listed one", sel(empty, fmt.Sprintf(fn, "lower", bad)), false},
		{"a collate", sel(empty, `{"class":"COLLATE","type":"COLLATE","child":`+one+`}`), false},
		{"a lambda", sel(empty, `{"class":"LAMBDA","type":"LAMBDA","lhs":`+one+`,"expr":`+one+`}`), false},
		{"a sample on a table", sel(`{"type":"BASE_TABLE","schema_name":"","catalog_name":"","table_name":"nodes","sample":{"method":"RESERVOIR"}}`, one), false},
		{"a sample on a table function", sel(`{"type":"TABLE_FUNCTION","sample":{"method":"RESERVOIR"},"function":{"class":"FUNCTION","function_name":"blast","schema":"","catalog":""}}`, one), false},

		{"a CTE read in its own node", sel(`{"type":"SUBQUERY","subquery":{"node":`+sub(cte("t", sub("", empty)), base("t"))+`}}`, one), true},
		{"a CTE read after its node", sel(`{"type":"JOIN","left":{"type":"SUBQUERY","subquery":{"node":`+sub(cte("t", sub("", empty)), base("t"))+`}},"right":`+base("t")+`}`, one), false},
		{"a CTE read before its node", sel(`{"type":"JOIN","left":`+base("t")+`,"right":{"type":"SUBQUERY","subquery":{"node":`+sub(cte("t", sub("", empty)), base("t"))+`}}}`, one), false},
		{"a CTE read by its own definition", sel(`{"type":"SUBQUERY","subquery":{"node":`+sub(cte("t", sub("", base("t"))), empty)+`}}`, one), false},
		{"a CTE read by a later definition", sel(`{"type":"SUBQUERY","subquery":{"node":`+sub(cte("a", sub("", empty))+","+cte("b", sub("", base("a"))), empty)+`}}`, one), true},
		{"a CTE read by an earlier definition", sel(`{"type":"SUBQUERY","subquery":{"node":`+sub(cte("a", sub("", base("b")))+","+cte("b", sub("", empty)), empty)+`}}`, one), false},
		{"a recursive CTE read by itself", sel(`{"type":"SUBQUERY","subquery":{"node":`+sub(cte("r", `{"type":"RECURSIVE_CTE_NODE","left":`+sub("", empty)+`,"right":`+sub("", base("r"))+`}`), empty)+`}}`, one), true},
		{"a CTE in scope in a nested node", sel(`{"type":"SUBQUERY","subquery":{"node":`+sub(cte("t", sub("", empty)), `{"type":"SUBQUERY","subquery":{"node":`+sub("", base("t"))+`}}`)+`}}`, one), true},
		{"a CTE of the same name popped twice", sel(`{"type":"JOIN","left":{"type":"SUBQUERY","subquery":{"node":`+sub(cte("t", sub("", empty)), `{"type":"SUBQUERY","subquery":{"node":`+sub(cte("t", sub("", empty)), empty)+`}}`)+`}},"right":`+base("t")+`}`, one), false},
		{"a CTE with no name", sel(`{"type":"SUBQUERY","subquery":{"node":`+sub(`{"key":"","value":{}}`, empty)+`}}`, one), false},
		{"a CTE map that is not a map", sel(`{"type":"SUBQUERY","subquery":{"node":{"type":"SELECT_NODE","cte_map":"t","select_list":[],"from_table":`+empty+`}}}`, one), false},
		{"a CTE map with an unreadable list", sel(`{"type":"SUBQUERY","subquery":{"node":{"type":"SELECT_NODE","cte_map":{"map":"t"},"select_list":[],"from_table":`+empty+`}}}`, one), false},
		{"a bad function in a CTE definition", sel(`{"type":"SUBQUERY","subquery":{"node":`+sub(cte("t", `{"type":"SELECT_NODE","modifiers":[],"select_list":[`+bad+`],"from_table":`+empty+`}`), empty)+`}}`, one), false},
	}
	for _, c := range cases {
		err := CheckSerialized(c.tree)
		if c.ok && err != nil {
			t.Errorf("%s: refused: %v", c.name, err)
		}
		if !c.ok && !errors.Is(err, ErrRejected) {
			t.Errorf("%s: want a refusal, got %v", c.name, err)
		}
	}
}

// A CTE name is a table only for the statement that declares it.
func TestCTENamesAreNotGlobal(t *testing.T) {
	withCTE := `{"error":false,"statements":[{"node":{"type":"SELECT_NODE","modifiers":[],"select_list":[],"cte_map":{"map":[{"key":"mine","value":{}}]},"from_table":{"type":"BASE_TABLE","schema_name":"","catalog_name":"","table_name":"mine"}}}]}`
	if err := CheckSerialized(withCTE); err != nil {
		t.Errorf("a CTE read in its own statement: %v", err)
	}
	without := strings.Replace(withCTE, `"key":"mine"`, `"key":"other"`, 1)
	if err := CheckSerialized(without); err == nil {
		t.Error("a table that is not declared was allowed")
	}
}

func TestOrderedIsRead(t *testing.T) {
	trees := readSerialized(t)
	for sql, want := range map[string]bool{
		"SELECT * FROM nodes":                                 false,
		"SELECT * FROM nodes ORDER BY name":                   true,
		"SELECT name FROM nodes UNION SELECT name FROM nodes": false,
		"SELECT * FROM nodes LIMIT 5":                         false,
		"SELECT row_number() OVER (PARTITION BY account ORDER BY name) AS rn, name FROM nodes": false,
	} {
		js, ok := trees[sql]
		if !ok {
			t.Fatalf("no recorded tree for %q", sql)
		}
		got, err := checkTree(js)
		if err != nil || got != want {
			t.Errorf("%q: ordered = %t, %v; want %t", sql, got, err, want)
		}
	}
}

// collectCTEs collects every CTE name in a tree, wherever it is declared: the
// loosest view of what a table name may be, which the fuzz target holds the
// scoped walker inside.
func collectCTEs(v any, out map[string]bool) {
	switch t := v.(type) {
	case map[string]any:
		if cm, ok := t["cte_map"].(map[string]any); ok {
			entries, _ := cm["map"].([]any)
			for _, e := range entries {
				if em, ok := e.(map[string]any); ok {
					if k := str(em["key"]); k != "" {
						out[strings.ToLower(k)] = true
					}
				}
			}
		}
		for _, c := range t {
			collectCTEs(c, out)
		}
	case []any:
		for _, c := range t {
			collectCTEs(c, out)
		}
	}
}

// walkNames collects every function and table name in a tree, with no regard
// for where they sit: an independent view the fuzz target checks the walker
// against.
func walkNames(v any, funcs, tables *[]string) {
	switch t := v.(type) {
	case map[string]any:
		if s, ok := t["function_name"].(string); ok {
			*funcs = append(*funcs, strings.ToLower(s))
		}
		if s, ok := t["table_name"].(string); ok {
			*tables = append(*tables, strings.ToLower(s))
		}
		for _, c := range t {
			walkNames(c, funcs, tables)
		}
	case []any:
		for _, c := range t {
			walkNames(c, funcs, tables)
		}
	}
}

// FuzzCheckSerialized feeds the checker mutated parse trees. It must never
// panic, and a tree it accepts must name only functions and tables the
// dialect lists, wherever in the tree they sit.
func FuzzCheckSerialized(f *testing.F) {
	for _, js := range readSerialized(f) {
		f.Add(js)
	}
	f.Add(`{"error":false,"statements":[{"node":{"type":"SELECT_NODE"}}]}`)
	f.Fuzz(func(t *testing.T, js string) {
		if CheckSerialized(js) != nil {
			return
		}
		var root any
		if err := json.Unmarshal([]byte(js), &root); err != nil {
			t.Fatalf("accepted text that is not JSON: %q", js)
		}
		var funcs, tables []string
		walkNames(root, &funcs, &tables)
		ctes := map[string]bool{}
		collectCTEs(root, ctes)
		for _, fn := range funcs {
			if !okFuncs[fn] && !okOperators[fn] && !okTableFuncs[fn] {
				t.Fatalf("accepted function %q in %s", fn, js)
			}
		}
		for _, tb := range tables {
			if !okTableSet[tb] && !ctes[tb] {
				t.Fatalf("accepted table %q in %s", tb, js)
			}
		}
	})
}

var okTableSet = set(tableNames...)
