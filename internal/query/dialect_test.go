// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package query

import (
	"encoding/json"
	"errors"
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
