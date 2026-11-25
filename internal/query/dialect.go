// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package query

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// CheckSerialized checks the output of DuckDB's json_serialize_sql against the
// dialect: one statement, a SELECT or WITH ... SELECT, over the snapshot
// tables and the blast and cone macros. It is an allow-list: a kind of node, a
// class of expression, a function or a table that is not named below is
// refused, so a DuckDB feature that appears later is refused until someone
// reviews it. It is pure Go: DuckDB does the parsing, this walks the tree.
func CheckSerialized(js string) error {
	_, err := checkTree(js)
	return err
}

// checkTree is CheckSerialized and, for an accepted statement, whether its
// outermost query has an ORDER BY.
func checkTree(js string) (ordered bool, err error) {
	var root map[string]any
	if err := json.Unmarshal([]byte(js), &root); err != nil {
		return false, reject("the parse tree is not readable")
	}
	if failed, _ := root["error"].(bool); failed {
		return false, reject("%s", str(root["error_message"]))
	}
	stmts, _ := root["statements"].([]any)
	if len(stmts) != 1 {
		return false, reject("exactly one statement is allowed, got %d", len(stmts))
	}
	stmt, _ := stmts[0].(map[string]any)
	if stmt == nil {
		return false, reject("the parse tree has no statement")
	}
	node, _ := stmt["node"].(map[string]any)
	if node == nil {
		return false, reject("the statement is not a query")
	}
	ctes := map[string]bool{}
	collectCTEs(stmt, ctes)
	if err := walk(stmt, ctes); err != nil {
		return false, err
	}
	return hasOrder(node), nil
}

// hasOrder reports whether a query node orders its own result.
func hasOrder(node map[string]any) bool {
	mods, _ := node["modifiers"].([]any)
	return slices.ContainsFunc(mods, func(m any) bool {
		mm, _ := m.(map[string]any)
		return str(mm["type"]) == "ORDER_MODIFIER"
	})
}

func reject(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrRejected, fmt.Sprintf(format, args...))
}

// Nodes of a query and references in its FROM clause: a map with a "type" and
// no "class". Anything else is refused. Expressions are governed by okClasses
// instead: their "type" (COMPARE_EQUAL, WINDOW_ROW_NUMBER, ...) cannot reach a
// file or the system by itself, only a function call or a table can.
var okTypes = set(
	"SELECT_NODE", "SET_OPERATION_NODE", "RECURSIVE_CTE_NODE", "CTE_NODE",
	"BASE_TABLE", "SUBQUERY", "JOIN", "EMPTY", "TABLE_FUNCTION", "EXPRESSION_LIST",
	"ORDER_MODIFIER", "LIMIT_MODIFIER", "LIMIT_PERCENT_MODIFIER", "DISTINCT_MODIFIER",
	"ASCENDING", "DESCENDING", "ORDER_DEFAULT", "NULLS_FIRST", "NULLS_LAST",
	"ORDER_DEFAULT_NULLS", // spelling of a default null order in some versions
)

// Classes of expression a query may use. LAMBDA, PARAMETER, DEFAULT and the
// rest are refused.
var okClasses = set(
	"CASE", "CAST", "COLUMN_REF", "COMPARISON", "CONJUNCTION", "CONSTANT",
	"FUNCTION", "OPERATOR", "STAR", "SUBQUERY", "WINDOW", "BETWEEN", "TYPE",
)

// Scalar and aggregate functions. A function not here is refused, including
// every function that reads a file, the environment or the settings, and
// every higher-order list function. Each addition is reviewed.
var okFuncs = set(
	// aggregates
	"count", "count_star", "sum", "min", "max", "avg", "any_value", "first", "last", "arbitrary",
	"list", "array_agg", "string_agg", "group_concat", "bool_and", "bool_or", "median", "mode",
	"approx_count_distinct",
	// null handling and comparison
	"coalesce", "ifnull", "nullif", "least", "greatest", "if", "typeof",
	// text
	"lower", "upper", "length", "len", "strlen", "substr", "substring", "left", "right", "concat",
	"concat_ws", "contains", "starts_with", "ends_with", "prefix", "suffix", "split_part", "string_split",
	"regexp_matches", "regexp_extract", "regexp_replace", "replace", "trim", "ltrim", "rtrim", "reverse",
	// numbers
	"abs", "round", "floor", "ceil", "ceiling",
	// lists
	"list_contains", "list_has", "list_append", "list_concat", "list_distinct", "list_sort", "list_value",
	"list_extract", "array_length", "cardinality", "unnest", "list_has_any", "list_has_all", "array_extract",
	// windows and ranking
	"row_number", "rank", "dense_rank", "lag", "lead", "first_value", "last_value", "ntile", "percent_rank",
	// tags are a list of key and value structs
	"struct_extract", "struct_pack", "row",
)

// Operators the parser writes as functions with is_operator set.
var okOperators = set(
	"+", "-", "*", "/", "//", "%", "**", "^", "||",
	"~~", "~~*", "!~~", "!~~*", "~~~", "!~~~", // LIKE, ILIKE, NOT LIKE, NOT ILIKE, GLOB
	"^@", "&&", "@>", "<@",
)

// Table functions: the two macros the session defines, and unnest, which
// turns a list (the tags of a node) into rows and reads nothing else.
var okTableFuncs = set(append(slices.Clone(MacroNames), "unnest")...)

// TableFunctionNames lists the table functions a query may call.
func TableFunctionNames() []string { return slices.Sorted(maps.Keys(okTableFuncs)) }

func set(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

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

func walk(v any, ctes map[string]bool) error {
	switch t := v.(type) {
	case map[string]any:
		// A sample picks rows at random: the same query would not give the
		// same answer twice.
		if sample, ok := t["sample"]; ok && sample != nil {
			return reject("sampling is not allowed: an answer must be the same each time")
		}
		if err := checkNode(t, ctes); err != nil {
			return err
		}
		for k, c := range t {
			// The function of a table function was checked with its table.
			if k == "function" && str(t["type"]) == "TABLE_FUNCTION" {
				fn, _ := c.(map[string]any)
				if err := walk(fn["children"], ctes); err != nil {
					return err
				}
				continue
			}
			if err := walk(c, ctes); err != nil {
				return err
			}
		}
	case []any:
		for _, c := range t {
			if err := walk(c, ctes); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkNode checks one map of the tree: an expression if it has a class, a
// query node or table reference if it has only a type.
func checkNode(t map[string]any, ctes map[string]bool) error {
	if class, isExpr := t["class"].(string); isExpr {
		if !okClasses[class] {
			return reject("expression class %s is not allowed", class)
		}
		if class == "FUNCTION" {
			return checkFunction(t)
		}
		return nil
	}
	ty, ok := t["type"].(string)
	if !ok {
		return nil
	}
	if !okTypes[ty] {
		return reject("node type %s is not allowed", ty)
	}
	switch ty {
	case "BASE_TABLE":
		name := strings.ToLower(str(t["table_name"]))
		if str(t["catalog_name"]) != "" || str(t["schema_name"]) != "" {
			return reject("qualified table %s.%s.%s is not allowed", str(t["catalog_name"]), str(t["schema_name"]), name)
		}
		if !slices.Contains(tableNames, name) && !ctes[name] {
			return reject("table %q is not allowed: a query may read %s", name, strings.Join(tableNames, ", "))
		}
	case "TABLE_FUNCTION":
		fn, _ := t["function"].(map[string]any)
		name := strings.ToLower(str(fn["function_name"]))
		if str(fn["catalog"]) != "" || str(fn["schema"]) != "" {
			return reject("qualified table function %s.%s.%s is not allowed", str(fn["catalog"]), str(fn["schema"]), name)
		}
		if !okTableFuncs[name] {
			return reject("table function %s() is not allowed: a query may call %s", name, strings.Join(TableFunctionNames(), ", "))
		}
	}
	return nil
}

func checkFunction(t map[string]any) error {
	name := strings.ToLower(str(t["function_name"]))
	if str(t["catalog"]) != "" || str(t["schema"]) != "" {
		return reject("qualified function %s.%s.%s is not allowed", str(t["catalog"]), str(t["schema"]), name)
	}
	if op, _ := t["is_operator"].(bool); op {
		if !okOperators[name] {
			return reject("operator %s is not allowed", name)
		}
		return nil
	}
	if !okFuncs[name] {
		return reject("function %s() is not allowed", name)
	}
	return nil
}

func str(v any) string { s, _ := v.(string); return s }
