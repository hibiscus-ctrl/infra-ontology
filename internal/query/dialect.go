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
	if err := newWalker().walk(stmt); err != nil {
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
var okFuncs = set(slices.Concat(aggregateFuncs, windowFuncs, scalarFuncs)...)

// What a window expression may be: a ranking or offset function, or an
// aggregate. Nothing else is a window, whatever its name is elsewhere.
var okWindowFuncs = set(slices.Concat(aggregateFuncs, windowFuncs)...)

var aggregateFuncs = []string{
	"count", "count_star", "sum", "min", "max", "avg", "any_value", "first", "last", "arbitrary",
	"list", "array_agg", "string_agg", "group_concat", "bool_and", "bool_or", "median", "mode",
	"approx_count_distinct",
}

var windowFuncs = []string{
	"row_number", "rank", "dense_rank", "lag", "lead", "first_value", "last_value", "ntile", "percent_rank",
}

var scalarFuncs = []string{
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
	// tags are a list of key and value structs
	"struct_extract", "struct_pack", "row",
}

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

// walker walks a parse tree. Nothing in the tree is trusted by default: every
// member of every map is walked, so a field a later DuckDB adds cannot hide an
// expression. The members it does not walk are the plain strings, numbers and
// booleans, which cannot hold one.
type walker struct {
	// scope counts the CTE names visible at the node being walked: the names
	// of the WITH clauses on the path from the root to it, and no others.
	scope map[string]int
}

func newWalker() *walker { return &walker{scope: map[string]int{}} }

func (w *walker) push(name string) { w.scope[name]++ }

func (w *walker) pop(names []string) {
	for _, n := range names {
		if w.scope[n]--; w.scope[n] <= 0 {
			delete(w.scope, n)
		}
	}
}

func (w *walker) walk(v any) error {
	switch t := v.(type) {
	case map[string]any:
		return w.walkMap(t)
	case []any:
		for _, c := range t {
			if err := w.walk(c); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w *walker) walkMap(t map[string]any) error {
	// A sample picks rows at random: the same query would not give the same
	// answer twice.
	if sample, ok := t["sample"]; ok && sample != nil {
		return reject("sampling is not allowed: an answer must be the same each time")
	}
	if err := w.checkNode(t); err != nil {
		return err
	}
	// A WITH clause names tables for its own node and what is below it, and
	// for nothing else: the names go in on the way down and out on the way up.
	cm, hasCTEs := t["cte_map"]
	if hasCTEs && cm != nil {
		pushed, err := w.walkCTEMap(cm)
		defer w.pop(pushed)
		if err != nil {
			return err
		}
	}
	for k, c := range t {
		if k == "cte_map" {
			continue
		}
		if k == "function" && str(t["type"]) == "TABLE_FUNCTION" {
			if err := w.walkTableFunction(c); err != nil {
				return err
			}
			continue
		}
		if err := w.walk(c); err != nil {
			return err
		}
	}
	return nil
}

// walkCTEMap walks the definitions of a WITH clause and returns the names it
// brought into scope, which the caller takes out again. A definition sees the
// names before it, and its own only if it is recursive; the rest of the node
// sees all of them.
func (w *walker) walkCTEMap(cm any) (pushed []string, err error) {
	m, ok := cm.(map[string]any)
	if !ok {
		return nil, reject("a WITH clause is not readable")
	}
	var entries []any
	if raw, present := m["map"]; present && raw != nil {
		if entries, ok = raw.([]any); !ok {
			return nil, reject("a WITH clause is not readable")
		}
	}
	for _, e := range entries {
		em, ok := e.(map[string]any)
		name := strings.ToLower(str(em["key"]))
		if !ok || name == "" {
			return pushed, reject("a WITH clause has an entry with no name")
		}
		recursive := false
		if val, ok := em["value"].(map[string]any); ok {
			if qn, ok := val["query_node"].(map[string]any); ok {
				recursive = str(qn["type"]) == "RECURSIVE_CTE_NODE"
			}
		}
		if recursive {
			w.push(name)
			pushed = append(pushed, name)
		}
		if err := w.walk(em["value"]); err != nil {
			return pushed, err
		}
		if !recursive {
			w.push(name)
			pushed = append(pushed, name)
		}
	}
	for k, c := range m {
		if k != "map" {
			if err := w.walk(c); err != nil {
				return pushed, err
			}
		}
	}
	return pushed, nil
}

// walkTableFunction walks the function of a table function. Its name, schema
// and catalog were checked with the table; everything else it holds, its
// arguments above all, is walked like any other expression.
func (w *walker) walkTableFunction(v any) error {
	fn, _ := v.(map[string]any)
	for k, c := range fn {
		switch k {
		case "function_name", "schema", "catalog", "qualified_name":
			continue
		}
		if err := w.walk(c); err != nil {
			return err
		}
	}
	return nil
}

// checkNode checks one map of the tree: an expression if it has a class, a
// query node or table reference if it has only a type. A map that is neither
// may hold no name of a function or a table, so a name cannot escape the
// checks by leaving out the class or the type that triggers them.
func (w *walker) checkNode(t map[string]any) error {
	ty, hasType := t["type"].(string)
	if class, isExpr := t["class"].(string); isExpr {
		if !okClasses[class] {
			return reject("expression class %s is not allowed", class)
		}
		if okTypes[ty] && ty != "SUBQUERY" {
			return reject("node type %s is not an expression", ty)
		}
		if _, ok := t["table_name"]; ok {
			return reject("a table name in an expression is not allowed")
		}
		switch class {
		case "FUNCTION":
			return checkFunction(t)
		case "WINDOW":
			return checkWindow(t)
		}
		if _, ok := t["function_name"]; ok {
			return reject("a function name in a %s expression is not allowed", class)
		}
		return nil
	}
	if _, ok := t["function_name"]; ok {
		return reject("a function name outside a function call is not allowed")
	}
	if !hasType {
		if _, ok := t["table_name"]; ok {
			return reject("a table name outside a table reference is not allowed")
		}
		return nil
	}
	if !okTypes[ty] {
		return reject("node type %s is not allowed", ty)
	}
	if _, ok := t["table_name"]; ok && ty != "BASE_TABLE" {
		return reject("a table name in a %s is not allowed", ty)
	}
	switch ty {
	case "BASE_TABLE":
		name := strings.ToLower(str(t["table_name"]))
		if str(t["catalog_name"]) != "" || str(t["schema_name"]) != "" {
			return reject("qualified table %s.%s.%s is not allowed", str(t["catalog_name"]), str(t["schema_name"]), name)
		}
		if err := checkPath(t, name, "table"); err != nil {
			return err
		}
		if !slices.Contains(tableNames, name) && w.scope[name] == 0 {
			return reject("table %q is not allowed: a query may read %s", name, strings.Join(tableNames, ", "))
		}
	case "TABLE_FUNCTION":
		fn, _ := t["function"].(map[string]any)
		name := strings.ToLower(str(fn["function_name"]))
		if fn["class"] != "FUNCTION" {
			return reject("a table function without a function call is not allowed")
		}
		if str(fn["catalog"]) != "" || str(fn["schema"]) != "" {
			return reject("qualified table function %s.%s.%s is not allowed", str(fn["catalog"]), str(fn["schema"]), name)
		}
		if err := checkPath(fn, name, "table function"); err != nil {
			return err
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
	if err := checkPath(t, name, "function"); err != nil {
		return err
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

// checkWindow holds a window expression to the rules of a function call, with
// the narrower list of what may be used as a window: ranking and offset
// functions, and the aggregates.
func checkWindow(t map[string]any) error {
	name := strings.ToLower(str(t["function_name"]))
	if str(t["catalog"]) != "" || str(t["schema"]) != "" {
		return reject("qualified window function %s.%s.%s is not allowed", str(t["catalog"]), str(t["schema"]), name)
	}
	if err := checkPath(t, name, "window function"); err != nil {
		return err
	}
	if !okWindowFuncs[name] {
		return reject("window function %s() is not allowed", name)
	}
	return nil
}

// checkPath refuses a name whose qualified form, when the tree has one, says
// anything but the plain name that was checked.
func checkPath(t map[string]any, name, what string) error {
	qn, present := t["qualified_name"]
	if !present || qn == nil {
		return nil
	}
	m, _ := qn.(map[string]any)
	path, _ := m["path"].([]any)
	if len(path) != 1 || strings.ToLower(str(path[0])) != name {
		return reject("the qualified name of the %s %s is not allowed", what, name)
	}
	return nil
}

func str(v any) string { s, _ := v.(string); return s }
