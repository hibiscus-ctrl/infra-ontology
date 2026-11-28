# SQL dialect

`infra-ontology/sql/v1` is the SQL that `infra-ontology query`, `verify --answer` and the MCP `query` tool accept: one read-only `SELECT` over a snapshot, checked against an allow-list and run under caps. This page is the short version of what it allows and refuses. [query.md](query.md) has the full lists, how the session is locked and how an answer is cited.

## The rule

A query is exactly one statement, a `SELECT` or a `WITH ... SELECT` (recursive or not), of at most 64 KiB. It may read these and nothing else:

| Name | What it is |
| --- | --- |
| `nodes`, `edges`, `sources` | the tables of the snapshot ([snapshot-format.md](snapshot-format.md)) |
| `snapshot` | one row from the manifest: id, label, parent, status, the oldest and newest source time and the limits text |
| `blast(node_id, depth)` | what depends on a node, directly or through others (follows dependency edges backwards) |
| `cone(node_id, depth)` | what a node needs (follows dependency edges forwards) |
| `blast(node_id, depth, true)`, `cone(node_id, depth, true)` | the same, also following `can_assume`, `can_read` and `can_write` edges |
| `unnest(...)` | the tags, which are a list of `{key, value}` pairs |

The macros stop at the depth you give or 50, whichever is less. They return `node_id`, `depth`, `edge_kind` (the kind of the edge that reached the node) and `confidence` (the weakest along the path). Without the third argument they skip access edges (`can_assume`, `can_read`, `can_write`), which say who may reach a node, not what breaks with it. The query's own CTEs are fine.

An allow-list means anything not named is refused until someone reviews it. The checker is `internal/query/dialect.go`, and `internal/query/testdata/corpus.txt` is the corpus of allowed and refused queries, with a fuzz target over the parse trees.

## What it allows

- Joins, subqueries (`LATERAL` too), `UNION`, `EXCEPT`, `INTERSECT`, `VALUES`, `GROUP BY`, `HAVING`, window functions, `ORDER BY`, `LIMIT`, `OFFSET`, `DISTINCT`, `COLUMNS(...)` and `* EXCLUDE (...)`.
- `CASE`, casts, comparisons, `BETWEEN`, `IN`, `LIKE`, `ILIKE`, `GLOB`, arithmetic and `||`.
- 83 functions: aggregates (`count`, `sum`, `min`, `max`, `avg`, `list`, `string_agg`, `bool_and`, `median`, ...), ranking and offset window functions (`row_number`, `rank`, `lag`, `lead`, `ntile`, ...), null handling (`coalesce`, `nullif`, `least`, `greatest`), text (`lower`, `substr`, `contains`, `split_part`, `regexp_matches`, `replace`, `trim`, ...), numbers (`abs`, `round`, `floor`, `ceil`) and lists and structs (`list_contains`, `list_distinct`, `array_length`, `unnest`, `struct_extract`, ...).

## What it refuses

| Refused | Examples |
| --- | --- |
| any statement but a `SELECT` | `COPY`, `EXPORT`, `INSTALL`, `LOAD`, `ATTACH`, `SET`, `PRAGMA`, `CALL`, `EXPLAIN`, `DESCRIBE`, `SHOW`, `PIVOT`, `CREATE`, `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, transactions, an empty text |
| more than one statement, or text over 64 KiB | `SELECT 1; SELECT 2` |
| any other table, a qualified table, or a file used as a table | `information_schema.tables`, `memory.main.nodes`, `'/etc/passwd'` |
| any other table function | `read_csv`, `read_parquet`, `read_json`, `read_text`, `glob`, `range`, `duckdb_settings` |
| any function not on the list | `getenv`, `current_setting`, `read_text` (file system, environment, settings), `now`, `random`, `uuid` (clock, randomness), the list functions that take lambdas, anything with a schema or catalog in front |
| lambdas, parameters and sampling | `x -> x + 1`, `$1`, `?`, `USING SAMPLE`: an answer has to be the same each time |

A refusal says what was refused and why, and the command exits 1 (a bad flag is 2):

```text
$ infra-ontology query "$SNAP" --sql "SELECT getenv('HOME')"
infra-ontology query: statement rejected by the read-only dialect: function getenv() is not allowed
```

## Caps

Every result is capped. A cap that cuts a result says so in the answer (`truncated`, and `truncated_by`).

| Cap | Default | Hard maximum | Flag |
| --- | --- | --- | --- |
| Rows | 1,000 | 10,000 | `--limit` |
| Columns | 64 | 64 | |
| Bytes of result, as JSON | 4 MiB | 64 MiB | `--max-bytes` |
| Time | 10 s | 5 min | `--timeout` |
| Engine memory | 512 MB | | `--memory` |

A flag above the hard maximum takes the maximum. A result wider than 64 columns is refused. The MCP `query` tool is tighter: `limit` is 1 to 1000 (default 100), a result is cut at 256 KiB of JSON and a call at 10 seconds ([mcp.md](mcp.md#the-tools)).

## Why the checker is not the only guard

A query is never run as written. DuckDB parses the text to a tree, the checker walks the whole tree, DuckDB writes SQL back from the checked tree, and that canonical text is what runs and what the answer cites. Below that, the session has file access turned off and its configuration locked, and a long-lived session (the MCP server) attaches the data read-only, so a query that got past the checker would still find nothing to read or write. The tests prove the lock without the checker in front of it. See [query.md](query.md#what-the-session-guarantees) and, for the threat model, [security.md](security.md).

## Without the engine

The dialect is checked by DuckDB's parser, so a build made with `-tags noduckdb` has no `query`: it says so and prints the SQL to run with your own DuckDB on the snapshot folder. A snapshot is plain Parquet, and DuckDB's own session then has none of the guarantees above.
