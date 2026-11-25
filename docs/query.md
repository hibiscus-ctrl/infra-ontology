# Query

`infra-ontology query` answers read-only SQL over a snapshot and cites every answer. This page says what a query may say, what the session guarantees, how an answer is cited, and how to check one.

```sh
infra-ontology query <snapshot-dir> --sql "SELECT kind, count(*) AS n FROM nodes GROUP BY kind ORDER BY kind"
infra-ontology query <snapshot-dir> --stored blast --param node=module.network --param depth=3
infra-ontology query --list                            # the stored queries and their parameters
infra-ontology query <snapshot-dir> --sql "..." --json --answer-out answer.json
infra-ontology verify --answer answer.json [--snapshot <snapshot-dir>]
```

The command reads local files only. It first verifies the snapshot (the same check as `snapshot verify`), so an answer never cites a snapshot whose files do not match its manifest.

## What a query may read

The tables are `nodes`, `edges`, `sources` and `snapshot` (one row from the manifest: the snapshot id, label, parent, status, the oldest and newest source time and the limits text). The columns are the ones in the [snapshot format](architecture.md#the-snapshot) and the JSON Schemas; `nodes.tags` is a list of `{key, value}` pairs.

Two table macros walk the edges. An edge runs from a thing to what it needs, so:

- `blast(node_id, depth)` is what depends on a node, directly or through others: what breaks or changes if it does. It follows edges backwards.
- `cone(node_id, depth)` is what a node needs: its dependency cone. It follows edges forwards.

Both return `(node_id, depth)`, the fewest hops to each node, and stop at the given depth or 50, whichever is less. They are written as a recursive query over `UNION`, so a cycle or two paths to one node cost nothing extra. `unnest` may also be used as a table function, for the tags.

## The dialect

`infra-ontology/sql/v1` is exactly one statement, a `SELECT` or `WITH ... SELECT` (recursive or not), over the tables above, the two macros and the query's own CTEs. It is an allow-list: anything not named here is refused until someone reviews it.

Allowed:

- joins, subqueries (including `LATERAL`), `UNION`, `EXCEPT`, `INTERSECT`, `VALUES`, `GROUP BY`, `HAVING`, window functions, `ORDER BY`, `LIMIT`, `OFFSET`, `DISTINCT`, `COLUMNS(...)`, `* EXCLUDE (...)`;
- `CASE`, casts, comparisons, `BETWEEN`, `IN`, `LIKE`, `ILIKE`, `GLOB`, arithmetic and `||`;
- about eighty functions: the common aggregates (`count`, `sum`, `min`, `max`, `avg`, `list`, `array_agg`, `string_agg`, `bool_and`, ...), null handling (`coalesce`, `nullif`, `least`, `greatest`), text (`lower`, `upper`, `length`, `substr`, `concat`, `contains`, `split_part`, `regexp_matches`, `regexp_extract`, `replace`, `trim`, ...), numbers (`abs`, `round`, `floor`, `ceil`), lists (`list_contains`, `list_distinct`, `list_sort`, `unnest`, `array_length`, ...) and the ranking and offset window functions (`row_number`, `rank`, `lag`, `lead`, ...).

Refused:

- every other kind of statement: `COPY`, `EXPORT`, `INSTALL`, `LOAD`, `ATTACH`, `DETACH`, `USE`, `SET`, `RESET`, `PRAGMA`, `CALL`, `EXPLAIN`, `DESCRIBE`, `SHOW`, `SUMMARIZE`, `PIVOT`, `CREATE`, `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, transactions, and an empty or comment-only text;
- more than one statement, and a text over 64 KiB;
- every table that is not one of the four, any qualified table (`memory.main.nodes`, `information_schema.tables`) and a file name used as a table (`'/etc/passwd'`);
- every table function but the macros and `unnest`: `read_csv`, `read_parquet`, `read_json`, `read_text`, `glob`, `query`, `range`, `duckdb_settings`, `parquet_metadata` and the rest;
- every function not on the list, including those that read the file system, the environment or the settings (`getenv`, `current_setting`, `read_text`), the clock and randomness (`now`, `random`, `uuid`), the higher-order list functions that take lambdas, and any function with a schema or catalog in front of its name;
- lambdas, parameters (`$1`, `?`), and sampling (`USING SAMPLE`): an answer must be the same each time.

A refusal is an error that says what was refused and why. The checker is `internal/query/dialect.go`; the corpus of allowed and refused queries is `internal/query/testdata/corpus.txt`, and a fuzz target runs it against mutated parse trees.

## What the session guarantees

A query is never run as the user wrote it.

1. **Parse.** DuckDB turns the text into a JSON parse tree (`json_serialize_sql`). A parse error, no statement or more than one is refused.
2. **Check.** The checker walks the whole tree against the allow-list: the kind of every query node, the class of every expression, every function name, every table.
3. **Re-emit.** DuckDB writes SQL back from the checked tree (`json_deserialize_sql`). That canonical text is what runs and what the answer cites, so the checker and the executor cannot read one text two ways.
4. **Wrap and run.** The canonical text runs as `SELECT * FROM (<canonical>) AS q LIMIT <rows + 1>`, under the time limit.

Below the checker, the session is locked, so a query that got past it would still find nothing to read or write:

- the snapshot's Parquet files are read into tables first, and the settings that cannot change later (no extension install or load, no community or unsigned extensions, no temp directory, memory limit, threads) are in the connection string;
- `enable_external_access` is turned off with **no allowed paths or directories**, then `lock_configuration` is turned on. No file can be read or written, nothing can be attached, installed or loaded, and no setting can be changed back. DuckDB's `allowed_directories` and `allowed_paths` are deliberately not used: both still let a `COPY` overwrite an allowed file;
- a long-lived session (the [MCP server](mcp.md)) loads the tables into a private database file, attaches it read-only, and deletes the file, so the engine itself refuses every write to the data and the catalog. A one-shot `query` copies the snapshot into memory tables, which opens faster.

The tests prove the lock without the checker in front of it: `COPY`, `EXPORT DATABASE`, `read_csv`, `glob`, `INSTALL`, `LOAD`, `ATTACH`, `SET` and `RESET` after the lock all fail, and the snapshot folder is byte-for-byte the same afterwards.

What this does not claim: a query can still use memory and time up to the caps, a cited answer is only as true as the snapshot, and the guarantee is the engine's lock plus the checker, not a separate process. Keep DuckDB current: the engine is C++ and `govulncheck` cannot see it, so read DuckDB's security advisories when you bump the pinned version (`github.com/duckdb/duckdb-go/v2` in `go.mod`).

## Caps

| Cap | Default | Hard maximum | Flag |
| --- | --- | --- | --- |
| Rows | 1,000 | 10,000 | `--limit` |
| Columns | 64 | 64 | |
| Bytes of result, as JSON (approximate) | 4 MiB | 64 MiB | `--max-bytes` |
| Time | 10 s | 5 min | `--timeout` |
| Engine memory | 512 MB | | `--memory` |

Rows are capped with `LIMIT cap + 1`: the extra row proves that more exist without a second query, and is dropped. A result wider than the column cap is refused. The time limit comes from a Go context, which stops a running query within a millisecond or two and leaves the session usable. When a cap cuts the result the answer says `truncated: true` and which cap (`truncated_by`), and the row count is the rows returned.

## Stored queries

Named, versioned SQL files in `queries/`, compiled into the binary. The header says what each is:

```sql
-- name: blast
-- version: 1
-- description: What depends on a node ...
-- param: node string required A node id, a Terraform address, an ARN or path, or a native id
-- param: depth int[0..50] 5 How many hops to follow
```

A parameter is `string` or `int` (optionally `int[lo..hi]`), with a default, `required`, or `-` for an optional filter that defaults to empty. A string is written into the query as a quoted literal, an integer as a checked number; a value cannot add SQL. The rendered text goes through the same checker as any other. The stored queries are `blast` and `cone` (a node by id, Terraform address, ARN or path, or native id, and a depth), `unmanaged` (resources in the inventory that no state holds), `summary` (nodes by kind and managed status) and `inventory` (the nodes in a fixed order, filtered by type, account, environment, module and address prefix, with an offset for paging: what the MCP `inventory` tool runs). `query --list` prints them with their parameters.

## The citation

Every answer is printed with, and `--json` returns, a record that matches [`schemas/answer-v1.schema.json`](../schemas/answer-v1.schema.json):

```json
{
  "query": "SELECT ...",
  "query_hash": "sha256:...",
  "stored_query": "blast", "stored_query_version": 1, "stored_query_hash": "sha256:...",
  "parameters": {"node": "module.network", "depth": "3"},
  "snapshot_id": "56eda5cee85096e7...",
  "dialect": "infra-ontology/sql/v1",
  "engine": "duckdb 2.0.1",
  "caps": {"max_rows": 1000, "max_columns": 64, "max_bytes": 4194304},
  "row_count": 42, "truncated": false, "ordered": true,
  "result_hash": "sha256:...",
  "limits": {
    "oldest_source": "2026-11-25T09:05:00Z", "failed_sources": 0, "status": "ok",
    "covered": {"clouds": ["aws"], "accounts": ["111111111111"], "types_read": 4},
    "note": "the snapshot's own statement of its limits"
  }
}
```

- `query` is the canonical SQL that ran, and `query_hash` is the SHA-256 of that text. White space, comments and the spelling of keywords do not change it; the case of identifiers does. For a stored query the parameters are part of the text.
- `snapshot_id` is the snapshot's content hash, from its manifest.
- `result_hash` is the SHA-256 of the column names and then each row as JSON, one to a line. If the query has an `ORDER BY` of its own (`ordered: true`) the rows are hashed in order; otherwise they are sorted first, so the order the engine happened to return them in does not matter. A cut result with no `ORDER BY` keeps whichever rows the engine reached first, which is not fixed: add an `ORDER BY` to a query you mean to cite.
- `limits` says what the data cannot tell you: when the oldest source was read, which sources failed and why, whether the snapshot is `partial`, what it covers, and the snapshot's own limits text. A snapshot that is missing a source does not look complete.

## Checking an answer

`infra-ontology verify --answer answer.json` re-runs the cited query against the cited snapshot, under the answer's caps, and compares: the snapshot id, the dialect, the hash of the query, the row count, truncation, ordering and the result hash. The file may be the citation alone (`query --answer-out`) or the whole `--json` output. The snapshot is `--snapshot DIR`, or found by its id in `--snapshots` (default `.infra-ontology/snapshots`). It exits 0 if the answer is reproduced and 4 if not, listing each difference; a different engine version is a note, not a failure.

This checks an answer against a snapshot, not a snapshot against the world: a reproduced answer proves the query gave this result over this snapshot, and `snapshot verify` proves the snapshot is the one its manifest describes.

## Build without the engine

DuckDB needs cgo, so `go build` needs a C and C++ compiler (`gcc` and `g++`, or the Xcode command line tools). `go build -tags noduckdb` builds the command in pure Go, without it: `query` and `verify --answer` then say that the build has no query engine and print the SQL to run with DuckDB on the snapshot folder, and `snapshot verify` and `diff` work as usual.

A build with DuckDB is about 77 MB stripped and links `libstdc++.so.6`, `libgcc_s.so.1` and glibc dynamically on Linux, so it runs on a glibc distribution that has libstdc++ installed and not on `scratch`, distroless-static or Alpine without more work. CI lists the linked libraries with `ldd` (`scripts/check-ldd.sh`) and fails on one it does not expect.
