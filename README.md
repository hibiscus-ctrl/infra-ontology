# infra-ontology

A cited, read-only graph of your cloud estate and Terraform, for people and coding agents.

infra-ontology reads Terraform state (from any backend) and an inventory of what is live in your cloud, and writes a **snapshot**: a few Parquet files and a manifest that say what exists, what Terraform manages, what it doesn't, and what depends on what. You ask it questions in read-only SQL. Every answer carries the query, the snapshot it ran against and the age of its oldest data, so a person, an auditor or a coding agent can check it. Two of the questions it is built for: "what is in this account that no Terraform manages?" and "what breaks if I change this resource?"

It runs on your laptop or in your CI, with your own credentials. It holds no secret values, writes nothing to the cloud and needs no server.

## Status

**Early: not yet usable on a real estate.** The snapshot format is written: the JSON Schemas, a pure-Go Parquet writer with stable bytes and a content-addressed manifest, `snapshot verify` and `diff`. So is the query layer: read-only SQL over a snapshot with row caps and a cited answer (`query`, `verify --answer`). The MCP server (`serve-mcp`, [docs/mcp.md](docs/mcp.md)) is written too. So is a lossy export to infraharvest's `graph/v1`, which Terragram draws (`export graph`, [docs/export.md](docs/export.md)). The state and inventory readers are planned and land in later changes, so for now a snapshot can only be built from a JSON file (`snapshot build --from-json`, a path for tests and development). Nothing here is stable, and the name and the module path may still change.

## What it will do

- **Snapshot.** Read Terraform state and a live inventory into one typed snapshot: nodes, edges and sources, in open Parquet files with a content-addressed manifest. Anyone can query a snapshot with their own DuckDB.
- **Cited, read-only SQL.** A restricted `SELECT` dialect with row caps ([docs/query.md](docs/query.md)). An answer is evidence, not a claim: it names its query, its snapshot, its caps and the age of its data, and `verify --answer` re-runs it.
- **MCP tools.** `infra-ontology serve-mcp <snapshot>` is a stdio server that gives coding agents the same answers: `inventory`, `blast_radius`, a read-only `query` and `snapshot_info`, with an audit log of every call ([docs/mcp.md](docs/mcp.md), [SKILL.md](SKILL.md)). Written; waiting on the readers.
- **Export to a picture.** `infra-ontology export graph <snapshot>` writes the resources, module calls and references of a snapshot as an infraharvest `graph/v1` document that Terragram draws. It is lossy, redaction carries over, and the same snapshot gives the same bytes ([docs/export.md](docs/export.md)).

See [docs/architecture.md](docs/architecture.md) for how the parts fit together.

## Red lines

- No secret values, and no attribute values, are ever stored in a snapshot.
- Read-only: it never writes to the cloud or to Terraform state.
- It uses your own credentials, from your environment, and never prints, stores or sends them.
- No network calls except to the backends you name. No telemetry.

## Install

Download an archive from the [releases page](https://github.com/hibiscus-ctrl/infra-ontology/releases) and [check its signature](docs/install.md#check-the-download). There is nothing else to install on macOS and Windows. The full build, with the query engine (`query`, `verify --answer` and `serve-mcp`), is released for Linux (amd64, arm64), macOS (Intel, Apple silicon) and Windows (amd64). On Linux it links `libstdc++` at run time, so it needs a glibc distribution with libstdc++ installed. Every other platform, and images without glibc and libstdc++, get a smaller pure-Go `_noquery` archive that has no query engine. [docs/install.md](docs/install.md) says which archive to pick.

## Build

You need Go (the version in `go.mod`) and, for the query engine, cgo: a C and C++ compiler (`gcc` and `g++`, or the Xcode command line tools; Windows builds without the engine for now). `go build -tags noduckdb` builds without the engine, in pure Go; `query` then says so. A build with DuckDB is about 77 MB and links `libstdc++` at run time, so on Linux it needs a glibc distribution with libstdc++ installed.

```sh
make build        # builds ./infra-ontology
./infra-ontology version
make test

# a snapshot is a folder; these work offline
./infra-ontology snapshot verify <snapshot-folder>   # check a snapshot against its manifest, offline
./infra-ontology diff <a> <b>                       # what changed from snapshot a to snapshot b
./infra-ontology export graph <snapshot-folder> -o graph.json   # a graph/v1 document for Terragram (lossy)
./infra-ontology query <snapshot-folder> --stored unmanaged   # cited, read-only SQL (needs the engine)
./infra-ontology verify --answer answer.json        # re-run a cited answer against its snapshot
./infra-ontology serve-mcp <snapshot-folder> --audit-log audit.jsonl   # an MCP server on stdio (needs the engine)
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions need a signed [CLA](CLA.md). Report vulnerabilities privately, as [SECURITY.md](SECURITY.md) says.

## Licence

The code is licensed under the [GNU Affero General Public License v3.0 only](LICENSE) (`AGPL-3.0-only`). The JSON Schemas under [`schemas/`](schemas/) are licensed under [Apache-2.0](LICENSES/Apache-2.0.txt), so any tool can validate and generate types from them. The repository follows the [REUSE](https://reuse.software/) specification.

Commercial licence: if the AGPL does not fit your use, a commercial licence is available; contact [contact@infraweaver.io](mailto:contact@infraweaver.io).
