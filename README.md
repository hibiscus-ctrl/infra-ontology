# infra-ontology

A cited, read-only graph of your cloud estate and Terraform, for people and coding agents.

infra-ontology reads Terraform state (from any backend) and an inventory of what is live in your cloud, and writes a **snapshot**: a few Parquet files and a manifest that say what exists, what Terraform manages, what it doesn't, and what depends on what. You ask it questions in read-only SQL. Every answer carries the query, the snapshot it ran against and the age of its oldest data, so a person, an auditor or a coding agent can check it. Two of the questions it is built for: "what is in this account that no Terraform manages?" and "what breaks if I change this resource?"

It runs on your laptop or in your CI, with your own credentials. It holds no secret values, writes nothing to the cloud and needs no server.

## Status

**Early: not yet usable on a real estate.** The snapshot format is written: the JSON Schemas, a pure-Go Parquet writer with stable bytes and a content-addressed manifest, `snapshot verify` and `diff`. The state and inventory readers, the query layer and the MCP server are planned and land in later changes, so for now a snapshot can only be built from a JSON file (`snapshot build --from-json`, a path for tests and development). Nothing here is stable, and the name and the module path may still change.

## What it will do

- **Snapshot.** Read Terraform state and a live inventory into one typed snapshot: nodes, edges and sources, in open Parquet files with a content-addressed manifest. Anyone can query a snapshot with their own DuckDB.
- **Cited, read-only SQL.** A restricted `SELECT` dialect with row caps. An answer is evidence, not a claim: it names its query, its snapshot and the age of its data.
- **MCP tools.** A stdio server that gives coding agents the same answers: `inventory`, `blast_radius`, a read-only `query` and `snapshot_info`.

See [docs/architecture.md](docs/architecture.md) for how the parts fit together.

## Red lines

- No secret values, and no attribute values, are ever stored in a snapshot.
- Read-only: it never writes to the cloud or to Terraform state.
- It uses your own credentials, from your environment, and never prints, stores or sends them.
- No network calls except to the backends you name. No telemetry.

## Build

You need Go (the version in `go.mod`).

```sh
make build        # builds ./infra-ontology
./infra-ontology version
make test

# a snapshot is a folder; these work offline
./infra-ontology snapshot verify <snapshot-folder>   # check a snapshot against its manifest, offline
./infra-ontology diff <a> <b>                       # what changed from snapshot a to snapshot b
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions need a signed [CLA](CLA.md). Report vulnerabilities privately, as [SECURITY.md](SECURITY.md) says.

## Licence

The code is licensed under the [GNU Affero General Public License v3.0 only](LICENSE) (`AGPL-3.0-only`). The JSON Schemas under [`schemas/`](schemas/) are licensed under [Apache-2.0](LICENSES/Apache-2.0.txt), so any tool can validate and generate types from them. The repository follows the [REUSE](https://reuse.software/) specification.

Commercial licence: if the AGPL does not fit your use, a commercial licence is available; contact [contact@infraweaver.io](mailto:contact@infraweaver.io).
