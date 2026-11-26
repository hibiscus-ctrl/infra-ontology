# Quickstart

From a Terraform state to a cited answer in five steps, using the fixtures in this repository, so it runs offline with no cloud account. The fixtures are made-up estates: five Terraform states (AWS, Azure and Google) and an infraharvest inventory of an AWS account.

## 1. Build the command

You need Go (the version in `go.mod`) and, for the query engine, a C and C++ compiler. See [install.md](install.md) for the release archives instead.

```sh
git clone https://github.com/hibiscus-ctrl/infra-ontology
cd infra-ontology
make build                 # ./infra-ontology, with the query engine (cgo)
./infra-ontology version
```

`make build TAGS=noduckdb` builds the pure-Go command. It does everything below except steps 4 and 5 (`query`, `verify --answer` and `serve-mcp` need the engine).

## 2. Build a snapshot

State is read, never changed, and only identifiers are kept ([state.md](state.md)). The inventory says what is live ([inventory.md](inventory.md)).

```sh
./infra-ontology snapshot build \
  --state internal/ingest/testdata/states \
  --inventory internal/ingest/testdata/inventory/aws.inventory.json \
  --out demo --label demo
```

It prints the new folder, such as `demo/20261125T180716Z-3fef29bc30bc`. A snapshot is a folder of `manifest.json`, `nodes.parquet`, `edges.parquet` and `sources.parquet` ([snapshot-format.md](snapshot-format.md)). From here, `SNAP` stands for that folder:

```sh
SNAP=$(ls -d demo/*/)
```

`--state` also takes `s3://`, `gs://`, `azblob://` and `hcp://` locations in a build made with the store's tag ([permissions.md](permissions.md)); the release archives have all four.

## 3. Check it

```sh
./infra-ontology snapshot verify "$SNAP"
```

`verify` checks every table against the manifest's hashes and the manifest against the snapshot id, offline. To say who made the snapshot, sign it ([signing.md](signing.md)).

## 4. Ask questions

Stored queries first: `query --list` shows them.

```sh
./infra-ontology query "$SNAP" --stored summary
./infra-ontology query "$SNAP" --stored unmanaged           # in the inventory, in no state
./infra-ontology query "$SNAP" --stored blast \
  --param node=module.network.aws_vpc.main --param depth=2  # what depends on the VPC
```

Then SQL of your own, in the [read-only dialect](sql-dialect.md):

```sh
./infra-ontology query "$SNAP" --sql \
  "SELECT tf_type, count(*) AS n FROM nodes WHERE managed_status = 'unmanaged' GROUP BY tf_type ORDER BY n DESC, tf_type"
```

Every answer cites its query, its snapshot, its caps and the age of its data. Keep the citation and check it later:

```sh
./infra-ontology query "$SNAP" --stored blast --param node=module.network.aws_vpc.main --answer-out answer.json
./infra-ontology verify --answer answer.json --snapshot "$SNAP"     # exit 0: reproduced
```

See [query.md](query.md) for the caps and the citation.

## 5. Give it to a coding agent

`serve-mcp` serves one verified snapshot over the Model Context Protocol on standard input and output: `inventory`, `blast_radius`, a read-only `query` and `snapshot_info`.

```sh
claude mcp add infra-ontology -- "$PWD/infra-ontology" serve-mcp "$PWD/$SNAP" --audit-log "$PWD/audit.jsonl"
```

Other clients, the tool list and the audit log are in [mcp.md](mcp.md); [SKILL.md](../SKILL.md) is a guide to hand the agent. Names in a snapshot are data, not instructions, and the server says so.

## Your own estate

Replace the fixtures with your states and an export of what is live:

```sh
infraharvest discover aws
infraharvest export infrastructure --command discover --out-file inventory.json
./infra-ontology snapshot build --state s3://acme-tfstate/prod/ --inventory inventory.json --label prod
```

Add `--hash-ids` to hash IDs, names and addresses before a snapshot leaves your machine ([state.md](state.md#hashing-ids)), and `--drop-addresses` to leave Terraform addresses out ([state.md](state.md#dropping-addresses)), and read [security.md](security.md) for what is and is not kept.
