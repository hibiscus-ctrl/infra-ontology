# Snapshot format

A snapshot is one immutable folder that says what exists, what Terraform manages and what depends on what, with no attribute values. This page is the map of the format; the schemas under [`schemas/`](../schemas/README.md) are the contract, and [architecture.md](architecture.md#the-snapshot) says how the writer works.

```text
20261125T101500Z-5343debee8ce/
  manifest.json
  nodes.parquet
  edges.parquet
  sources.parquet
  manifest.sig.json        optional: a Sigstore bundle, not part of the snapshot
```

The folder is named by the creation time (UTC) and the first twelve characters of the snapshot id. It is written under a temporary name and renamed, so a reader never sees half a snapshot, and writing the same snapshot again leaves the folder alone.

## The manifest

`manifest.json` ([`snapshot-v1.schema.json`](../schemas/snapshot-v1.schema.json)):

| Member | Holds |
| --- | --- |
| `format`, `format_minor` | `infra-ontology/snapshot/v1` and the minor version the writer used |
| `snapshot_id` | the content hash of the manifest (below) |
| `parent_id`, `label` | the snapshot this one follows (the default for `diff`), and a name |
| `created_at`, `tool` | when it was made, and the program and its version. The writer is given the time and does not read the clock |
| `status` | `ok`, or `partial` if a source did not read in full |
| `tables` | for each table: name, file, SHA-256, row count and row schema |
| `sources_summary` | how many sources, by kind, and the oldest and newest read time |
| `redaction` | the hash algorithm and whether IDs and addresses are hashed or dropped (`addresses_dropped` is true for a snapshot built with `--drop-addresses`, which leaves the `address` and `module` of every node empty, and the `name` of a module call and of a resource a state holds), which tag keys were dropped, and whether all tags were |
| `coverage` | the clouds, accounts and types the snapshot covers, and the sources that failed with their reasons |
| `limits` | plain text of what the snapshot cannot tell you |

## The tables

Three Parquet files, each row described by a schema ([schemas/README.md](../schemas/README.md)):

- **`nodes`** ([`node-v1`](../schemas/node-v1.schema.json)): one row per real thing. `kind` is `resource`, `module_call`, `state_root`, `account` or `external` (a placeholder for something referenced but not read). A node has its cloud, account, region, Terraform and inventory type, native ID, ARN or path, name, Terraform address, module and root, whether Terraform manages it (`managed`, `other_iac`, `unmanaged`, `unknown`, or `missing`: a state holds it and an inventory that listed its place in full, with no filter and the type among those it says it listed in full, does not, see [inventory.md](inventory.md#missing-resources)), its environment, its tags, a confidence and the source it came from.
- **`edges`** ([`edge-v1`](../schemas/edge-v1.schema.json)): a typed link from one node to another with its confidence and its basis. It reads from refers to, or depends on, to. The kinds written are `depends_on`, `contained_in`, `defined_in` and `reads_state_of`; the set is open, and a reader accepts a kind it does not know.
- **`sources`** ([`source-v1`](../schemas/source-v1.schema.json)): where facts came from and when: a state (backend, location, workspace, serial, lineage, Terraform version) or an inventory file, the hash of what was kept of it, the time it was read, the collector and its status.

The row schemas describe the Parquet columns and their JSON Lines form, so a tool without a Parquet reader can validate rows. Every column is a required string except a source's `serial`; tags are a list of key and value pairs sorted by key. Anyone can query the Parquet with their own DuckDB.

## IDs

IDs are SHA-256 hashes in hexadecimal, built so the same thing gets the same ID in every snapshot:

| ID | Hash of |
| --- | --- |
| `node_id` | the node's kind, cloud, account, region, type and native ID |
| `edge_id` | the edge's kind and its two ends' node IDs |
| `source_id` | a short name made from the hash of the source's location: `state-` or `inventory-` and twelve characters |
| `snapshot_id` | the manifest, below |

So a resource keeps its `node_id` as long as its identity does, and `diff` joins two snapshots on it ([architecture.md](architecture.md#the-snapshot)). With `--hash-ids`, node and source IDs are HMACs under your key and the native ID in them is hashed too, so the same estate gives the same IDs under the same key and none in common under another ([state.md](state.md#hashing-ids)).

## Hashing and stable bytes

- **Content-addressed.** The snapshot ID is the SHA-256 of the manifest with its `snapshot_id` member removed, in canonical form (member names sorted, no white space). The manifest holds the SHA-256 of every table file, so a change to any byte of any table changes the ID.
- **Stable bytes.** The same rows give the same files in whatever order they arrive: rows are sorted, times are in UTC, sets in the manifest are sorted, and the Parquet writer's settings are fixed (one row group, no compression, plain pages, no timestamp or file name in the metadata). A golden snapshot pins the bytes (`make golden`).
- **Verify.** `infra-ontology snapshot verify <dir>` checks, offline, that the format is one this build reads, that the ID is the hash of the manifest, that every table is there with the hash, row count and row schema the manifest states, that no other table is there, and that the rows are consistent: unique IDs, every edge between two nodes, every row citing a source. It exits 4 if any check fails and lists every problem.

## Signing

`snapshot sign` writes `manifest.sig.json`, a Sigstore bundle over the manifest's bytes. Because the manifest names every table's hash, one signature covers the whole snapshot. The signature is not in the table list or the ID, so signing later gives the same snapshot. See [signing.md](signing.md).

## Versioning

The major version is in the format name and the schema names. Within a major, a change only adds: columns, node and edge kinds, manifest members. A reader rejects a higher major, and accepts a column or kind it does not know. `format_minor` counts the additions: 1 added the `missing` status of `managed_status` (a reader that does not know it must accept it, as it accepts a kind it does not know). A snapshot has no `drifted` status: drift needs attribute values, which a snapshot never holds (see [inventory.md](inventory.md#missing-resources)).

## What is never in a snapshot

No attribute value, no output value, no credential. Identifiers, addresses, dependencies and the places `terraform_remote_state` reads from are kept; tags (labels on Google Cloud), from a state or an inventory, are the one value kept, after the secret detectors. See [security.md](security.md).
