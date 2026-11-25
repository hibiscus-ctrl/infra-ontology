# Schemas

The JSON Schemas (2020-12) of the documents infra-ontology writes. They are Apache-2.0, unlike the rest of the repository, so any tool can validate a snapshot or generate types from it.

| Schema | Describes |
| --- | --- |
| [`snapshot-v1.schema.json`](snapshot-v1.schema.json) | `manifest.json`: the format version, the snapshot id (a content hash), the parent, the label, the hash and row count of every table, the redaction mode and what was covered |
| [`node-v1.schema.json`](node-v1.schema.json) | A row of `nodes.parquet`: a resource, module call, state root, account or placeholder, with identifiers and no attribute values |
| [`edge-v1.schema.json`](edge-v1.schema.json) | A row of `edges.parquet`: a typed link between two nodes, with its confidence and basis |
| [`source-v1.schema.json`](source-v1.schema.json) | A row of `sources.parquet`: where facts came from, and when |
| [`answer-v1.schema.json`](answer-v1.schema.json) | The citation record of an answer: the query, the snapshot, the result hash and the limits |

The row schemas describe the columns of the Parquet tables and also their JSON Lines form, so a tool without a Parquet reader can validate rows. Two columns differ between the forms: an empty string is left out of the JSON, and the tags, a map in JSON, are a list of key and value pairs sorted by key in Parquet.

Versioning: the major version is in the schema's name and in the manifest's `format`. Within a major, changes only add members, columns and kinds, so a reader accepts one it does not know and rejects a higher major. The `$id` host is a placeholder until the project has a page.

The package in this directory embeds the files, so the command and its tests validate against what is published here.
