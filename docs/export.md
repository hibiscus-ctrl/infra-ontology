# Export

`infra-ontology export graph` writes a snapshot as an [infraharvest `graph/v1`](https://github.com/IgnatG/infraharvest/blob/main/schemas/graph-v1.schema.json) document, so that Terragram's renderer can draw it. The export is lossy by design: graph/v1 is a picture of resources, module calls and the references between them, and a snapshot holds more than that.

```sh
infra-ontology export graph <snapshot-dir>                 # the document on standard output
infra-ontology export graph <snapshot-dir> -o graph.json   # or in a file
infra-ontology export graph <snapshot-dir> --cloud aws     # needed if the snapshot has resources in more than one cloud
terragram graph graph.json -o estate.svg                   # Terragram draws it
```

The command verifies the snapshot first, as `snapshot verify` does, so a document never comes from a snapshot whose files do not match its manifest. It reads local files only. It prints the document and nothing else on standard output (with `-o`, one line naming the file, its nodes and its edges), and says on standard error what was left out.

## What a snapshot becomes

| In the snapshot | In graph/v1 |
| --- | --- |
| A `resource` node of the chosen cloud | A `resource` node. `type` is the Terraform type (the inventory type if there is none), `id` is the native id, `account` is the account, subscription or project (`unknown` if the node has none), and `region`, `environment`, `address` (the Terraform address) and `root` (the state root) come across as they are. |
| A `module_call` node | A `module` node with the module call's `module_address` (`module.network`), `root` and `environment`. A module call has no account or region of its own in a snapshot, so it takes the account that most of its resources have, and the region and environment if they all agree. Its `source` is `other`: a snapshot does not keep where a module comes from. |
| A `contained_in` edge from a resource to a module call | The resource's `parent`: the index of the module call. |
| A `depends_on` edge between two exported nodes | An edge: the `from` node refers to the `to` node. |
| `state_root`, `account` and `external` nodes | Nothing. The account and the state root live on as the `account` and `root` of the nodes they hold. |
| The cloud (`aws`, `azure`, `gcp`) | The document's `cloud` (`aws`, `azure`, `google`). A document has one cloud: with resources in several, give `--cloud`. |
| The snapshot id | The `run_id`, a UUID made from the snapshot id and the cloud. |
| The snapshot's `created_at` | `generated_at`, in UTC. |
| The manifest's redaction | The document's `redaction` (see below). |

Nodes are ordered modules first, then resources, by account, root, address, type and id (and, last, the snapshot's node id), and edges by `from` and `to`. The document is indented JSON with a closing newline.

## What is lost

graph/v1 cannot say these, so the export leaves them out:

- Tags, names, ARNs and resource paths. A graph/v1 document holds no names and no attribute values, which is why a picture of it can be shared.
- Managed status (managed, other IaC, unmanaged, unknown), confidence, sources and the manifest's coverage, limits and parent. An unmanaged resource is drawn like a managed one.
- State roots, accounts and the placeholders for state that was referenced but not read.
- Every edge kind but `depends_on`: containment of a module call in another module or in a state root, `defined_in`, `reads_state_of` and any kind a later version adds. Only a resource's containment in a module call survives, as its parent, so a nested module call is not drawn inside its parent.
- Resources of the other clouds, resources with no cloud, and resources with no type or no id.
- Where a module comes from, and its version.

`export graph` prints how many nodes and edges it left out, by kind, on standard error.

## Redaction

A document never says more than the snapshot's manifest allows.

- **Plain.** The addresses and roots come across as they are, and `redaction.addresses` is `plain`.
- **Ids hashed.** The snapshot's ids are already hashed (`hmac-sha256`), and so are its addresses and roots. They come across as they are, `redaction.ids_hashed` is true and `redaction.addresses` is `hashed`. The export never hashes anything itself and has no key. If a snapshot says its ids are hashed and a resource's id, address or root is not a hash, the export refuses and writes nothing, so that a document is never labelled hashed when a name is in it.
- **Addresses dropped.** A snapshot built with `--drop-addresses` has none to write (`redaction.addresses_dropped`). `address`, `module_address` and `root` are left out of every node, even if the snapshot's rows still have them, and `redaction.addresses` is `dropped`. Dropping wins over hashing.

The environment, the account and the region are not hashed in either export, as in infraharvest's.

## Checking a document

The tests validate every export against infraharvest's graph/v1 JSON Schema, vendored unchanged in `internal/export/testdata/` (the `NOTICE` there names the commit it was copied at; refresh it when graph/v1 changes). They also check what a schema cannot say and Terragram's reader does: every edge and parent is the index of a node, and a parent is a module call. A golden export of the estate fixture (`internal/export/testdata/estate.graph.json`) pins the bytes; rewrite it with `go test ./internal/export -update` and review the diff.

The same snapshot always gives the same bytes: the document holds no time or random value that does not come from the snapshot, and the order of the rows in the snapshot does not matter.

Terragram's reader and renderer are TypeScript and are not part of this repository's tests. To check by hand that Terragram accepts a document, from a checkout of Terragram with its dependencies installed and Node 24:

```sh
terragram graph graph.json -o estate.svg        # also: -f mermaid, -f json
```
