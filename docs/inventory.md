# Reading a live inventory

`infra-ontology snapshot build --inventory FILE` reads what [infraharvest](https://github.com/IgnatG/infraharvest) exports of a live estate, and joins it to Terraform state. State says what Terraform manages; the inventory says what is there. A resource in both is one node, `managed`; one only in the inventory is a node of its own, and is how you find what no Terraform manages.

```sh
infraharvest discover aws
infraharvest export infrastructure --command discover --out-file inventory.json

infra-ontology snapshot build \
  --state s3://acme-tfstate/prod/ \
  --inventory inventory.json \
  --label prod
```

`--inventory` can be given as many times as you like, with or without `--state`, and reads a file only: no cloud SDK is linked, no credential is used and nothing is called. `--out`, `--label`, `--parent` and `--created-at` are as for [state](state.md).

## What it reads

Two documents of infraharvest's [export](https://github.com/IgnatG/infraharvest/blob/main/docs/export.md), each described by a JSON Schema under infraharvest's `schemas/`. The command tells them apart by their `schema` member, and a file that is neither is a failed source.

| Document | What it gives |
| --- | --- |
| `infraharvest/inventory/v1` (`infraharvest export infrastructure`) | for each resource: its Terraform type, import ID, account, region, name, tags and who manages it (`managed`, `other_iac` or `unmanaged`, with whether a state, a tag or nothing says so) |
| `infraharvest/ocsf-inventory/v1` (`infraharvest export infrastructure --schema ocsf-inventory`) | the same resources as OCSF events, and what the first leaves out: the name the cloud itself gives a resource (`uid`, with the import ID as `uid_alt`: an ARN, or an Azure resource ID), and, for a resource an import took over, its Terraform address, module call and root |

infra-ontology does not import infraharvest's `internal/` packages and adds nothing to either format. It reads each document as a projection: it names the fields it keeps, the decoder skips every other member, and nothing it does not name can reach a snapshot.

## Joining to state

A resource of an inventory is the same thing as a node a state produced when they have the same Terraform type (`aws_alb` is `aws_lb`) and the same ID, or the same ARN or resource path, and their accounts and regions do not contradict each other. Azure resource IDs are compared without regard to case; ARNs and Google paths keep theirs. The joined node is the state's, with the same `node_id`, its address and its source. The inventory adds what the state does not hold: the account and region where the state's ARN has none (an S3 bucket's), `inventory_type`, the name, and the tags.

| Where the resource is | `managed_status` | `confidence` |
| --- | --- | --- |
| in a state and in an inventory | `managed`, whatever the inventory says: the inventory of a `discover` run lists everything as unmanaged, as it reads no state | `observed` |
| only in an inventory | the status the inventory gives it: `unmanaged`, `other_iac` (CloudFormation or another tool) or `managed` (a state infraharvest read that was not given here) | `observed`; `inferred` when the inventory says it is managed because of Terraform's tags and not a state |
| only in a state | `managed`, as before | `observed` |

The plan has four statuses and no `missing` or `drifted`, so a resource in a state that no inventory lists stays `managed`. A resource cannot be called gone because an inventory does not list it: the inventory may not cover its type, its account or its region. The manifest's `limits` counts them instead: the resources of the states read that are not in the inventories, where an inventory lists their type in their account.

An inventory that hashes its IDs (`infraharvest export --hash-ids`) is matched to state when the snapshot is built with `--hash-ids` and the same key ([docs/state.md](state.md#hashing-ids)): the build hashes the IDs and ARNs the states hold, as infraharvest does, and joins the two by hash. What is joined is the same as for an inventory that is not hashed, and what only the inventory lists keeps the status it gives it. Three things limit this:

- A hash cannot be folded to lower case, so an Azure resource ID is hashed as the export wrote it, and joins when the state writes it in the same case (or in lower case).
- Nothing says which key an export was hashed with. If a hashed inventory lists resources of the types and accounts the states manage and matches none of them, it was probably hashed with another key: what it calls `unmanaged` is `unknown` instead, and `limits` says how many inventories do so.
- Without `--hash-ids` (or with an inventory that is not hashed and states that are) the IDs cannot be compared. The inventory's resources are added as they are, and those it calls `unmanaged` are `unknown` when states were read, since being absent from them says nothing. `limits` says how many inventories do so.

Inventories that are not hashed are matched in the clear whatever `--hash-ids` says, and their IDs, names, addresses and paths are hashed as the snapshot is written.

A resource listed by more than one document is one node: it keeps the status that knows most (`managed`, then `other_iac`, then `unmanaged`) and what each document gives.

## Edges

Both are `contained_in` edges from the resource to the one around it, `computed` from identifiers, and cite the inventory that lists the resource. They are made only where an inventory is one end, so a snapshot of state alone has neither.

| `basis` | Where |
| --- | --- |
| `catalogue_child` | The infraharvest catalogue lists a type as a part of another (the versioning of an S3 bucket, its encryption and its policy), and a resource of the first has the same ID as one of the second: `aws_s3_bucket_versioning` `acme-logs` is in `aws_s3_bucket` `acme-logs`. Resources whose ID is not their parent's (a listener, whose ID is its own ARN) get no edge |
| `resource_path` | An Azure resource ID names its parent: `.../virtualNetworks/v/subnets/s` is in `.../virtualNetworks/v`, and a top-level resource is in its resource group. The edge goes to the nearest of them that is a node of the snapshot |

Google resource paths and AWS ARNs name no parent, so they get `catalogue_child` edges only. Account nodes are not made.

## What a snapshot keeps

The same as for state: identifiers, and no attribute value. From an inventory it keeps the resource's type, ID, ARN or path, account, region, name, status and tags, and, from an OCSF inventory, the address, module address and root of an import.

- **IDs.** A resource whose ID, or ARN, has or holds the format of a credential, or is a URL with a user name, a password or a query parameter, is left out, and `limits` counts them. It cannot be told from another thing without its ID.
- **Names, addresses and roots** that look like credentials are dropped; the node stays. A root is a location, so it goes through the same filter as a state's.
- **Tags** go through infraharvest's `pkg/secretscan` (`NewTagFilter`, `LooksSecret`): a tag is dropped when its key names a secret (`db_password`), or its key or value has a credential's format or looks random enough to be a key or a token. The dropped keys are listed in the manifest's `redaction.tag_keys_dropped`, except a key that is itself a credential, and `limits` counts the tags. The keys an export dropped before are listed too.
- `--drop-tag KEY` (repeat it, or separate keys with commas) drops a tag key, and `--drop-tags` drops every tag, as `infraharvest export` does. `--drop-tags` sets `redaction.all_tags_dropped`.

A test builds a snapshot from inventories that hold secrets in IDs, names, tags, addresses and members the reader does not name, and fails if any of them is in any file the command writes, or on its output.

## Sources

Each file is a `sources` row of kind `inventory`: backend `file`, its path, `collector` `infraharvest` with its version, the time the document says it was made (`generated_at`, or the newest event's time), and `document_sha256`, the hash of what was kept of it. A file that cannot be read, or is not one of the two documents, is a source with status `failed` and a reason, the snapshot is `partial` and the command exits with 3. If nothing could be read, nothing is written and it exits with 1. A file that does not exist is a usage error (2). An inventory that counts resources whose import failed (`coverage.totals.failed`) is `partial` too.

## What it cannot tell you

`limits` says, in plain text, that the snapshot was read from state and inventories, from inventories only, or from state only; how many inventory resources were left out for their ID and how many tags were dropped; how many inventories hash their IDs; how many resources an inventory calls managed that are in none of the states read; and how many resources of the states are not in the inventories.

- Without an ARN, a resource that is only in an inventory has a `node_id` from its account and region as the inventory gives them, which may not be the one a state later gives it: such a resource shows in a `diff` as removed and added when a state starts to hold it, not as changed. Ask for the ARN in the OCSF inventory, where infraharvest knows it.
- A joined node cites its state as its source. The inventory that listed it is the source of its edges, and its `document_sha256` and time are in `sources`.
- Google ancestors (folders, organisation) are not in `inventory/v1`, so no edge says which folder holds a project.
