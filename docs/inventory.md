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

A resource of an inventory is the same thing as a node a state produced when they have the same Terraform type (`aws_alb` is `aws_lb`) and the same ID, or the same ARN or resource path, and their accounts and regions do not contradict each other. Azure resource IDs are compared without regard to case; ARNs and Google paths keep theirs. The joined node is the state's, with the same `node_id`, its address and its source. The inventory adds what the state does not hold: the account and region where the state's ARN has none (an S3 bucket's), `inventory_type` and the name. Tags: the inventory's win where it has any, and replace the state's whole; the state's tags stay where the inventory has none for the resource, less what the inventory's export dropped (all its tags with `all_tags_dropped`, or the keys of `tag_keys_dropped`).

| Where the resource is | `managed_status` | `confidence` |
| --- | --- | --- |
| in a state and in an inventory | `managed`, whatever the inventory says: the inventory of a `discover` run lists everything as unmanaged, as it reads no state | `observed` |
| only in an inventory | the status the inventory gives it: `unmanaged`, `other_iac` (CloudFormation or another tool) or `managed` (a state infraharvest read that was not given here) | `observed`; `inferred` when the inventory says it is managed because of Terraform's tags and not a state |
| only in a state, and an inventory that listed its place in full does not list it | `missing` | `computed` |
| only in a state, otherwise | `managed`, as before | `observed` |

A resource a state holds that no inventory lists stays `managed` unless an inventory can say it is gone: see [Missing resources](#missing-resources). The manifest's `limits` counts the ones that stay `managed` where an inventory lists their type in their account.

An inventory that hashes its IDs (`infraharvest export --hash-ids`) is matched to state when the snapshot is built with `--hash-ids` and the same key ([docs/state.md](state.md#hashing-ids)): the build hashes the IDs and ARNs the states hold, as infraharvest does, and joins the two by hash. What is joined is the same as for an inventory that is not hashed, and what only the inventory lists keeps the status it gives it. Three things limit this:

- A hash cannot be folded to lower case, so an Azure resource ID is hashed as the export wrote it, and joins when the state writes it in the same case (or in lower case).
- Nothing says which key an export was hashed with. If a hashed inventory lists resources of the types and accounts the states manage and matches none of them, it was probably hashed with another key: what it calls `unmanaged` is `unknown` instead, and `limits` says how many inventories do so.
- Without `--hash-ids` (or with an inventory that is not hashed and states that are) the IDs cannot be compared. The inventory's resources are added as they are, and those it calls `unmanaged` are `unknown` when states were read, since being absent from them says nothing. `limits` says how many inventories do so.

Inventories that are not hashed are matched in the clear whatever `--hash-ids` says, and their IDs, names, addresses and paths are hashed as the snapshot is written.

The `ids_hashed` flag of a document is a claim, and is checked: a hashed inventory must hold only values with the shape of a hash (64 hexadecimal digits) in its IDs, names, addresses, module paths and roots. One that holds any other is read as not hashed, and `limits` says how many were, so that with `--hash-ids` its values are hashed here with the key and a document that is mislabelled cannot put a raw identifier into a snapshot whose manifest says `hmac-sha256`.

A resource listed by more than one document is one node: it keeps the status that knows most (`managed`, then `other_iac`, then `unmanaged`) and what each document gives.

## Missing resources

`missing` is a node a state holds that no inventory lists, where an inventory could have: a state resource is marked `missing` only when all of these hold for one inventory, and otherwise it stays `managed`, which proves nothing either way.

1. The inventory is an `infraharvest/inventory/v1` document, which says how complete its listing was: its `coverage` has `totals`, `types` and `scopes` (a document with `"coverage":{}`, or without one of the three, does not say, and counts as incomplete), and it has a `filters` member. An OCSF inventory does not, so it never marks anything missing. A document an earlier release of infraharvest wrote has none of the completeness fields below, so it never marks anything missing either: a field that is absent is taken as not complete.
2. No kind of filter narrowed the listing: `filters.id`, `tag`, `where`, `services`, `group` and `partial` are all `false` (`--id`, `--tag`, `--where`, `--services` or `--skip`, a provider scope of one group such as Azure's `--resource-group`, a listing in part such as `--resource-explorer`). A kind the member leaves out counts as used. Listings made from `--reuse-inventory` are not complete either, and say so in the scope.
3. No import failed (`coverage.totals.failed` is 0), the run's selection excluded nothing and nothing was left out of the import (`coverage.totals.excluded` and `left_out` are 0: an `infraharvest import` with a selection file, include or exclude rules lists only some of what is there), no resource of it was left out of the snapshot for its ID, and, if it hashes its IDs, the snapshot was built with `--hash-ids` and its key and the inventory matched the states.
4. Every scope of the document that is the resource's cloud, account and region (`aws/123456789012/eu-west-2`) has no failed, skipped, excluded or left-out resource in `coverage.scopes`, has `complete` true, and names the resource's type in its `complete_types` (the types it listed in full, including those it found none of). The resource's type has no failed, skipped, excluded or left-out resource in `coverage.types` and, where `coverage.types` has an entry for it, that entry has `complete` true (a type the document found none of has no entry, and `complete_types` says it was listed). Azure resource IDs have no region, so for Azure the account (the subscription) is the scope, and the inventory must also list some resource in the same resource group: a listing of one group says nothing of another.
5. The document lists, and so joins to the state, at least one resource of the type in that account: if none joins, the IDs of the type may not compare between state and inventory. It need not list a resource of the type in that region: a type in `complete_types` that the document lists none of is a type with none there.
6. The resource has an account and, outside Azure, a region. Joins are the ones in [Joining to state](#joining-to-state), so Azure IDs that differ only in case are one resource and are not missing.

If any inventory file could not be read, nothing is marked `missing`: the one that failed may list the resource. The node keeps its address, ID, tags and source; its `confidence` is `computed`, not `observed`, since the status comes from an absence.

`missing` says the resource was not in the listing when the inventory was made (its time is in `sources`). A resource created after the inventory also shows as missing, so build the inventory and the state close together. A listing infraharvest made with filters drops resources before they are counted; since infraharvest records the kinds of filter and the types it listed in full (see its `docs/export.md`), such a listing marks nothing missing. Use inventories of whole scopes.

**`drifted` is not a status.** Whether a live resource differs from its state needs the resource's attributes on both sides, and a snapshot never holds an attribute value. Comparing only tags would call a resource drifted when the cloud added a tag or a provider's default tags differ, and say nothing of the rest, so the format does not offer it. Use `terraform plan`, or `infraharvest drift`, for that.

## Edges

All are `contained_in` edges from the resource to the one around it, `computed` from identifiers, and cite the inventory that lists the resource. They are made only where an inventory is one end, so a snapshot of state alone has neither.

| `basis` | Where |
| --- | --- |
| `catalogue_child` | The infraharvest catalogue lists a type as a part of another (the versioning of an S3 bucket, its encryption and its policy), and a resource of the first has the same ID as one of the second: `aws_s3_bucket_versioning` `acme-logs` is in `aws_s3_bucket` `acme-logs`. Resources whose ID is not their parent's (a listener, whose ID is its own ARN) get no edge |
| `resource_path` | A resource ID names its parent. In Azure, `.../virtualNetworks/v/subnets/s` is in `.../virtualNetworks/v`, and a top-level resource is in its resource group. In Google, `projects/p/datasets/d/tables/t` is in `projects/p/datasets/d`. The edge goes to the nearest of them that is a node of the snapshot, and Google paths are compared as written, in the same case |
| `project` | A Google resource that no `resource_path` edge places is in its project: an `account` node with the native ID `projects/<project>`, made from the account the inventory (or the ID's `projects/<project>` path) gives the resource, and the same node for every resource in the project. The node has no address, no tags and the status `unknown`; with `--hash-ids` its native ID is hashed like the others |

AWS ARNs name no parent, so they get `catalogue_child` edges only. A Google ID names only what its own path says: a subnetwork's ID (`projects/p/regions/r/subnetworks/s`) does not name its network, a topic's subscription does not name the topic, and a bucket's name is no path, so those are in their project and not in the resource they refer to. Folders and the organization are not in an inventory, so no node or edge is made for them. An inventory exported with `--hash-ids` has no path to read, so its Google resources are in their project (from the account it keeps in clear) and in nothing nearer; build with `--hash-ids` yourself from an unhashed inventory to keep the paths.

## What a snapshot keeps

The same as for state: identifiers and tags, and no attribute value. From an inventory it keeps the resource's type, ID, ARN or path, account, region, name, status and tags, and, from an OCSF inventory, the address, module address and root of an import.

- **IDs.** A resource whose ID, or ARN, has or holds the format of a credential, or is a URL with a user name, a password or a query parameter, is left out, and `limits` counts them. It cannot be told from another thing without its ID.
- **Names, addresses and roots** that look like credentials are dropped; the node stays. A root is a location, so it goes through the same filter as a state's.
- **Tags** go through infraharvest's `pkg/secretscan` (`NewTagFilter`, `LooksSecret`): a tag is dropped when its key names a secret (`db_password`), or its key or value has a credential's format or looks random enough to be a key or a token. The dropped keys are listed in the manifest's `redaction.tag_keys_dropped`, except a key that is itself a credential, and `limits` counts the tags. The keys an export dropped before are listed too.
- `--drop-tag KEY` (repeat it, or separate keys with commas) drops a tag key, and `--drop-tags` drops every tag, as `infraharvest export` does. `--drop-tags` sets `redaction.all_tags_dropped`. The manifest also says so when every inventory read had dropped all its tags, but only if no node has a tag: the tags of a state, for a resource no such inventory lists, stay. With `--hash-ids`, a tag of an inventory that did not hash its IDs, whose value holds the resource's ARN or cloud path, is hashed with it, and one whose key holds it is dropped.

A test builds a snapshot from inventories that hold secrets in IDs, names, tags, addresses and members the reader does not name, and fails if any of them is in any file the command writes, or on its output.

## Sources

Each file is a `sources` row of kind `inventory`: backend `file`, its path, `collector` `infraharvest` with its version, the time the document says it was made (`generated_at`, or the newest event's time), and `document_sha256`, the hash of what was kept of it. A file that cannot be read, or is not one of the two documents, is a source with status `failed` and a reason, the snapshot is `partial` and the command exits with 3. If nothing could be read, nothing is written and it exits with 1. A file that does not exist is a usage error (2). An inventory that counts resources whose import failed (`coverage.totals.failed`) is `partial` too.

## What it cannot tell you

`limits` says, in plain text, that the snapshot was read from state and inventories, from inventories only, or from state only; how many inventory resources were left out for their ID and how many tags were dropped; how many inventories hash their IDs; how many resources an inventory calls managed that are in none of the states read; how many resources of the states are marked missing; how many are not in the inventories though one lists their type and account, and stay managed; and how many inventories could not be read, so that none is marked missing.

- Without an ARN, a resource that is only in an inventory has a `node_id` from its account and region as the inventory gives them, which may not be the one a state later gives it: such a resource shows in a `diff` as removed and added when a state starts to hold it, not as changed. Ask for the ARN in the OCSF inventory, where infraharvest knows it.
- A joined node cites its state as its source. The inventory that listed it is the source of its edges, and its `document_sha256` and time are in `sources`.
- Google ancestors (folders, organisation) are not in `inventory/v1`, so no edge says which folder holds a project.
