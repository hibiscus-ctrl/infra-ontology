# Reading Terraform state

`infra-ontology snapshot build --state LOCATION` reads Terraform or OpenTofu state into a snapshot. It uses [infraharvest](https://github.com/IgnatG/infraharvest)'s `pkg/tfstate`, so it reads state the way infraharvest does: no `terraform init`, no plan, no Terraform binary, only the credentials of the store. It is the only command that reads a backend; `query`, `diff`, `verify` and `serve-mcp` read local files.

```sh
infra-ontology snapshot build \
  --state s3://acme-tfstate/prod/ \
  --state gs://acme-gcs-state/dns \
  --state azblob://acmestate/tfstate/hub \
  --state hcp://acme/platform \
  --state ./legacy/terraform.tfstate \
  --label prod
```

`--state` can be given as many times as you like. `--out DIR` says where the snapshot folder goes (default `./.infra-ontology/snapshots/`), `--label` names the snapshot, `--parent ID` names the snapshot it follows, and `--created-at` fixes the time (RFC 3339) for a repeatable build. `--from-json` stays, as a path for tests; it cannot be mixed with `--state`.

## Locations

| Form | Reads |
| --- | --- |
| a file, or a folder | the state file, or every `*.tfstate` file in the folder, outside any `.terraform` folder |
| `s3://bucket/prefix` | every `*.tfstate` object under the prefix, and the workspaces of the S3 backend. `?region=`, `?profile=` and `?workspace_key_prefix=` are read from the location |
| `gs://bucket/prefix` | every `*.tfstate` object under the prefix |
| `azblob://account/container/prefix` | the same in Azure Blob Storage, workspaces of the `azurerm` backend included. `https://account.blob.core.windows.net/container/prefix` is accepted as it is, and so is the US Government or China host |
| `hcp://organization/workspace` | the current state of an HCP Terraform workspace. `workspace*` reads every workspace whose name starts so, and `?host=` names a Terraform Enterprise host. `tfc://` is accepted too |

A location that holds no state fails, rather than passing for a root with no resources. Credentials come from the environment's default chains (AWS, Azure and Google) and, for HCP Terraform, from `TF_TOKEN_*` or the Terraform CLI configuration. No flag takes a credential, and nothing is written to the cloud.

## What a snapshot keeps

State holds secrets, in attributes, in outputs and in the configuration of `terraform_remote_state`. The reader decodes a state one resource at a time and keeps only:

- the address, type, provider, module path and dependencies of each instance;
- its `id` and `arn` (and, for a resource with neither, its resource identity, which is used for the account and region only);
- its tags, or its labels on Google Cloud, for a managed resource and not for a data source (a data source's tags are the looked-up resource's, not one this state manages): the `tags` and `tags_all` attributes (AWS and Azure; `tags_all` wins where the two differ, so a provider's default tags are in) and the `labels` attribute, string values only, after the secret detectors (see below);
- for an `aws_iam_role`, who its trust policy names: each statement's effect, its principals, whether it can assume the role and whether it has a condition (see [Who can assume a role](#who-can-assume-a-role)), never the policy's text;
- the names of the outputs, never their values;
- the place each `terraform_remote_state` reads from: its backend, bucket or container, key or prefix, organization and workspace, never a credential.

Everything else is dropped while the state is read.

Tags go through the same filter as an inventory's ([inventory.md](inventory.md#what-a-snapshot-keeps)): a tag is dropped when its key names a secret, or its key or value has a credential's format or looks random enough to be one, and `--drop-tag KEY` and `--drop-tags` apply. The dropped keys are listed in `redaction.tag_keys_dropped` and `limits` counts the tags. Where a resource is in a state and in an inventory, the node has the inventory's tags if the inventory has any, whole and not mixed with the state's (the inventory is what the cloud holds now); the state's tags stay for a resource the inventory has none for, and for one no inventory lists, except what the inventory's export dropped: with `all_tags_dropped` the state's tags of the resources joined to that inventory go too, and the keys in its `tag_keys_dropped` are removed from them. `redaction.all_tags_dropped` is therefore true only when no node in the snapshot has a tag.

Two more rules keep a value out that is not an identifier. The `id` of a `random_*` resource is a generated value (`random_string`'s id is its result), so it is not kept, and nor are the ids of the `http`, `external`, `local`, `null`, `time`, `archive` and `tls` providers, which are free text (the URL `data.http` read, whatever an `external` program printed). And an `id` or ARN that has, or holds, the format of a credential, as found by infraharvest's `pkg/secretscan`, or that is a URL with a user name, a password or a query parameter, is not kept either: the instance is identified by its address instead, and the manifest's `limits` counts them. Locations also go through the secret detectors: a user name or password in a URL, a query parameter other than `region`, `profile`, `workspace_key_prefix` and `host`, and any part that has a credential's format are removed from the `location` of a source, a state root's name and an error's reason.

A test builds a snapshot from states that hold planted secrets in attributes, outputs and `terraform_remote_state` configuration, and fails if any of them is in any file the command writes, or on its output.

## What becomes what

| In the state | In the snapshot |
| --- | --- |
| a state | a `sources` row (backend, location, workspace, serial, lineage, Terraform version, the time it was read) and a `state_root` node |
| a resource instance or data source | a `resource` node: the Terraform type the infraharvest catalogue knows it by (`aws_alb` is `aws_lb`), the `id` as `native_id`, the ARN or resource path as `arn_or_path`, and the cloud, account and region its ARN, ID or identity gives. Azure resource IDs are folded to lower case. A resource managed by the state is `managed`; what a data source reads is `unknown` |
| the instance's state | a `defined_in` edge to the state root (`state_membership`, observed) |
| `dependencies` | a `depends_on` edge (`state_dependency`, observed). A dependency has no instance key, so it reaches every instance of `count` and `for_each`, and a dependency on a module reaches the module call |
| a module path | a `module_call` node for each call, and `contained_in` edges (`module_containment`, computed) from a resource to its module call, a call to the call around it, and a top-level call to the state root |
| `terraform_remote_state` | a `reads_state_of` edge (`remote_state`, observed) from its data node to the state root of the state it reads, when that state is among the sources; otherwise to an `external` placeholder node, and `limits` names it |
| an `aws_iam_role`'s trust policy | `can_assume` edges from the principals it names to the role (see [Who can assume a role](#who-can-assume-a-role)) |

Edges follow `graph/v1`: `from` refers to, or depends on, `to`. So what a change breaks follows edges backwards from the thing that changes, across states through the `remote_state` edges.

A `terraform_remote_state` is matched to a source by the backend's own naming: bucket and key (and `env:/<workspace>/` for a workspace of the S3 backend), bucket and prefix with `<workspace>.tfstate` for Cloud Storage, account, container and key (and `env:<workspace>`) for Azure, organization and workspace for HCP Terraform, and, for a local backend, a source whose path ends with the path the data source names. A path that leaves the data source's own folder (`../net/terraform.tfstate`) cannot be placed and goes to a placeholder.

A resource found in more than one state is one node, listed under the first state read (states are read in order of location), with a `defined_in` edge to each. A data source is identified by the state it is read in, since many states read the same thing.

## Who can assume a role

For each `aws_iam_role` a state holds, the trust policy (`assume_role_policy`) says who may assume it. The reader keeps only the principals each statement names; the snapshot gets a `can_assume` edge from each principal to the role (`from` can assume `to`), which is the first answer to "who can reach this". The policy's text, its `Sid`, its resources and the keys and values of its conditions are dropped while the state is read, and no output holds them.

| The trust policy names | The edge starts at | Confidence and basis |
| --- | --- | --- |
| a role or user in the role's account | that role or user, if the snapshot holds it, otherwise an `external` placeholder built from the ARN | `computed`, `trust_policy` |
| a role or user in another account | the same | `inferred`, `trust_policy_cross_account` |
| an account (`arn:aws:iam::123456789012:root`, or the 12 digits) | an `account` node | `inferred`, `trust_policy_account` |
| a service (`ec2.amazonaws.com`) | an `external` placeholder of type `service_principal` | `computed`, `trust_policy` |
| `"*"`, or every principal but those listed (`NotPrincipal`) | one `external` placeholder of type `any_principal` | `inferred`, `trust_policy_wildcard` |

A statement with a `Condition` makes its edges `inferred` (`trust_policy_condition`), and so does a `Deny` statement anywhere in the policy (`trust_policy_deny`): neither is evaluated, and the edge is kept rather than dropped, so a reader sees a possible path and a confidence that says it is only that. Where two statements give the same edge, the stronger confidence wins.

What it does not say. An edge says the trust policy allows the principal in, not that the principal can: identity policies, permission boundaries, service control policies and session policies are not read, and a principal in another account needs an identity policy there too. Only roles a state holds have edges, so a role made outside Terraform has none. Federated principals (OIDC and SAML providers), canonical users, assumed-role sessions, unique IDs of deleted principals and ARNs of other services are not turned into edges; `limits` counts them, and counts the roles whose policy could not be read. The edges are in the manifest's format from minor version 2 on.

With `--hash-ids`, the native ID, ARN and name of a placeholder are hashed with the other IDs (the account stays readable, as for every node, and so does its type), so the same key gives the same edges. `--drop-addresses` has nothing to drop from these edges: they carry no Terraform address.

## Hashing IDs

`--hash-ids` hashes what a snapshot says about where things are and what they are called, so that a snapshot can leave the machine that read the state:

```sh
export INFRA_ONTOLOGY_KEY=$(openssl rand -hex 32)      # or --hash-key-file FILE
infra-ontology snapshot build --state s3://acme-tfstate/prod/ --hash-ids
```

The key stays with you. It comes from the file `--hash-key-file` names or, without one, from `INFRA_ONTOLOGY_KEY` (`INFRAHARVEST_EXPORT_KEY`, which `infraharvest export` reads, is the fallback, so one key serves both tools). It must be 16 bytes or more. `--hash-ids` without a key is a usage error (2), and so is `--hash-key-file` without `--hash-ids` and `--hash-ids` with `--from-json`. The key is never written: not to the snapshot, not to the manifest (which records the algorithm, `hmac-sha256`, and no fingerprint of the key), not to standard output or error.

What is hashed, as the HMAC-SHA256 in hexadecimal that `infraharvest export --hash-ids` writes for the same key (`pkg/secretscan`):

| Hashed | Where |
| --- | --- |
| `native_id`, `arn_or_path`, `name` | `nodes`. A resource's ID is hashed as the state wrote it, so it is the hash an infraharvest export made with the same key has for the same ID |
| `address`, `module`, `root` | `nodes`: Terraform addresses, module paths and the location of the state a node is in |
| `location`, `workspace` | `sources`: where a state or an inventory file was read from, and the workspace its location names |
| `document_sha256` | `sources`: it hashes what was read, so it is keyed too |
| `node_id`, `source_id` | the HMAC of the node's kind, cloud, account, region, type and hashed native ID, and an identifier made from the hashed location. `edge_id` is the SHA-256 of an edge's kind and its two (hashed) ends |

Types, accounts, regions, kinds, statuses, counts and times stay readable, as in infraharvest. So do a state's serial, Terraform version and lineage, which is a random UUID. The tags of a state and of an inventory go through infraharvest's tag filter with the key, so a `Name` tag, or a tag whose value is or holds an ID or a name, is hashed too, and a tag whose key names the resource is dropped. The filter only looks for the ID and the name, so a second pass looks for the node's other identifiers (its ARN, its cloud path, the ID a cloud gives it, as for an SQS queue whose ID is its URL and whose ARN is another value): a tag whose value holds one, in any case, with at least four characters, is hashed the way the node's own ARN or path is, so the two are the same value, and a tag whose key holds one is dropped and not listed. The same holds for the tags of an inventory that did not hash its own IDs; one that did has hashed them upstream. A `terraform_remote_state` read from a state that is not in the snapshot is an `external` node with a hashed name, and `limits` does not list its location. The reason a source could not be read is replaced by a fixed text, since an error message holds paths and names; the source's status and hashed location remain.

The same key gives the same hashes, so the same estate gives the same `snapshot_id`, `verify` and `diff` work as they do on any snapshot, and two snapshots hashed with one key can be compared. Two keys give two snapshots with no node in common. A hashed snapshot says so in the manifest (`redaction.hash_algorithm` is `hmac-sha256` and `redaction.ids_hashed` is true) and in `limits`.

A test builds a hashed snapshot from the fixtures and fails if the key, in any form, or any value it hides is in any file the command writes.

## Dropping addresses

`--drop-addresses` leaves Terraform addresses out of a snapshot, for sharing it outside the team:

```sh
infra-ontology snapshot build --state s3://acme-tfstate/prod/ --drop-addresses
```

The `address` and `module` of every node are empty. The `name` is empty on every module call (it was the last part of the call's path, with its `for_each` or `count` key) and on every resource a state holds (it was the last part of the address, `main` of `aws_vpc.main`), so `tf_type` and `name` no longer give `type.name`. A module call node keeps no `native_id` (it was the state and the call's address), and the placeholder of a `terraform_remote_state` whose backend names no state is told apart by its place in the state, not by its address. The manifest says so: `redaction.addresses_dropped` is true, and `limits` says that addresses and module paths are left out. Edges, sources and the rest of the manifest never held an address; they are as they would be without the flag, and `export graph` writes `redaction.addresses` as `dropped`. Inventories are matched to state by address before they are dropped, so no status changes. A tag whose key or value holds, in any case, the node's address, its module path, its Terraform name, the name of a module call on its path or a `for_each` key of the address (each of four characters or more, as for secretscan's names; a count index is not looked for) is dropped with them, and so is a tag whose value (or key) is, in any case, the Terraform name, a call's name or a key whatever its length (`tf = web`, `module = network`, `az = s3`), so `tf_address = module.network.aws_vpc.main` or `Name = main` does not give them back; this covers a resource a state holds, with the inventory's tags where it was joined. These tags are counted in `limits` with the other dropped tags, and their keys are not listed in `redaction.tag_keys_dropped`, since a key can be the address.

What stays: the `name` of a resource only an inventory holds (the name the cloud gives it, not one made from an address), the `name` of a state root and of an external placeholder (a location), the `root` of each node (the location of its state), and every node ID, edge, status and count, so `diff` still joins. The node IDs of module calls, data sources and resources without an ID are SHA-256 hashes of the state location and the address, and the `root` is still there, so without `--hash-ids` anyone who guesses a state location and a module path or address can compute the hash and confirm the guess. Combine the two flags when the snapshot leaves your hands: with `--hash-ids` those IDs are keyed, the `root` is hashed and the names that stay are hashed too; the same key gives the same snapshot. The `limits` text says this when no key is used. `--drop-addresses` with `--from-json` is a usage error (2), as `--hash-ids` is.

A test builds a snapshot from the fixtures, with the flag alone and with `--hash-ids`, and fails if any address, module path, resource name, module call name or `for_each` key of the fixtures is in any file the command writes, in its output, or in what `verify`, `export graph` and `diff` write.

## What it cannot tell you

The manifest's `limits` says, in plain text: that no live inventory was read, so nothing is marked unmanaged (with [`--inventory`](inventory.md), what it says instead); which states `terraform_remote_state` reads that are not in the snapshot; how many dependencies name an address the state does not hold; how many resources more than one state holds; and how many ids were left out. A resource whose ARN or ID does not carry an account or a region has none.

`document_sha256` of a source is the hash of what the reader kept of the state (see `digest` in `internal/ingest`), not of the state's bytes, which the reader does not keep. It leaves out the tags, on purpose: an unkeyed hash over raw tag values would let anyone confirm a guess at one, so a change to a tag alone does not change it.

## Partial snapshots and exit codes

A location that cannot be read does not stop the others. It becomes a source with status `failed` and a reason (credentials scrubbed), the manifest is `partial` and lists it, and the command exits with 3. If no state could be read, nothing is written and it exits with 1. A location that is not one `pkg/tfstate` reads, a path that does not exist, or a store this build does not link, is a usage error (2) before anything is read.

## Build tags

The default build reads files and folders only, and links no cloud SDK. Each store is behind a build tag, so a build links the clouds it names and no others:

| Tag | Reads | Pulls in |
| --- | --- | --- |
| `s3` | `s3://` | the AWS SDK |
| `gcs` | `gs://` | the Google Cloud SDK |
| `azblob` | `azblob://`, `https://*.blob.core.windows.net` | the Azure SDK, which brings `apache/arrow-go` |
| `hcp` | `hcp://`, `tfc://` | HashiCorp's `terraform-svchost`, which finds the credentials Terraform uses |

```sh
go build -tags s3,gcs,azblob,hcp ./cmd/infra-ontology
go build -tags noduckdb,s3,gcs,azblob,hcp ./cmd/infra-ontology   # pure Go, no query engine
```

The release archives are built with all four tags. A build that does not link a store says so, and names the tag, when it is given a location of that kind.
