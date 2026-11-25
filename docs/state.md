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
- the names of the outputs, never their values;
- the place each `terraform_remote_state` reads from: its backend, bucket or container, key or prefix, organization and workspace, never a credential.

Everything else is dropped while the state is read. Tags are not read at all, so a state snapshot has none.

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

Edges follow `graph/v1`: `from` refers to, or depends on, `to`. So what a change breaks follows edges backwards from the thing that changes, across states through the `remote_state` edges.

A `terraform_remote_state` is matched to a source by the backend's own naming: bucket and key (and `env:/<workspace>/` for a workspace of the S3 backend), bucket and prefix with `<workspace>.tfstate` for Cloud Storage, account, container and key (and `env:<workspace>`) for Azure, organization and workspace for HCP Terraform, and, for a local backend, a source whose path ends with the path the data source names. A path that leaves the data source's own folder (`../net/terraform.tfstate`) cannot be placed and goes to a placeholder.

A resource found in more than one state is one node, listed under the first state read (states are read in order of location), with a `defined_in` edge to each. A data source is identified by the state it is read in, since many states read the same thing.

## What it cannot tell you

The manifest's `limits` says, in plain text: that no live inventory was read, so nothing is marked unmanaged; which states `terraform_remote_state` reads that are not in the snapshot; how many dependencies name an address the state does not hold; how many resources more than one state holds; and how many ids were left out. A resource whose ARN or ID does not carry an account or a region has none.

`document_sha256` of a source is the hash of what the reader kept of the state (see `digest` in `internal/ingest`), not of the state's bytes, which the reader does not keep. It changes whenever anything the snapshot holds changes.

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
