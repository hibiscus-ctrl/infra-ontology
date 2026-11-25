# Permissions

What each source needs to be read, and no more. infra-ontology only reads: no permission below creates, changes or deletes anything, and none is needed for locking, because the command takes no state lock. Credentials come from the environment's default chains, never from a flag's value ([security.md](security.md)).

State holds secrets, so the identity that reads it can see them even though the tool drops them. Give it a role of its own, scoped to the state it needs, and run it where reading that state is acceptable.

Only `snapshot build` reads a backend. `query`, `diff`, `verify`, `export` and `serve-mcp` read local files and need no cloud permission. A store is read only in a build that links it (`s3`, `gcs`, `azblob` or `hcp` build tags; the release archives have all four, see [state.md](state.md#build-tags)).

| Source | Permissions | Credentials from |
| --- | --- | --- |
| A file or folder | read access to the files | the file system |
| `s3://` | `s3:ListBucket` and `s3:GetObject` | the AWS default chain |
| `gs://` | `storage.objects.list` and `storage.objects.get` | Google application default credentials |
| `azblob://` | list and read blobs | Azure's default chain, or the `ARM_*` variables |
| `hcp://` | read workspaces and state versions | `TF_TOKEN_*` or the Terraform CLI configuration |
| `--inventory FILE` | read access to the file | the file system |

## Local files

`--state` takes a file, or a folder: every `*.tfstate` file in it, outside any `.terraform` folder. Nothing else is needed.

## S3

The store lists the objects under the prefix and reads each `*.tfstate`. For the other workspaces of the S3 backend, which live at `<workspace_key_prefix>/<workspace>/<key>` at the root of the bucket (`env:` unless the location says `?workspace_key_prefix=`), it lists that prefix too.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListState",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::acme-tfstate",
      "Condition": { "StringLike": { "s3:prefix": ["prod/*", "env:/*"] } }
    },
    {
      "Sid": "ReadState",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": ["arn:aws:s3:::acme-tfstate/prod/*", "arn:aws:s3:::acme-tfstate/env:/*"]
    }
  ]
}
```

If the bucket encrypts with a KMS key, the role also needs `kms:Decrypt` on that key, as for any read of the object. No DynamoDB or lock-file permission is needed. `?region=` and `?profile=` in the location choose the region and the shared-config profile.

## Cloud Storage

`roles/storage.objectViewer` on the bucket (or on the prefix, with an IAM condition) gives `storage.objects.list` and `storage.objects.get`. The client asks for the read-only scope. Credentials are Google's application default credentials: `GOOGLE_APPLICATION_CREDENTIALS`, `gcloud auth application-default login` or the workload identity of the job.

## Azure Blob Storage

Give the identity **Storage Blob Data Reader** on the storage account or the container: it lists and reads blobs and nothing else. The credentials are, in order:

1. `ARM_ACCESS_KEY`, the account's access key. It can do everything on the account, so prefer a role.
2. `ARM_SAS_TOKEN`, which needs the read and list permissions on the container.
3. `ARM_CLIENT_ID`, `ARM_CLIENT_SECRET` and `ARM_TENANT_ID`, a service principal that has the role.
4. Azure's default credential chain: the Azure CLI's login, a managed identity or workload identity federation, with the role.

## HCP Terraform and Terraform Enterprise

The reader calls the workspace API of the host (`app.terraform.io`, or `?host=` for Terraform Enterprise): it looks a workspace up by name, lists an organization's workspaces when the location ends in `*`, and reads the current state version. The token needs to see those workspaces and read their state versions, which is more than reading their outputs. Use a team token with the workspace permission to read state versions on the workspaces you name (the built-in access levels that include it are set out in HCP Terraform's documentation), and the organization permission to read workspaces if you use `*`. The token comes from `TF_TOKEN_<host>` (dots as underscores) or the credentials `terraform login` saved. It is sent only to the host's API over https.

## A live inventory

`--inventory` reads the files infraharvest exports (`inventory/v1` and `ocsf-inventory/v1`); infra-ontology itself calls no cloud API for it. The read-only access infraharvest needs to make those files is described in [its permissions documentation](https://github.com/IgnatG/infraharvest/blob/main/docs/permissions.md).
