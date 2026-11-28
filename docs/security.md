# Security

What infra-ontology protects, from what, and where it stops. The rules are the red lines in [AGENTS.md](../AGENTS.md); a break of one is a vulnerability under [SECURITY.md](../SECURITY.md), which also says how to report one privately.

## What it protects

| Asset | Why it matters |
| --- | --- |
| Secrets in Terraform state | State holds passwords, keys and tokens in attributes, in outputs and in `terraform_remote_state` configuration |
| Your credentials | The cloud, backend and HCP Terraform credentials the command reads from your environment |
| The cloud and the state | Nothing the tool does should change either |
| The snapshot | It should be what the manifest says it is, and say who made it if you ask |
| An agent that reads the answers | Names and tags in a cloud account are chosen by whoever can create resources there |

## What it never stores

- **No attribute value and no output value.** State is read in memory, one resource at a time, and only the address, type, provider, module path, dependencies, `id`, `arn` and tags of each instance, the names of its outputs and the places a `terraform_remote_state` reads from are kept. Everything else is dropped as the state is read ([state.md](state.md#what-a-snapshot-keeps)). Tags (labels on Google Cloud) are read from state, and are the one value kept, after the secret detectors.
- **No credential, ever.** Credentials come from the environment's default chains and are never taken from a flag's value, printed, stored or sent. A hash key (`--hash-ids`) is never written: not to the snapshot, not to the manifest, not to standard output or error.
- **No secret-shaped identifier.** An `id` or ARN that has, or holds, the format of a credential, or is a URL with a user name, password or query parameter, is left out and counted in the manifest's `limits`; the ids of providers whose ids are free text or generated values (`random_*`, `http`, `external`, `local`, `null`, `time`, `archive`, `tls`) are not kept. Locations lose user names, passwords and unknown query parameters ([state.md](state.md#what-a-snapshot-keeps)).
- **No query text or row in the audit log.** The MCP audit log holds hashes and counts ([mcp.md](mcp.md#the-audit-log)).

## Redaction

Redaction is layered, and each layer has a test that plants secrets and fails if one comes out:

1. **The reader drops values.** Nothing that is not an identifier leaves the parser (`pkg/tfstate` in infraharvest, which this repository reads state through).
2. **Detectors filter what is kept.** `pkg/secretscan` checks IDs, ARNs, locations, names, addresses and tags. A tag is dropped when its key names a secret or its key or value has a credential's format or looks random enough to be one. The dropped keys are listed in `redaction.tag_keys_dropped`.
3. **You can drop more.** `--drop-tag KEY` and `--drop-tags` leave tags out; `--hash-ids` replaces IDs, names, addresses and state locations with an HMAC-SHA256 under your key, so a snapshot can leave the machine and still join other hashed data ([state.md](state.md#hashing-ids)); `--drop-addresses` leaves Terraform addresses, module paths and the Terraform names of resources and module calls out of the nodes (and the tags that hold or name one of them, including the names of module calls and `for_each` keys), with or without it (without `--hash-ids`, the node IDs of module calls, data sources and resources without an ID are unkeyed SHA-256 hashes of the state location and the address, which can confirm a guessed address) ([state.md](state.md#dropping-addresses)). Types, accounts, regions, kinds, statuses, counts and times stay readable: hashing hides names, not the shape of an estate.

The planted-secret tests build snapshots from states and inventories that hold secrets in attributes, outputs, remote state configuration, IDs, names and tags, and fail if any is in a file the command writes or on its output. A fuzz test (`FuzzStateIngest` in `internal/ingest`) does the same for mutated state documents, and checks that the same state always gives the same rows.

## Read-only and the network

- The code has no call that creates, updates or deletes a cloud resource or a state object. State stores are listed and read, with no lock taken. The only files written are the snapshot folder, the files you name (`--answer-out`, `-o`) and the audit log.
- The only network calls are to the backends you name, with your credentials. There is no telemetry and no update check. The one other connection is `snapshot sign --keyless`, which you ask for and which talks to Sigstore's public-good services ([signing.md](signing.md#signing-keyless)). HCP Terraform's token is sent only to that host's API, and dropped on a redirect anywhere else.
- Which permissions each backend needs, and nothing more, is in [permissions.md](permissions.md).

## Queries and agents

- **SQL is restricted.** One `SELECT` over four tables and two macros, an allow-list of functions, caps on rows, columns, bytes and time, and a session whose file access is off and configuration locked, with the data attached read-only for a long-lived server. The checker and the lock are tested separately, so a hole in one does not open the other ([sql-dialect.md](sql-dialect.md), [query.md](query.md)).
- **Answers are evidence.** An answer names its query, its snapshot, its caps and the age of its data, and `verify --answer` re-runs it.
- **The MCP server** opens no port, reads no cloud, takes no credential and writes only its audit log, created with mode 0600 and only appended to. `--tools` can leave out `query` so an agent cannot write SQL.
- **Names are data, not instructions.** Anyone who can name or tag a resource in the account can write text an agent will read in a result. The server's instructions and [SKILL.md](../SKILL.md) say so; a client that runs tools without asking should still show the agent's actions to a person ([mcp.md](mcp.md#what-the-server-does-not-protect-against)).

## Integrity and signing

A snapshot is content-addressed: the manifest holds the SHA-256 of every table and the snapshot ID is the hash of the manifest, so `verify` catches a changed byte anywhere. That shows the snapshot is whole, not who made it. `snapshot sign` adds a Sigstore bundle over the manifest, from a key you hold or a keyless CI identity, and `verify` checks it against a key or an identity you trust ([signing.md](signing.md)). `serve-mcp` refuses a snapshot that does not verify, and with `--require-signature` one that is not signed by whom you expect.

Releases are built by a workflow from a tag: the checksums file is signed with cosign keyless and each archive has a build-provenance attestation ([install.md](install.md#check-the-download)). Every GitHub Action is pinned by full commit SHA, workflows run with the least permissions that work, and the repository runs CodeQL, `govulncheck` and OpenSSF Scorecard.

## Limits of the model

- **Tags are the one value kept**, from states and inventories, after the detectors. With `--hash-ids`, a tag value that holds an identifier of its node (the ID, the name, the ARN or the cloud path) is hashed, and a tag whose key holds one is dropped. A tag that is sensitive and does not look it gets through; `--drop-tags` removes them all.
- **A hashed snapshot still shows the shape of the estate**: types, accounts, regions, counts and times. Two snapshots hashed with one key can be compared; keep the key.
- **A snapshot is as true as what it was read from.** `limits` says what is missing and the age of the oldest source; it cannot say what was never read.
- **The files are read once.** The query engine loads the bytes that were hashed, from a private copy the process makes, not the snapshot folder a second time, so a change made to the folder after `verify` is not served ([signing.md](signing.md#what-is-read-once)).
- **The engine is C++.** `govulncheck` cannot see DuckDB; read its security advisories when you bump the pinned version.
- **The identity that reads state can read its secrets.** The tool drops them in memory, but the role you give it can see them. Scope it to the state it needs ([permissions.md](permissions.md)).
- **Not covered:** vulnerabilities in Terraform, OpenTofu, DuckDB or the clouds themselves, and what someone does with an answer.
