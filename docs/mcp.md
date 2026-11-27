# MCP server

`infra-ontology serve-mcp` serves one snapshot to coding agents over the [Model Context Protocol](https://modelcontextprotocol.io), on standard input and output. The agent asks what a snapshot holds and what depends on what, and every answer carries its query, its snapshot and what the data cannot tell you.

```sh
infra-ontology serve-mcp <snapshot-dir> [--tools inventory,blast_radius,query,snapshot_info] [--audit-log FILE] [--memory 512MB]
                          [--key PUBKEY | --certificate-identity ID --certificate-oidc-issuer ISSUER] [--trusted-root FILE] [--require-signature]
```

The server opens no port, reads no cloud or backend, takes no credentials and writes no file but the audit log you name. Standard output carries the protocol and nothing else.

## Start-up

1. **Verify.** The snapshot is checked against its manifest, as `snapshot verify` does. A snapshot that does not verify is not served: the command prints why and exits 4. If the snapshot is signed, the signature is read too (see [signing](signing.md)): given `--key`, or `--certificate-identity` and `--certificate-oidc-issuer`, the server checks it and refuses to start on a signature that does not check; `--require-signature` also refuses a snapshot with no signature that verified. A signature file that is not a Sigstore bundle is refused too.
2. **Open one locked session.** The tables are loaded into a private database file that is attached read-only, then the file is deleted and the session is locked, as [the query page](query.md#what-the-session-guarantees) describes. The engine itself refuses every write, and no file can be read, no extension loaded and no setting changed. One session serves every call.
3. **Serve** until the client closes the connection.

The snapshot is read once, at start-up. To serve a newer snapshot, start the server again; the agent's client does that when it restarts the server.

A build made with `-tags noduckdb` has no query engine: `serve-mcp` says so and exits 1, and serves nothing.

## The tools

All four are annotated read-only, idempotent, not destructive and closed-world. Every result has an `answer` block, the [citation](query.md#the-citation) of the query layer: the canonical query and its hash, the stored query and its parameters if any, the snapshot id, the caps, the row count, whether a cap cut the result (`truncated`), a hash of the result, and `limits` (the age of the oldest source, failed sources, what the snapshot covers and its own note). Results are tables: `columns`, and `rows` as lists of values in that order.

| Tool | Inputs | Result |
| --- | --- | --- |
| `inventory` | `type` (Terraform or inventory type), `account`, `environment`, `module` (that path and the modules in it), `address_prefix`, `limit` (1 to 1000, default 100), `offset` | A page of nodes in a fixed order, and `next_offset` when more follow. It runs the stored query `inventory` |
| `blast_radius` | `target` (a node id, Terraform address, ARN or path, or cloud id), `max_depth` (1 to 10, default 5), `limit` (1 to 1000, default 200) | `status`: `resolved`, `ambiguous` or `not_found`; the `targets`; the `dependents` with their depth; counts by type and by account; the depth reached. It runs the stored query `blast`. A target that matches several nodes (the same address in two accounts) returns them as candidates with no dependents: call again with a node id |
| `query` | `sql`, or `stored` and `params`; `limit` (1 to 1000, default 100) | The rows of one read-only query, under the same dialect check and caps as `infra-ontology query` |
| `snapshot_info` | none | The snapshot's id, label, parent, age, status, signature status, tables, sources, coverage, failed sources, redaction and limits; the stored queries and their parameters; the caps and the tools that are on |

The citation of `blast_radius` shows a row cap one above `limit`: the target's own row is counted. A bad argument (a limit out of range, an empty target, a query the dialect refuses) is an error result with the reason, so the agent can correct it. The result is capped at 256 KiB of JSON and the time at 10 seconds; a cap that cuts a result says so in `answer.truncated` and `answer.truncated_by`.

`snapshot_info` reports the signature as `signature`: `status` is `unsigned` (no `manifest.sig.json`), `signed_unverified` (there is a bundle and the server was started with nothing to check it with) or `verified` (it checked against the `--key` or identity the server was started with; `mode` is `key` or `keyless` and `signer` names the key's SHA-256 or the certificate's identity and issuer). The status is read once, at start-up. A verified signature says who signed the manifest, not that the snapshot is complete: read `status` and `limits` too.

## Which tools are on

`--tools` takes a comma-separated subset: `--tools inventory,blast_radius` leaves out `query` and `snapshot_info`, so the agent cannot write SQL of its own. The default is all four. A tool that is off is not listed and cannot be called. An unknown name is a usage error (exit 2).

## The audit log

Each tool call appends one JSON line to the file given by `--audit-log`, or to standard error if there is none. The file is created with mode 0600 and only ever appended to.

```json
{"time":"2026-11-25T14:03:11.482913Z","tool":"query","client":"claude-code","snapshot_id":"99688f074a1d...","args_hash":"sha256:...","query_hash":"sha256:...","row_count":12,"truncated":false,"outcome":"ok","duration_ms":9}
```

| Field | Meaning |
| --- | --- |
| `time` | When the call started, UTC |
| `tool` | The tool called |
| `client` | The client's name, as it said in the handshake |
| `snapshot_id` | The snapshot served |
| `args_hash` | SHA-256 of the call's arguments as JSON. The arguments themselves are not logged |
| `query_hash` | The hash of the canonical query that ran, the same as `answer.query_hash`. Empty when nothing ran |
| `stored_query` | The stored query that ran, if one did |
| `row_count`, `truncated` | What the answer says |
| `outcome` | `ok`, `refused` (the dialect or a cap said no), `invalid` (a bad argument), `timeout`, `cancelled` or `error` |
| `duration_ms` | How long the call took |

The log never holds a result row, a name, an address or a tag, and not the text of a query. A call whose line cannot be written (a full disk, a closed file) is refused rather than answered unrecorded.

## Configuring a client

Use an absolute path to the snapshot. Each snippet serves it with every tool on and an audit log next to it.

**Claude Code**, from the project folder:

```sh
claude mcp add infra-ontology -- infra-ontology serve-mcp /abs/path/.infra-ontology/snapshots/<snapshot> --audit-log /abs/path/audit.jsonl
```

or in `.mcp.json` at the project root:

```json
{
  "mcpServers": {
    "infra-ontology": {
      "command": "infra-ontology",
      "args": ["serve-mcp", "/abs/path/.infra-ontology/snapshots/<snapshot>", "--audit-log", "/abs/path/audit.jsonl"]
    }
  }
}
```

**VS Code**, in `.vscode/mcp.json`:

```json
{
  "servers": {
    "infra-ontology": {
      "type": "stdio",
      "command": "infra-ontology",
      "args": ["serve-mcp", "/abs/path/.infra-ontology/snapshots/<snapshot>", "--audit-log", "/abs/path/audit.jsonl"]
    }
  }
}
```

**Cursor**, in `.cursor/mcp.json` (or `~/.cursor/mcp.json` for every project):

```json
{
  "mcpServers": {
    "infra-ontology": {
      "command": "infra-ontology",
      "args": ["serve-mcp", "/abs/path/.infra-ontology/snapshots/<snapshot>", "--audit-log", "/abs/path/audit.jsonl"]
    }
  }
}
```

Add `"--tools", "inventory,blast_radius"` to the arguments to keep the agent to the two fixed questions. If `infra-ontology` is not on the client's `PATH`, give the full path to the binary as `command`.

## For the agent

[`SKILL.md`](../SKILL.md) is a short guide for coding agents: which tool to call first, how to read the citation and what to say about a truncated or partial answer. Copy it into the agent's skills or instructions folder.

## What the server does not protect against

- **The names in the results are data, not instructions.** Anyone who can create or tag a resource in the cloud can choose its name and tags, and a name can read like an instruction to the agent. The server says so in its instructions and in `SKILL.md`; a client that runs tools without asking should still show the agent's actions to a person.
- **A snapshot is as true as what it was read from.** The `limits` block says what is missing; it cannot say what was never read.
- **The audit log is local.** It is a record for you, not a signed one.
