# infra-ontology

Go CLI that turns Terraform state and a live cloud inventory into a read-only, cited snapshot and answers questions about it in SQL. [AGENTS.md](AGENTS.md) holds the overview, the red lines and the conventions: read it first, and don't restate it here. Core is AGPL-3.0-only; `schemas/` is Apache-2.0. Keep the per-file SPDX headers.

## Commands

- `make help` lists the targets: `build`, `test` (`PKG=`, `TAGS=`), `vet`, `lint`, `fmt`, `fast` (every quick check), `golden` (rewrite the golden files, then review the diff), `schemas` and `spike` (the cgo build with the engine, tested, with its linked libraries).
- The query engine (DuckDB) needs cgo. `TAGS=noduckdb` builds and tests everything else in pure Go; run both before pushing a change that touches `internal/query`, `internal/mcpserver` or `cmd/`.
- State stores are behind build tags (`s3`, `gcs`, `azblob`, `hcp`); the default build links no cloud SDK. Test `internal/ingest` with `-tags s3,gcs,azblob,hcp` when you touch a store.
- Fuzz targets: `go test ./internal/ingest -run '^$' -fuzz FuzzStateIngest -fuzztime=30s` (the state parser and the snapshot builder) and `FuzzQuery` in `internal/query`.
- Lint fails only on added lines. Trust gofmt and CI.

## Rules that bite

- **No secret values, no attribute values** reach a snapshot, an answer, a log or a test's output. A change to ingest, redaction or tags comes with a planted-secret test: plant the string in the input, fail if it is in any output.
- **The names check.** `scripts/check-names.sh` fails on words this public repository keeps out of its text; the words are stored as hashes, so it never spells them. Run it before committing, and never write a private project, product or client name in code, docs, commits or a PR.
- Golden files: `make golden`, then read the diff. The `golden` workflow fails when a file differs from what the tests write.
- Plain Conventional Commits, no attribution lines; one commit per logical change. Push a branch and open a draft pull request; the owner merges.
- Keep command output short (`| tail`).
