# infra-ontology

Go CLI that turns Terraform state and a live cloud inventory into a read-only, cited snapshot, and answers questions about it in SQL, for people and coding agents. Core is AGPL-3.0-only; the `schemas/` directory is Apache-2.0. Keep the per-file SPDX headers. Early days: most of what the README describes isn't written yet.

## Commands

- `make help` lists the targets.
- `make build` builds `./infra-ontology`.
- `make test` runs `go test -race ./...`; narrow it with `make test PKG=./cmd/...`.
- `make vet` runs `go vet`; `make lint` runs golangci-lint with `.golangci.json`; `make fmt` formats.
- `make fast` runs the quick checks: gofmt, vet, `scripts/check-names.sh`, `reuse lint` and `actionlint`.
- Lint fails only on the lines a pull request adds.

## Red lines

These hold for every change. A change that breaks one doesn't merge.

- **No secret values, ever.** A snapshot holds no attribute values. State is parsed in memory and only identifiers are kept. Tags that look like credentials are dropped.
- **Read-only.** The code has no call that creates, updates or deletes a cloud resource or a state object. The only files it writes are the snapshot folder and the files the user names.
- **The user's own credentials.** They come from the environment's default chains, never from a flag's value, and are never printed, stored or sent.
- **No writes to the cloud.** No network calls except to the backends the user names. No telemetry, no update check.
- **Answers are evidence.** No answer without its query and snapshot. SQL is restricted, capped and read-only.

## Conventions

- Plain Conventional Commits for commits and PR titles, one commit per logical change, no attribution lines.
- Branch from `main`, push a branch and open a pull request; don't push to `main`.
- Every Go file starts with the two-line copyright and SPDX licence header shown in CONTRIBUTING.md; `reuse lint` checks it.
- Pin every GitHub Action by full SHA with a version comment; workflows default to `permissions: contents: read`.
- Keep command output short.
- State stores are optional: `internal/ingest` reads state through infraharvest's `pkg/tfstate`, and each cloud store is behind a build tag (`s3`, `gcs`, `azblob`, `hcp`) in a file of its own. The default build links no cloud SDK (CI checks `go list -deps`); release builds use all four tags.
